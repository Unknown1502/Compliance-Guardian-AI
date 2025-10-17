"""Consent management system."""

from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ConsentStatus(Enum):
    """Consent status."""
    GRANTED = "granted"
    DENIED = "denied"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"
    PENDING = "pending"


class ProcessingPurpose(Enum):
    """Data processing purposes."""
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    PERSONALIZATION = "personalization"
    ESSENTIAL = "essential"
    RESEARCH = "research"
    THIRD_PARTY_SHARING = "third_party_sharing"


@dataclass
class ConsentRecord:
    """Individual consent record."""
    
    consent_id: str
    user_id: str
    purpose: str
    status: ConsentStatus
    granted_at: Optional[datetime] = None
    withdrawn_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    scope: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_valid(self) -> bool:
        """Check if consent is valid."""
        if self.status != ConsentStatus.GRANTED:
            return False
        
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        
        return True


class ConsentManager:
    """
    GDPR-compliant consent management system.
    
    Features:
    - Granular consent tracking
    - Purpose-based consent
    - Consent withdrawal
    - Expiration management
    - Audit trail
    - Consent reporting
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize consent manager."""
        self.config = config or {}
        
        # In-memory storage (use database in production)
        self.consents: Dict[str, ConsentRecord] = {}
        self.user_consents: Dict[str, List[str]] = {}  # user_id -> consent_ids
        
        # Default consent expiration
        self.default_expiration_days = config.get('consent_expiration_days', 365)
    
    async def grant_consent(
        self,
        user_id: str,
        purpose: str,
        scope: Optional[Set[str]] = None,
        expires_in_days: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ConsentRecord:
        """Grant consent for specific purpose."""
        try:
            consent_id = f"consent_{user_id}_{purpose}_{datetime.utcnow().timestamp()}"
            
            expires_in = expires_in_days or self.default_expiration_days
            expires_at = datetime.utcnow() + timedelta(days=expires_in)
            
            consent = ConsentRecord(
                consent_id=consent_id,
                user_id=user_id,
                purpose=purpose,
                status=ConsentStatus.GRANTED,
                granted_at=datetime.utcnow(),
                expires_at=expires_at,
                scope=scope or set(),
                metadata=metadata or {}
            )
            
            # Store consent
            self.consents[consent_id] = consent
            
            if user_id not in self.user_consents:
                self.user_consents[user_id] = []
            self.user_consents[user_id].append(consent_id)
            
            logger.info(f"Granted consent {consent_id} for user {user_id}, purpose: {purpose}")
            
            return consent
            
        except Exception as e:
            logger.error(f"Failed to grant consent: {e}")
            raise
    
    async def withdraw_consent(self, consent_id: str) -> bool:
        """Withdraw previously granted consent."""
        try:
            if consent_id not in self.consents:
                logger.warning(f"Consent {consent_id} not found")
                return False
            
            consent = self.consents[consent_id]
            consent.status = ConsentStatus.WITHDRAWN
            consent.withdrawn_at = datetime.utcnow()
            
            logger.info(f"Withdrew consent {consent_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to withdraw consent: {e}")
            raise
    
    async def check_consent(self, user_id: str, purpose: str, scope: Optional[str] = None) -> bool:
        """Check if user has valid consent for purpose."""
        try:
            user_consent_ids = self.user_consents.get(user_id, [])
            
            for consent_id in user_consent_ids:
                consent = self.consents.get(consent_id)
                
                if not consent or consent.purpose != purpose:
                    continue
                
                # Check if consent is valid
                if not consent.is_valid():
                    continue
                
                # Check scope if specified
                if scope and scope not in consent.scope:
                    continue
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to check consent: {e}")
            return False
    
    async def get_user_consents(self, user_id: str) -> List[ConsentRecord]:
        """Get all consents for user."""
        consent_ids = self.user_consents.get(user_id, [])
        return [self.consents[cid] for cid in consent_ids if cid in self.consents]
    
    async def get_active_consents(self, user_id: str) -> List[ConsentRecord]:
        """Get active (valid) consents for user."""
        all_consents = await self.get_user_consents(user_id)
        return [c for c in all_consents if c.is_valid()]
    
    async def update_consent_scope(self, consent_id: str, scope: Set[str]) -> bool:
        """Update consent scope."""
        try:
            if consent_id not in self.consents:
                logger.warning(f"Consent {consent_id} not found")
                return False
            
            consent = self.consents[consent_id]
            consent.scope = scope
            
            logger.info(f"Updated scope for consent {consent_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update consent scope: {e}")
            raise
    
    async def renew_consent(self, consent_id: str, expires_in_days: Optional[int] = None) -> bool:
        """Renew expiring consent."""
        try:
            if consent_id not in self.consents:
                logger.warning(f"Consent {consent_id} not found")
                return False
            
            consent = self.consents[consent_id]
            
            expires_in = expires_in_days or self.default_expiration_days
            consent.expires_at = datetime.utcnow() + timedelta(days=expires_in)
            
            if consent.status == ConsentStatus.EXPIRED:
                consent.status = ConsentStatus.GRANTED
            
            logger.info(f"Renewed consent {consent_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to renew consent: {e}")
            raise
    
    async def check_expiring_consents(self, days_threshold: int = 30) -> List[ConsentRecord]:
        """Find consents expiring within threshold."""
        threshold_date = datetime.utcnow() + timedelta(days=days_threshold)
        expiring = []
        
        for consent in self.consents.values():
            if (consent.status == ConsentStatus.GRANTED and 
                consent.expires_at and 
                consent.expires_at <= threshold_date):
                expiring.append(consent)
        
        return expiring
    
    async def expire_old_consents(self) -> int:
        """Expire consents past their expiration date."""
        expired_count = 0
        
        for consent in self.consents.values():
            if (consent.status == ConsentStatus.GRANTED and 
                consent.expires_at and 
                datetime.utcnow() > consent.expires_at):
                consent.status = ConsentStatus.EXPIRED
                expired_count += 1
        
        if expired_count > 0:
            logger.info(f"Expired {expired_count} consents")
        
        return expired_count
    
    async def get_consent_report(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Generate consent report."""
        if user_id:
            consents = await self.get_user_consents(user_id)
        else:
            consents = list(self.consents.values())
        
        by_status = {}
        by_purpose = {}
        
        for consent in consents:
            # By status
            status_key = consent.status.value
            if status_key not in by_status:
                by_status[status_key] = 0
            by_status[status_key] += 1
            
            # By purpose
            if consent.purpose not in by_purpose:
                by_purpose[consent.purpose] = 0
            by_purpose[consent.purpose] += 1
        
        active_consents = [c for c in consents if c.is_valid()]
        
        return {
            "total_consents": len(consents),
            "active_consents": len(active_consents),
            "by_status": by_status,
            "by_purpose": by_purpose,
            "user_id": user_id,
            "generated_at": datetime.utcnow().isoformat()
        }
    
    async def export_consents(self, user_id: str) -> Dict[str, Any]:
        """Export user's consent data (GDPR right to data portability)."""
        consents = await self.get_user_consents(user_id)
        
        return {
            "user_id": user_id,
            "export_date": datetime.utcnow().isoformat(),
            "consents": [
                {
                    "consent_id": c.consent_id,
                    "purpose": c.purpose,
                    "status": c.status.value,
                    "granted_at": c.granted_at.isoformat() if c.granted_at else None,
                    "withdrawn_at": c.withdrawn_at.isoformat() if c.withdrawn_at else None,
                    "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                    "scope": list(c.scope),
                    "metadata": c.metadata
                }
                for c in consents
            ]
        }
    
    async def delete_user_consents(self, user_id: str) -> int:
        """Delete all consents for user (GDPR right to erasure)."""
        try:
            consent_ids = self.user_consents.get(user_id, [])
            
            for consent_id in consent_ids:
                if consent_id in self.consents:
                    del self.consents[consent_id]
            
            if user_id in self.user_consents:
                del self.user_consents[user_id]
            
            logger.info(f"Deleted {len(consent_ids)} consents for user {user_id}")
            
            return len(consent_ids)
            
        except Exception as e:
            logger.error(f"Failed to delete user consents: {e}")
            raise
    
    async def validate_processing(self, user_id: str, purpose: str, data_items: List[str]) -> Dict[str, Any]:
        """Validate if data processing is allowed based on consent."""
        # Check if consent exists
        has_consent = await self.check_consent(user_id, purpose)
        
        if not has_consent:
            return {
                "allowed": False,
                "reason": "no_valid_consent",
                "message": f"No valid consent found for purpose: {purpose}"
            }
        
        # Check scope
        user_consent_ids = self.user_consents.get(user_id, [])
        matching_consents = [
            self.consents[cid] for cid in user_consent_ids
            if cid in self.consents and self.consents[cid].purpose == purpose
        ]
        
        if not matching_consents:
            return {
                "allowed": False,
                "reason": "no_matching_consent",
                "message": "No consent matches the purpose"
            }
        
        # Check if all data items are in scope
        consent = matching_consents[0]
        if consent.scope:
            unauthorized_items = [item for item in data_items if item not in consent.scope]
            if unauthorized_items:
                return {
                    "allowed": False,
                    "reason": "scope_violation",
                    "message": f"Items not in consent scope: {unauthorized_items}",
                    "unauthorized_items": unauthorized_items
                }
        
        return {
            "allowed": True,
            "consent_id": consent.consent_id,
            "expires_at": consent.expires_at.isoformat() if consent.expires_at else None
        }
