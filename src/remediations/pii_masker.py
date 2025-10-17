"""PII masking and tokenization system."""

import re
import hashlib
import secrets
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from ..utils.logger import get_logger
from ..utils.encryption import EncryptionManager

logger = get_logger(__name__)


class MaskingStrategy(Enum):
    """PII masking strategies."""
    FULL_MASK = "full_mask"          # Replace all with ***
    PARTIAL_MASK = "partial_mask"    # Keep first/last chars
    TOKENIZE = "tokenize"            # Replace with reversible token
    HASH = "hash"                    # One-way hash
    REDACT = "redact"                # Remove completely
    FORMAT_PRESERVE = "format_preserve"  # Keep format but randomize


@dataclass
class MaskingResult:
    """Result of masking operation."""
    
    original_value: str
    masked_value: str
    strategy: str
    field_type: str
    reversible: bool
    token_id: Optional[str] = None


class PIIMasker:
    """
    PII masking and tokenization system.
    
    Supports:
    - Automatic PII detection
    - Multiple masking strategies
    - Reversible tokenization
    - Format-preserving encryption
    - Batch processing
    - Audit trail
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize PII masker."""
        self.config = config or {}
        self.encryption_manager = EncryptionManager(config)
        
        # Token storage (in production, use encrypted database)
        self.token_store: Dict[str, str] = {}
        
        # PII patterns
        self._init_patterns()
    
    def _init_patterns(self) -> None:
        """Initialize PII detection patterns."""
        self.pii_patterns = {
            "ssn": {
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "default_strategy": MaskingStrategy.TOKENIZE
            },
            "credit_card": {
                "pattern": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
                "default_strategy": MaskingStrategy.PARTIAL_MASK
            },
            "email": {
                "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "default_strategy": MaskingStrategy.PARTIAL_MASK
            },
            "phone": {
                "pattern": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
                "default_strategy": MaskingStrategy.PARTIAL_MASK
            },
            "passport": {
                "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",
                "default_strategy": MaskingStrategy.TOKENIZE
            },
            "driver_license": {
                "pattern": r"\b[A-Z]{1,2}\d{6,8}\b",
                "default_strategy": MaskingStrategy.TOKENIZE
            },
            "ip_address": {
                "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
                "default_strategy": MaskingStrategy.PARTIAL_MASK
            },
            "date_of_birth": {
                "pattern": r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
                "default_strategy": MaskingStrategy.HASH
            }
        }
    
    async def mask_text(self, text: str, strategy: Optional[MaskingStrategy] = None) -> Tuple[str, List[MaskingResult]]:
        """
        Mask PII in text.
        
        Args:
            text: Text to mask
            strategy: Masking strategy (if None, uses default per PII type)
        
        Returns:
            Tuple of (masked_text, masking_results)
        """
        try:
            masked_text = text
            results = []
            
            for pii_type, config in self.pii_patterns.items():
                pattern = config["pattern"]
                matches = re.finditer(pattern, text)
                
                for match in matches:
                    original = match.group()
                    mask_strategy = strategy or config["default_strategy"]
                    
                    masked, result = await self._mask_value(original, pii_type, mask_strategy)
                    masked_text = masked_text.replace(original, masked, 1)
                    results.append(result)
            
            logger.info(f"Masked {len(results)} PII instances in text")
            
            return masked_text, results
            
        except Exception as e:
            logger.error(f"PII masking failed: {e}")
            raise
    
    async def mask_dict(self, data: Dict[str, Any], field_strategies: Optional[Dict[str, MaskingStrategy]] = None) -> Tuple[Dict[str, Any], List[MaskingResult]]:
        """
        Mask PII in dictionary.
        
        Args:
            data: Dictionary to mask
            field_strategies: Field-specific masking strategies
        
        Returns:
            Tuple of (masked_dict, masking_results)
        """
        field_strategies = field_strategies or {}
        masked_data = {}
        results = []
        
        for key, value in data.items():
            if isinstance(value, str):
                strategy = field_strategies.get(key)
                
                # Check if field name suggests PII
                pii_type = self._detect_pii_field(key)
                
                if pii_type:
                    if not strategy:
                        strategy = self.pii_patterns[pii_type]["default_strategy"]
                    
                    masked, result = await self._mask_value(value, pii_type, strategy)
                    masked_data[key] = masked
                    results.append(result)
                else:
                    # Still check content for PII patterns
                    masked_text, text_results = await self.mask_text(value, strategy)
                    masked_data[key] = masked_text
                    results.extend(text_results)
            
            elif isinstance(value, dict):
                masked_nested, nested_results = await self.mask_dict(value, field_strategies)
                masked_data[key] = masked_nested
                results.extend(nested_results)
            
            elif isinstance(value, list):
                masked_list = []
                for item in value:
                    if isinstance(item, dict):
                        masked_item, item_results = await self.mask_dict(item, field_strategies)
                        masked_list.append(masked_item)
                        results.extend(item_results)
                    elif isinstance(item, str):
                        masked_text, text_results = await self.mask_text(item)
                        masked_list.append(masked_text)
                        results.extend(text_results)
                    else:
                        masked_list.append(item)
                masked_data[key] = masked_list
            
            else:
                masked_data[key] = value
        
        return masked_data, results
    
    async def _mask_value(self, value: str, pii_type: str, strategy: MaskingStrategy) -> Tuple[str, MaskingResult]:
        """Apply masking strategy to value."""
        if strategy == MaskingStrategy.FULL_MASK:
            masked = "*" * len(value)
            reversible = False
            token_id = None
        
        elif strategy == MaskingStrategy.PARTIAL_MASK:
            masked = self._partial_mask(value, pii_type)
            reversible = False
            token_id = None
        
        elif strategy == MaskingStrategy.TOKENIZE:
            masked, token_id = await self._tokenize(value)
            reversible = True
        
        elif strategy == MaskingStrategy.HASH:
            masked = self._hash_value(value)
            reversible = False
            token_id = None
        
        elif strategy == MaskingStrategy.REDACT:
            masked = "[REDACTED]"
            reversible = False
            token_id = None
        
        elif strategy == MaskingStrategy.FORMAT_PRESERVE:
            masked = self._format_preserve_mask(value, pii_type)
            reversible = False
            token_id = None
        
        else:
            masked = value
            reversible = False
            token_id = None
        
        return masked, MaskingResult(
            original_value=value,
            masked_value=masked,
            strategy=strategy.value,
            field_type=pii_type,
            reversible=reversible,
            token_id=token_id
        )
    
    def _partial_mask(self, value: str, pii_type: str) -> str:
        """Partially mask value."""
        if pii_type == "email":
            local, domain = value.split("@")
            if len(local) <= 2:
                return f"{'*' * len(local)}@{domain}"
            return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"
        
        elif pii_type == "credit_card":
            digits = re.sub(r'[^0-9]', '', value)
            return f"{'*' * (len(digits) - 4)}{digits[-4:]}"
        
        elif pii_type == "phone":
            digits = re.sub(r'[^0-9]', '', value)
            return f"***-***-{digits[-4:]}"
        
        elif pii_type == "ip_address":
            parts = value.split(".")
            return f"{parts[0]}.{parts[1]}.***.**"
        
        else:
            if len(value) <= 4:
                return "*" * len(value)
            return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
    
    async def _tokenize(self, value: str) -> Tuple[str, str]:
        """Create reversible token for value."""
        # Generate unique token
        token_id = f"TOK_{secrets.token_hex(16)}"
        
        # Encrypt and store
        encrypted = await self.encryption_manager.encrypt(value.encode())
        self.token_store[token_id] = encrypted.hex()
        
        return token_id, token_id
    
    async def detokenize(self, token_id: str) -> Optional[str]:
        """Reverse tokenization."""
        try:
            encrypted_hex = self.token_store.get(token_id)
            if not encrypted_hex:
                logger.warning(f"Token not found: {token_id}")
                return None
            
            encrypted = bytes.fromhex(encrypted_hex)
            decrypted = await self.encryption_manager.decrypt(encrypted)
            return decrypted.decode()
            
        except Exception as e:
            logger.error(f"Detokenization failed: {e}")
            return None
    
    def _hash_value(self, value: str) -> str:
        """One-way hash of value."""
        return hashlib.sha256(value.encode()).hexdigest()[:16]
    
    def _format_preserve_mask(self, value: str, pii_type: str) -> str:
        """Mask while preserving format."""
        if pii_type == "ssn":
            return f"{secrets.randbelow(1000):03d}-{secrets.randbelow(100):02d}-{secrets.randbelow(10000):04d}"
        
        elif pii_type == "credit_card":
            return f"{secrets.randbelow(10000):04d} {secrets.randbelow(10000):04d} {secrets.randbelow(10000):04d} {secrets.randbelow(10000):04d}"
        
        elif pii_type == "phone":
            return f"{secrets.randbelow(1000):03d}-{secrets.randbelow(1000):03d}-{secrets.randbelow(10000):04d}"
        
        else:
            # Randomize each character based on type
            result = []
            for char in value:
                if char.isdigit():
                    result.append(str(secrets.randbelow(10)))
                elif char.isalpha():
                    if char.isupper():
                        result.append(chr(65 + secrets.randbelow(26)))
                    else:
                        result.append(chr(97 + secrets.randbelow(26)))
                else:
                    result.append(char)
            return ''.join(result)
    
    def _detect_pii_field(self, field_name: str) -> Optional[str]:
        """Detect PII type from field name."""
        field_lower = field_name.lower()
        
        pii_keywords = {
            "ssn": ["ssn", "social_security", "social_security_number"],
            "credit_card": ["credit_card", "cc_number", "card_number", "pan"],
            "email": ["email", "email_address"],
            "phone": ["phone", "phone_number", "mobile", "telephone"],
            "passport": ["passport", "passport_number"],
            "driver_license": ["driver_license", "dl_number", "license_number"],
            "date_of_birth": ["dob", "date_of_birth", "birth_date", "birthdate"]
        }
        
        for pii_type, keywords in pii_keywords.items():
            if any(keyword in field_lower for keyword in keywords):
                return pii_type
        
        return None
    
    async def batch_mask(self, items: List[Dict[str, Any]], field_strategies: Optional[Dict[str, MaskingStrategy]] = None) -> Tuple[List[Dict[str, Any]], List[MaskingResult]]:
        """Batch mask multiple items."""
        masked_items = []
        all_results = []
        
        for item in items:
            masked_item, results = await self.mask_dict(item, field_strategies)
            masked_items.append(masked_item)
            all_results.extend(results)
        
        logger.info(f"Batch masked {len(items)} items, {len(all_results)} PII instances")
        
        return masked_items, all_results
    
    def get_masking_report(self, results: List[MaskingResult]) -> Dict[str, Any]:
        """Generate masking report."""
        by_type = {}
        by_strategy = {}
        reversible_count = 0
        
        for result in results:
            # By type
            if result.field_type not in by_type:
                by_type[result.field_type] = 0
            by_type[result.field_type] += 1
            
            # By strategy
            if result.strategy not in by_strategy:
                by_strategy[result.strategy] = 0
            by_strategy[result.strategy] += 1
            
            # Reversible count
            if result.reversible:
                reversible_count += 1
        
        return {
            "total_masked": len(results),
            "by_type": by_type,
            "by_strategy": by_strategy,
            "reversible_count": reversible_count,
            "tokens_generated": len([r for r in results if r.token_id])
        }
