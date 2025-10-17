"""GDPR compliance scanner."""

import re
import json
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class GDPRViolation:
    """GDPR-specific violation."""
    
    article: str
    principle: str
    description: str
    severity: str
    resource: str
    evidence: Dict[str, Any]
    remediation: str


class GDPRScanner:
    """
    GDPR (General Data Protection Regulation) compliance scanner.
    
    Scans for:
    - Personal data processing without legal basis
    - Missing consent mechanisms
    - Data minimization violations
    - Storage limitation issues
    - Security measure inadequacies
    - Data subject rights implementation
    - Cross-border transfer violations
    - DPIA requirements
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize GDPR scanner."""
        self.config = config or {}
        self.violations: List[GDPRViolation] = []
        
        # GDPR principles
        self.principles = {
            "lawfulness": "Article 6 - Legal basis for processing",
            "fairness": "Article 5(1)(a) - Fair processing",
            "transparency": "Article 5(1)(a) - Transparent processing",
            "purpose_limitation": "Article 5(1)(b) - Purpose limitation",
            "data_minimization": "Article 5(1)(c) - Data minimization",
            "accuracy": "Article 5(1)(d) - Data accuracy",
            "storage_limitation": "Article 5(1)(e) - Storage limitation",
            "integrity_confidentiality": "Article 5(1)(f) - Security",
            "accountability": "Article 5(2) - Accountability"
        }
        
        # Personal data categories
        self.personal_data_categories = {
            "basic": ["name", "email", "phone", "address", "ip_address"],
            "sensitive": ["health", "biometric", "genetic", "racial", "religious", "political", "sexual_orientation"],
            "financial": ["bank_account", "credit_card", "income", "transaction_history"],
            "location": ["gps_coordinates", "geolocation", "tracking_data"],
            "online": ["cookies", "device_id", "browsing_history", "social_media"]
        }
    
    async def scan(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform GDPR compliance scan.
        
        Args:
            resource: Resource to scan (database, API, application, etc.)
            
        Returns:
            Scan results with violations and recommendations
        """
        try:
            logger.info(f"Starting GDPR scan for {resource.get('resource_id', 'unknown')}")
            
            self.violations = []
            
            # Article 6 - Lawfulness of processing
            await self._check_legal_basis(resource)
            
            # Article 7 - Conditions for consent
            await self._check_consent_mechanism(resource)
            
            # Article 5(1)(c) - Data minimization
            await self._check_data_minimization(resource)
            
            # Article 5(1)(e) - Storage limitation
            await self._check_storage_limitation(resource)
            
            # Article 32 - Security of processing
            await self._check_security_measures(resource)
            
            # Articles 15-22 - Data subject rights
            await self._check_data_subject_rights(resource)
            
            # Article 35 - Data Protection Impact Assessment
            await self._check_dpia_requirements(resource)
            
            # Articles 44-50 - Cross-border transfers
            await self._check_data_transfers(resource)
            
            # Article 30 - Records of processing
            await self._check_processing_records(resource)
            
            # Article 33 - Breach notification
            await self._check_breach_notification(resource)
            
            results = {
                "framework": "GDPR",
                "resource_id": resource.get("resource_id", "unknown"),
                "scan_timestamp": resource.get("scan_timestamp"),
                "violations": [self._violation_to_dict(v) for v in self.violations],
                "violation_count": len(self.violations),
                "compliance_score": self._calculate_compliance_score(),
                "critical_issues": self._get_critical_issues(),
                "recommendations": self._generate_recommendations()
            }
            
            logger.info(f"GDPR scan completed: {len(self.violations)} violations found")
            
            return results
            
        except Exception as e:
            logger.error(f"GDPR scan failed: {e}")
            raise
    
    async def _check_legal_basis(self, resource: Dict[str, Any]) -> None:
        """Check Article 6 - Legal basis for processing."""
        processing_activities = resource.get("processing_activities", [])
        
        for activity in processing_activities:
            legal_basis = activity.get("legal_basis")
            
            # Check if legal basis is specified
            if not legal_basis:
                self.violations.append(GDPRViolation(
                    article="Article 6",
                    principle="lawfulness",
                    description="No legal basis specified for personal data processing",
                    severity="critical",
                    resource=resource.get("resource_id", "unknown"),
                    evidence={
                        "activity": activity.get("activity_name", "unknown"),
                        "data_processed": activity.get("data_categories", [])
                    },
                    remediation="Identify and document legal basis (consent, contract, legal obligation, vital interests, public task, or legitimate interests)"
                ))
            
            # Check if consent is properly obtained when used as legal basis
            elif legal_basis == "consent":
                if not activity.get("consent_mechanism"):
                    self.violations.append(GDPRViolation(
                        article="Article 7",
                        principle="lawfulness",
                        description="Consent claimed as legal basis but no consent mechanism implemented",
                        severity="critical",
                        resource=resource.get("resource_id", "unknown"),
                        evidence={
                            "activity": activity.get("activity_name"),
                            "legal_basis": legal_basis
                        },
                        remediation="Implement valid consent mechanism with opt-in, granular choices, and easy withdrawal"
                    ))
    
    async def _check_consent_mechanism(self, resource: Dict[str, Any]) -> None:
        """Check Article 7 - Conditions for consent."""
        consent_config = resource.get("consent_management", {})
        
        if not consent_config.get("enabled", False):
            self.violations.append(GDPRViolation(
                article="Article 7",
                principle="lawfulness",
                description="No consent management system in place",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"consent_config": consent_config},
                remediation="Implement consent management system with granular controls and audit trail"
            ))
            return
        
        # Check for specific consent requirements
        if not consent_config.get("granular_choices", False):
            self.violations.append(GDPRViolation(
                article="Article 7(2)",
                principle="transparency",
                description="Consent mechanism lacks granular choices",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"consent_config": consent_config},
                remediation="Provide granular consent options for different processing purposes"
            ))
        
        if not consent_config.get("easy_withdrawal", False):
            self.violations.append(GDPRViolation(
                article="Article 7(3)",
                principle="fairness",
                description="No easy mechanism to withdraw consent",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"consent_config": consent_config},
                remediation="Implement easy-to-use consent withdrawal mechanism"
            ))
    
    async def _check_data_minimization(self, resource: Dict[str, Any]) -> None:
        """Check Article 5(1)(c) - Data minimization."""
        data_collection = resource.get("data_collection", {})
        processing_purposes = resource.get("processing_purposes", [])
        
        collected_fields = set(data_collection.get("fields", []))
        necessary_fields = set()
        
        for purpose in processing_purposes:
            necessary_fields.update(purpose.get("required_fields", []))
        
        # Check for unnecessary data collection
        unnecessary_fields = collected_fields - necessary_fields
        
        if unnecessary_fields:
            self.violations.append(GDPRViolation(
                article="Article 5(1)(c)",
                principle="data_minimization",
                description="Collecting more personal data than necessary for stated purposes",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={
                    "unnecessary_fields": list(unnecessary_fields),
                    "collected_fields": list(collected_fields),
                    "necessary_fields": list(necessary_fields)
                },
                remediation="Remove unnecessary data fields from collection forms and databases"
            ))
    
    async def _check_storage_limitation(self, resource: Dict[str, Any]) -> None:
        """Check Article 5(1)(e) - Storage limitation."""
        retention_policy = resource.get("retention_policy", {})
        
        if not retention_policy:
            self.violations.append(GDPRViolation(
                article="Article 5(1)(e)",
                principle="storage_limitation",
                description="No data retention policy defined",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"retention_policy": None},
                remediation="Define and implement data retention policy with specific retention periods"
            ))
            return
        
        # Check if retention periods are specified
        if not retention_policy.get("retention_periods"):
            self.violations.append(GDPRViolation(
                article="Article 5(1)(e)",
                principle="storage_limitation",
                description="Retention policy exists but no specific retention periods defined",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"retention_policy": retention_policy},
                remediation="Specify retention periods for each data category based on legal requirements and business needs"
            ))
        
        # Check for automated deletion
        if not retention_policy.get("automated_deletion", False):
            self.violations.append(GDPRViolation(
                article="Article 5(1)(e)",
                principle="storage_limitation",
                description="No automated deletion mechanism for expired data",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"retention_policy": retention_policy},
                remediation="Implement automated data deletion for records exceeding retention period"
            ))
    
    async def _check_security_measures(self, resource: Dict[str, Any]) -> None:
        """Check Article 32 - Security of processing."""
        security_config = resource.get("security", {})
        
        # Check encryption
        encryption = security_config.get("encryption", {})
        if not encryption.get("at_rest", False):
            self.violations.append(GDPRViolation(
                article="Article 32(1)(a)",
                principle="integrity_confidentiality",
                description="Personal data not encrypted at rest",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"encryption": encryption},
                remediation="Enable encryption at rest using AES-256 or equivalent"
            ))
        
        if not encryption.get("in_transit", False):
            self.violations.append(GDPRViolation(
                article="Article 32(1)(a)",
                principle="integrity_confidentiality",
                description="Personal data not encrypted in transit",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"encryption": encryption},
                remediation="Enable TLS 1.3 for all data transmissions"
            ))
        
        # Check access controls
        access_controls = security_config.get("access_controls", {})
        if not access_controls.get("authentication", False):
            self.violations.append(GDPRViolation(
                article="Article 32(1)(b)",
                principle="integrity_confidentiality",
                description="Inadequate authentication mechanisms",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"access_controls": access_controls},
                remediation="Implement strong authentication with MFA for access to personal data"
            ))
        
        # Check audit logging
        if not security_config.get("audit_logging", {}).get("enabled", False):
            self.violations.append(GDPRViolation(
                article="Article 32(1)(d)",
                principle="accountability",
                description="No audit logging for personal data access",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"audit_logging": security_config.get("audit_logging", {})},
                remediation="Enable comprehensive audit logging for all personal data operations"
            ))
    
    async def _check_data_subject_rights(self, resource: Dict[str, Any]) -> None:
        """Check Articles 15-22 - Data subject rights implementation."""
        rights_implementation = resource.get("data_subject_rights", {})
        
        required_rights = {
            "right_to_access": "Article 15",
            "right_to_rectification": "Article 16",
            "right_to_erasure": "Article 17",
            "right_to_restriction": "Article 18",
            "right_to_portability": "Article 20",
            "right_to_object": "Article 21"
        }
        
        for right, article in required_rights.items():
            if not rights_implementation.get(right, {}).get("implemented", False):
                self.violations.append(GDPRViolation(
                    article=article,
                    principle="transparency",
                    description=f"{right.replace('_', ' ').title()} not implemented",
                    severity="high",
                    resource=resource.get("resource_id", "unknown"),
                    evidence={"rights_implementation": rights_implementation},
                    remediation=f"Implement {right.replace('_', ' ')} with automated processing where possible"
                ))
    
    async def _check_dpia_requirements(self, resource: Dict[str, Any]) -> None:
        """Check Article 35 - Data Protection Impact Assessment requirements."""
        processing_activities = resource.get("processing_activities", [])
        dpia_conducted = resource.get("dpia_conducted", False)
        
        # Check if DPIA is required
        dpia_required = False
        risk_factors = []
        
        for activity in processing_activities:
            # Check for high-risk processing
            if activity.get("automated_decision_making", False):
                dpia_required = True
                risk_factors.append("Automated decision-making")
            
            if activity.get("large_scale_processing", False):
                dpia_required = True
                risk_factors.append("Large-scale processing")
            
            data_categories = activity.get("data_categories", [])
            if any(cat in self.personal_data_categories["sensitive"] for cat in data_categories):
                dpia_required = True
                risk_factors.append("Sensitive data processing")
        
        if dpia_required and not dpia_conducted:
            self.violations.append(GDPRViolation(
                article="Article 35",
                principle="accountability",
                description="DPIA required but not conducted",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"risk_factors": risk_factors},
                remediation="Conduct Data Protection Impact Assessment before processing"
            ))
    
    async def _check_data_transfers(self, resource: Dict[str, Any]) -> None:
        """Check Articles 44-50 - Cross-border data transfers."""
        data_transfers = resource.get("data_transfers", [])
        
        for transfer in data_transfers:
            destination = transfer.get("destination_country")
            
            # Check if transfer is to non-EU country
            if destination and destination not in self._get_adequate_countries():
                # Check for appropriate safeguards
                safeguards = transfer.get("safeguards", {})
                
                if not safeguards.get("standard_contractual_clauses", False) and \
                   not safeguards.get("binding_corporate_rules", False) and \
                   not safeguards.get("adequacy_decision", False):
                    self.violations.append(GDPRViolation(
                        article="Article 46",
                        principle="lawfulness",
                        description=f"International data transfer to {destination} without appropriate safeguards",
                        severity="critical",
                        resource=resource.get("resource_id", "unknown"),
                        evidence={
                            "destination": destination,
                            "safeguards": safeguards
                        },
                        remediation="Implement Standard Contractual Clauses (SCCs) or other appropriate safeguards"
                    ))
    
    async def _check_processing_records(self, resource: Dict[str, Any]) -> None:
        """Check Article 30 - Records of processing activities."""
        processing_records = resource.get("processing_records", {})
        
        if not processing_records.get("maintained", False):
            self.violations.append(GDPRViolation(
                article="Article 30",
                principle="accountability",
                description="No records of processing activities maintained",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"processing_records": processing_records},
                remediation="Create and maintain records of all processing activities (ROPA)"
            ))
    
    async def _check_breach_notification(self, resource: Dict[str, Any]) -> None:
        """Check Article 33 - Breach notification procedures."""
        breach_procedures = resource.get("breach_notification_procedures", {})
        
        if not breach_procedures.get("documented", False):
            self.violations.append(GDPRViolation(
                article="Article 33",
                principle="accountability",
                description="No documented breach notification procedures",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"breach_procedures": breach_procedures},
                remediation="Document breach notification procedures including 72-hour notification timeline"
            ))
        
        if not breach_procedures.get("notification_mechanism", False):
            self.violations.append(GDPRViolation(
                article="Article 33",
                principle="accountability",
                description="No automated breach notification mechanism",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"breach_procedures": breach_procedures},
                remediation="Implement automated breach detection and notification system"
            ))
    
    def _get_adequate_countries(self) -> Set[str]:
        """Get list of countries with adequacy decisions."""
        return {
            "Andorra", "Argentina", "Canada", "Faroe Islands", "Guernsey", "Israel",
            "Isle of Man", "Japan", "Jersey", "New Zealand", "Switzerland", "United Kingdom",
            "Uruguay", "South Korea"
        }
    
    def _calculate_compliance_score(self) -> float:
        """Calculate GDPR compliance score."""
        if not self.violations:
            return 100.0
        
        # Weight violations by severity
        severity_weights = {
            "critical": 10,
            "high": 5,
            "medium": 2,
            "low": 1,
            "informational": 0.5
        }
        
        total_deductions = sum(
            severity_weights.get(v.severity, 1) 
            for v in self.violations
        )
        
        # Calculate score (max 100 points)
        score = max(0, 100 - total_deductions)
        
        return round(score, 2)
    
    def _get_critical_issues(self) -> List[Dict[str, Any]]:
        """Get critical GDPR issues."""
        critical = [v for v in self.violations if v.severity == "critical"]
        
        return [self._violation_to_dict(v) for v in critical]
    
    def _generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        # Group violations by article
        by_article = {}
        for v in self.violations:
            if v.article not in by_article:
                by_article[v.article] = []
            by_article[v.article].append(v)
        
        # Generate recommendations
        for article, violations in sorted(by_article.items()):
            if violations:
                priority = "critical" if any(v.severity == "critical" for v in violations) else "high"
                
                recommendations.append({
                    "article": article,
                    "priority": priority,
                    "violation_count": len(violations),
                    "recommendation": violations[0].remediation,
                    "affected_areas": list(set([v.principle for v in violations]))
                })
        
        return recommendations
    
    def _violation_to_dict(self, violation: GDPRViolation) -> Dict[str, Any]:
        """Convert violation to dictionary."""
        return {
            "article": violation.article,
            "principle": violation.principle,
            "description": violation.description,
            "severity": violation.severity,
            "resource": violation.resource,
            "evidence": violation.evidence,
            "remediation": violation.remediation
        }
