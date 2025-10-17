"""HIPAA compliance scanner."""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class HIPAAViolation:
    """HIPAA-specific violation."""
    
    regulation: str
    safeguard_type: str
    description: str
    severity: str
    resource: str
    evidence: Dict[str, Any]
    remediation: str


class HIPAAScanner:
    """
    HIPAA (Health Insurance Portability and Accountability Act) compliance scanner.
    
    Scans for:
    - Administrative safeguards (164.308)
    - Physical safeguards (164.310)
    - Technical safeguards (164.312)
    - Organizational requirements (164.314)
    - PHI protection measures
    - Access controls and audit logs
    - Breach notification procedures
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize HIPAA scanner."""
        self.config = config or {}
        self.violations: List[HIPAAViolation] = []
    
    async def scan(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Perform HIPAA compliance scan."""
        try:
            logger.info(f"Starting HIPAA scan for {resource.get('resource_id', 'unknown')}")
            
            self.violations = []
            
            # Administrative Safeguards (164.308)
            await self._check_administrative_safeguards(resource)
            
            # Physical Safeguards (164.310)
            await self._check_physical_safeguards(resource)
            
            # Technical Safeguards (164.312)
            await self._check_technical_safeguards(resource)
            
            # Organizational Requirements (164.314)
            await self._check_organizational_requirements(resource)
            
            # Breach Notification (164.402-414)
            await self._check_breach_notification(resource)
            
            results = {
                "framework": "HIPAA",
                "resource_id": resource.get("resource_id", "unknown"),
                "violations": [self._violation_to_dict(v) for v in self.violations],
                "violation_count": len(self.violations),
                "compliance_score": self._calculate_compliance_score(),
                "critical_issues": self._get_critical_issues(),
                "recommendations": self._generate_recommendations()
            }
            
            logger.info(f"HIPAA scan completed: {len(self.violations)} violations found")
            
            return results
            
        except Exception as e:
            logger.error(f"HIPAA scan failed: {e}")
            raise
    
    async def _check_administrative_safeguards(self, resource: Dict[str, Any]) -> None:
        """Check 164.308 - Administrative Safeguards."""
        admin_safeguards = resource.get("administrative_safeguards", {})
        
        # 164.308(a)(1) - Security Management Process
        if not admin_safeguards.get("risk_analysis_conducted", False):
            self.violations.append(HIPAAViolation(
                regulation="164.308(a)(1)(ii)(A)",
                safeguard_type="administrative",
                description="No risk analysis conducted",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"admin_safeguards": admin_safeguards},
                remediation="Conduct accurate and thorough assessment of potential risks to ePHI"
            ))
        
        # 164.308(a)(3) - Workforce Security
        if not admin_safeguards.get("workforce_training", {}).get("conducted", False):
            self.violations.append(HIPAAViolation(
                regulation="164.308(a)(5)",
                safeguard_type="administrative",
                description="No security awareness training for workforce",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"training": admin_safeguards.get("workforce_training", {})},
                remediation="Implement security awareness and training program for all workforce members"
            ))
        
        # 164.308(a)(6) - Security Incident Procedures
        if not admin_safeguards.get("incident_response_plan", {}).get("documented", False):
            self.violations.append(HIPAAViolation(
                regulation="164.308(a)(6)(i)",
                safeguard_type="administrative",
                description="No documented security incident response plan",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"incident_plan": admin_safeguards.get("incident_response_plan", {})},
                remediation="Develop and implement security incident response and reporting procedures"
            ))
    
    async def _check_physical_safeguards(self, resource: Dict[str, Any]) -> None:
        """Check 164.310 - Physical Safeguards."""
        physical_safeguards = resource.get("physical_safeguards", {})
        
        # 164.310(a)(1) - Facility Access Controls
        if not physical_safeguards.get("facility_access_controls", {}).get("implemented", False):
            self.violations.append(HIPAAViolation(
                regulation="164.310(a)(1)",
                safeguard_type="physical",
                description="Inadequate facility access controls",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"facility_controls": physical_safeguards.get("facility_access_controls", {})},
                remediation="Implement policies and procedures to limit physical access to ePHI"
            ))
        
        # 164.310(d)(1) - Device and Media Controls
        if not physical_safeguards.get("media_disposal", {}).get("documented", False):
            self.violations.append(HIPAAViolation(
                regulation="164.310(d)(2)(i)",
                safeguard_type="physical",
                description="No documented media disposal procedures",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"media_disposal": physical_safeguards.get("media_disposal", {})},
                remediation="Implement secure disposal procedures for hardware and media containing ePHI"
            ))
    
    async def _check_technical_safeguards(self, resource: Dict[str, Any]) -> None:
        """Check 164.312 - Technical Safeguards."""
        technical_safeguards = resource.get("technical_safeguards", {})
        
        # 164.312(a)(1) - Access Control
        access_control = technical_safeguards.get("access_control", {})
        if not access_control.get("unique_user_id", False):
            self.violations.append(HIPAAViolation(
                regulation="164.312(a)(2)(i)",
                safeguard_type="technical",
                description="No unique user identification for ePHI access",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"access_control": access_control},
                remediation="Assign unique user ID for identifying and tracking user identity"
            ))
        
        if not access_control.get("automatic_logoff", False):
            self.violations.append(HIPAAViolation(
                regulation="164.312(a)(2)(iii)",
                safeguard_type="technical",
                description="No automatic logoff mechanism",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"access_control": access_control},
                remediation="Implement automatic logoff after period of inactivity"
            ))
        
        # 164.312(b) - Audit Controls
        if not technical_safeguards.get("audit_controls", {}).get("enabled", False):
            self.violations.append(HIPAAViolation(
                regulation="164.312(b)",
                safeguard_type="technical",
                description="No audit controls for ePHI access",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"audit_controls": technical_safeguards.get("audit_controls", {})},
                remediation="Implement hardware, software, and procedural mechanisms to record and examine ePHI access"
            ))
        
        # 164.312(c)(1) - Integrity Controls
        if not technical_safeguards.get("integrity_controls", {}).get("implemented", False):
            self.violations.append(HIPAAViolation(
                regulation="164.312(c)(1)",
                safeguard_type="technical",
                description="No integrity controls for ePHI",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"integrity_controls": technical_safeguards.get("integrity_controls", {})},
                remediation="Implement mechanisms to ensure ePHI is not improperly altered or destroyed"
            ))
        
        # 164.312(d) - Person or Entity Authentication
        if not technical_safeguards.get("authentication", {}).get("implemented", False):
            self.violations.append(HIPAAViolation(
                regulation="164.312(d)",
                safeguard_type="technical",
                description="Inadequate authentication mechanisms",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"authentication": technical_safeguards.get("authentication", {})},
                remediation="Implement procedures to verify person or entity seeking access to ePHI is authorized"
            ))
        
        # 164.312(e)(1) - Transmission Security
        encryption = technical_safeguards.get("encryption", {})
        if not encryption.get("in_transit", False):
            self.violations.append(HIPAAViolation(
                regulation="164.312(e)(2)(ii)",
                safeguard_type="technical",
                description="ePHI transmitted without encryption",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"encryption": encryption},
                remediation="Implement encryption for ePHI transmission over electronic networks"
            ))
    
    async def _check_organizational_requirements(self, resource: Dict[str, Any]) -> None:
        """Check 164.314 - Organizational Requirements."""
        org_requirements = resource.get("organizational_requirements", {})
        
        # 164.314(a)(1) - Business Associate Contracts
        ba_agreements = org_requirements.get("business_associate_agreements", {})
        if not ba_agreements.get("in_place", False):
            self.violations.append(HIPAAViolation(
                regulation="164.314(a)(1)",
                safeguard_type="organizational",
                description="No Business Associate Agreements in place",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"ba_agreements": ba_agreements},
                remediation="Obtain satisfactory assurances from business associates through written contracts"
            ))
    
    async def _check_breach_notification(self, resource: Dict[str, Any]) -> None:
        """Check 164.402-414 - Breach Notification Rule."""
        breach_notification = resource.get("breach_notification", {})
        
        if not breach_notification.get("procedures_documented", False):
            self.violations.append(HIPAAViolation(
                regulation="164.404",
                safeguard_type="administrative",
                description="No documented breach notification procedures",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"breach_notification": breach_notification},
                remediation="Document procedures for notifying individuals within 60 days of breach discovery"
            ))
    
    def _calculate_compliance_score(self) -> float:
        """Calculate HIPAA compliance score."""
        if not self.violations:
            return 100.0
        
        severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
        total_deductions = sum(severity_weights.get(v.severity, 1) for v in self.violations)
        
        return max(0, round(100 - total_deductions, 2))
    
    def _get_critical_issues(self) -> List[Dict[str, Any]]:
        """Get critical HIPAA issues."""
        return [self._violation_to_dict(v) for v in self.violations if v.severity == "critical"]
    
    def _generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate prioritized recommendations."""
        recommendations = []
        by_regulation = {}
        
        for v in self.violations:
            if v.regulation not in by_regulation:
                by_regulation[v.regulation] = []
            by_regulation[v.regulation].append(v)
        
        for regulation, violations in sorted(by_regulation.items()):
            priority = "critical" if any(v.severity == "critical" for v in violations) else "high"
            recommendations.append({
                "regulation": regulation,
                "priority": priority,
                "violation_count": len(violations),
                "recommendation": violations[0].remediation
            })
        
        return recommendations
    
    def _violation_to_dict(self, violation: HIPAAViolation) -> Dict[str, Any]:
        """Convert violation to dictionary."""
        return {
            "regulation": violation.regulation,
            "safeguard_type": violation.safeguard_type,
            "description": violation.description,
            "severity": violation.severity,
            "resource": violation.resource,
            "evidence": violation.evidence,
            "remediation": violation.remediation
        }
