"""PCI DSS compliance scanner."""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PCIViolation:
    """PCI DSS-specific violation."""
    
    requirement: str
    control_objective: str
    description: str
    severity: str
    resource: str
    evidence: Dict[str, Any]
    remediation: str


class PCIScanner:
    """
    PCI DSS (Payment Card Industry Data Security Standard) compliance scanner.
    
    Scans for:
    - Build and Maintain a Secure Network (Req 1-2)
    - Protect Cardholder Data (Req 3-4)
    - Maintain Vulnerability Management Program (Req 5-6)
    - Implement Strong Access Control Measures (Req 7-9)
    - Regularly Monitor and Test Networks (Req 10-11)
    - Maintain Information Security Policy (Req 12)
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize PCI DSS scanner."""
        self.config = config or {}
        self.violations: List[PCIViolation] = []
        
        # PCI DSS requirements mapping
        self.requirements = {
            "req_1": "Install and maintain firewall configuration",
            "req_2": "Do not use vendor-supplied defaults",
            "req_3": "Protect stored cardholder data",
            "req_4": "Encrypt transmission of cardholder data",
            "req_5": "Use and regularly update anti-virus software",
            "req_6": "Develop and maintain secure systems",
            "req_7": "Restrict access to cardholder data by business need-to-know",
            "req_8": "Assign unique ID to each person with computer access",
            "req_9": "Restrict physical access to cardholder data",
            "req_10": "Track and monitor all access to network resources and cardholder data",
            "req_11": "Regularly test security systems and processes",
            "req_12": "Maintain policy that addresses information security"
        }
    
    async def scan(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Perform PCI DSS compliance scan."""
        try:
            logger.info(f"Starting PCI DSS scan for {resource.get('resource_id', 'unknown')}")
            
            self.violations = []
            
            # Requirement 1-2: Secure Network
            await self._check_network_security(resource)
            
            # Requirement 3-4: Protect Cardholder Data
            await self._check_cardholder_data_protection(resource)
            
            # Requirement 5-6: Vulnerability Management
            await self._check_vulnerability_management(resource)
            
            # Requirement 7-9: Access Control
            await self._check_access_control(resource)
            
            # Requirement 10-11: Monitoring and Testing
            await self._check_monitoring_testing(resource)
            
            # Requirement 12: Information Security Policy
            await self._check_security_policy(resource)
            
            results = {
                "framework": "PCI DSS",
                "resource_id": resource.get("resource_id", "unknown"),
                "violations": [self._violation_to_dict(v) for v in self.violations],
                "violation_count": len(self.violations),
                "compliance_score": self._calculate_compliance_score(),
                "critical_issues": self._get_critical_issues(),
                "recommendations": self._generate_recommendations()
            }
            
            logger.info(f"PCI DSS scan completed: {len(self.violations)} violations found")
            
            return results
            
        except Exception as e:
            logger.error(f"PCI DSS scan failed: {e}")
            raise
    
    async def _check_network_security(self, resource: Dict[str, Any]) -> None:
        """Check Requirements 1-2: Build and Maintain a Secure Network."""
        network_security = resource.get("network_security", {})
        
        # Requirement 1
        firewall_config = network_security.get("firewall", {})
        if not firewall_config.get("configured", False):
            self.violations.append(PCIViolation(
                requirement="1.1",
                control_objective="Install and maintain firewall configuration",
                description="No firewall configuration to protect cardholder data",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"firewall": firewall_config},
                remediation="Establish and implement firewall and router configuration standards"
            ))
        
        # Requirement 2
        if network_security.get("default_passwords_used", False):
            self.violations.append(PCIViolation(
                requirement="2.1",
                control_objective="Do not use vendor-supplied defaults",
                description="Vendor-supplied default passwords in use",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"default_passwords": True},
                remediation="Change all vendor-supplied defaults before installing system on network"
            ))
    
    async def _check_cardholder_data_protection(self, resource: Dict[str, Any]) -> None:
        """Check Requirements 3-4: Protect Cardholder Data."""
        data_protection = resource.get("data_protection", {})
        
        # Requirement 3
        storage = data_protection.get("storage", {})
        if storage.get("unencrypted_pan", False):
            self.violations.append(PCIViolation(
                requirement="3.4",
                control_objective="Protect stored cardholder data",
                description="Primary Account Number (PAN) stored without encryption",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"unencrypted_data": True},
                remediation="Render PAN unreadable using strong cryptography with associated key-management"
            ))
        
        if storage.get("retention_period_days", 0) > 90:
            self.violations.append(PCIViolation(
                requirement="3.1",
                control_objective="Protect stored cardholder data",
                description="Cardholder data retained longer than necessary",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"retention_days": storage.get("retention_period_days", 0)},
                remediation="Limit data retention time to business, legal, regulatory requirements only"
            ))
        
        # Requirement 4
        transmission = data_protection.get("transmission", {})
        if not transmission.get("encrypted", False):
            self.violations.append(PCIViolation(
                requirement="4.1",
                control_objective="Encrypt transmission of cardholder data",
                description="Cardholder data transmitted over open, public networks without encryption",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"transmission": transmission},
                remediation="Use strong cryptography and security protocols (TLS 1.2+, SSH, etc.)"
            ))
    
    async def _check_vulnerability_management(self, resource: Dict[str, Any]) -> None:
        """Check Requirements 5-6: Maintain Vulnerability Management Program."""
        vuln_management = resource.get("vulnerability_management", {})
        
        # Requirement 5
        antivirus = vuln_management.get("antivirus", {})
        if not antivirus.get("deployed", False):
            self.violations.append(PCIViolation(
                requirement="5.1",
                control_objective="Use and regularly update anti-virus software",
                description="No anti-virus software on systems commonly affected by malware",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"antivirus": antivirus},
                remediation="Deploy anti-virus software on all systems affected by malicious software"
            ))
        
        # Requirement 6
        secure_development = vuln_management.get("secure_development", {})
        if not secure_development.get("training_conducted", False):
            self.violations.append(PCIViolation(
                requirement="6.5",
                control_objective="Develop and maintain secure systems",
                description="No secure coding training for developers",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"training": secure_development},
                remediation="Train developers in secure coding techniques and vulnerability prevention"
            ))
        
        if not vuln_management.get("vulnerability_scanning", {}).get("quarterly", False):
            self.violations.append(PCIViolation(
                requirement="11.2",
                control_objective="Regularly test security systems",
                description="No quarterly vulnerability scans performed",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"scanning": vuln_management.get("vulnerability_scanning", {})},
                remediation="Perform quarterly internal and external vulnerability scans"
            ))
    
    async def _check_access_control(self, resource: Dict[str, Any]) -> None:
        """Check Requirements 7-9: Implement Strong Access Control Measures."""
        access_control = resource.get("access_control", {})
        
        # Requirement 7
        if not access_control.get("need_to_know", {}).get("enforced", False):
            self.violations.append(PCIViolation(
                requirement="7.1",
                control_objective="Restrict access by business need-to-know",
                description="Access not restricted based on job role and function",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"access_control": access_control},
                remediation="Limit access to cardholder data to only those whose job requires such access"
            ))
        
        # Requirement 8
        user_ids = access_control.get("user_identification", {})
        if not user_ids.get("unique_per_user", False):
            self.violations.append(PCIViolation(
                requirement="8.1",
                control_objective="Assign unique ID to each person",
                description="Shared or generic user IDs in use",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"user_ids": user_ids},
                remediation="Assign unique ID before allowing access and authenticate users"
            ))
        
        mfa = access_control.get("multi_factor_authentication", {})
        if not mfa.get("enabled", False):
            self.violations.append(PCIViolation(
                requirement="8.3",
                control_objective="Secure remote access",
                description="No multi-factor authentication for remote access",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"mfa": mfa},
                remediation="Implement multi-factor authentication for all remote network access"
            ))
        
        # Requirement 9
        physical_access = access_control.get("physical_access", {})
        if not physical_access.get("restricted", False):
            self.violations.append(PCIViolation(
                requirement="9.1",
                control_objective="Restrict physical access",
                description="Inadequate physical access controls to cardholder data",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"physical_access": physical_access},
                remediation="Use facility entry controls to limit and monitor physical access to systems"
            ))
    
    async def _check_monitoring_testing(self, resource: Dict[str, Any]) -> None:
        """Check Requirements 10-11: Regularly Monitor and Test Networks."""
        monitoring = resource.get("monitoring", {})
        
        # Requirement 10
        logging = monitoring.get("logging", {})
        if not logging.get("enabled", False):
            self.violations.append(PCIViolation(
                requirement="10.1",
                control_objective="Track and monitor all access",
                description="No logging mechanism for user access to cardholder data",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"logging": logging},
                remediation="Implement audit trails to link all access to cardholder data to individual users"
            ))
        
        if logging.get("retention_days", 0) < 90:
            self.violations.append(PCIViolation(
                requirement="10.7",
                control_objective="Retain audit trail history",
                description="Audit logs not retained for at least one year",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"retention_days": logging.get("retention_days", 0)},
                remediation="Retain audit trail history for at least one year, with minimum 90 days immediately available"
            ))
        
        # Requirement 11
        penetration_testing = monitoring.get("penetration_testing", {})
        if not penetration_testing.get("annual", False):
            self.violations.append(PCIViolation(
                requirement="11.3",
                control_objective="Regularly test security systems",
                description="No annual penetration testing performed",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"pen_testing": penetration_testing},
                remediation="Perform external and internal penetration testing at least annually"
            ))
    
    async def _check_security_policy(self, resource: Dict[str, Any]) -> None:
        """Check Requirement 12: Maintain Information Security Policy."""
        security_policy = resource.get("security_policy", {})
        
        if not security_policy.get("documented", False):
            self.violations.append(PCIViolation(
                requirement="12.1",
                control_objective="Maintain information security policy",
                description="No documented information security policy",
                severity="critical",
                resource=resource.get("resource_id", "unknown"),
                evidence={"policy": security_policy},
                remediation="Establish, publish, maintain, and disseminate security policy"
            ))
        
        if not security_policy.get("annual_review", False):
            self.violations.append(PCIViolation(
                requirement="12.1.1",
                control_objective="Review security policy annually",
                description="Security policy not reviewed at least annually",
                severity="medium",
                resource=resource.get("resource_id", "unknown"),
                evidence={"policy_review": security_policy},
                remediation="Review security policy at least annually and update when environment changes"
            ))
        
        incident_response = security_policy.get("incident_response", {})
        if not incident_response.get("plan_documented", False):
            self.violations.append(PCIViolation(
                requirement="12.10",
                control_objective="Implement incident response plan",
                description="No incident response plan in place",
                severity="high",
                resource=resource.get("resource_id", "unknown"),
                evidence={"incident_response": incident_response},
                remediation="Create incident response plan and be prepared to respond immediately to system breach"
            ))
    
    def _calculate_compliance_score(self) -> float:
        """Calculate PCI DSS compliance score."""
        if not self.violations:
            return 100.0
        
        severity_weights = {"critical": 15, "high": 8, "medium": 3, "low": 1}
        total_deductions = sum(severity_weights.get(v.severity, 1) for v in self.violations)
        
        return max(0, round(100 - total_deductions, 2))
    
    def _get_critical_issues(self) -> List[Dict[str, Any]]:
        """Get critical PCI DSS issues."""
        return [self._violation_to_dict(v) for v in self.violations if v.severity == "critical"]
    
    def _generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate prioritized recommendations."""
        recommendations = []
        by_requirement = {}
        
        for v in self.violations:
            if v.requirement not in by_requirement:
                by_requirement[v.requirement] = []
            by_requirement[v.requirement].append(v)
        
        for requirement, violations in sorted(by_requirement.items()):
            priority = "critical" if any(v.severity == "critical" for v in violations) else "high"
            recommendations.append({
                "requirement": requirement,
                "control_objective": violations[0].control_objective,
                "priority": priority,
                "violation_count": len(violations),
                "recommendation": violations[0].remediation
            })
        
        return recommendations
    
    def _violation_to_dict(self, violation: PCIViolation) -> Dict[str, Any]:
        """Convert violation to dictionary."""
        return {
            "requirement": violation.requirement,
            "control_objective": violation.control_objective,
            "description": violation.description,
            "severity": violation.severity,
            "resource": violation.resource,
            "evidence": violation.evidence,
            "remediation": violation.remediation
        }
