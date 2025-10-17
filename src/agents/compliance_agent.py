"""Compliance Agent - Specialized agent for compliance scanning and policy enforcement."""

import asyncio
import json
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import time

from .base_agent import BaseAgent, AgentTask, AgentStatus, AgentCapability
from ..core.bedrock_client import BedrockResponse
from ..utils.logger import get_logger
from ..utils.validators import validate_scan_request, validate_pii_data

logger = get_logger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    ISO27001 = "iso27001"
    CCPA = "ccpa"
    NIST = "nist"


class ViolationType(Enum):
    """Types of compliance violations."""
    DATA_EXPOSURE = "data_exposure"
    INSUFFICIENT_ENCRYPTION = "insufficient_encryption"
    ACCESS_CONTROL = "access_control"
    AUDIT_LOGGING = "audit_logging"
    DATA_RETENTION = "data_retention"
    CONSENT_MANAGEMENT = "consent_management"
    PRIVACY_NOTICE = "privacy_notice"
    DATA_MINIMIZATION = "data_minimization"
    BREACH_NOTIFICATION = "breach_notification"
    VENDOR_MANAGEMENT = "vendor_management"


class SeverityLevel(Enum):
    """Severity levels for violations."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class ComplianceViolation:
    """Represents a compliance violation."""
    
    violation_id: str
    violation_type: ViolationType
    severity: SeverityLevel
    framework: ComplianceFramework
    resource_id: str
    resource_type: str
    description: str
    evidence: Dict[str, Any]
    regulation_reference: str
    remediation_guidance: str
    risk_score: float = 0.0
    financial_impact: float = 0.0
    detected_at: float = field(default_factory=time.time)
    auto_remediatable: bool = False
    remediation_status: str = "pending"


@dataclass
class CompliancePolicy:
    """Represents a compliance policy rule."""
    
    policy_id: str
    framework: ComplianceFramework
    policy_name: str
    description: str
    regulation_reference: str
    severity: SeverityLevel
    detection_rules: List[Dict[str, Any]]
    remediation_actions: List[Dict[str, Any]]
    enabled: bool = True
    last_updated: float = field(default_factory=time.time)


class ComplianceAgent(BaseAgent):
    """
    Compliance Agent specializes in compliance scanning and policy enforcement.
    
    Responsibilities:
    - Multi-framework compliance scanning (GDPR, HIPAA, PCI DSS, etc.)
    - PII and sensitive data detection
    - Policy rule interpretation and enforcement
    - Real-time compliance monitoring
    - Violation detection and classification
    - Risk assessment and scoring
    """
    
    def __init__(self, config: Dict[str, Any], **kwargs):
        """Initialize Compliance Agent."""
        super().__init__(
            agent_id="compliance-agent",
            config=config,
            **kwargs
        )
        
        # Compliance-specific state
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.detected_violations: List[ComplianceViolation] = []
        self.compliance_policies: Dict[str, CompliancePolicy] = {}
        
        # PII Detection patterns
        self.pii_patterns = self._initialize_pii_patterns()
        
        # Load compliance policies
        self._load_compliance_policies()
        
        # Configuration
        self.max_concurrent_scans = config.get("max_concurrent_scans", 5)
        self.scan_depth = config.get("scan_depth", "comprehensive")
        self.auto_remediation_enabled = config.get("auto_remediation", True)
        
    def _initialize_capabilities(self) -> None:
        """Initialize compliance agent capabilities."""
        self.capabilities = {
            AgentCapability.COMPLIANCE_SCANNING,
            AgentCapability.RISK_ASSESSMENT,
            AgentCapability.POLICY_INTERPRETATION,
            AgentCapability.DATA_ANALYSIS
        }
    
    def _initialize_pii_patterns(self) -> Dict[str, List[str]]:
        """Initialize PII detection patterns."""
        return {
            "ssn": [
                r'\b\d{3}-\d{2}-\d{4}\b',
                r'\b\d{3}\s\d{2}\s\d{4}\b',
                r'\b\d{9}\b'
            ],
            "credit_card": [
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
                r'\b5[1-5][0-9]{14}\b',  # MasterCard
                r'\b3[47][0-9]{13}\b',  # American Express
                r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'  # Discover
            ],
            "email": [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ],
            "phone": [
                r'\b\d{3}-\d{3}-\d{4}\b',
                r'\(\d{3}\)\s\d{3}-\d{4}',
                r'\b\d{10}\b'
            ],
            "ip_address": [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ],
            "medical_record": [
                r'\bMRN\s*:?\s*\d+',
                r'\bMedical\s+Record\s*:?\s*\d+',
                r'\bPatient\s+ID\s*:?\s*\d+'
            ],
            "financial_account": [
                r'\bAccount\s*:?\s*\d{8,17}',
                r'\bRouting\s*:?\s*\d{9}',
                r'\bIBAN\s*:?\s*[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}'
            ]
        }
    
    def _load_compliance_policies(self) -> None:
        """Load compliance policies for different frameworks."""
        
        # GDPR Policies
        self.compliance_policies.update({
            "gdpr_data_minimization": CompliancePolicy(
                policy_id="gdpr_data_minimization",
                framework=ComplianceFramework.GDPR,
                policy_name="Data Minimization",
                description="Personal data must be adequate, relevant and limited to what is necessary",
                regulation_reference="Article 5(1)(c)",
                severity=SeverityLevel.HIGH,
                detection_rules=[
                    {"type": "excessive_data_collection", "threshold": 0.7},
                    {"type": "unnecessary_pii_fields", "patterns": self.pii_patterns}
                ],
                remediation_actions=[
                    {"action": "remove_unnecessary_fields", "auto": True},
                    {"action": "implement_data_retention", "auto": False}
                ]
            ),
            
            "gdpr_consent_management": CompliancePolicy(
                policy_id="gdpr_consent_management",
                framework=ComplianceFramework.GDPR,
                policy_name="Consent Management",
                description="Valid consent must be obtained for processing personal data",
                regulation_reference="Article 6, Article 7",
                severity=SeverityLevel.CRITICAL,
                detection_rules=[
                    {"type": "missing_consent_records", "required": True},
                    {"type": "invalid_consent_mechanism", "check_opt_out": True}
                ],
                remediation_actions=[
                    {"action": "implement_consent_system", "auto": False},
                    {"action": "audit_consent_records", "auto": True}
                ]
            ),
            
            "gdpr_data_encryption": CompliancePolicy(
                policy_id="gdpr_data_encryption",
                framework=ComplianceFramework.GDPR,
                policy_name="Data Encryption",
                description="Personal data must be encrypted in transit and at rest",
                regulation_reference="Article 32",
                severity=SeverityLevel.HIGH,
                detection_rules=[
                    {"type": "unencrypted_pii_storage", "check_at_rest": True},
                    {"type": "unencrypted_pii_transmission", "check_in_transit": True}
                ],
                remediation_actions=[
                    {"action": "enable_encryption_at_rest", "auto": True},
                    {"action": "enable_encryption_in_transit", "auto": True}
                ]
            )
        })
        
        # HIPAA Policies
        self.compliance_policies.update({
            "hipaa_phi_protection": CompliancePolicy(
                policy_id="hipaa_phi_protection",
                framework=ComplianceFramework.HIPAA,
                policy_name="PHI Protection",
                description="Protected Health Information must be secured",
                regulation_reference="164.312(a)(1)",
                severity=SeverityLevel.CRITICAL,
                detection_rules=[
                    {"type": "exposed_phi", "patterns": self.pii_patterns["medical_record"]},
                    {"type": "insufficient_access_controls", "min_controls": 3}
                ],
                remediation_actions=[
                    {"action": "encrypt_phi_data", "auto": True},
                    {"action": "implement_access_controls", "auto": False}
                ]
            ),
            
            "hipaa_audit_controls": CompliancePolicy(
                policy_id="hipaa_audit_controls",
                framework=ComplianceFramework.HIPAA,
                policy_name="Audit Controls",
                description="Implement hardware, software, and procedural mechanisms for audit logs",
                regulation_reference="164.312(b)",
                severity=SeverityLevel.HIGH,
                detection_rules=[
                    {"type": "missing_audit_logs", "required_events": ["access", "modification", "deletion"]},
                    {"type": "insufficient_log_retention", "min_retention_days": 365}
                ],
                remediation_actions=[
                    {"action": "enable_comprehensive_logging", "auto": True},
                    {"action": "configure_log_retention", "auto": True}
                ]
            )
        })
        
        # PCI DSS Policies
        self.compliance_policies.update({
            "pci_cardholder_data": CompliancePolicy(
                policy_id="pci_cardholder_data",
                framework=ComplianceFramework.PCI_DSS,
                policy_name="Cardholder Data Protection",
                description="Protect stored cardholder data",
                regulation_reference="Requirement 3",
                severity=SeverityLevel.CRITICAL,
                detection_rules=[
                    {"type": "exposed_cardholder_data", "patterns": self.pii_patterns["credit_card"]},
                    {"type": "unencrypted_card_storage", "check_encryption": True}
                ],
                remediation_actions=[
                    {"action": "encrypt_cardholder_data", "auto": True},
                    {"action": "implement_data_masking", "auto": True}
                ]
            ),
            
            "pci_access_control": CompliancePolicy(
                policy_id="pci_access_control",
                framework=ComplianceFramework.PCI_DSS,
                policy_name="Access Control",
                description="Restrict access to cardholder data by business need-to-know",
                regulation_reference="Requirement 7",
                severity=SeverityLevel.HIGH,
                detection_rules=[
                    {"type": "excessive_access_privileges", "check_principle": "least_privilege"},
                    {"type": "missing_access_controls", "required": True}
                ],
                remediation_actions=[
                    {"action": "implement_rbac", "auto": False},
                    {"action": "audit_access_privileges", "auto": True}
                ]
            )
        })
    
    async def _execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute compliance-specific tasks."""
        task_type = task.task_type
        payload = task.payload
        
        try:
            if task_type == "compliance_scan":
                return await self._perform_compliance_scan(payload)
            elif task_type == "pii_detection":
                return await self._detect_pii(payload)
            elif task_type == "policy_evaluation":
                return await self._evaluate_policies(payload)
            elif task_type == "violation_assessment":
                return await self._assess_violations(payload)
            elif task_type == "framework_analysis":
                return await self._analyze_framework_compliance(payload)
            elif task_type == "risk_scoring":
                return await self._calculate_risk_score(payload)
            elif task_type == "compliance_report":
                return await self._generate_compliance_report(payload)
            else:
                raise ValueError(f"Unknown task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Failed to execute compliance task {task_type}: {e}")
            raise
    
    async def _perform_compliance_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive compliance scan."""
        try:
            # Validate scan request
            validate_scan_request(payload)
            
            target_resource = payload["target_resource"]
            frameworks = payload.get("compliance_frameworks", ["gdpr"])
            scan_type = payload.get("scan_type", "comprehensive")
            workflow_id = payload.get("workflow_id")
            
            scan_id = f"scan_{int(time.time() * 1000)}"
            
            logger.info(f"Starting compliance scan {scan_id} for {target_resource}")
            
            # Store scan start
            self.active_scans[scan_id] = {
                "scan_id": scan_id,
                "target_resource": target_resource,
                "frameworks": frameworks,
                "scan_type": scan_type,
                "workflow_id": workflow_id,
                "started_at": time.time(),
                "status": "running"
            }
            
            scan_results = {
                "scan_id": scan_id,
                "target_resource": target_resource,
                "frameworks_scanned": frameworks,
                "violations": [],
                "pii_findings": [],
                "policy_violations": [],
                "risk_score": 0.0,
                "compliance_scores": {},
                "recommendations": []
            }
            
            # Perform framework-specific scans
            for framework in frameworks:
                framework_result = await self._scan_framework(
                    target_resource, 
                    ComplianceFramework(framework), 
                    scan_type
                )
                
                scan_results["violations"].extend(framework_result["violations"])
                scan_results["policy_violations"].extend(framework_result["policy_violations"])
                scan_results["compliance_scores"][framework] = framework_result["compliance_score"]
                scan_results["recommendations"].extend(framework_result["recommendations"])
            
            # Detect PII in target resource
            pii_results = await self._detect_pii_in_resource(target_resource)
            scan_results["pii_findings"] = pii_results["findings"]
            
            # Calculate overall risk score
            scan_results["risk_score"] = await self._calculate_overall_risk_score(scan_results)
            
            # Generate AI-powered analysis
            ai_analysis = await self._generate_ai_analysis(scan_results)
            scan_results["ai_analysis"] = ai_analysis
            
            # Update scan status
            self.active_scans[scan_id]["status"] = "completed"
            self.active_scans[scan_id]["completed_at"] = time.time()
            
            # Store results in memory
            await self.store_memory(
                content={
                    "compliance_scan_completed": scan_id,
                    "target_resource": target_resource,
                    "violations_found": len(scan_results["violations"]),
                    "risk_score": scan_results["risk_score"],
                    "frameworks": frameworks
                },
                memory_type="working",
                importance_score=0.9
            )
            
            logger.info(f"Compliance scan {scan_id} completed with {len(scan_results['violations'])} violations")
            
            return scan_results
            
        except Exception as e:
            if scan_id in self.active_scans:
                self.active_scans[scan_id]["status"] = "failed"
                self.active_scans[scan_id]["error"] = str(e)
            
            logger.error(f"Compliance scan failed: {e}")
            raise
    
    async def _scan_framework(
        self, 
        resource: str, 
        framework: ComplianceFramework, 
        scan_type: str
    ) -> Dict[str, Any]:
        """Scan for specific compliance framework violations."""
        try:
            violations = []
            policy_violations = []
            recommendations = []
            
            # Get policies for this framework
            framework_policies = [
                policy for policy in self.compliance_policies.values()
                if policy.framework == framework and policy.enabled
            ]
            
            # Evaluate each policy
            for policy in framework_policies:
                policy_result = await self._evaluate_policy(resource, policy)
                
                if policy_result["violations"]:
                    violations.extend(policy_result["violations"])
                    policy_violations.append({
                        "policy_id": policy.policy_id,
                        "policy_name": policy.policy_name,
                        "violations": policy_result["violations"],
                        "severity": policy.severity.value
                    })
                
                recommendations.extend(policy_result.get("recommendations", []))
            
            # Calculate compliance score
            total_policies = len(framework_policies)
            violated_policies = len(policy_violations)
            compliance_score = ((total_policies - violated_policies) / max(total_policies, 1)) * 100
            
            return {
                "framework": framework.value,
                "violations": violations,
                "policy_violations": policy_violations,
                "compliance_score": compliance_score,
                "recommendations": recommendations,
                "policies_evaluated": total_policies,
                "policies_violated": violated_policies
            }
            
        except Exception as e:
            logger.error(f"Framework scan failed for {framework.value}: {e}")
            raise
    
    async def _evaluate_policy(self, resource: str, policy: CompliancePolicy) -> Dict[str, Any]:
        """Evaluate a specific compliance policy against a resource."""
        try:
            violations = []
            recommendations = []
            
            # Simulate resource data analysis (in production, this would connect to actual resources)
            resource_data = await self._analyze_resource_data(resource)
            
            # Apply detection rules
            for rule in policy.detection_rules:
                rule_violations = await self._apply_detection_rule(resource, resource_data, rule, policy)
                violations.extend(rule_violations)
            
            # Generate recommendations if violations found
            if violations:
                for action in policy.remediation_actions:
                    recommendations.append({
                        "action": action["action"],
                        "auto_remediatable": action["auto"],
                        "priority": policy.severity.value,
                        "policy_reference": policy.regulation_reference
                    })
            
            return {
                "policy_id": policy.policy_id,
                "violations": violations,
                "recommendations": recommendations,
                "compliant": len(violations) == 0
            }
            
        except Exception as e:
            logger.error(f"Policy evaluation failed for {policy.policy_id}: {e}")
            raise
    
    async def _apply_detection_rule(
        self, 
        resource: str, 
        resource_data: Dict[str, Any], 
        rule: Dict[str, Any], 
        policy: CompliancePolicy
    ) -> List[ComplianceViolation]:
        """Apply a detection rule and return any violations found."""
        violations = []
        rule_type = rule["type"]
        
        try:
            if rule_type == "exposed_pii":
                # Check for exposed PII data
                pii_exposure = await self._check_pii_exposure(resource_data, rule.get("patterns", {}))
                if pii_exposure["exposed"]:
                    violation = ComplianceViolation(
                        violation_id=f"pii_exposure_{int(time.time() * 1000)}",
                        violation_type=ViolationType.DATA_EXPOSURE,
                        severity=policy.severity,
                        framework=policy.framework,
                        resource_id=resource,
                        resource_type=resource_data.get("type", "unknown"),
                        description=f"PII data exposed without proper protection",
                        evidence=pii_exposure["evidence"],
                        regulation_reference=policy.regulation_reference,
                        remediation_guidance="Implement encryption and access controls for PII data",
                        risk_score=self._calculate_violation_risk_score(policy.severity, pii_exposure),
                        auto_remediatable=True
                    )
                    violations.append(violation)
            
            elif rule_type == "unencrypted_pii_storage":
                # Check for unencrypted PII storage
                encryption_status = resource_data.get("encryption", {})
                if not encryption_status.get("at_rest", False):
                    violation = ComplianceViolation(
                        violation_id=f"unencrypted_storage_{int(time.time() * 1000)}",
                        violation_type=ViolationType.INSUFFICIENT_ENCRYPTION,
                        severity=policy.severity,
                        framework=policy.framework,
                        resource_id=resource,
                        resource_type=resource_data.get("type", "unknown"),
                        description="PII data stored without encryption at rest",
                        evidence={"encryption_status": encryption_status},
                        regulation_reference=policy.regulation_reference,
                        remediation_guidance="Enable encryption at rest for all PII storage",
                        risk_score=self._calculate_violation_risk_score(policy.severity, encryption_status),
                        auto_remediatable=True
                    )
                    violations.append(violation)
            
            elif rule_type == "missing_access_controls":
                # Check for missing access controls
                access_controls = resource_data.get("access_controls", {})
                required_controls = rule.get("min_controls", 1)
                
                if len(access_controls.get("controls", [])) < required_controls:
                    violation = ComplianceViolation(
                        violation_id=f"access_control_{int(time.time() * 1000)}",
                        violation_type=ViolationType.ACCESS_CONTROL,
                        severity=policy.severity,
                        framework=policy.framework,
                        resource_id=resource,
                        resource_type=resource_data.get("type", "unknown"),
                        description="Insufficient access controls for sensitive data",
                        evidence={"current_controls": access_controls},
                        regulation_reference=policy.regulation_reference,
                        remediation_guidance="Implement role-based access controls and principle of least privilege",
                        risk_score=self._calculate_violation_risk_score(policy.severity, access_controls),
                        auto_remediatable=False
                    )
                    violations.append(violation)
            
            elif rule_type == "missing_audit_logs":
                # Check for missing audit logs
                audit_config = resource_data.get("audit_logging", {})
                required_events = rule.get("required_events", [])
                
                logged_events = set(audit_config.get("logged_events", []))
                missing_events = set(required_events) - logged_events
                
                if missing_events:
                    violation = ComplianceViolation(
                        violation_id=f"audit_logging_{int(time.time() * 1000)}",
                        violation_type=ViolationType.AUDIT_LOGGING,
                        severity=policy.severity,
                        framework=policy.framework,
                        resource_id=resource,
                        resource_type=resource_data.get("type", "unknown"),
                        description=f"Missing audit logging for events: {', '.join(missing_events)}",
                        evidence={"missing_events": list(missing_events), "current_config": audit_config},
                        regulation_reference=policy.regulation_reference,
                        remediation_guidance="Enable comprehensive audit logging for all required events",
                        risk_score=self._calculate_violation_risk_score(policy.severity, audit_config),
                        auto_remediatable=True
                    )
                    violations.append(violation)
            
            elif rule_type == "missing_consent_records":
                # Check for missing consent management
                consent_system = resource_data.get("consent_management", {})
                
                if not consent_system.get("enabled", False):
                    violation = ComplianceViolation(
                        violation_id=f"consent_mgmt_{int(time.time() * 1000)}",
                        violation_type=ViolationType.CONSENT_MANAGEMENT,
                        severity=policy.severity,
                        framework=policy.framework,
                        resource_id=resource,
                        resource_type=resource_data.get("type", "unknown"),
                        description="No consent management system in place",
                        evidence={"consent_system": consent_system},
                        regulation_reference=policy.regulation_reference,
                        remediation_guidance="Implement consent management system with opt-in/opt-out capabilities",
                        risk_score=self._calculate_violation_risk_score(policy.severity, consent_system),
                        auto_remediatable=False
                    )
                    violations.append(violation)
            
        except Exception as e:
            logger.error(f"Detection rule application failed for {rule_type}: {e}")
        
        return violations
    
    async def _analyze_resource_data(self, resource: str) -> Dict[str, Any]:
        """Analyze resource data for compliance scanning."""
        # In production, this would connect to actual AWS resources
        # For demonstration, we'll simulate resource analysis
        
        # Simulate different resource types
        if "s3" in resource.lower():
            return {
                "type": "s3_bucket",
                "encryption": {
                    "at_rest": False,  # Simulated violation
                    "in_transit": True,
                    "kms_key": None
                },
                "access_controls": {
                    "controls": ["bucket_policy"],  # Insufficient
                    "public_access": True
                },
                "audit_logging": {
                    "enabled": False,  # Violation
                    "logged_events": []
                },
                "pii_detected": True,
                "data_classification": "sensitive"
            }
        elif "rds" in resource.lower():
            return {
                "type": "rds_database",
                "encryption": {
                    "at_rest": True,
                    "in_transit": True,
                    "kms_key": "arn:aws:kms:region:account:key/key-id"
                },
                "access_controls": {
                    "controls": ["iam_database_authentication", "security_groups", "vpc"],
                    "public_access": False
                },
                "audit_logging": {
                    "enabled": True,
                    "logged_events": ["connect", "query", "error"]
                },
                "pii_detected": True,
                "data_classification": "highly_sensitive",
                "consent_management": {
                    "enabled": False  # Violation for GDPR
                }
            }
        else:
            return {
                "type": "generic_resource",
                "encryption": {"at_rest": True, "in_transit": True},
                "access_controls": {"controls": ["iam"], "public_access": False},
                "audit_logging": {"enabled": True, "logged_events": ["access"]},
                "pii_detected": False,
                "data_classification": "public"
            }
    
    async def _check_pii_exposure(self, resource_data: Dict[str, Any], patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Check for PII exposure in resource data."""
        exposed = False
        evidence = {}
        
        # Check if PII is detected and properly protected
        if resource_data.get("pii_detected", False):
            # Check encryption
            encryption = resource_data.get("encryption", {})
            if not encryption.get("at_rest", False):
                exposed = True
                evidence["unencrypted_pii"] = True
            
            # Check access controls
            access_controls = resource_data.get("access_controls", {})
            if access_controls.get("public_access", False):
                exposed = True
                evidence["public_pii_access"] = True
            
            # Check for specific PII patterns if provided
            if patterns:
                # Simulate pattern detection in resource content
                evidence["pii_types_detected"] = ["email", "ssn", "credit_card"]
        
        return {
            "exposed": exposed,
            "evidence": evidence,
            "pii_detected": resource_data.get("pii_detected", False)
        }
    
    async def _detect_pii_in_resource(self, resource: str) -> Dict[str, Any]:
        """Detect PII in the target resource."""
        findings = []
        
        # Simulate PII detection (in production, this would scan actual data)
        simulated_data = [
            "User email: john.doe@example.com",
            "SSN: 123-45-6789",
            "Credit Card: 4532-1234-5678-9012",
            "Phone: (555) 123-4567"
        ]
        
        for data_sample in simulated_data:
            for pii_type, patterns in self.pii_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, data_sample)
                    if matches:
                        findings.append({
                            "pii_type": pii_type,
                            "pattern": pattern,
                            "matches": matches,
                            "location": f"Sample data in {resource}",
                            "confidence": 0.95,
                            "masked_value": self._mask_pii_value(matches[0], pii_type)
                        })
        
        return {
            "resource": resource,
            "findings": findings,
            "total_pii_instances": len(findings),
            "pii_types_found": list(set([f["pii_type"] for f in findings]))
        }
    
    def _mask_pii_value(self, value: str, pii_type: str) -> str:
        """Mask PII value for safe logging."""
        if pii_type == "ssn":
            return f"***-**-{value[-4:]}" if len(value) >= 4 else "***"
        elif pii_type == "credit_card":
            return f"****-****-****-{value[-4:]}" if len(value) >= 4 else "****"
        elif pii_type == "email":
            parts = value.split("@")
            if len(parts) == 2:
                return f"{parts[0][:2]}***@{parts[1]}"
        elif pii_type == "phone":
            return f"***-***-{value[-4:]}" if len(value) >= 4 else "***"
        
        return "***"
    
    def _calculate_violation_risk_score(self, severity: SeverityLevel, evidence: Dict[str, Any]) -> float:
        """Calculate risk score for a violation."""
        base_scores = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFORMATIONAL: 1.0
        }
        
        base_score = base_scores[severity]
        
        # Adjust based on evidence
        multiplier = 1.0
        
        if evidence.get("public_pii_access", False):
            multiplier += 0.5
        if evidence.get("unencrypted_pii", False):
            multiplier += 0.3
        if evidence.get("missing_events", []):
            multiplier += 0.2
        
        return min(base_score * multiplier, 10.0)
    
    async def _calculate_overall_risk_score(self, scan_results: Dict[str, Any]) -> float:
        """Calculate overall risk score for the scan."""
        if not scan_results["violations"]:
            return 0.0
        
        total_risk = sum([v.risk_score for v in scan_results["violations"]])
        max_possible_risk = len(scan_results["violations"]) * 10.0
        
        # Normalize to 0-10 scale
        normalized_score = (total_risk / max_possible_risk) * 10.0
        
        return round(normalized_score, 2)
    
    async def _generate_ai_analysis(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-powered analysis of scan results."""
        try:
            violations_summary = []
            for violation in scan_results["violations"]:
                violations_summary.append({
                    "type": violation.violation_type.value,
                    "severity": violation.severity.value,
                    "framework": violation.framework.value,
                    "risk_score": violation.risk_score
                })
            
            analysis_prompt = f"""
            Analyze the following compliance scan results and provide insights:
            
            Target Resource: {scan_results['target_resource']}
            Frameworks Scanned: {scan_results['frameworks_scanned']}
            Total Violations: {len(scan_results['violations'])}
            Overall Risk Score: {scan_results['risk_score']}/10
            
            Violations Found:
            {json.dumps(violations_summary, indent=2)}
            
            Compliance Scores:
            {json.dumps(scan_results['compliance_scores'], indent=2)}
            
            Please provide:
            1. Risk assessment summary
            2. Priority violations that need immediate attention
            3. Compliance posture evaluation
            4. Strategic recommendations for improvement
            5. Potential business impact of current violations
            """
            
            response = await self.invoke_llm(
                prompt=analysis_prompt,
                system_prompt="You are an expert compliance analyst. Provide detailed, actionable insights."
            )
            
            return {
                "analysis": response.content,
                "key_insights": self._extract_key_insights(response.content),
                "generated_at": time.time()
            }
            
        except Exception as e:
            logger.error(f"AI analysis generation failed: {e}")
            return {
                "analysis": "AI analysis temporarily unavailable",
                "error": str(e),
                "generated_at": time.time()
            }
    
    def _extract_key_insights(self, analysis_text: str) -> List[str]:
        """Extract key insights from AI analysis."""
        # Simple extraction logic - in production, could use more sophisticated NLP
        insights = []
        
        if "critical" in analysis_text.lower():
            insights.append("Critical violations require immediate attention")
        if "encryption" in analysis_text.lower():
            insights.append("Encryption improvements needed")
        if "access control" in analysis_text.lower():
            insights.append("Access control mechanisms need enhancement")
        if "audit" in analysis_text.lower():
            insights.append("Audit logging requires configuration")
        if "gdpr" in analysis_text.lower():
            insights.append("GDPR compliance gaps identified")
        if "hipaa" in analysis_text.lower():
            insights.append("HIPAA requirements not fully met")
        
        return insights
    
    async def _detect_pii(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Perform PII detection task."""
        try:
            data_source = payload["data_source"]
            pii_types = payload.get("pii_types", list(self.pii_patterns.keys()))
            
            # Validate PII data
            validate_pii_data({"data_source": data_source})
            
            detection_results = await self._detect_pii_in_resource(data_source)
            
            # Filter by requested PII types
            if pii_types != list(self.pii_patterns.keys()):
                detection_results["findings"] = [
                    finding for finding in detection_results["findings"]
                    if finding["pii_type"] in pii_types
                ]
            
            return {
                "data_source": data_source,
                "pii_detection_results": detection_results,
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(f"PII detection failed: {e}")
            raise
    
    async def _evaluate_policies(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate specific compliance policies."""
        try:
            resource = payload["resource"]
            policy_ids = payload.get("policy_ids", [])
            
            if not policy_ids:
                policy_ids = list(self.compliance_policies.keys())
            
            evaluation_results = []
            
            for policy_id in policy_ids:
                if policy_id in self.compliance_policies:
                    policy = self.compliance_policies[policy_id]
                    result = await self._evaluate_policy(resource, policy)
                    result["policy_id"] = policy_id
                    result["framework"] = policy.framework.value
                    evaluation_results.append(result)
            
            return {
                "resource": resource,
                "policy_evaluations": evaluation_results,
                "total_policies": len(evaluation_results),
                "compliant_policies": len([r for r in evaluation_results if r["compliant"]]),
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(f"Policy evaluation failed: {e}")
            raise
    
    async def _assess_violations(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Assess and categorize violations."""
        try:
            violations = payload["violations"]
            
            assessment = {
                "total_violations": len(violations),
                "by_severity": {},
                "by_framework": {},
                "by_type": {},
                "auto_remediatable": 0,
                "financial_impact_estimate": 0.0,
                "priority_violations": []
            }
            
            for violation_data in violations:
                violation = ComplianceViolation(**violation_data)
                
                # Count by severity
                severity = violation.severity.value
                assessment["by_severity"][severity] = assessment["by_severity"].get(severity, 0) + 1
                
                # Count by framework
                framework = violation.framework.value
                assessment["by_framework"][framework] = assessment["by_framework"].get(framework, 0) + 1
                
                # Count by type
                vtype = violation.violation_type.value
                assessment["by_type"][vtype] = assessment["by_type"].get(vtype, 0) + 1
                
                # Count auto-remediatable
                if violation.auto_remediatable:
                    assessment["auto_remediatable"] += 1
                
                # Add to priority if critical or high
                if violation.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                    assessment["priority_violations"].append({
                        "violation_id": violation.violation_id,
                        "severity": violation.severity.value,
                        "type": violation.violation_type.value,
                        "risk_score": violation.risk_score
                    })
                
                # Estimate financial impact
                assessment["financial_impact_estimate"] += self._estimate_violation_cost(violation)
            
            return assessment
            
        except Exception as e:
            logger.error(f"Violation assessment failed: {e}")
            raise
    
    def _estimate_violation_cost(self, violation: ComplianceViolation) -> float:
        """Estimate potential financial impact of a violation."""
        # Base costs by framework and severity
        base_costs = {
            ComplianceFramework.GDPR: {
                SeverityLevel.CRITICAL: 50000,
                SeverityLevel.HIGH: 25000,
                SeverityLevel.MEDIUM: 10000,
                SeverityLevel.LOW: 2500,
                SeverityLevel.INFORMATIONAL: 500
            },
            ComplianceFramework.HIPAA: {
                SeverityLevel.CRITICAL: 75000,
                SeverityLevel.HIGH: 35000,
                SeverityLevel.MEDIUM: 15000,
                SeverityLevel.LOW: 5000,
                SeverityLevel.INFORMATIONAL: 1000
            },
            ComplianceFramework.PCI_DSS: {
                SeverityLevel.CRITICAL: 100000,
                SeverityLevel.HIGH: 45000,
                SeverityLevel.MEDIUM: 20000,
                SeverityLevel.LOW: 7500,
                SeverityLevel.INFORMATIONAL: 1500
            }
        }
        
        framework_costs = base_costs.get(violation.framework, base_costs[ComplianceFramework.GDPR])
        base_cost = framework_costs.get(violation.severity, 1000)
        
        # Adjust based on risk score
        multiplier = violation.risk_score / 10.0
        
        return base_cost * multiplier
    
    async def _analyze_framework_compliance(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compliance posture for specific frameworks."""
        try:
            framework = payload["framework"]
            target_resource = payload["target_resource"]
            
            framework_enum = ComplianceFramework(framework)
            
            # Perform framework-specific analysis
            analysis_result = await self._scan_framework(target_resource, framework_enum, "comprehensive")
            
            # Add framework-specific insights
            insights = await self._generate_framework_insights(framework_enum, analysis_result)
            
            return {
                "framework": framework,
                "target_resource": target_resource,
                "analysis": analysis_result,
                "insights": insights,
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(f"Framework analysis failed: {e}")
            raise
    
    async def _generate_framework_insights(
        self, 
        framework: ComplianceFramework, 
        analysis_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate framework-specific insights."""
        insights = {
            "compliance_level": "partial",
            "key_gaps": [],
            "strengths": [],
            "next_steps": []
        }
        
        compliance_score = analysis_result["compliance_score"]
        
        if compliance_score >= 95:
            insights["compliance_level"] = "excellent"
        elif compliance_score >= 80:
            insights["compliance_level"] = "good"
        elif compliance_score >= 60:
            insights["compliance_level"] = "moderate"
        else:
            insights["compliance_level"] = "poor"
        
        # Framework-specific insights
        if framework == ComplianceFramework.GDPR:
            insights["key_requirements"] = [
                "Data minimization",
                "Consent management",
                "Right to be forgotten",
                "Data protection by design",
                "Breach notification"
            ]
        elif framework == ComplianceFramework.HIPAA:
            insights["key_requirements"] = [
                "PHI protection",
                "Access controls",
                "Audit controls",
                "Integrity",
                "Transmission security"
            ]
        elif framework == ComplianceFramework.PCI_DSS:
            insights["key_requirements"] = [
                "Cardholder data protection",
                "Network security",
                "Access control",
                "Monitoring",
                "Security policies"
            ]
        
        return insights
    
    async def _calculate_risk_score(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate detailed risk scores."""
        try:
            violations = payload.get("violations", [])
            resource_context = payload.get("resource_context", {})
            
            if isinstance(violations[0], dict):
                # Convert dict to ComplianceViolation objects
                violation_objects = [ComplianceViolation(**v) for v in violations]
            else:
                violation_objects = violations
            
            risk_breakdown = {
                "overall_risk_score": 0.0,
                "risk_by_category": {},
                "risk_by_framework": {},
                "critical_risks": [],
                "risk_factors": [],
                "mitigation_priority": []
            }
            
            total_risk = 0.0
            category_risks = {}
            framework_risks = {}
            
            for violation in violation_objects:
                risk_score = violation.risk_score
                total_risk += risk_score
                
                # Categorize risk
                category = violation.violation_type.value
                category_risks[category] = category_risks.get(category, 0) + risk_score
                
                # Framework risk
                framework = violation.framework.value
                framework_risks[framework] = framework_risks.get(framework, 0) + risk_score
                
                # Critical risks
                if violation.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                    risk_breakdown["critical_risks"].append({
                        "violation_id": violation.violation_id,
                        "type": violation.violation_type.value,
                        "risk_score": risk_score,
                        "framework": framework
                    })
            
            # Calculate overall score
            risk_breakdown["overall_risk_score"] = min(total_risk / max(len(violation_objects), 1), 10.0)
            risk_breakdown["risk_by_category"] = category_risks
            risk_breakdown["risk_by_framework"] = framework_risks
            
            # Generate mitigation priorities
            risk_breakdown["mitigation_priority"] = sorted(
                risk_breakdown["critical_risks"],
                key=lambda x: x["risk_score"],
                reverse=True
            )[:5]  # Top 5 priority items
            
            return risk_breakdown
            
        except Exception as e:
            logger.error(f"Risk score calculation failed: {e}")
            raise
    
    async def _generate_compliance_report(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive compliance report."""
        try:
            scan_results = payload["scan_results"]
            report_type = payload.get("report_type", "comprehensive")
            
            report = {
                "report_id": f"report_{int(time.time() * 1000)}",
                "report_type": report_type,
                "generated_at": time.time(),
                "target_resource": scan_results["target_resource"],
                "executive_summary": {},
                "detailed_findings": {},
                "recommendations": [],
                "compliance_posture": {},
                "appendix": {}
            }
            
            # Executive summary
            report["executive_summary"] = {
                "total_violations": len(scan_results["violations"]),
                "overall_risk_score": scan_results["risk_score"],
                "frameworks_assessed": scan_results["frameworks_scanned"],
                "compliance_scores": scan_results["compliance_scores"],
                "critical_issues": len([v for v in scan_results["violations"] 
                                     if v.severity == SeverityLevel.CRITICAL]),
                "auto_remediatable_issues": len([v for v in scan_results["violations"] 
                                               if v.auto_remediatable])
            }
            
            # Detailed findings
            report["detailed_findings"] = {
                "by_framework": {},
                "by_severity": {},
                "by_type": {}
            }
            
            for violation in scan_results["violations"]:
                framework = violation.framework.value
                if framework not in report["detailed_findings"]["by_framework"]:
                    report["detailed_findings"]["by_framework"][framework] = []
                
                report["detailed_findings"]["by_framework"][framework].append({
                    "violation_id": violation.violation_id,
                    "type": violation.violation_type.value,
                    "severity": violation.severity.value,
                    "description": violation.description,
                    "risk_score": violation.risk_score,
                    "auto_remediatable": violation.auto_remediatable
                })
            
            # Recommendations
            report["recommendations"] = scan_results.get("recommendations", [])
            
            # Add AI analysis if available
            if "ai_analysis" in scan_results:
                report["ai_insights"] = scan_results["ai_analysis"]
            
            return report
            
        except Exception as e:
            logger.error(f"Compliance report generation failed: {e}")
            raise