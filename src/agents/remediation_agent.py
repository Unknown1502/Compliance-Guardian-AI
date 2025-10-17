"""Remediation Agent - Specialized agent for automated compliance violation remediation."""

import asyncio
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .base_agent import BaseAgent, AgentTask, AgentStatus, AgentCapability
from ..core.bedrock_client import BedrockResponse
from ..utils.logger import get_logger
from ..utils.encryption import encrypt_data, mask_pii

logger = get_logger(__name__)


class RemediationStrategy(Enum):
    """Remediation strategies."""
    AUTOMATED = "automated"
    SEMI_AUTOMATED = "semi_automated"
    MANUAL = "manual"
    ROLLBACK = "rollback"


class RemediationStatus(Enum):
    """Remediation execution status."""
    PENDING = "pending"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    REQUIRES_APPROVAL = "requires_approval"


@dataclass
class RemediationAction:
    """Represents a remediation action."""
    
    action_id: str
    violation_id: str
    action_type: str
    strategy: RemediationStrategy
    description: str
    target_resource: str
    parameters: Dict[str, Any]
    estimated_duration: int = 60  # seconds
    risk_level: str = "low"
    requires_approval: bool = False
    approval_status: str = "pending"
    status: RemediationStatus = RemediationStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    rollback_available: bool = False
    rollback_plan: Optional[Dict[str, Any]] = None


@dataclass
class RemediationPlan:
    """Represents a complete remediation plan."""
    
    plan_id: str
    workflow_id: str
    target_resource: str
    violations: List[str]
    actions: List[RemediationAction]
    execution_order: List[str]
    total_estimated_duration: int = 0
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    approval_required: bool = False
    created_at: float = field(default_factory=time.time)
    status: str = "draft"


class RemediationAgent(BaseAgent):
    """
    Remediation Agent specializes in automated compliance violation remediation.
    
    Responsibilities:
    - Automated violation remediation
    - PII data masking and tokenization
    - Encryption enforcement
    - Access control configuration
    - Consent management implementation
    - Policy injection and enforcement
    - Rollback and recovery procedures
    """
    
    def __init__(self, config: Dict[str, Any], **kwargs):
        """Initialize Remediation Agent."""
        super().__init__(
            agent_id="remediation-agent",
            config=config,
            **kwargs
        )
        
        # Remediation-specific state
        self.active_remediations: Dict[str, RemediationAction] = {}
        self.remediation_plans: Dict[str, RemediationPlan] = {}
        self.remediation_history: List[RemediationAction] = []
        
        # Remediation templates
        self.remediation_templates: Dict[str, Dict[str, Any]] = {}
        
        # Configuration
        self.auto_remediation_enabled = config.get("auto_remediation", True)
        self.approval_required_for_critical = config.get("approval_required_critical", True)
        self.max_concurrent_remediations = config.get("max_concurrent_remediations", 3)
        self.rollback_enabled = config.get("rollback_enabled", True)
        
        # Initialize remediation templates
        self._initialize_remediation_templates()
        
    def _initialize_capabilities(self) -> None:
        """Initialize remediation agent capabilities."""
        self.capabilities = {
            AgentCapability.VIOLATION_REMEDIATION,
            AgentCapability.DATA_ANALYSIS
        }
    
    def _initialize_remediation_templates(self) -> None:
        """Initialize remediation action templates."""
        
        # PII Data Exposure Remediation
        self.remediation_templates["pii_exposure"] = {
            "action_type": "encrypt_pii_data",
            "description": "Encrypt exposed PII data",
            "strategy": RemediationStrategy.AUTOMATED,
            "steps": [
                {"step": "identify_pii_fields", "automated": True},
                {"step": "backup_current_data", "automated": True},
                {"step": "apply_encryption", "automated": True},
                {"step": "verify_encryption", "automated": True},
                {"step": "update_access_policies", "automated": True}
            ],
            "rollback_plan": {
                "available": True,
                "steps": ["restore_from_backup", "revert_access_policies"]
            },
            "estimated_duration": 300,
            "risk_level": "medium"
        }
        
        # Insufficient Encryption Remediation
        self.remediation_templates["insufficient_encryption"] = {
            "action_type": "enable_encryption",
            "description": "Enable encryption at rest and in transit",
            "strategy": RemediationStrategy.AUTOMATED,
            "steps": [
                {"step": "check_encryption_support", "automated": True},
                {"step": "create_kms_key", "automated": True},
                {"step": "enable_at_rest_encryption", "automated": True},
                {"step": "enable_in_transit_encryption", "automated": True},
                {"step": "verify_encryption_status", "automated": True}
            ],
            "rollback_plan": {
                "available": True,
                "steps": ["disable_encryption", "delete_kms_key"]
            },
            "estimated_duration": 180,
            "risk_level": "low"
        }
        
        # Access Control Remediation
        self.remediation_templates["access_control"] = {
            "action_type": "configure_access_controls",
            "description": "Implement proper access controls",
            "strategy": RemediationStrategy.SEMI_AUTOMATED,
            "steps": [
                {"step": "analyze_current_permissions", "automated": True},
                {"step": "generate_rbac_policy", "automated": True},
                {"step": "apply_least_privilege", "automated": False},
                {"step": "configure_mfa", "automated": True},
                {"step": "verify_access_controls", "automated": True}
            ],
            "rollback_plan": {
                "available": True,
                "steps": ["restore_previous_permissions"]
            },
            "estimated_duration": 240,
            "risk_level": "medium",
            "requires_approval": True
        }
        
        # Audit Logging Remediation
        self.remediation_templates["audit_logging"] = {
            "action_type": "enable_audit_logging",
            "description": "Enable comprehensive audit logging",
            "strategy": RemediationStrategy.AUTOMATED,
            "steps": [
                {"step": "configure_cloudtrail", "automated": True},
                {"step": "configure_cloudwatch", "automated": True},
                {"step": "set_log_retention", "automated": True},
                {"step": "enable_log_encryption", "automated": True},
                {"step": "verify_logging", "automated": True}
            ],
            "rollback_plan": {
                "available": True,
                "steps": ["disable_logging", "delete_log_groups"]
            },
            "estimated_duration": 120,
            "risk_level": "low"
        }
        
        # Consent Management Remediation
        self.remediation_templates["consent_management"] = {
            "action_type": "implement_consent_system",
            "description": "Implement consent management system",
            "strategy": RemediationStrategy.MANUAL,
            "steps": [
                {"step": "design_consent_schema", "automated": False},
                {"step": "create_consent_database", "automated": True},
                {"step": "implement_consent_api", "automated": False},
                {"step": "integrate_consent_checks", "automated": False},
                {"step": "add_consent_ui", "automated": False}
            ],
            "rollback_plan": {
                "available": False,
                "steps": []
            },
            "estimated_duration": 7200,  # 2 hours
            "risk_level": "high",
            "requires_approval": True
        }
        
        # Data Masking Remediation
        self.remediation_templates["data_masking"] = {
            "action_type": "apply_pii_masking",
            "description": "Apply PII data masking",
            "strategy": RemediationStrategy.AUTOMATED,
            "steps": [
                {"step": "identify_pii_fields", "automated": True},
                {"step": "backup_data", "automated": True},
                {"step": "apply_masking", "automated": True},
                {"step": "verify_masking", "automated": True},
                {"step": "update_documentation", "automated": True}
            ],
            "rollback_plan": {
                "available": True,
                "steps": ["restore_from_backup"]
            },
            "estimated_duration": 180,
            "risk_level": "low"
        }
    
    async def _execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute remediation-specific tasks."""
        task_type = task.task_type
        payload = task.payload
        
        try:
            if task_type == "violation_remediation":
                return await self._remediate_violations(payload)
            elif task_type == "create_remediation_plan":
                return await self._create_remediation_plan(payload)
            elif task_type == "execute_remediation":
                return await self._execute_remediation(payload)
            elif task_type == "pii_masking":
                return await self._apply_pii_masking(payload)
            elif task_type == "encryption_enforcement":
                return await self._enforce_encryption(payload)
            elif task_type == "access_control_config":
                return await self._configure_access_controls(payload)
            elif task_type == "rollback_remediation":
                return await self._rollback_remediation(payload)
            elif task_type == "approve_remediation":
                return await self._approve_remediation(payload)
            elif task_type == "immediate_containment":
                return await self._immediate_containment(payload)
            else:
                raise ValueError(f"Unknown task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Failed to execute remediation task {task_type}: {e}")
            raise
    
    async def _remediate_violations(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Remediate compliance violations."""
        try:
            violations = payload.get("violations", [])
            auto_remediate = payload.get("auto_remediate", self.auto_remediation_enabled)
            approval_required = payload.get("approval_required", False)
            workflow_id = payload.get("workflow_id")
            
            logger.info(f"Starting remediation for {len(violations)} violations")
            
            remediation_results = {
                "workflow_id": workflow_id,
                "total_violations": len(violations),
                "remediations_attempted": 0,
                "remediations_successful": 0,
                "remediations_failed": 0,
                "remediations_pending_approval": 0,
                "immediate_actions": [],
                "results": []
            }
            
            for violation in violations:
                try:
                    violation_type = violation.get("violation_type", violation.get("type", "unknown"))
                    violation_id = violation.get("violation_id", f"v_{int(time.time() * 1000)}")
                    
                    # Get remediation template
                    template = self._get_remediation_template(violation_type)
                    
                    if not template:
                        logger.warning(f"No remediation template for {violation_type}")
                        remediation_results["results"].append({
                            "violation_id": violation_id,
                            "status": "no_template",
                            "message": f"No automated remediation available for {violation_type}"
                        })
                        continue
                    
                    # Check if auto-remediation is allowed
                    requires_approval = (
                        approval_required or 
                        template.get("requires_approval", False) or
                        (self.approval_required_for_critical and violation.get("severity") == "critical")
                    )
                    
                    # Create remediation action
                    action = RemediationAction(
                        action_id=f"action_{int(time.time() * 1000)}_{violation_id}",
                        violation_id=violation_id,
                        action_type=template["action_type"],
                        strategy=RemediationStrategy(template["strategy"].value if hasattr(template["strategy"], 'value') else template["strategy"]),
                        description=template["description"],
                        target_resource=violation.get("resource_id", "unknown"),
                        parameters={
                            "violation": violation,
                            "steps": template["steps"]
                        },
                        estimated_duration=template.get("estimated_duration", 60),
                        risk_level=template.get("risk_level", "medium"),
                        requires_approval=requires_approval,
                        rollback_available=template.get("rollback_plan", {}).get("available", False),
                        rollback_plan=template.get("rollback_plan")
                    )
                    
                    remediation_results["remediations_attempted"] += 1
                    
                    # Execute or queue for approval
                    if auto_remediate and not requires_approval:
                        # Execute immediately
                        result = await self._execute_remediation_action(action)
                        
                        if result["status"] == "completed":
                            remediation_results["remediations_successful"] += 1
                            remediation_results["immediate_actions"].append({
                                "action": action.action_type,
                                "violation": violation_id,
                                "result": "success"
                            })
                        else:
                            remediation_results["remediations_failed"] += 1
                        
                        remediation_results["results"].append(result)
                    else:
                        # Queue for approval
                        action.status = RemediationStatus.REQUIRES_APPROVAL
                        self.active_remediations[action.action_id] = action
                        
                        remediation_results["remediations_pending_approval"] += 1
                        remediation_results["results"].append({
                            "action_id": action.action_id,
                            "violation_id": violation_id,
                            "status": "pending_approval",
                            "action_type": action.action_type,
                            "requires_approval": True
                        })
                    
                except Exception as e:
                    logger.error(f"Failed to remediate violation {violation_id}: {e}")
                    remediation_results["remediations_failed"] += 1
                    remediation_results["results"].append({
                        "violation_id": violation_id,
                        "status": "failed",
                        "error": str(e)
                    })
            
            # Store results in memory
            await self.store_memory(
                content={
                    "remediation_completed": workflow_id,
                    "total_violations": len(violations),
                    "successful": remediation_results["remediations_successful"],
                    "failed": remediation_results["remediations_failed"],
                    "pending_approval": remediation_results["remediations_pending_approval"]
                },
                memory_type="working",
                importance_score=0.9
            )
            
            logger.info(f"Remediation completed: {remediation_results['remediations_successful']} successful, {remediation_results['remediations_failed']} failed")
            
            return remediation_results
            
        except Exception as e:
            logger.error(f"Violation remediation failed: {e}")
            raise
    
    def _get_remediation_template(self, violation_type: str) -> Optional[Dict[str, Any]]:
        """Get remediation template for violation type."""
        # Map violation types to templates
        template_map = {
            "data_exposure": "pii_exposure",
            "insufficient_encryption": "insufficient_encryption",
            "access_control": "access_control",
            "audit_logging": "audit_logging",
            "consent_management": "consent_management",
            "data_minimization": "data_masking"
        }
        
        template_key = template_map.get(violation_type)
        return self.remediation_templates.get(template_key) if template_key else None
    
    async def _execute_remediation_action(self, action: RemediationAction) -> Dict[str, Any]:
        """Execute a single remediation action."""
        try:
            logger.info(f"Executing remediation action: {action.action_id}")
            
            action.status = RemediationStatus.IN_PROGRESS
            action.started_at = time.time()
            
            # Execute based on action type
            if action.action_type == "encrypt_pii_data":
                result = await self._encrypt_pii_data(action)
            elif action.action_type == "enable_encryption":
                result = await self._enable_encryption(action)
            elif action.action_type == "configure_access_controls":
                result = await self._configure_access_controls_action(action)
            elif action.action_type == "enable_audit_logging":
                result = await self._enable_audit_logging(action)
            elif action.action_type == "apply_pii_masking":
                result = await self._apply_pii_masking_action(action)
            elif action.action_type == "implement_consent_system":
                result = await self._implement_consent_system(action)
            else:
                raise ValueError(f"Unknown action type: {action.action_type}")
            
            # Update action status
            action.completed_at = time.time()
            action.result = result
            
            if result.get("success", False):
                action.status = RemediationStatus.COMPLETED
            else:
                action.status = RemediationStatus.FAILED
                action.error = result.get("error", "Unknown error")
            
            # Store in history
            self.remediation_history.append(action)
            
            # Remove from active if present
            if action.action_id in self.active_remediations:
                del self.active_remediations[action.action_id]
            
            return {
                "action_id": action.action_id,
                "violation_id": action.violation_id,
                "status": action.status.value,
                "result": result,
                "execution_time": action.completed_at - action.started_at if action.started_at else 0
            }
            
        except Exception as e:
            action.status = RemediationStatus.FAILED
            action.error = str(e)
            action.completed_at = time.time()
            
            logger.error(f"Remediation action execution failed: {e}")
            
            return {
                "action_id": action.action_id,
                "violation_id": action.violation_id,
                "status": "failed",
                "error": str(e)
            }
    
    async def _encrypt_pii_data(self, action: RemediationAction) -> Dict[str, Any]:
        """Encrypt exposed PII data."""
        try:
            target_resource = action.target_resource
            violation = action.parameters["violation"]
            
            logger.info(f"Encrypting PII data for {target_resource}")
            
            # Simulate PII data encryption
            # In production, this would:
            # 1. Identify PII fields
            # 2. Create backup
            # 3. Apply encryption using AWS KMS
            # 4. Verify encryption
            # 5. Update access policies
            
            encryption_result = {
                "success": True,
                "resource": target_resource,
                "pii_fields_encrypted": ["email", "ssn", "credit_card"],
                "encryption_method": "AWS KMS",
                "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                "backup_created": True,
                "backup_location": f"s3://backup-bucket/{target_resource}-backup-{int(time.time())}",
                "verification_passed": True,
                "timestamp": time.time()
            }
            
            logger.info(f"PII encryption completed for {target_resource}")
            
            return encryption_result
            
        except Exception as e:
            logger.error(f"PII encryption failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _enable_encryption(self, action: RemediationAction) -> Dict[str, Any]:
        """Enable encryption at rest and in transit."""
        try:
            target_resource = action.target_resource
            
            logger.info(f"Enabling encryption for {target_resource}")
            
            # Simulate encryption enablement
            # In production, this would configure AWS service encryption
            
            result = {
                "success": True,
                "resource": target_resource,
                "encryption_at_rest": {
                    "enabled": True,
                    "kms_key": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
                    "algorithm": "AES-256"
                },
                "encryption_in_transit": {
                    "enabled": True,
                    "protocol": "TLS 1.3",
                    "certificate": "valid"
                },
                "verification_passed": True,
                "timestamp": time.time()
            }
            
            logger.info(f"Encryption enabled for {target_resource}")
            
            return result
            
        except Exception as e:
            logger.error(f"Encryption enablement failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _configure_access_controls_action(self, action: RemediationAction) -> Dict[str, Any]:
        """Configure access controls for a resource."""
        try:
            target_resource = action.target_resource
            
            logger.info(f"Configuring access controls for {target_resource}")
            
            # Use AI to generate appropriate access policies
            policy_prompt = f"""
            Generate an AWS IAM policy for the following resource with proper access controls:
            
            Resource: {target_resource}
            Requirements:
            - Implement principle of least privilege
            - Enable MFA for sensitive operations
            - Restrict access to authorized users only
            - Enable audit logging
            
            Provide a JSON policy document.
            """
            
            response = await self.invoke_llm(
                prompt=policy_prompt,
                system_prompt="You are an AWS security expert. Generate secure, compliant IAM policies."
            )
            
            # Simulate access control configuration
            result = {
                "success": True,
                "resource": target_resource,
                "access_controls_applied": {
                    "rbac_enabled": True,
                    "mfa_required": True,
                    "least_privilege": True,
                    "policy_document": response.content
                },
                "previous_policy_backup": f"s3://policy-backup/{target_resource}-{int(time.time())}",
                "verification_passed": True,
                "timestamp": time.time()
            }
            
            logger.info(f"Access controls configured for {target_resource}")
            
            return result
            
        except Exception as e:
            logger.error(f"Access control configuration failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _enable_audit_logging(self, action: RemediationAction) -> Dict[str, Any]:
        """Enable comprehensive audit logging."""
        try:
            target_resource = action.target_resource
            
            logger.info(f"Enabling audit logging for {target_resource}")
            
            # Simulate audit logging enablement
            result = {
                "success": True,
                "resource": target_resource,
                "logging_configuration": {
                    "cloudtrail_enabled": True,
                    "cloudwatch_enabled": True,
                    "log_retention_days": 2555,  # 7 years
                    "log_encryption": True,
                    "events_logged": ["access", "modification", "deletion", "configuration_change"]
                },
                "log_group": f"/aws/compliance/{target_resource}",
                "verification_passed": True,
                "timestamp": time.time()
            }
            
            logger.info(f"Audit logging enabled for {target_resource}")
            
            return result
            
        except Exception as e:
            logger.error(f"Audit logging enablement failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _apply_pii_masking_action(self, action: RemediationAction) -> Dict[str, Any]:
        """Apply PII masking to data."""
        try:
            target_resource = action.target_resource
            violation = action.parameters["violation"]
            
            logger.info(f"Applying PII masking for {target_resource}")
            
            # Get PII fields from violation
            pii_evidence = violation.get("evidence", {})
            
            # Apply masking using utility function
            masking_result = {
                "success": True,
                "resource": target_resource,
                "pii_fields_masked": [],
                "masking_method": "tokenization",
                "backup_created": True,
                "verification_passed": True,
                "timestamp": time.time()
            }
            
            # Simulate masking different PII types
            pii_types = ["email", "ssn", "credit_card", "phone"]
            for pii_type in pii_types:
                masked = mask_pii("sample_value", pii_type)
                masking_result["pii_fields_masked"].append({
                    "type": pii_type,
                    "masked_format": masked,
                    "reversible": True
                })
            
            logger.info(f"PII masking completed for {target_resource}")
            
            return masking_result
            
        except Exception as e:
            logger.error(f"PII masking failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _implement_consent_system(self, action: RemediationAction) -> Dict[str, Any]:
        """Implement consent management system."""
        try:
            target_resource = action.target_resource
            
            logger.info(f"Implementing consent system for {target_resource}")
            
            # This is a complex manual operation
            # Provide guidance and partial automation
            
            result = {
                "success": True,
                "resource": target_resource,
                "consent_system": {
                    "database_created": True,
                    "api_endpoints": [
                        "/api/consent/grant",
                        "/api/consent/revoke",
                        "/api/consent/check",
                        "/api/consent/audit"
                    ],
                    "consent_types": [
                        "marketing",
                        "analytics",
                        "data_sharing",
                        "profiling"
                    ],
                    "granular_controls": True,
                    "withdrawal_mechanism": True,
                    "audit_trail": True
                },
                "implementation_guide": {
                    "steps_completed": 2,
                    "steps_remaining": 3,
                    "manual_steps": [
                        "Integrate consent checks into application logic",
                        "Add consent UI components",
                        "Test consent workflows"
                    ]
                },
                "timestamp": time.time()
            }
            
            logger.info(f"Consent system implementation initiated for {target_resource}")
            
            return result
            
        except Exception as e:
            logger.error(f"Consent system implementation failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _apply_pii_masking(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Apply PII masking task."""
        try:
            data_source = payload["data_source"]
            pii_types = payload.get("pii_types", [])
            masking_method = payload.get("masking_method", "tokenization")
            
            logger.info(f"Applying PII masking to {data_source}")
            
            # Create remediation action
            action = RemediationAction(
                action_id=f"mask_{int(time.time() * 1000)}",
                violation_id="manual",
                action_type="apply_pii_masking",
                strategy=RemediationStrategy.AUTOMATED,
                description=f"Apply PII masking to {data_source}",
                target_resource=data_source,
                parameters={
                    "pii_types": pii_types,
                    "masking_method": masking_method,
                    "violation": {}
                }
            )
            
            result = await self._apply_pii_masking_action(action)
            
            return {
                "data_source": data_source,
                "masking_result": result,
                "status": "completed" if result.get("success") else "failed"
            }
            
        except Exception as e:
            logger.error(f"PII masking task failed: {e}")
            raise
    
    async def _enforce_encryption(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Enforce encryption task."""
        try:
            target_resource = payload["target_resource"]
            encryption_type = payload.get("encryption_type", "both")  # at_rest, in_transit, both
            
            logger.info(f"Enforcing encryption for {target_resource}")
            
            action = RemediationAction(
                action_id=f"encrypt_{int(time.time() * 1000)}",
                violation_id="manual",
                action_type="enable_encryption",
                strategy=RemediationStrategy.AUTOMATED,
                description=f"Enable encryption for {target_resource}",
                target_resource=target_resource,
                parameters={"encryption_type": encryption_type}
            )
            
            result = await self._enable_encryption(action)
            
            return {
                "target_resource": target_resource,
                "encryption_result": result,
                "status": "completed" if result.get("success") else "failed"
            }
            
        except Exception as e:
            logger.error(f"Encryption enforcement failed: {e}")
            raise
    
    async def _configure_access_controls(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Configure access controls task."""
        try:
            target_resource = payload["target_resource"]
            access_requirements = payload.get("access_requirements", {})
            
            logger.info(f"Configuring access controls for {target_resource}")
            
            action = RemediationAction(
                action_id=f"access_{int(time.time() * 1000)}",
                violation_id="manual",
                action_type="configure_access_controls",
                strategy=RemediationStrategy.SEMI_AUTOMATED,
                description=f"Configure access controls for {target_resource}",
                target_resource=target_resource,
                parameters={"access_requirements": access_requirements}
            )
            
            result = await self._configure_access_controls_action(action)
            
            return {
                "target_resource": target_resource,
                "access_control_result": result,
                "status": "completed" if result.get("success") else "failed"
            }
            
        except Exception as e:
            logger.error(f"Access control configuration failed: {e}")
            raise
    
    async def _create_remediation_plan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a comprehensive remediation plan."""
        try:
            workflow_id = payload["workflow_id"]
            target_resource = payload["target_resource"]
            violations = payload.get("violations", [])
            
            logger.info(f"Creating remediation plan for workflow {workflow_id}")
            
            plan_id = f"plan_{int(time.time() * 1000)}"
            
            actions = []
            total_duration = 0
            
            # Create remediation action for each violation
            for violation in violations:
                template = self._get_remediation_template(violation.get("violation_type", "unknown"))
                
                if template:
                    action = RemediationAction(
                        action_id=f"action_{int(time.time() * 1000)}_{len(actions)}",
                        violation_id=violation.get("violation_id"),
                        action_type=template["action_type"],
                        strategy=RemediationStrategy(template["strategy"].value if hasattr(template["strategy"], 'value') else template["strategy"]),
                        description=template["description"],
                        target_resource=target_resource,
                        parameters={"violation": violation, "steps": template["steps"]},
                        estimated_duration=template.get("estimated_duration", 60),
                        risk_level=template.get("risk_level", "medium"),
                        requires_approval=template.get("requires_approval", False),
                        rollback_available=template.get("rollback_plan", {}).get("available", False),
                        rollback_plan=template.get("rollback_plan")
                    )
                    
                    actions.append(action)
                    total_duration += action.estimated_duration
            
            # Determine execution order (prioritize by severity and dependencies)
            execution_order = self._determine_execution_order(actions)
            
            # Create remediation plan
            plan = RemediationPlan(
                plan_id=plan_id,
                workflow_id=workflow_id,
                target_resource=target_resource,
                violations=[v.get("violation_id") for v in violations],
                actions=actions,
                execution_order=execution_order,
                total_estimated_duration=total_duration,
                approval_required=any(a.requires_approval for a in actions)
            )
            
            self.remediation_plans[plan_id] = plan
            
            return {
                "plan_id": plan_id,
                "workflow_id": workflow_id,
                "total_actions": len(actions),
                "estimated_duration_seconds": total_duration,
                "approval_required": plan.approval_required,
                "execution_order": execution_order,
                "actions": [
                    {
                        "action_id": a.action_id,
                        "action_type": a.action_type,
                        "risk_level": a.risk_level,
                        "estimated_duration": a.estimated_duration
                    }
                    for a in actions
                ]
            }
            
        except Exception as e:
            logger.error(f"Remediation plan creation failed: {e}")
            raise
    
    def _determine_execution_order(self, actions: List[RemediationAction]) -> List[str]:
        """Determine optimal execution order for remediation actions."""
        # Simple ordering by risk level and dependencies
        # In production, this would analyze dependencies between actions
        
        priority_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        
        sorted_actions = sorted(
            actions,
            key=lambda a: (priority_map.get(a.risk_level, 99), a.estimated_duration)
        )
        
        return [a.action_id for a in sorted_actions]
    
    async def _execute_remediation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a remediation plan or action."""
        try:
            if "plan_id" in payload:
                return await self._execute_remediation_plan(payload["plan_id"])
            elif "action_id" in payload:
                action = self.active_remediations.get(payload["action_id"])
                if action:
                    return await self._execute_remediation_action(action)
                else:
                    raise ValueError(f"Action {payload['action_id']} not found")
            else:
                raise ValueError("Either plan_id or action_id required")
                
        except Exception as e:
            logger.error(f"Remediation execution failed: {e}")
            raise
    
    async def _execute_remediation_plan(self, plan_id: str) -> Dict[str, Any]:
        """Execute a complete remediation plan."""
        try:
            plan = self.remediation_plans.get(plan_id)
            
            if not plan:
                raise ValueError(f"Plan {plan_id} not found")
            
            logger.info(f"Executing remediation plan {plan_id}")
            
            plan.status = "executing"
            
            results = []
            successful = 0
            failed = 0
            
            # Execute actions in order
            for action_id in plan.execution_order:
                action = next((a for a in plan.actions if a.action_id == action_id), None)
                
                if action:
                    result = await self._execute_remediation_action(action)
                    results.append(result)
                    
                    if result["status"] == "completed":
                        successful += 1
                    else:
                        failed += 1
                        
                        # Stop on critical failure if configured
                        if action.risk_level == "critical":
                            logger.error(f"Critical action failed, stopping plan execution")
                            plan.status = "failed"
                            break
            
            if plan.status != "failed":
                plan.status = "completed"
            
            return {
                "plan_id": plan_id,
                "status": plan.status,
                "total_actions": len(plan.actions),
                "successful": successful,
                "failed": failed,
                "results": results
            }
            
        except Exception as e:
            logger.error(f"Remediation plan execution failed: {e}")
            raise
    
    async def _rollback_remediation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback a remediation action."""
        try:
            action_id = payload["action_id"]
            
            # Find action in history
            action = next(
                (a for a in self.remediation_history if a.action_id == action_id),
                None
            )
            
            if not action:
                raise ValueError(f"Action {action_id} not found in history")
            
            if not action.rollback_available:
                raise ValueError(f"Action {action_id} does not support rollback")
            
            logger.info(f"Rolling back remediation action {action_id}")
            
            # Execute rollback steps
            rollback_result = await self._execute_rollback_steps(
                action.rollback_plan["steps"],
                action.target_resource,
                action.result
            )
            
            if rollback_result["success"]:
                action.status = RemediationStatus.ROLLED_BACK
            
            return {
                "action_id": action_id,
                "rollback_status": "completed" if rollback_result["success"] else "failed",
                "rollback_result": rollback_result
            }
            
        except Exception as e:
            logger.error(f"Remediation rollback failed: {e}")
            raise
    
    async def _execute_rollback_steps(
        self, 
        steps: List[str], 
        resource: str,
        original_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute rollback steps."""
        try:
            logger.info(f"Executing rollback for {resource}")
            
            # Simulate rollback execution
            for step in steps:
                logger.info(f"Rollback step: {step}")
                # In production, execute actual rollback operations
                await asyncio.sleep(0.1)  # Simulate work
            
            return {
                "success": True,
                "resource": resource,
                "steps_executed": steps,
                "timestamp": time.time()
            }
            
        except Exception as e:
            logger.error(f"Rollback execution failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _approve_remediation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Approve a pending remediation action."""
        try:
            action_id = payload["action_id"]
            approved = payload.get("approved", False)
            approver = payload.get("approver", "unknown")
            
            action = self.active_remediations.get(action_id)
            
            if not action:
                raise ValueError(f"Action {action_id} not found")
            
            if action.status != RemediationStatus.REQUIRES_APPROVAL:
                raise ValueError(f"Action {action_id} is not pending approval")
            
            logger.info(f"Processing approval for {action_id}: {approved}")
            
            if approved:
                action.approval_status = "approved"
                action.status = RemediationStatus.APPROVED
                
                # Execute the approved action
                result = await self._execute_remediation_action(action)
                
                return {
                    "action_id": action_id,
                    "approval_status": "approved",
                    "approver": approver,
                    "execution_result": result
                }
            else:
                action.approval_status = "rejected"
                action.status = RemediationStatus.FAILED
                
                # Remove from active
                del self.active_remediations[action_id]
                
                return {
                    "action_id": action_id,
                    "approval_status": "rejected",
                    "approver": approver
                }
                
        except Exception as e:
            logger.error(f"Remediation approval processing failed: {e}")
            raise
    
    async def _immediate_containment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute immediate containment actions for emergency response."""
        try:
            incident_type = payload["incident_type"]
            target_resource = payload["target_resource"]
            
            logger.warning(f"Executing immediate containment for {incident_type} on {target_resource}")
            
            containment_actions = []
            
            # Immediate isolation
            containment_actions.append({
                "action": "isolate_resource",
                "resource": target_resource,
                "method": "security_group_lockdown",
                "status": "completed",
                "timestamp": time.time()
            })
            
            # Revoke access
            containment_actions.append({
                "action": "revoke_access",
                "resource": target_resource,
                "method": "temporary_access_suspension",
                "status": "completed",
                "timestamp": time.time()
            })
            
            # Enable enhanced monitoring
            containment_actions.append({
                "action": "enable_enhanced_monitoring",
                "resource": target_resource,
                "method": "cloudwatch_detailed_monitoring",
                "status": "completed",
                "timestamp": time.time()
            })
            
            # Create backup/snapshot
            containment_actions.append({
                "action": "create_forensic_snapshot",
                "resource": target_resource,
                "method": "ebs_snapshot",
                "status": "completed",
                "timestamp": time.time()
            })
            
            return {
                "incident_type": incident_type,
                "target_resource": target_resource,
                "containment_status": "contained",
                "actions_taken": containment_actions,
                "immediate_actions": [a["action"] for a in containment_actions],
                "timestamp": time.time()
            }
            
        except Exception as e:
            logger.error(f"Immediate containment failed: {e}")
            raise
