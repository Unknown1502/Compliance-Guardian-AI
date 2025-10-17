"""Automated compliance decision-making engine."""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from ..utils.logger import get_logger
from ..core.bedrock_client import BedrockClient
from .risk_assessor import RiskAssessor
from .policy_interpreter import PolicyInterpreter

logger = get_logger(__name__)


class DecisionType(Enum):
    """Types of compliance decisions."""
    APPROVE = "approve"
    REJECT = "reject"
    ESCALATE = "escalate"
    DEFER = "defer"
    REMEDIATE = "remediate"


@dataclass
class ComplianceDecision:
    """Compliance decision result."""
    
    decision_id: str
    decision_type: DecisionType
    confidence: float  # 0-1
    reasoning: str
    actions: List[Dict[str, Any]]
    approval_required: bool
    approvers: List[str]
    risk_level: str
    estimated_impact: Dict[str, Any]


class DecisionMaker:
    """
    Automated compliance decision-making engine.
    
    Makes intelligent decisions about:
    - Remediation prioritization
    - Approval workflows
    - Risk acceptance
    - Exception handling
    - Resource allocation
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize decision maker."""
        self.config = config or {}
        self.bedrock_client = BedrockClient(config)
        self.risk_assessor = RiskAssessor(config)
        self.policy_interpreter = PolicyInterpreter(config)
        
        # Decision thresholds
        self.thresholds = {
            "auto_approve_risk": 30,  # Auto-approve if risk < 30
            "auto_escalate_risk": 80,  # Auto-escalate if risk > 80
            "high_cost_threshold": 100000,  # Escalate if cost > $100k
            "high_impact_threshold": 1000  # Escalate if >1000 users affected
        }
    
    async def make_remediation_decision(
        self,
        violation: Dict[str, Any],
        remediation_options: List[Dict[str, Any]]
    ) -> ComplianceDecision:
        """Make decision on remediation approach."""
        try:
            logger.info(f"Making remediation decision for violation: {violation.get('violation_id')}")
            
            # Assess risk
            risk_score = await self.risk_assessor.assess_violation_risk(violation)
            
            # Analyze remediation options
            best_option = await self._select_best_remediation(
                violation,
                remediation_options,
                risk_score
            )
            
            # Determine if approval is needed
            approval_required, approvers = self._determine_approval_requirements(
                risk_score,
                best_option
            )
            
            # Make decision
            decision_type = self._determine_decision_type(risk_score, best_option)
            
            # Generate reasoning
            reasoning = await self._generate_decision_reasoning(
                violation,
                risk_score,
                best_option,
                decision_type
            )
            
            # Define actions
            actions = self._define_remediation_actions(best_option)
            
            # Estimate impact
            impact = self._estimate_decision_impact(best_option, risk_score)
            
            decision = ComplianceDecision(
                decision_id=f"DEC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                decision_type=decision_type,
                confidence=self._calculate_decision_confidence(risk_score, best_option),
                reasoning=reasoning,
                actions=actions,
                approval_required=approval_required,
                approvers=approvers,
                risk_level=risk_score.severity,
                estimated_impact=impact
            )
            
            logger.info(f"Decision made: {decision_type.value} (confidence: {decision.confidence})")
            
            return decision
        
        except Exception as e:
            logger.error(f"Decision making failed: {e}")
            raise
    
    async def _select_best_remediation(
        self,
        violation: Dict[str, Any],
        options: List[Dict[str, Any]],
        risk_score: Any
    ) -> Dict[str, Any]:
        """Select best remediation option using multi-criteria analysis."""
        if not options:
            return {
                "type": "manual_review",
                "cost": 0,
                "time_estimate": "unknown",
                "effectiveness": 0.5
            }
        
        # Score each option
        scored_options = []
        for option in options:
            score = await self._score_remediation_option(option, violation, risk_score)
            scored_options.append({
                "option": option,
                "score": score
            })
        
        # Select highest scoring option
        best = max(scored_options, key=lambda x: x["score"])
        return best["option"]
    
    async def _score_remediation_option(
        self,
        option: Dict[str, Any],
        violation: Dict[str, Any],
        risk_score: Any
    ) -> float:
        """Score a remediation option using weighted criteria."""
        weights = {
            "effectiveness": 0.35,
            "cost": 0.25,
            "time": 0.20,
            "risk_reduction": 0.20
        }
        
        # Effectiveness score
        effectiveness = option.get("effectiveness", 0.5)
        effectiveness_score = effectiveness * 100
        
        # Cost score (inverse - lower cost = higher score)
        cost = option.get("cost", 10000)
        cost_score = max(0, 100 - (cost / 1000))  # Normalize
        
        # Time score (inverse - faster = higher score)
        time_hours = self._parse_time_estimate(option.get("time_estimate", "1 day"))
        time_score = max(0, 100 - time_hours)
        
        # Risk reduction score
        risk_reduction = option.get("risk_reduction", 0.5)
        risk_reduction_score = risk_reduction * 100
        
        # Calculate weighted score
        total_score = (
            effectiveness_score * weights["effectiveness"] +
            cost_score * weights["cost"] +
            time_score * weights["time"] +
            risk_reduction_score * weights["risk_reduction"]
        )
        
        return total_score
    
    def _parse_time_estimate(self, time_str: str) -> float:
        """Parse time estimate string to hours."""
        import re
        
        # Extract number
        numbers = re.findall(r'\d+', time_str)
        if not numbers:
            return 24  # Default 1 day
        
        value = int(numbers[0])
        
        # Convert to hours
        if 'hour' in time_str.lower():
            return value
        elif 'day' in time_str.lower():
            return value * 24
        elif 'week' in time_str.lower():
            return value * 24 * 7
        else:
            return value
    
    def _determine_approval_requirements(
        self,
        risk_score: Any,
        remediation: Dict[str, Any]
    ) -> tuple[bool, List[str]]:
        """Determine if approval is required and who should approve."""
        approvers = []
        
        # High risk always requires approval
        if risk_score.overall_score >= self.thresholds["auto_escalate_risk"]:
            approvers.extend(["CISO", "DPO", "Legal"])
        
        # High cost requires CFO approval
        if remediation.get("cost", 0) >= self.thresholds["high_cost_threshold"]:
            approvers.append("CFO")
        
        # Production changes require change board
        if remediation.get("affects_production", False):
            approvers.append("Change_Board")
        
        # Data deletion requires DPO
        if remediation.get("type") == "data_deletion":
            approvers.append("DPO")
        
        return len(approvers) > 0, list(set(approvers))
    
    def _determine_decision_type(self, risk_score: Any, remediation: Dict[str, Any]) -> DecisionType:
        """Determine decision type based on risk and remediation."""
        # Critical risk - escalate immediately
        if risk_score.severity == "critical":
            return DecisionType.ESCALATE
        
        # Low risk with low-cost remediation - auto-approve
        if (risk_score.overall_score < self.thresholds["auto_approve_risk"] and
            remediation.get("cost", 0) < 10000):
            return DecisionType.APPROVE
        
        # High effectiveness remediation - proceed with remediation
        if remediation.get("effectiveness", 0) > 0.8:
            return DecisionType.REMEDIATE
        
        # Uncertain - defer for manual review
        if remediation.get("effectiveness", 0) < 0.5:
            return DecisionType.DEFER
        
        # Default - escalate for approval
        return DecisionType.ESCALATE
    
    async def _generate_decision_reasoning(
        self,
        violation: Dict[str, Any],
        risk_score: Any,
        remediation: Dict[str, Any],
        decision_type: DecisionType
    ) -> str:
        """Generate natural language reasoning for the decision."""
        prompt = f"""
        Generate a concise explanation for this compliance decision:
        
        Violation: {violation.get('violation_type')}
        Risk Score: {risk_score.overall_score}/100 ({risk_score.severity})
        Remediation: {remediation.get('type')} (effectiveness: {remediation.get('effectiveness', 0)})
        Decision: {decision_type.value}
        
        Explain the reasoning in 2-3 sentences. Be specific about why this decision was made.
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            return response.get("completion", "Decision based on risk assessment and remediation analysis.")
        
        except Exception as e:
            logger.warning(f"Failed to generate reasoning: {e}")
            return f"{decision_type.value.title()} based on risk level: {risk_score.severity}"
    
    def _define_remediation_actions(self, remediation: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Define specific actions for remediation."""
        actions = []
        
        remediation_type = remediation.get("type", "manual_review")
        
        # Define actions based on remediation type
        if remediation_type == "encryption":
            actions = [
                {
                    "action": "enable_encryption",
                    "target": remediation.get("target"),
                    "method": remediation.get("encryption_method", "AES-256"),
                    "priority": "high"
                },
                {
                    "action": "verify_encryption",
                    "target": remediation.get("target"),
                    "validation": "encryption_enabled",
                    "priority": "high"
                }
            ]
        
        elif remediation_type == "access_control":
            actions = [
                {
                    "action": "update_permissions",
                    "target": remediation.get("target"),
                    "new_permissions": remediation.get("permissions", {}),
                    "priority": "high"
                },
                {
                    "action": "audit_access",
                    "target": remediation.get("target"),
                    "frequency": "daily",
                    "priority": "medium"
                }
            ]
        
        elif remediation_type == "data_deletion":
            actions = [
                {
                    "action": "backup_data",
                    "target": remediation.get("target"),
                    "backup_location": "secure_archive",
                    "priority": "critical"
                },
                {
                    "action": "delete_data",
                    "target": remediation.get("target"),
                    "verification": "hard_delete",
                    "priority": "high"
                },
                {
                    "action": "confirm_deletion",
                    "target": remediation.get("target"),
                    "proof_required": True,
                    "priority": "high"
                }
            ]
        
        elif remediation_type == "policy_update":
            actions = [
                {
                    "action": "draft_policy",
                    "policy": remediation.get("policy_name"),
                    "changes": remediation.get("changes", []),
                    "priority": "medium"
                },
                {
                    "action": "review_policy",
                    "reviewers": ["Legal", "DPO"],
                    "priority": "medium"
                },
                {
                    "action": "publish_policy",
                    "effective_date": remediation.get("effective_date"),
                    "priority": "low"
                }
            ]
        
        else:
            actions = [
                {
                    "action": "manual_review",
                    "assigned_to": "compliance_team",
                    "priority": "medium"
                }
            ]
        
        return actions
    
    def _estimate_decision_impact(
        self,
        remediation: Dict[str, Any],
        risk_score: Any
    ) -> Dict[str, Any]:
        """Estimate the impact of the decision."""
        return {
            "risk_reduction": remediation.get("risk_reduction", 0.5) * risk_score.overall_score,
            "estimated_cost": remediation.get("cost", 0),
            "estimated_time": remediation.get("time_estimate", "unknown"),
            "affected_systems": remediation.get("affected_systems", []),
            "business_impact": self._assess_business_impact(remediation),
            "compliance_improvement": remediation.get("effectiveness", 0.5) * 100
        }
    
    def _assess_business_impact(self, remediation: Dict[str, Any]) -> str:
        """Assess business impact of remediation."""
        if remediation.get("downtime_required", False):
            return "high"
        elif remediation.get("affects_production", False):
            return "medium"
        else:
            return "low"
    
    def _calculate_decision_confidence(self, risk_score: Any, remediation: Dict[str, Any]) -> float:
        """Calculate confidence in the decision."""
        factors = []
        
        # Risk assessment confidence
        factors.append(risk_score.confidence)
        
        # Remediation effectiveness certainty
        effectiveness = remediation.get("effectiveness", 0.5)
        if effectiveness > 0.8 or effectiveness < 0.3:
            factors.append(0.9)  # High confidence in clear cases
        else:
            factors.append(0.6)  # Lower confidence in uncertain cases
        
        # Cost certainty
        if remediation.get("cost", 0) > 0:
            factors.append(0.8)  # Known cost
        else:
            factors.append(0.5)  # Unknown cost
        
        # Average confidence
        return sum(factors) / len(factors)
    
    async def prioritize_violations(
        self,
        violations: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Prioritize violations for remediation."""
        logger.info(f"Prioritizing {len(violations)} violations")
        
        # Assess risk for each violation
        prioritized = []
        for violation in violations:
            risk_score = await self.risk_assessor.assess_violation_risk(violation)
            
            priority_score = self._calculate_priority_score(violation, risk_score)
            
            prioritized.append({
                "violation": violation,
                "risk_score": risk_score.overall_score,
                "priority_score": priority_score,
                "severity": risk_score.severity
            })
        
        # Sort by priority score (descending)
        prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return prioritized
    
    def _calculate_priority_score(self, violation: Dict[str, Any], risk_score: Any) -> float:
        """Calculate priority score for a violation."""
        score = risk_score.overall_score
        
        # Boost priority for certain conditions
        
        # Regulatory deadline approaching
        if violation.get("deadline"):
            # Simplified: boost if deadline field exists
            score += 20
        
        # Public-facing systems
        if violation.get("public_facing", False):
            score += 15
        
        # Data breach potential
        if "breach" in violation.get("violation_type", "").lower():
            score += 25
        
        # Customer impact
        affected = violation.get("affected_individuals", 0)
        if affected > 1000:
            score += 20
        elif affected > 100:
            score += 10
        
        return min(100, score)
    
    async def make_exception_decision(
        self,
        exception_request: Dict[str, Any]
    ) -> ComplianceDecision:
        """Make decision on compliance exception request."""
        logger.info(f"Evaluating exception request: {exception_request.get('request_id')}")
        
        # Analyze exception request
        risk_level = await self._assess_exception_risk(exception_request)
        
        # Get policy interpretation
        policy_context = await self.policy_interpreter.interpret_policy(
            framework=exception_request.get("framework", ""),
            policy_reference=exception_request.get("policy_reference", "")
        )
        
        # Make decision
        if risk_level < 30 and exception_request.get("justification"):
            decision_type = DecisionType.APPROVE
            reasoning = "Low risk exception with valid justification"
        elif risk_level > 70:
            decision_type = DecisionType.REJECT
            reasoning = "High risk - exception cannot be granted"
        else:
            decision_type = DecisionType.ESCALATE
            reasoning = "Moderate risk - requires executive approval"
        
        return ComplianceDecision(
            decision_id=f"EXC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            decision_type=decision_type,
            confidence=0.75,
            reasoning=reasoning,
            actions=[],
            approval_required=decision_type == DecisionType.ESCALATE,
            approvers=["CISO", "DPO"] if decision_type == DecisionType.ESCALATE else [],
            risk_level="medium",
            estimated_impact={}
        )
    
    async def _assess_exception_risk(self, exception_request: Dict[str, Any]) -> float:
        """Assess risk of granting an exception."""
        base_risk = 50
        
        # Increase risk based on factors
        if exception_request.get("duration_days", 0) > 90:
            base_risk += 20
        
        if not exception_request.get("justification"):
            base_risk += 30
        
        if not exception_request.get("compensating_controls"):
            base_risk += 25
        
        return min(100, base_risk)
