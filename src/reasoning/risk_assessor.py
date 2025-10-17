"""ML-based risk assessment engine."""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
import numpy as np

from ..utils.logger import get_logger
from ..core.bedrock_client import BedrockClient

logger = get_logger(__name__)


@dataclass
class RiskScore:
    """Risk assessment score."""
    
    overall_score: float  # 0-100
    severity: str  # low, medium, high, critical
    confidence: float  # 0-1
    factors: Dict[str, float]
    recommendations: List[str]


class RiskAssessor:
    """
    ML-based risk assessment engine.
    
    Assesses risks based on:
    - Violation severity
    - Data sensitivity
    - Exposure scope
    - Historical patterns
    - Regulatory penalties
    - Business impact
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize risk assessor."""
        self.config = config or {}
        self.bedrock_client = BedrockClient(config)
        
        # Risk factor weights
        self.weights = {
            "violation_severity": 0.25,
            "data_sensitivity": 0.20,
            "exposure_scope": 0.15,
            "regulatory_penalty": 0.20,
            "business_impact": 0.15,
            "remediation_difficulty": 0.05
        }
    
    async def assess_violation_risk(self, violation: Dict[str, Any]) -> RiskScore:
        """Assess risk for a compliance violation."""
        try:
            logger.info(f"Assessing risk for violation: {violation.get('violation_id', 'unknown')}")
            
            # Calculate individual risk factors
            factors = {
                "violation_severity": self._assess_violation_severity(violation),
                "data_sensitivity": self._assess_data_sensitivity(violation),
                "exposure_scope": self._assess_exposure_scope(violation),
                "regulatory_penalty": await self._assess_regulatory_penalty(violation),
                "business_impact": self._assess_business_impact(violation),
                "remediation_difficulty": self._assess_remediation_difficulty(violation)
            }
            
            # Calculate weighted overall score
            overall_score = sum(
                factors[factor] * self.weights[factor]
                for factor in factors
            )
            
            # Determine severity
            severity = self._determine_severity(overall_score)
            
            # Calculate confidence based on data completeness
            confidence = self._calculate_confidence(violation, factors)
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(violation, factors, overall_score)
            
            risk_score = RiskScore(
                overall_score=round(overall_score, 2),
                severity=severity,
                confidence=round(confidence, 2),
                factors=factors,
                recommendations=recommendations
            )
            
            logger.info(f"Risk assessment complete: {severity} ({overall_score})")
            
            return risk_score
        
        except Exception as e:
            logger.error(f"Risk assessment failed: {e}")
            raise
    
    def _assess_violation_severity(self, violation: Dict[str, Any]) -> float:
        """Assess violation severity (0-100)."""
        severity_mapping = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25
        }
        
        severity = violation.get("severity", "medium").lower()
        return severity_mapping.get(severity, 50)
    
    def _assess_data_sensitivity(self, violation: Dict[str, Any]) -> float:
        """Assess data sensitivity (0-100)."""
        data_types = violation.get("data_types", [])
        
        sensitivity_scores = {
            "phi": 100,  # Protected Health Information
            "pci": 90,   # Payment Card Industry data
            "pii": 80,   # Personally Identifiable Information
            "restricted": 70,
            "confidential": 60,
            "internal": 40,
            "public": 10
        }
        
        if not data_types:
            return 50
        
        # Get maximum sensitivity
        max_sensitivity = max(
            (sensitivity_scores.get(dt.lower(), 50) for dt in data_types),
            default=50
        )
        
        return max_sensitivity
    
    def _assess_exposure_scope(self, violation: Dict[str, Any]) -> float:
        """Assess exposure scope (0-100)."""
        affected_count = violation.get("affected_individuals", 0)
        
        # Logarithmic scale for affected individuals
        if affected_count == 0:
            return 0
        elif affected_count < 10:
            return 20
        elif affected_count < 100:
            return 40
        elif affected_count < 1000:
            return 60
        elif affected_count < 10000:
            return 80
        else:
            return 100
    
    async def _assess_regulatory_penalty(self, violation: Dict[str, Any]) -> float:
        """Assess potential regulatory penalty (0-100)."""
        framework = violation.get("framework", "").upper()
        
        # Use LLM to assess penalty based on violation details
        prompt = f"""
        Assess the potential regulatory penalty for this compliance violation:
        
        Framework: {framework}
        Violation Type: {violation.get('violation_type')}
        Description: {violation.get('description')}
        Severity: {violation.get('severity')}
        
        Consider:
        - Regulatory fines for this framework
        - Violation type and severity
        - Precedent cases
        
        Provide a penalty risk score from 0-100 where:
        - 0-20: Minimal penalty risk
        - 21-40: Low penalty risk
        - 41-60: Moderate penalty risk
        - 61-80: High penalty risk
        - 81-100: Severe penalty risk (potentially millions in fines)
        
        Return only the numeric score.
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            # Extract score from response
            score = self._extract_score(response.get("completion", "50"))
            return min(100, max(0, score))
        
        except Exception as e:
            logger.warning(f"Failed to assess regulatory penalty via LLM: {e}")
            
            # Fallback: framework-based scoring
            penalty_scores = {
                "GDPR": 90,  # Up to €20M or 4% of revenue
                "HIPAA": 80,  # Up to $1.5M per violation
                "PCI": 70,   # Fines + card brand penalties
                "SOX": 85,   # Criminal penalties possible
                "CCPA": 75   # Up to $7,500 per violation
            }
            
            return penalty_scores.get(framework, 60)
    
    def _assess_business_impact(self, violation: Dict[str, Any]) -> float:
        """Assess business impact (0-100)."""
        impacts = []
        
        # Reputation impact
        if violation.get("public_disclosure_required", False):
            impacts.append(80)
        
        # Operational impact
        if violation.get("service_disruption", False):
            impacts.append(70)
        
        # Financial impact
        estimated_cost = violation.get("estimated_remediation_cost", 0)
        if estimated_cost > 1000000:
            impacts.append(90)
        elif estimated_cost > 100000:
            impacts.append(70)
        elif estimated_cost > 10000:
            impacts.append(50)
        
        return max(impacts) if impacts else 50
    
    def _assess_remediation_difficulty(self, violation: Dict[str, Any]) -> float:
        """Assess remediation difficulty (0-100)."""
        difficulty = violation.get("remediation_difficulty", "medium").lower()
        
        difficulty_scores = {
            "easy": 20,
            "medium": 50,
            "hard": 80,
            "very_hard": 100
        }
        
        return difficulty_scores.get(difficulty, 50)
    
    def _determine_severity(self, score: float) -> str:
        """Determine severity from score."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"
    
    def _calculate_confidence(self, violation: Dict[str, Any], factors: Dict[str, float]) -> float:
        """Calculate confidence score based on data completeness."""
        required_fields = [
            "violation_type", "severity", "description", "framework",
            "affected_individuals", "data_types"
        ]
        
        present_fields = sum(1 for field in required_fields if violation.get(field))
        completeness = present_fields / len(required_fields)
        
        # Factor in the consistency of factor scores
        factor_values = list(factors.values())
        if len(factor_values) > 1:
            std_dev = np.std(factor_values)
            consistency = 1 - (std_dev / 100)  # Normalize
        else:
            consistency = 0.5
        
        confidence = (completeness * 0.7) + (consistency * 0.3)
        
        return confidence
    
    async def _generate_recommendations(
        self,
        violation: Dict[str, Any],
        factors: Dict[str, float],
        overall_score: float
    ) -> List[str]:
        """Generate risk mitigation recommendations."""
        recommendations = []
        
        # High violation severity
        if factors["violation_severity"] >= 75:
            recommendations.append("Immediate executive escalation required")
        
        # High data sensitivity
        if factors["data_sensitivity"] >= 80:
            recommendations.append("Engage data protection officer immediately")
        
        # Large exposure scope
        if factors["exposure_scope"] >= 60:
            recommendations.append("Prepare for potential regulatory notification")
        
        # High regulatory penalty
        if factors["regulatory_penalty"] >= 70:
            recommendations.append("Consult legal counsel before remediation")
        
        # High business impact
        if factors["business_impact"] >= 70:
            recommendations.append("Activate incident response team")
        
        # Use LLM for additional context-specific recommendations
        if overall_score >= 60:
            llm_recommendations = await self._get_llm_recommendations(violation, overall_score)
            recommendations.extend(llm_recommendations)
        
        return recommendations[:5]  # Top 5 recommendations
    
    async def _get_llm_recommendations(self, violation: Dict[str, Any], score: float) -> List[str]:
        """Get additional recommendations from LLM."""
        prompt = f"""
        Given this compliance violation with risk score {score}/100:
        
        Framework: {violation.get('framework')}
        Type: {violation.get('violation_type')}
        Description: {violation.get('description')}
        
        Provide 2-3 specific, actionable recommendations to mitigate the risk.
        Be concise and prioritize high-impact actions.
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            # Parse recommendations from response
            recommendations = self._parse_recommendations(response.get("completion", ""))
            return recommendations
        
        except Exception as e:
            logger.warning(f"Failed to get LLM recommendations: {e}")
            return []
    
    def _parse_recommendations(self, text: str) -> List[str]:
        """Parse recommendations from LLM response."""
        # Simple parsing - look for numbered lists or bullet points
        import re
        
        patterns = [
            r'\d+\.\s*(.+?)(?=\d+\.|$)',  # Numbered list
            r'[-•]\s*(.+?)(?=[-•]|$)',     # Bullet points
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.MULTILINE | re.DOTALL)
            if matches:
                return [m.strip() for m in matches if m.strip()]
        
        # Fallback: split by newlines
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        return lines[:3]
    
    def _extract_score(self, text: str) -> float:
        """Extract numeric score from text."""
        import re
        
        # Look for numbers
        numbers = re.findall(r'\d+\.?\d*', text)
        
        if numbers:
            return float(numbers[0])
        
        return 50.0  # Default
    
    async def assess_overall_compliance_risk(self, violations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall compliance risk across multiple violations."""
        if not violations:
            return {
                "overall_risk_score": 0,
                "severity": "low",
                "total_violations": 0,
                "breakdown": {}
            }
        
        # Assess each violation
        risk_scores = []
        for violation in violations:
            score = await self.assess_violation_risk(violation)
            risk_scores.append(score)
        
        # Calculate overall score
        overall_score = np.mean([rs.overall_score for rs in risk_scores])
        
        # Get severity distribution
        severity_counts = {}
        for rs in risk_scores:
            severity_counts[rs.severity] = severity_counts.get(rs.severity, 0) + 1
        
        # Get framework breakdown
        framework_scores = {}
        for violation, score in zip(violations, risk_scores):
            framework = violation.get("framework", "Unknown")
            if framework not in framework_scores:
                framework_scores[framework] = []
            framework_scores[framework].append(score.overall_score)
        
        framework_avg = {
            framework: np.mean(scores)
            for framework, scores in framework_scores.items()
        }
        
        return {
            "overall_risk_score": round(overall_score, 2),
            "severity": self._determine_severity(overall_score),
            "total_violations": len(violations),
            "severity_distribution": severity_counts,
            "framework_breakdown": framework_avg,
            "highest_risk_violation": max(risk_scores, key=lambda x: x.overall_score).__dict__
        }
