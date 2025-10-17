"""Explainability Agent - Specialized agent for compliance explanations and transparency."""

import asyncio
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .base_agent import BaseAgent, AgentTask, AgentStatus, AgentCapability
from ..core.bedrock_client import BedrockResponse
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ExplanationType(Enum):
    """Types of explanations."""
    VIOLATION_EXPLANATION = "violation_explanation"
    POLICY_INTERPRETATION = "policy_interpretation"
    RISK_JUSTIFICATION = "risk_justification"
    REMEDIATION_RATIONALE = "remediation_rationale"
    WORKFLOW_EXPLANATION = "workflow_explanation"
    COMPLIANCE_GUIDANCE = "compliance_guidance"
    DECISION_EXPLANATION = "decision_explanation"


class AudienceLevel(Enum):
    """Target audience expertise levels."""
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    LEGAL = "legal"
    OPERATIONAL = "operational"
    GENERAL = "general"


@dataclass
class Explanation:
    """Represents an explanation."""
    
    explanation_id: str
    explanation_type: ExplanationType
    subject: str
    audience_level: AudienceLevel
    summary: str
    detailed_explanation: str
    key_points: List[str]
    regulatory_references: List[Dict[str, str]]
    visual_aids: Optional[Dict[str, Any]] = None
    related_topics: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExplainabilityAgent(BaseAgent):
    """
    Explainability Agent specializes in providing clear, understandable explanations
    of compliance concepts, violations, and remediation actions.
    
    Responsibilities:
    - Generate human-readable explanations of violations
    - Interpret regulatory policies and requirements
    - Explain risk assessments and scores
    - Provide remediation rationales
    - Create compliance guidance documentation
    - Translate technical findings for different audiences
    - Generate visual representations of compliance data
    """
    
    def __init__(self, config: Dict[str, Any], **kwargs):
        """Initialize Explainability Agent."""
        super().__init__(
            agent_id="explainability-agent",
            config=config,
            **kwargs
        )
        
        # Explainability-specific state
        self.explanations: Dict[str, Explanation] = {}
        self.explanation_templates: Dict[str, str] = {}
        
        # Configuration
        self.default_audience = AudienceLevel(config.get("default_audience", "technical"))
        self.include_visual_aids = config.get("include_visual_aids", True)
        self.max_explanation_length = config.get("max_explanation_length", 2000)
        
        # Initialize explanation templates
        self._initialize_explanation_templates()
        
    def _initialize_capabilities(self) -> None:
        """Initialize explainability agent capabilities."""
        self.capabilities = {
            AgentCapability.EXPLAINABILITY,
            AgentCapability.POLICY_INTERPRETATION,
            AgentCapability.DATA_ANALYSIS
        }
    
    def _initialize_explanation_templates(self) -> None:
        """Initialize explanation templates for different contexts."""
        
        self.explanation_templates = {
            "violation_explanation": """
            Explain the following compliance violation in clear, {audience_level} terms:
            
            Violation Type: {violation_type}
            Framework: {framework}
            Severity: {severity}
            Resource: {resource}
            Description: {description}
            Evidence: {evidence}
            
            Provide:
            1. What the violation means
            2. Why it's a compliance issue
            3. Potential consequences
            4. How it should be addressed
            5. Relevant regulatory requirements
            
            Keep the explanation {tone} and actionable.
            """,
            
            "policy_interpretation": """
            Interpret the following regulatory policy requirement:
            
            Framework: {framework}
            Policy Name: {policy_name}
            Regulation Reference: {regulation_reference}
            Policy Description: {description}
            
            Provide a clear interpretation covering:
            1. Plain language summary
            2. Who it applies to
            3. What compliance requires
            4. Common compliance gaps
            5. Best practices for implementation
            
            Target audience: {audience_level}
            """,
            
            "risk_justification": """
            Explain the risk assessment for the following compliance scenario:
            
            Risk Score: {risk_score}/10
            Risk Level: {risk_level}
            Violation Count: {violation_count}
            Frameworks Affected: {frameworks}
            
            Provide:
            1. How the risk score was calculated
            2. Key risk factors
            3. Business impact assessment
            4. Regulatory enforcement likelihood
            5. Recommended risk mitigation priorities
            
            Audience: {audience_level}
            """,
            
            "remediation_rationale": """
            Explain the rationale for the following remediation action:
            
            Action Type: {action_type}
            Violation Addressed: {violation_type}
            Target Resource: {resource}
            Remediation Strategy: {strategy}
            
            Explain:
            1. Why this remediation is necessary
            2. How it addresses the compliance gap
            3. Benefits of implementation
            4. Potential impacts and considerations
            5. Alternative approaches (if any)
            
            Tone: {tone}
            """,
            
            "workflow_explanation": """
            Provide an executive summary of the following compliance workflow:
            
            Workflow Type: {workflow_type}
            Target Resource: {target_resource}
            Frameworks: {frameworks}
            Total Violations: {total_violations}
            Resolved Violations: {resolved_violations}
            Risk Score: {risk_score}
            
            Generate:
            1. Workflow overview and objectives
            2. Key findings and outcomes
            3. Compliance posture assessment
            4. Business impact summary
            5. Strategic recommendations
            
            Audience: {audience_level}
            Keep it concise and focused on business value.
            """
        }
    
    async def _execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute explainability-specific tasks."""
        task_type = task.task_type
        payload = task.payload
        
        try:
            if task_type == "violation_explanation":
                return await self._explain_violation(payload)
            elif task_type == "policy_interpretation":
                return await self._interpret_policy(payload)
            elif task_type == "risk_justification":
                return await self._justify_risk_assessment(payload)
            elif task_type == "remediation_rationale":
                return await self._explain_remediation(payload)
            elif task_type == "workflow_explanation":
                return await self._explain_workflow(payload)
            elif task_type == "compliance_guidance":
                return await self._provide_compliance_guidance(payload)
            elif task_type == "decision_explanation":
                return await self._explain_decision(payload)
            elif task_type == "generate_faq":
                return await self._generate_compliance_faq(payload)
            elif task_type == "translate_for_audience":
                return await self._translate_for_audience(payload)
            else:
                raise ValueError(f"Unknown task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Failed to execute explainability task {task_type}: {e}")
            raise
    
    async def _explain_violation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate explanation for a compliance violation."""
        try:
            violation = payload["violation"]
            audience_level = AudienceLevel(payload.get("audience", "technical"))
            
            violation_type = violation.get("violation_type", violation.get("type", "unknown"))
            framework = violation.get("framework", "unknown")
            severity = violation.get("severity", "unknown")
            resource = violation.get("resource_id", violation.get("resource", "unknown"))
            description = violation.get("description", "No description available")
            evidence = violation.get("evidence", {})
            
            logger.info(f"Generating violation explanation for {violation_type}")
            
            # Prepare prompt
            tone = self._get_tone_for_audience(audience_level)
            
            prompt = self.explanation_templates["violation_explanation"].format(
                audience_level=audience_level.value,
                violation_type=violation_type,
                framework=framework,
                severity=severity,
                resource=resource,
                description=description,
                evidence=json.dumps(evidence, indent=2),
                tone=tone
            )
            
            # Generate explanation using LLM
            response = await self.invoke_llm(
                prompt=prompt,
                system_prompt=f"You are a compliance expert explaining to {audience_level.value} audience."
            )
            
            # Parse and structure the explanation
            explanation_text = response.content
            
            # Extract key points
            key_points = self._extract_key_points(explanation_text)
            
            # Get regulatory references
            regulatory_refs = self._extract_regulatory_references(
                framework,
                violation_type,
                violation.get("regulation_reference", "")
            )
            
            # Create explanation object
            explanation = Explanation(
                explanation_id=f"exp_{int(time.time() * 1000)}",
                explanation_type=ExplanationType.VIOLATION_EXPLANATION,
                subject=f"{violation_type} violation",
                audience_level=audience_level,
                summary=self._extract_summary(explanation_text),
                detailed_explanation=explanation_text,
                key_points=key_points,
                regulatory_references=regulatory_refs,
                confidence_score=0.9,
                metadata={
                    "violation_id": violation.get("violation_id"),
                    "framework": framework,
                    "severity": severity
                }
            )
            
            # Generate visual aids if enabled
            if self.include_visual_aids:
                explanation.visual_aids = self._generate_violation_visuals(violation)
            
            # Store explanation
            self.explanations[explanation.explanation_id] = explanation
            
            # Store in memory
            await self.store_memory(
                content={
                    "explanation_generated": explanation.explanation_id,
                    "type": "violation_explanation",
                    "subject": explanation.subject,
                    "audience": audience_level.value
                },
                memory_type="context",
                importance_score=0.7
            )
            
            return {
                "explanation_id": explanation.explanation_id,
                "summary": explanation.summary,
                "explanation": explanation.detailed_explanation,
                "key_points": explanation.key_points,
                "regulatory_references": explanation.regulatory_references,
                "visual_aids": explanation.visual_aids,
                "confidence_score": explanation.confidence_score
            }
            
        except Exception as e:
            logger.error(f"Violation explanation failed: {e}")
            raise
    
    async def _interpret_policy(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Interpret a regulatory policy in clear terms."""
        try:
            policy = payload["policy"]
            audience_level = AudienceLevel(payload.get("audience", "technical"))
            
            framework = policy.get("framework", "unknown")
            policy_name = policy.get("policy_name", "Unknown Policy")
            regulation_reference = policy.get("regulation_reference", "")
            description = policy.get("description", "")
            
            logger.info(f"Interpreting policy: {policy_name}")
            
            # Generate interpretation
            prompt = self.explanation_templates["policy_interpretation"].format(
                framework=framework,
                policy_name=policy_name,
                regulation_reference=regulation_reference,
                description=description,
                audience_level=audience_level.value
            )
            
            response = await self.invoke_llm(
                prompt=prompt,
                system_prompt="You are a regulatory compliance expert. Provide clear, actionable policy interpretations."
            )
            
            interpretation = response.content
            
            # Extract structured information
            key_points = self._extract_key_points(interpretation)
            
            # Create explanation
            explanation = Explanation(
                explanation_id=f"exp_{int(time.time() * 1000)}",
                explanation_type=ExplanationType.POLICY_INTERPRETATION,
                subject=policy_name,
                audience_level=audience_level,
                summary=self._extract_summary(interpretation),
                detailed_explanation=interpretation,
                key_points=key_points,
                regulatory_references=[{
                    "framework": framework,
                    "reference": regulation_reference,
                    "url": self._get_regulation_url(framework, regulation_reference)
                }],
                confidence_score=0.85
            )
            
            self.explanations[explanation.explanation_id] = explanation
            
            return {
                "explanation_id": explanation.explanation_id,
                "policy_name": policy_name,
                "framework": framework,
                "interpretation": interpretation,
                "key_points": key_points,
                "regulatory_references": explanation.regulatory_references
            }
            
        except Exception as e:
            logger.error(f"Policy interpretation failed: {e}")
            raise
    
    async def _justify_risk_assessment(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Provide justification for risk assessment."""
        try:
            risk_data = payload["risk_data"]
            audience_level = AudienceLevel(payload.get("audience", "executive"))
            
            risk_score = risk_data.get("risk_score", 0)
            risk_level = risk_data.get("risk_level", "unknown")
            violation_count = risk_data.get("violation_count", 0)
            frameworks = risk_data.get("frameworks", [])
            
            logger.info(f"Generating risk justification for score {risk_score}")
            
            prompt = self.explanation_templates["risk_justification"].format(
                risk_score=risk_score,
                risk_level=risk_level,
                violation_count=violation_count,
                frameworks=", ".join(frameworks),
                audience_level=audience_level.value
            )
            
            response = await self.invoke_llm(
                prompt=prompt,
                system_prompt="You are a risk management expert. Provide clear risk assessments."
            )
            
            justification = response.content
            key_points = self._extract_key_points(justification)
            
            # Create explanation
            explanation = Explanation(
                explanation_id=f"exp_{int(time.time() * 1000)}",
                explanation_type=ExplanationType.RISK_JUSTIFICATION,
                subject=f"Risk Assessment - Score {risk_score}/10",
                audience_level=audience_level,
                summary=self._extract_summary(justification),
                detailed_explanation=justification,
                key_points=key_points,
                regulatory_references=[],
                confidence_score=0.88,
                metadata={
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "frameworks": frameworks
                }
            )
            
            # Add visual risk representation
            if self.include_visual_aids:
                explanation.visual_aids = self._generate_risk_visuals(risk_data)
            
            self.explanations[explanation.explanation_id] = explanation
            
            return {
                "explanation_id": explanation.explanation_id,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "justification": justification,
                "key_points": key_points,
                "visual_aids": explanation.visual_aids
            }
            
        except Exception as e:
            logger.error(f"Risk justification failed: {e}")
            raise
    
    async def _explain_remediation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Explain remediation action rationale."""
        try:
            remediation = payload["remediation"]
            audience_level = AudienceLevel(payload.get("audience", "technical"))
            
            action_type = remediation.get("action_type", "unknown")
            violation_type = remediation.get("violation_type", "unknown")
            resource = remediation.get("target_resource", "unknown")
            strategy = remediation.get("strategy", "automated")
            
            logger.info(f"Generating remediation explanation for {action_type}")
            
            tone = self._get_tone_for_audience(audience_level)
            
            prompt = self.explanation_templates["remediation_rationale"].format(
                action_type=action_type,
                violation_type=violation_type,
                resource=resource,
                strategy=strategy,
                tone=tone
            )
            
            response = await self.invoke_llm(
                prompt=prompt,
                system_prompt="You are a compliance remediation expert. Explain why actions are necessary."
            )
            
            rationale = response.content
            key_points = self._extract_key_points(rationale)
            
            explanation = Explanation(
                explanation_id=f"exp_{int(time.time() * 1000)}",
                explanation_type=ExplanationType.REMEDIATION_RATIONALE,
                subject=f"Remediation: {action_type}",
                audience_level=audience_level,
                summary=self._extract_summary(rationale),
                detailed_explanation=rationale,
                key_points=key_points,
                regulatory_references=[],
                confidence_score=0.9,
                metadata={
                    "action_type": action_type,
                    "strategy": strategy
                }
            )
            
            self.explanations[explanation.explanation_id] = explanation
            
            return {
                "explanation_id": explanation.explanation_id,
                "action_type": action_type,
                "rationale": rationale,
                "key_points": key_points
            }
            
        except Exception as e:
            logger.error(f"Remediation explanation failed: {e}")
            raise
    
    async def _explain_workflow(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate workflow explanation and summary."""
        try:
            workflow_id = payload.get("workflow_id")
            workflow_type = payload.get("workflow_type", "compliance_scan")
            target_resource = payload.get("target_resource", "unknown")
            compliance_frameworks = payload.get("compliance_frameworks", [])
            results = payload.get("results", {})
            total_violations = payload.get("total_violations", 0)
            resolved_violations = payload.get("resolved_violations", 0)
            risk_score = payload.get("risk_score", 0)
            
            audience_level = AudienceLevel(payload.get("audience", "executive"))
            
            logger.info(f"Generating workflow explanation for {workflow_id}")
            
            prompt = self.explanation_templates["workflow_explanation"].format(
                workflow_type=workflow_type,
                target_resource=target_resource,
                frameworks=", ".join(compliance_frameworks),
                total_violations=total_violations,
                resolved_violations=resolved_violations,
                risk_score=risk_score,
                audience_level=audience_level.value
            )
            
            response = await self.invoke_llm(
                prompt=prompt,
                system_prompt="You are an executive compliance advisor. Provide strategic insights."
            )
            
            workflow_summary = response.content
            key_points = self._extract_key_points(workflow_summary)
            
            # Generate recommendations
            recommendations = await self._generate_workflow_recommendations(
                total_violations,
                resolved_violations,
                risk_score,
                compliance_frameworks
            )
            
            explanation = Explanation(
                explanation_id=f"exp_{int(time.time() * 1000)}",
                explanation_type=ExplanationType.WORKFLOW_EXPLANATION,
                subject=f"Workflow Summary: {workflow_type}",
                audience_level=audience_level,
                summary=self._extract_summary(workflow_summary),
                detailed_explanation=workflow_summary,
                key_points=key_points,
                regulatory_references=[],
                confidence_score=0.92,
                metadata={
                    "workflow_id": workflow_id,
                    "workflow_type": workflow_type,
                    "total_violations": total_violations,
                    "resolved_violations": resolved_violations,
                    "risk_score": risk_score
                }
            )
            
            # Add workflow visuals
            if self.include_visual_aids:
                explanation.visual_aids = self._generate_workflow_visuals(payload)
            
            self.explanations[explanation.explanation_id] = explanation
            
            return {
                "explanation_id": explanation.explanation_id,
                "workflow_id": workflow_id,
                "summary": explanation.summary,
                "detailed_explanation": workflow_summary,
                "key_points": key_points,
                "recommendations": recommendations,
                "visual_aids": explanation.visual_aids,
                "compliance_posture": self._assess_compliance_posture(
                    total_violations,
                    resolved_violations,
                    risk_score
                )
            }
            
        except Exception as e:
            logger.error(f"Workflow explanation failed: {e}")
            raise
    
    async def _provide_compliance_guidance(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Provide general compliance guidance."""
        try:
            topic = payload["topic"]
            framework = payload.get("framework", "gdpr")
            audience_level = AudienceLevel(payload.get("audience", "general"))
            
            logger.info(f"Providing compliance guidance for {topic}")
            
            guidance_prompt = f"""
            Provide comprehensive compliance guidance on the following topic:
            
            Topic: {topic}
            Framework: {framework}
            Target Audience: {audience_level.value}
            
            Include:
            1. Overview and importance
            2. Key requirements
            3. Common compliance challenges
            4. Best practices and recommendations
            5. Practical implementation steps
            6. Resources for further learning
            
            Make it actionable and easy to understand for {audience_level.value} audience.
            """
            
            response = await self.invoke_llm(
                prompt=guidance_prompt,
                system_prompt="You are a compliance educator. Provide clear, helpful guidance."
            )
            
            guidance = response.content
            key_points = self._extract_key_points(guidance)
            
            explanation = Explanation(
                explanation_id=f"exp_{int(time.time() * 1000)}",
                explanation_type=ExplanationType.COMPLIANCE_GUIDANCE,
                subject=topic,
                audience_level=audience_level,
                summary=self._extract_summary(guidance),
                detailed_explanation=guidance,
                key_points=key_points,
                regulatory_references=self._get_framework_references(framework),
                confidence_score=0.87
            )
            
            self.explanations[explanation.explanation_id] = explanation
            
            return {
                "explanation_id": explanation.explanation_id,
                "topic": topic,
                "framework": framework,
                "guidance": guidance,
                "key_points": key_points,
                "regulatory_references": explanation.regulatory_references
            }
            
        except Exception as e:
            logger.error(f"Compliance guidance generation failed: {e}")
            raise
    
    async def _explain_decision(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Explain an automated decision or recommendation."""
        try:
            decision = payload["decision"]
            decision_type = payload.get("decision_type", "unknown")
            context = payload.get("context", {})
            audience_level = AudienceLevel(payload.get("audience", "technical"))
            
            logger.info(f"Explaining decision: {decision_type}")
            
            decision_prompt = f"""
            Explain the following automated compliance decision:
            
            Decision Type: {decision_type}
            Decision: {decision}
            Context: {json.dumps(context, indent=2)}
            
            Provide:
            1. What decision was made
            2. Why this decision was made
            3. Data and factors considered
            4. Alternative options considered
            5. Confidence level in the decision
            6. How to override or appeal if needed
            
            Target audience: {audience_level.value}
            """
            
            response = await self.invoke_llm(
                prompt=decision_prompt,
                system_prompt="You are an AI transparency expert. Explain automated decisions clearly."
            )
            
            decision_explanation = response.content
            key_points = self._extract_key_points(decision_explanation)
            
            explanation = Explanation(
                explanation_id=f"exp_{int(time.time() * 1000)}",
                explanation_type=ExplanationType.DECISION_EXPLANATION,
                subject=f"Decision: {decision_type}",
                audience_level=audience_level,
                summary=self._extract_summary(decision_explanation),
                detailed_explanation=decision_explanation,
                key_points=key_points,
                regulatory_references=[],
                confidence_score=0.85,
                metadata={
                    "decision_type": decision_type,
                    "decision": decision
                }
            )
            
            self.explanations[explanation.explanation_id] = explanation
            
            return {
                "explanation_id": explanation.explanation_id,
                "decision_type": decision_type,
                "explanation": decision_explanation,
                "key_points": key_points
            }
            
        except Exception as e:
            logger.error(f"Decision explanation failed: {e}")
            raise
    
    async def _generate_compliance_faq(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate FAQ for compliance topics."""
        try:
            framework = payload.get("framework", "gdpr")
            topic_area = payload.get("topic_area", "general")
            question_count = payload.get("question_count", 10)
            
            logger.info(f"Generating FAQ for {framework} - {topic_area}")
            
            faq_prompt = f"""
            Generate a comprehensive FAQ for {framework} compliance focusing on {topic_area}.
            
            Create {question_count} frequently asked questions covering:
            - Basic concepts and definitions
            - Requirements and obligations
            - Common compliance challenges
            - Implementation best practices
            - Enforcement and penalties
            - Recent updates and changes
            
            Format each entry as:
            Q: [Question]
            A: [Clear, concise answer]
            """
            
            response = await self.invoke_llm(
                prompt=faq_prompt,
                system_prompt="You are a compliance expert creating helpful FAQ content."
            )
            
            faq_content = response.content
            
            # Parse FAQ entries
            faq_entries = self._parse_faq_content(faq_content)
            
            return {
                "framework": framework,
                "topic_area": topic_area,
                "faq_entries": faq_entries,
                "total_questions": len(faq_entries),
                "generated_at": time.time()
            }
            
        except Exception as e:
            logger.error(f"FAQ generation failed: {e}")
            raise
    
    async def _translate_for_audience(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Translate technical content for different audiences."""
        try:
            content = payload["content"]
            source_audience = AudienceLevel(payload.get("source_audience", "technical"))
            target_audience = AudienceLevel(payload["target_audience"])
            
            logger.info(f"Translating content from {source_audience.value} to {target_audience.value}")
            
            translation_prompt = f"""
            Translate the following compliance content from {source_audience.value} to {target_audience.value} audience:
            
            Original Content:
            {content}
            
            Adapt the:
            - Language complexity
            - Technical depth
            - Focus areas (technical details vs business impact)
            - Examples and analogies
            - Level of regulatory detail
            
            Maintain accuracy while making it appropriate for {target_audience.value} audience.
            """
            
            response = await self.invoke_llm(
                prompt=translation_prompt,
                system_prompt="You are a compliance communication specialist."
            )
            
            translated_content = response.content
            
            return {
                "source_audience": source_audience.value,
                "target_audience": target_audience.value,
                "original_content": content,
                "translated_content": translated_content,
                "timestamp": time.time()
            }
            
        except Exception as e:
            logger.error(f"Content translation failed: {e}")
            raise
    
    def _get_tone_for_audience(self, audience_level: AudienceLevel) -> str:
        """Get appropriate tone for audience."""
        tone_map = {
            AudienceLevel.EXECUTIVE: "concise, business-focused, and strategic",
            AudienceLevel.TECHNICAL: "detailed, technical, and precise",
            AudienceLevel.LEGAL: "formal, regulatory-focused, and comprehensive",
            AudienceLevel.OPERATIONAL: "practical, action-oriented, and clear",
            AudienceLevel.GENERAL: "simple, accessible, and easy to understand"
        }
        return tone_map.get(audience_level, "clear and professional")
    
    def _extract_summary(self, text: str, max_length: int = 200) -> str:
        """Extract summary from explanation text."""
        # Simple extraction - take first paragraph or sentence
        paragraphs = text.split('\n\n')
        if paragraphs:
            summary = paragraphs[0].strip()
            if len(summary) > max_length:
                summary = summary[:max_length-3] + "..."
            return summary
        return text[:max_length]
    
    def _extract_key_points(self, text: str) -> List[str]:
        """Extract key points from explanation text."""
        key_points = []
        
        # Look for numbered lists or bullet points
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            # Check for numbered items
            if line and (line[0].isdigit() or line.startswith('-') or line.startswith('•')):
                # Clean up the line
                cleaned = line.lstrip('0123456789.-•) ').strip()
                if cleaned and len(cleaned) > 10:
                    key_points.append(cleaned)
        
        # If no structured points found, extract sentences with key indicators
        if not key_points:
            for line in lines:
                if any(indicator in line.lower() for indicator in ['important', 'key', 'must', 'require', 'critical']):
                    key_points.append(line.strip())
        
        return key_points[:10]  # Limit to top 10 points
    
    def _extract_regulatory_references(
        self, 
        framework: str, 
        violation_type: str,
        regulation_ref: str
    ) -> List[Dict[str, str]]:
        """Extract regulatory references."""
        references = []
        
        # Framework-specific references
        if framework == "gdpr":
            references.append({
                "framework": "GDPR",
                "reference": regulation_ref or "Articles 5, 32",
                "url": self._get_regulation_url("gdpr", regulation_ref),
                "description": "General Data Protection Regulation"
            })
        elif framework == "hipaa":
            references.append({
                "framework": "HIPAA",
                "reference": regulation_ref or "164.312",
                "url": self._get_regulation_url("hipaa", regulation_ref),
                "description": "Health Insurance Portability and Accountability Act"
            })
        elif framework == "pci_dss":
            references.append({
                "framework": "PCI DSS",
                "reference": regulation_ref or "Requirement 3",
                "url": self._get_regulation_url("pci_dss", regulation_ref),
                "description": "Payment Card Industry Data Security Standard"
            })
        
        return references
    
    def _get_regulation_url(self, framework: str, reference: str) -> str:
        """Get URL for regulatory reference."""
        base_urls = {
            "gdpr": "https://gdpr-info.eu/art-",
            "hipaa": "https://www.hhs.gov/hipaa/for-professionals/privacy/laws-regulations/index.html",
            "pci_dss": "https://www.pcisecuritystandards.org/document_library",
            "ccpa": "https://oag.ca.gov/privacy/ccpa",
            "sox": "https://www.sec.gov/spotlight/sarbanes-oxley.htm"
        }
        
        base_url = base_urls.get(framework, "")
        
        # For GDPR, extract article number
        if framework == "gdpr" and reference:
            import re
            article_match = re.search(r'Article (\d+)', reference)
            if article_match:
                article_num = article_match.group(1)
                return f"{base_url}{article_num}"
        
        return base_url
    
    def _get_framework_references(self, framework: str) -> List[Dict[str, str]]:
        """Get general framework references."""
        references = {
            "gdpr": [{
                "framework": "GDPR",
                "reference": "EU Regulation 2016/679",
                "url": "https://gdpr-info.eu/",
                "description": "Official GDPR text and guidance"
            }],
            "hipaa": [{
                "framework": "HIPAA",
                "reference": "45 CFR Parts 160, 162, and 164",
                "url": "https://www.hhs.gov/hipaa/index.html",
                "description": "Official HIPAA information"
            }],
            "pci_dss": [{
                "framework": "PCI DSS",
                "reference": "PCI DSS v4.0",
                "url": "https://www.pcisecuritystandards.org/",
                "description": "PCI Security Standards Council"
            }]
        }
        
        return references.get(framework, [])
    
    def _generate_violation_visuals(self, violation: Dict[str, Any]) -> Dict[str, Any]:
        """Generate visual representations of violation data."""
        return {
            "severity_indicator": {
                "type": "gauge",
                "value": self._severity_to_score(violation.get("severity", "medium")),
                "max": 10,
                "color": self._severity_to_color(violation.get("severity", "medium"))
            },
            "impact_chart": {
                "type": "bar",
                "categories": ["Financial", "Reputational", "Regulatory"],
                "values": [
                    violation.get("financial_impact", 50),
                    70,  # Reputational impact estimate
                    self._severity_to_score(violation.get("severity", "medium")) * 10
                ]
            },
            "timeline": {
                "type": "timeline",
                "events": [
                    {"time": "detection", "label": "Violation Detected"},
                    {"time": "assessment", "label": "Risk Assessed"},
                    {"time": "remediation", "label": "Remediation Planned"}
                ]
            }
        }
    
    def _generate_risk_visuals(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate visual representations of risk data."""
        return {
            "risk_score_gauge": {
                "type": "gauge",
                "value": risk_data.get("risk_score", 0),
                "max": 10,
                "thresholds": [3, 6, 8],
                "colors": ["green", "yellow", "orange", "red"]
            },
            "risk_breakdown": {
                "type": "pie",
                "categories": list(risk_data.get("risk_by_category", {}).keys()),
                "values": list(risk_data.get("risk_by_category", {}).values())
            },
            "framework_compliance": {
                "type": "horizontal_bar",
                "frameworks": list(risk_data.get("risk_by_framework", {}).keys()),
                "scores": list(risk_data.get("risk_by_framework", {}).values())
            }
        }
    
    def _generate_workflow_visuals(self, workflow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate visual representations of workflow data."""
        total = workflow_data.get("total_violations", 1)
        resolved = workflow_data.get("resolved_violations", 0)
        
        return {
            "completion_progress": {
                "type": "progress_bar",
                "value": resolved,
                "max": total,
                "percentage": (resolved / max(total, 1)) * 100
            },
            "risk_trend": {
                "type": "line",
                "points": [
                    {"stage": "initial", "risk": workflow_data.get("risk_score", 0)},
                    {"stage": "after_remediation", "risk": workflow_data.get("risk_score", 0) * 0.3}
                ]
            },
            "violation_distribution": {
                "type": "donut",
                "categories": ["Resolved", "In Progress", "Pending"],
                "values": [resolved, 0, total - resolved]
            }
        }
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity to numeric score."""
        severity_scores = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "informational": 1.0
        }
        return severity_scores.get(severity.lower(), 5.0)
    
    def _severity_to_color(self, severity: str) -> str:
        """Convert severity to color code."""
        severity_colors = {
            "critical": "#DC143C",  # Crimson
            "high": "#FF8C00",      # Dark Orange
            "medium": "#FFD700",    # Gold
            "low": "#32CD32",       # Lime Green
            "informational": "#4169E1"  # Royal Blue
        }
        return severity_colors.get(severity.lower(), "#808080")
    
    async def _generate_workflow_recommendations(
        self,
        total_violations: int,
        resolved_violations: int,
        risk_score: float,
        frameworks: List[str]
    ) -> List[Dict[str, str]]:
        """Generate strategic recommendations for workflow results."""
        recommendations = []
        
        # Resolution rate recommendation
        resolution_rate = (resolved_violations / max(total_violations, 1)) * 100
        
        if resolution_rate < 50:
            recommendations.append({
                "priority": "high",
                "category": "remediation",
                "recommendation": "Accelerate remediation efforts - less than 50% of violations resolved",
                "action": "Review and prioritize remaining violations"
            })
        elif resolution_rate >= 90:
            recommendations.append({
                "priority": "low",
                "category": "maintenance",
                "recommendation": "Maintain current compliance posture with periodic reviews",
                "action": "Schedule quarterly compliance audits"
            })
        
        # Risk score recommendation
        if risk_score >= 7:
            recommendations.append({
                "priority": "critical",
                "category": "risk_mitigation",
                "recommendation": "High risk score requires immediate executive attention",
                "action": "Convene compliance committee and allocate emergency resources"
            })
        elif risk_score >= 5:
            recommendations.append({
                "priority": "medium",
                "category": "risk_reduction",
                "recommendation": "Moderate risk level - implement systematic remediation plan",
                "action": "Create 30-day action plan for priority violations"
            })
        
        # Framework-specific recommendations
        if "gdpr" in frameworks:
            recommendations.append({
                "priority": "medium",
                "category": "gdpr_compliance",
                "recommendation": "Review data processing activities and consent mechanisms",
                "action": "Conduct DPIA for high-risk processing activities"
            })
        
        return recommendations
    
    def _assess_compliance_posture(
        self,
        total_violations: int,
        resolved_violations: int,
        risk_score: float
    ) -> Dict[str, Any]:
        """Assess overall compliance posture."""
        resolution_rate = (resolved_violations / max(total_violations, 1)) * 100
        
        if resolution_rate >= 90 and risk_score < 3:
            posture = "excellent"
            status = "compliant"
        elif resolution_rate >= 70 and risk_score < 5:
            posture = "good"
            status = "mostly_compliant"
        elif resolution_rate >= 50 and risk_score < 7:
            posture = "fair"
            status = "partial_compliance"
        else:
            posture = "needs_improvement"
            status = "non_compliant"
        
        return {
            "posture": posture,
            "status": status,
            "resolution_rate": resolution_rate,
            "risk_score": risk_score,
            "assessment": f"Compliance posture is {posture} with {resolution_rate:.1f}% resolution rate"
        }
    
    def _parse_faq_content(self, content: str) -> List[Dict[str, str]]:
        """Parse FAQ content into structured entries."""
        entries = []
        
        lines = content.split('\n')
        current_question = None
        current_answer = []
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('Q:'):
                # Save previous entry if exists
                if current_question and current_answer:
                    entries.append({
                        "question": current_question,
                        "answer": ' '.join(current_answer).strip()
                    })
                
                # Start new entry
                current_question = line[2:].strip()
                current_answer = []
                
            elif line.startswith('A:'):
                current_answer.append(line[2:].strip())
                
            elif current_answer and line:
                current_answer.append(line)
        
        # Add last entry
        if current_question and current_answer:
            entries.append({
                "question": current_question,
                "answer": ' '.join(current_answer).strip()
            })
        
        return entries
