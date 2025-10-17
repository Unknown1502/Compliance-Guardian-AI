"""LLM-powered policy interpretation engine."""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

from ..utils.logger import get_logger
from ..core.bedrock_client import BedrockClient

logger = get_logger(__name__)


@dataclass
class PolicyInterpretation:
    """Policy interpretation result."""
    
    policy_id: str
    framework: str
    requirements: List[str]
    controls: List[Dict[str, Any]]
    applicability_score: float  # 0-1
    interpretation: str
    examples: List[str]
    related_policies: List[str]


class PolicyInterpreter:
    """
    LLM-powered policy interpretation engine.
    
    Uses Claude 3.5 Sonnet to:
    - Parse regulatory policies
    - Extract technical requirements
    - Map controls to violations
    - Provide implementation guidance
    - Identify policy conflicts
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize policy interpreter."""
        self.config = config or {}
        self.bedrock_client = BedrockClient(config)
        
        # Policy knowledge base
        self.policy_templates = {
            "GDPR": {
                "Article 5": "Principles relating to processing of personal data",
                "Article 6": "Lawfulness of processing",
                "Article 17": "Right to erasure (right to be forgotten)",
                "Article 25": "Data protection by design and by default",
                "Article 32": "Security of processing",
                "Article 33": "Notification of a personal data breach"
            },
            "HIPAA": {
                "164.308": "Administrative safeguards",
                "164.310": "Physical safeguards",
                "164.312": "Technical safeguards",
                "164.502": "Uses and disclosures of PHI",
                "164.520": "Notice of privacy practices"
            },
            "PCI_DSS": {
                "Requirement 1": "Install and maintain firewall configuration",
                "Requirement 2": "Do not use vendor-supplied defaults",
                "Requirement 3": "Protect stored cardholder data",
                "Requirement 4": "Encrypt transmission of data",
                "Requirement 6": "Develop and maintain secure systems"
            }
        }
    
    async def interpret_policy(
        self,
        framework: str,
        policy_reference: str,
        context: Optional[Dict[str, Any]] = None
    ) -> PolicyInterpretation:
        """Interpret a regulatory policy using LLM."""
        try:
            logger.info(f"Interpreting policy {framework} {policy_reference}")
            
            # Build prompt with policy context
            prompt = self._build_interpretation_prompt(framework, policy_reference, context)
            
            # Get LLM interpretation
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            interpretation_text = response.get("completion", "")
            
            # Extract structured information
            requirements = await self._extract_requirements(interpretation_text)
            controls = await self._extract_controls(framework, policy_reference, interpretation_text)
            applicability = self._assess_applicability(context or {})
            examples = await self._extract_examples(interpretation_text)
            related_policies = await self._find_related_policies(framework, policy_reference)
            
            interpretation = PolicyInterpretation(
                policy_id=policy_reference,
                framework=framework,
                requirements=requirements,
                controls=controls,
                applicability_score=applicability,
                interpretation=interpretation_text,
                examples=examples,
                related_policies=related_policies
            )
            
            logger.info(f"Policy interpretation complete: {len(requirements)} requirements found")
            
            return interpretation
        
        except Exception as e:
            logger.error(f"Policy interpretation failed: {e}")
            raise
    
    def _build_interpretation_prompt(
        self,
        framework: str,
        policy_reference: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build LLM prompt for policy interpretation."""
        # Get policy description from knowledge base
        policy_desc = self.policy_templates.get(framework, {}).get(
            policy_reference,
            "Unknown policy"
        )
        
        prompt = f"""
        You are a compliance expert specializing in {framework}. 
        
        Interpret the following regulatory policy:
        
        Policy Reference: {policy_reference}
        Description: {policy_desc}
        
        """
        
        if context:
            prompt += f"""
        Application Context:
        - Organization Type: {context.get('organization_type', 'Not specified')}
        - Data Types: {', '.join(context.get('data_types', []))}
        - Industry: {context.get('industry', 'Not specified')}
        
        """
        
        prompt += """
        Provide a detailed interpretation including:
        
        1. TECHNICAL REQUIREMENTS:
           - Specific technical controls needed
           - Implementation standards
           - Measurable criteria for compliance
        
        2. IMPLEMENTATION GUIDANCE:
           - Step-by-step implementation approach
           - Common pitfalls to avoid
           - Best practices
        
        3. VERIFICATION:
           - How to verify compliance
           - Audit procedures
           - Documentation requirements
        
        4. EXAMPLES:
           - Concrete examples of compliant implementations
           - Examples of non-compliant scenarios
        
        Be specific and technical. Focus on actionable requirements.
        """
        
        return prompt
    
    async def _extract_requirements(self, interpretation: str) -> List[str]:
        """Extract technical requirements from interpretation."""
        prompt = f"""
        From the following policy interpretation, extract a list of specific, 
        measurable technical requirements:
        
        {interpretation}
        
        Return only the requirements as a numbered list. Be concise.
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            requirements_text = response.get("completion", "")
            
            # Parse requirements
            requirements = self._parse_list(requirements_text)
            return requirements
        
        except Exception as e:
            logger.warning(f"Failed to extract requirements: {e}")
            return []
    
    async def _extract_controls(
        self,
        framework: str,
        policy_reference: str,
        interpretation: str
    ) -> List[Dict[str, Any]]:
        """Extract security controls from interpretation."""
        prompt = f"""
        From the following {framework} {policy_reference} interpretation, 
        extract specific security controls that need to be implemented:
        
        {interpretation}
        
        For each control, provide:
        - Control name
        - Control type (preventive/detective/corrective)
        - Implementation method
        - Validation approach
        
        Format as a structured list.
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            controls_text = response.get("completion", "")
            
            # Parse controls (simplified parsing)
            controls = []
            lines = controls_text.split('\n')
            current_control = {}
            
            for line in lines:
                line = line.strip()
                if not line:
                    if current_control:
                        controls.append(current_control)
                        current_control = {}
                    continue
                
                if line.startswith('-'):
                    parts = line[1:].split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].strip().lower().replace(' ', '_')
                        value = parts[1].strip()
                        current_control[key] = value
            
            if current_control:
                controls.append(current_control)
            
            return controls[:10]  # Limit to top 10 controls
        
        except Exception as e:
            logger.warning(f"Failed to extract controls: {e}")
            return []
    
    def _assess_applicability(self, context: Dict[str, Any]) -> float:
        """Assess policy applicability based on context."""
        score = 0.5  # Default moderate applicability
        
        # Increase if specific data types mentioned
        if context.get('data_types'):
            score += 0.2
        
        # Increase if organization type specified
        if context.get('organization_type'):
            score += 0.1
        
        # Increase if industry specified
        if context.get('industry'):
            score += 0.1
        
        # Increase if processing activities specified
        if context.get('processing_activities'):
            score += 0.1
        
        return min(1.0, score)
    
    async def _extract_examples(self, interpretation: str) -> List[str]:
        """Extract implementation examples from interpretation."""
        import re
        
        # Look for example sections
        example_pattern = r'Example[s]?:(.+?)(?=\n\n|\Z)'
        matches = re.findall(example_pattern, interpretation, re.DOTALL | re.IGNORECASE)
        
        examples = []
        for match in matches:
            # Parse individual examples
            example_lines = [line.strip() for line in match.split('\n') if line.strip()]
            examples.extend(example_lines[:3])  # Up to 3 examples per section
        
        return examples[:5]  # Total limit of 5 examples
    
    async def _find_related_policies(self, framework: str, policy_reference: str) -> List[str]:
        """Find related policies using LLM."""
        prompt = f"""
        For {framework} {policy_reference}, what are the most closely related policies 
        or requirements within the same framework?
        
        List up to 5 related policy references with brief explanation of the relationship.
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            related_text = response.get("completion", "")
            
            # Extract policy references
            import re
            
            # Look for policy reference patterns
            patterns = [
                r'Article \d+',
                r'Section \d+',
                r'Requirement \d+',
                r'\d+\.\d+',
            ]
            
            related = []
            for pattern in patterns:
                matches = re.findall(pattern, related_text)
                related.extend(matches)
            
            return list(set(related))[:5]
        
        except Exception as e:
            logger.warning(f"Failed to find related policies: {e}")
            return []
    
    def _parse_list(self, text: str) -> List[str]:
        """Parse numbered or bulleted list from text."""
        import re
        
        # Try numbered list
        pattern = r'\d+\.\s*(.+?)(?=\n\d+\.|\Z)'
        matches = re.findall(pattern, text, re.DOTALL)
        
        if matches:
            return [m.strip() for m in matches if m.strip()]
        
        # Try bullet points
        pattern = r'[-•]\s*(.+?)(?=\n[-•]|\Z)'
        matches = re.findall(pattern, text, re.DOTALL)
        
        if matches:
            return [m.strip() for m in matches if m.strip()]
        
        # Fallback: split by newlines
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        return lines[:10]
    
    async def map_violation_to_policies(
        self,
        violation: Dict[str, Any]
    ) -> List[PolicyInterpretation]:
        """Map a violation to relevant policies."""
        framework = violation.get("framework", "")
        violation_type = violation.get("violation_type", "")
        description = violation.get("description", "")
        
        prompt = f"""
        Given this compliance violation:
        
        Framework: {framework}
        Type: {violation_type}
        Description: {description}
        
        Which specific policies or requirements from {framework} does this violate?
        
        List the specific policy references (e.g., Article numbers, Section numbers).
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            policy_text = response.get("completion", "")
            
            # Extract policy references
            import re
            policy_refs = re.findall(r'(?:Article|Section|Requirement)\s+\d+(?:\.\d+)?', policy_text)
            
            # Get interpretations for each policy
            interpretations = []
            for policy_ref in policy_refs[:5]:  # Limit to 5 most relevant
                interpretation = await self.interpret_policy(
                    framework=framework,
                    policy_reference=policy_ref,
                    context=violation
                )
                interpretations.append(interpretation)
            
            return interpretations
        
        except Exception as e:
            logger.error(f"Failed to map violation to policies: {e}")
            return []
    
    async def check_policy_conflicts(
        self,
        policies: List[PolicyInterpretation]
    ) -> List[Dict[str, Any]]:
        """Check for conflicts between policies."""
        if len(policies) < 2:
            return []
        
        conflicts = []
        
        # Compare policies pairwise
        for i in range(len(policies)):
            for j in range(i + 1, len(policies)):
                policy1 = policies[i]
                policy2 = policies[j]
                
                prompt = f"""
                Compare these two regulatory requirements and identify any conflicts,
                contradictions, or areas where compliance with one might hinder 
                compliance with the other:
                
                Policy 1: {policy1.framework} {policy1.policy_id}
                Requirements: {', '.join(policy1.requirements[:3])}
                
                Policy 2: {policy2.framework} {policy2.policy_id}
                Requirements: {', '.join(policy2.requirements[:3])}
                
                If there are conflicts, describe them. If not, respond with "No conflict".
                """
                
                try:
                    response = await self.bedrock_client.invoke_agent(
                        agent_id="compliance_agent",
                        prompt=prompt
                    )
                    
                    conflict_text = response.get("completion", "")
                    
                    if "no conflict" not in conflict_text.lower():
                        conflicts.append({
                            "policy1": f"{policy1.framework} {policy1.policy_id}",
                            "policy2": f"{policy2.framework} {policy2.policy_id}",
                            "conflict_description": conflict_text,
                            "severity": "medium"
                        })
                
                except Exception as e:
                    logger.warning(f"Failed to check conflict: {e}")
                    continue
        
        return conflicts
    
    async def generate_compliance_checklist(
        self,
        framework: str,
        scope: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Generate compliance checklist for a framework."""
        prompt = f"""
        Generate a comprehensive compliance checklist for {framework}.
        """
        
        if scope:
            prompt += f"""
        
        Scope:
        - Data Types: {', '.join(scope.get('data_types', []))}
        - Systems: {', '.join(scope.get('systems', []))}
        - Processes: {', '.join(scope.get('processes', []))}
        """
        
        prompt += """
        
        For each checklist item, provide:
        1. Policy reference
        2. Requirement description
        3. Verification method
        4. Evidence needed
        
        Organize by category (e.g., Technical, Administrative, Physical).
        """
        
        try:
            response = await self.bedrock_client.invoke_agent(
                agent_id="compliance_agent",
                prompt=prompt
            )
            
            checklist_text = response.get("completion", "")
            
            # Parse checklist items
            checklist = []
            lines = checklist_text.split('\n')
            current_item = {}
            
            for line in lines:
                line = line.strip()
                if not line:
                    if current_item:
                        checklist.append(current_item)
                        current_item = {}
                    continue
                
                if line.startswith(('1.', '2.', '3.', '4.')):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key = parts[0].split('.')[1].strip().lower().replace(' ', '_')
                        value = parts[1].strip()
                        current_item[key] = value
            
            if current_item:
                checklist.append(current_item)
            
            return checklist
        
        except Exception as e:
            logger.error(f"Failed to generate checklist: {e}")
            return []
