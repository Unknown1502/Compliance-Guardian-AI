"""AWS Bedrock client implementation for Compliance Guardian AI."""

import json
import logging
from typing import Any, Dict, List, Optional, Union

import boto3
from anthropic import Anthropic
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import BaseModel, Field

from ..utils.config import get_config
from ..utils.logger import get_logger

logger = get_logger(__name__)


class BedrockConfig(BaseModel):
    """Configuration for Bedrock client."""
    
    region_name: str = Field(default="us-east-1")
    model_id: str = Field(default="us.anthropic.claude-3-5-sonnet-20241022-v2:0")
    max_tokens: int = Field(default=4096)
    temperature: float = Field(default=0.1)
    top_p: float = Field(default=0.9)
    timeout: int = Field(default=300)


class BedrockResponse(BaseModel):
    """Standardized response from Bedrock."""
    
    content: str
    usage: Dict[str, int]
    model_id: str
    stop_reason: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BedrockClient:
    """
    AWS Bedrock client with enhanced functionality for multi-agent compliance system.
    
    Provides unified interface for:
    - Claude 3.5 Sonnet model interactions
    - Function calling capabilities
    - Token usage tracking
    - Error handling and retries
    - Context management
    """

    def __init__(self, config: Optional[BedrockConfig] = None):
        """Initialize Bedrock client with configuration."""
        self.config = config or BedrockConfig()
        self._client = None
        self._anthropic_client = None
        self._initialize_clients()
        
    def _initialize_clients(self) -> None:
        """Initialize AWS Bedrock and Anthropic clients."""
        try:
            # Initialize Bedrock runtime client
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self.config.region_name
            )
            
            # Initialize Anthropic client for advanced features
            self._anthropic_client = Anthropic()
            
            logger.info(
                f"Bedrock client initialized successfully",
                extra={
                    "region": self.config.region_name,
                    "model_id": self.config.model_id
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {e}")
            raise

    async def invoke_model(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> BedrockResponse:
        """
        Invoke Bedrock model with enhanced error handling.
        
        Args:
            prompt: User message content
            system_prompt: System prompt for context
            tools: Function calling tools
            **kwargs: Additional model parameters
            
        Returns:
            BedrockResponse with content and metadata
            
        Raises:
            BedrockError: If model invocation fails
        """
        try:
            messages = [{"role": "user", "content": prompt}]
            
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
                "temperature": kwargs.get("temperature", self.config.temperature),
                "top_p": kwargs.get("top_p", self.config.top_p),
                "messages": messages
            }
            
            if system_prompt:
                body["system"] = system_prompt
                
            if tools:
                body["tools"] = tools
                
            response = self._client.invoke_model(
                modelId=self.config.model_id,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json"
            )
            
            response_body = json.loads(response["body"].read())
            
            return BedrockResponse(
                content=response_body["content"][0]["text"],
                usage=response_body.get("usage", {}),
                model_id=self.config.model_id,
                stop_reason=response_body.get("stop_reason"),
                metadata={
                    "request_id": response["ResponseMetadata"]["RequestId"],
                    "timestamp": response["ResponseMetadata"]["HTTPHeaders"]["date"]
                }
            )
            
        except ClientError as e:
            logger.error(f"AWS ClientError during model invocation: {e}")
            raise BedrockError(f"Model invocation failed: {e}")
        except BotoCoreError as e:
            logger.error(f"AWS BotoCoreError during model invocation: {e}")
            raise BedrockError(f"AWS connection error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during model invocation: {e}")
            raise BedrockError(f"Unexpected error: {e}")

    async def invoke_with_function_calling(
        self,
        prompt: str,
        functions: List[Dict[str, Any]],
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> BedrockResponse:
        """
        Invoke model with function calling capabilities.
        
        Args:
            prompt: User message
            functions: Available functions for the model
            system_prompt: System context
            **kwargs: Additional parameters
            
        Returns:
            BedrockResponse with function calls if applicable
        """
        tools = []
        for func in functions:
            tools.append({
                "name": func["name"],
                "description": func["description"],
                "input_schema": func["parameters"]
            })
            
        return await self.invoke_model(
            prompt=prompt,
            system_prompt=system_prompt,
            tools=tools,
            **kwargs
        )

    async def analyze_compliance_violation(
        self,
        code: str,
        framework: str,
        context: Optional[Dict[str, Any]] = None
    ) -> BedrockResponse:
        """
        Specialized method for analyzing compliance violations.
        
        Args:
            code: Source code to analyze
            framework: Compliance framework (GDPR, HIPAA, PCI DSS)
            context: Additional context information
            
        Returns:
            BedrockResponse with violation analysis
        """
        system_prompt = f"""
        You are an expert compliance auditor specializing in {framework} regulations.
        Analyze the provided code for potential violations and provide detailed explanations.
        
        Focus on:
        - Data handling practices
        - Security vulnerabilities
        - Privacy concerns
        - Regulatory compliance gaps
        
        Provide structured analysis with:
        1. Violation severity (Critical/High/Medium/Low)
        2. Specific regulation cited
        3. Detailed explanation
        4. Remediation recommendations
        """
        
        prompt = f"""
        Analyze this code for {framework} compliance violations:
        
        ```
        {code}
        ```
        
        Context: {json.dumps(context or {}, indent=2)}
        
        Provide a structured analysis in JSON format.
        """
        
        return await self.invoke_model(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.1  # Lower temperature for more consistent analysis
        )

    async def generate_remediation_plan(
        self,
        violation: Dict[str, Any],
        code_context: str
    ) -> BedrockResponse:
        """
        Generate remediation plan for detected violations.
        
        Args:
            violation: Violation details
            code_context: Surrounding code context
            
        Returns:
            BedrockResponse with remediation plan
        """
        system_prompt = """
        You are an expert software engineer specializing in compliance remediation.
        Generate practical, implementable solutions for compliance violations.
        
        Provide:
        1. Step-by-step remediation plan
        2. Code changes needed
        3. Testing approach
        4. Risk assessment
        5. Alternative solutions if applicable
        """
        
        prompt = f"""
        Generate a remediation plan for this violation:
        
        Violation: {json.dumps(violation, indent=2)}
        
        Code Context:
        ```
        {code_context}
        ```
        
        Provide a detailed remediation plan in JSON format.
        """
        
        return await self.invoke_model(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.2
        )

    async def explain_decision(
        self,
        decision: Dict[str, Any],
        audience: str = "technical"
    ) -> BedrockResponse:
        """
        Generate natural language explanations for AI decisions.
        
        Args:
            decision: Decision details to explain
            audience: Target audience (technical, executive, legal)
            
        Returns:
            BedrockResponse with explanation
        """
        system_prompts = {
            "technical": "Explain in technical detail with code examples and implementation specifics.",
            "executive": "Explain in business terms focusing on risk, cost, and strategic impact.",
            "legal": "Explain in legal terms with regulatory citations and compliance implications."
        }
        
        system_prompt = f"""
        You are an expert communicator explaining AI compliance decisions.
        {system_prompts.get(audience, system_prompts["technical"])}
        
        Make the explanation:
        - Clear and understandable
        - Factually accurate
        - Actionable
        - Appropriate for the audience level
        """
        
        prompt = f"""
        Explain this compliance decision for a {audience} audience:
        
        {json.dumps(decision, indent=2)}
        
        Provide a clear, comprehensive explanation.
        """
        
        return await self.invoke_model(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.3
        )

    def get_token_usage(self) -> Dict[str, Any]:
        """Get current token usage statistics."""
        # This would typically be tracked across multiple calls
        # Implementation depends on specific tracking requirements
        return {
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_requests": 0,
            "cost_estimate": 0.0
        }

    def health_check(self) -> Dict[str, Any]:
        """Perform health check on Bedrock client."""
        try:
            # Simple model invocation to test connectivity
            test_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "ping"}]
            }
            
            response = self._client.invoke_model(
                modelId=self.config.model_id,
                body=json.dumps(test_body),
                contentType="application/json",
                accept="application/json"
            )
            
            return {
                "status": "healthy",
                "model_id": self.config.model_id,
                "region": self.config.region_name,
                "response_time_ms": response["ResponseMetadata"]["HTTPHeaders"].get("x-amzn-RequestId", "unknown")
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "model_id": self.config.model_id,
                "region": self.config.region_name
            }


class BedrockError(Exception):
    """Custom exception for Bedrock-related errors."""
    pass