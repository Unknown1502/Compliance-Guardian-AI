"""Amazon Q Client for Compliance Intelligence.

This module provides a client for interacting with Amazon Q to retrieve
compliance-related intelligence, regulatory guidance, and policy interpretation.
"""

import os
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    boto3 = None
    ClientError = Exception
    BotoCoreError = Exception

logger = logging.getLogger(__name__)


@dataclass
class AmazonQConfig:
    """Configuration for Amazon Q client."""
    
    application_id: str
    region: str = "us-east-1"
    index_id: Optional[str] = None
    max_results: int = 10
    enable_mock: bool = False
    
    @classmethod
    def from_env(cls) -> "AmazonQConfig":
        """Load configuration from environment variables."""
        return cls(
            application_id=os.getenv("AMAZON_Q_APPLICATION_ID", ""),
            region=os.getenv("AWS_REGION", "us-east-1"),
            index_id=os.getenv("AMAZON_Q_INDEX_ID"),
            max_results=int(os.getenv("AMAZON_Q_MAX_RESULTS", "10")),
            enable_mock=os.getenv("AMAZON_Q_MOCK", "false").lower() == "true"
        )


@dataclass
class ComplianceQuery:
    """Represents a compliance intelligence query."""
    
    query: str
    framework: Optional[str] = None  # e.g., "GDPR", "HIPAA", "PCI-DSS"
    context: Optional[Dict[str, Any]] = None
    filters: Optional[Dict[str, List[str]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API calls."""
        result = {"query": self.query}
        if self.framework:
            result["framework"] = self.framework
        if self.context:
            result["context"] = self.context
        if self.filters:
            result["filters"] = self.filters
        return result


@dataclass
class ComplianceResponse:
    """Response from Amazon Q compliance query."""
    
    query_id: str
    results: List[Dict[str, Any]]
    confidence_score: float
    sources: List[str]
    timestamp: datetime
    framework: Optional[str] = None
    
    @property
    def top_result(self) -> Optional[Dict[str, Any]]:
        """Get the highest confidence result."""
        return self.results[0] if self.results else None
    
    def get_guidance(self) -> str:
        """Extract compliance guidance from results."""
        if not self.results:
            return "No guidance available."
        
        guidance_parts = []
        for result in self.results[:3]:  # Top 3 results
            if "excerpt" in result:
                guidance_parts.append(result["excerpt"])
            elif "text" in result:
                guidance_parts.append(result["text"])
        
        return "\n\n".join(guidance_parts)


class AmazonQClient:
    """Client for interacting with Amazon Q for compliance intelligence."""
    
    def __init__(self, config: Optional[AmazonQConfig] = None):
        """Initialize the Amazon Q client.
        
        Args:
            config: Configuration object. If None, loads from environment.
        """
        self.config = config or AmazonQConfig.from_env()
        self._client = None
        self._validate_config()
        
        if not self.config.enable_mock:
            self._initialize_client()
        
        logger.info(
            f"Amazon Q client initialized (mock={self.config.enable_mock})",
            extra={"application_id": self.config.application_id}
        )
    
    def _validate_config(self):
        """Validate the configuration."""
        if not self.config.enable_mock and not self.config.application_id:
            raise ValueError(
                "AMAZON_Q_APPLICATION_ID must be set in environment or config. "
                "Set AMAZON_Q_MOCK=true for testing without AWS credentials."
            )
        
        if not self.config.enable_mock and boto3 is None:
            raise ImportError(
                "boto3 is required for Amazon Q integration. "
                "Install with: pip install boto3"
            )
    
    def _initialize_client(self):
        """Initialize the boto3 Q Business client."""
        try:
            self._client = boto3.client(
                "qbusiness",
                region_name=self.config.region
            )
            logger.info(f"Connected to Amazon Q in region {self.config.region}")
        except Exception as e:
            logger.error(f"Failed to initialize Amazon Q client: {e}")
            raise
    
    def query_compliance(
        self,
        query: str,
        framework: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> ComplianceResponse:
        """Query Amazon Q for compliance intelligence.
        
        Args:
            query: The compliance question or topic
            framework: Optional compliance framework filter (GDPR, HIPAA, etc.)
            context: Optional additional context for the query
        
        Returns:
            ComplianceResponse with results and guidance
        
        Raises:
            ValueError: If query is empty
            RuntimeError: If API call fails
        """
        if not query or not query.strip():
            raise ValueError("Query cannot be empty")
        
        compliance_query = ComplianceQuery(
            query=query,
            framework=framework,
            context=context
        )
        
        logger.info(
            f"Querying Amazon Q for compliance: {query[:100]}...",
            extra={"framework": framework}
        )
        
        if self.config.enable_mock:
            return self._mock_query(compliance_query)
        
        return self._execute_query(compliance_query)
    
    def _execute_query(self, query: ComplianceQuery) -> ComplianceResponse:
        """Execute a real query against Amazon Q.
        
        Args:
            query: The compliance query object
        
        Returns:
            ComplianceResponse with results
        """
        try:
            # Build the request
            request_params = {
                "applicationId": self.config.application_id,
                "userMessage": query.query,
            }
            
            if self.config.index_id:
                request_params["indexId"] = self.config.index_id
            
            # Add framework as attribute filter if specified
            if query.framework:
                request_params["attributeFilter"] = {
                    "equalsTo": {
                        "name": "framework",
                        "value": {"stringValue": query.framework}
                    }
                }
            
            # Execute the query
            response = self._client.chat_sync(
                **request_params
            )
            
            # Parse response
            results = []
            sources = []
            
            if "sourceAttributions" in response:
                for attribution in response["sourceAttributions"]:
                    result = {
                        "title": attribution.get("title", ""),
                        "excerpt": attribution.get("snippet", ""),
                        "url": attribution.get("url", ""),
                        "score": attribution.get("score", 0.0)
                    }
                    results.append(result)
                    
                    if "citationNumber" in attribution:
                        sources.append(f"[{attribution['citationNumber']}] {result['title']}")
            
            # Add system response if available
            if "systemMessage" in response:
                results.insert(0, {
                    "title": "Amazon Q Response",
                    "text": response["systemMessage"],
                    "score": 1.0
                })
            
            confidence = response.get("systemMessageConfidence", 0.8)
            
            return ComplianceResponse(
                query_id=response.get("conversationId", "unknown"),
                results=results,
                confidence_score=confidence,
                sources=sources,
                timestamp=datetime.utcnow(),
                framework=query.framework
            )
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            logger.error(f"Amazon Q API error [{error_code}]: {error_msg}")
            raise RuntimeError(f"Amazon Q query failed: {error_msg}") from e
        
        except Exception as e:
            logger.error(f"Unexpected error querying Amazon Q: {e}")
            raise RuntimeError(f"Failed to query Amazon Q: {e}") from e
    
    def _mock_query(self, query: ComplianceQuery) -> ComplianceResponse:
        """Generate a mock response for testing.
        
        Args:
            query: The compliance query object
        
        Returns:
            Mock ComplianceResponse
        """
        framework = query.framework or "General"
        
        mock_results = [
            {
                "title": f"{framework} Compliance Guidance",
                "text": f"Mock guidance for {query.query[:50]}...",
                "excerpt": f"This is simulated compliance guidance for {framework}. "
                          f"In production, this would return actual regulatory guidance "
                          f"and policy interpretations from Amazon Q.",
                "score": 0.95,
                "url": f"https://example.com/compliance/{framework.lower()}"
            },
            {
                "title": f"Best Practices for {framework}",
                "excerpt": f"Mock best practices related to: {query.query[:30]}",
                "score": 0.87,
                "url": "https://example.com/best-practices"
            }
        ]
        
        mock_sources = [
            f"[1] {framework} Official Documentation",
            "[2] Industry Best Practices Guide"
        ]
        
        logger.info(f"Returning mock response for query: {query.query[:50]}...")
        
        return ComplianceResponse(
            query_id=f"mock-{datetime.utcnow().timestamp()}",
            results=mock_results,
            confidence_score=0.90,
            sources=mock_sources,
            timestamp=datetime.utcnow(),
            framework=framework
        )
    
    def get_policy_interpretation(
        self,
        policy_text: str,
        framework: str
    ) -> str:
        """Get AI interpretation of a compliance policy.
        
        Args:
            policy_text: The policy text to interpret
            framework: The compliance framework context
        
        Returns:
            Interpreted policy guidance
        """
        query = f"Interpret this {framework} policy: {policy_text}"
        response = self.query_compliance(query, framework=framework)
        return response.get_guidance()
    
    def check_requirement(
        self,
        requirement: str,
        framework: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Check if a specific requirement is being met.
        
        Args:
            requirement: The requirement to check
            framework: The compliance framework
            context: Optional context about the implementation
        
        Returns:
            Dictionary with compliance status and recommendations
        """
        query = f"How to comply with {framework} requirement: {requirement}"
        response = self.query_compliance(
            query=query,
            framework=framework,
            context=context
        )
        
        return {
            "requirement": requirement,
            "framework": framework,
            "guidance": response.get_guidance(),
            "confidence": response.confidence_score,
            "sources": response.sources,
            "timestamp": response.timestamp.isoformat()
        }
    
    def get_remediation_guidance(
        self,
        violation: str,
        framework: str
    ) -> str:
        """Get guidance on how to remediate a compliance violation.
        
        Args:
            violation: Description of the violation
            framework: The compliance framework
        
        Returns:
            Remediation guidance
        """
        query = f"How to fix this {framework} violation: {violation}"
        response = self.query_compliance(query, framework=framework)
        return response.get_guidance()
    
    def health_check(self) -> Dict[str, Any]:
        """Check if the Amazon Q client is healthy.
        
        Returns:
            Health status dictionary
        """
        try:
            if self.config.enable_mock:
                return {
                    "status": "healthy",
                    "mode": "mock",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Try a simple query
            test_response = self.query_compliance(
                query="test health check",
                framework="GDPR"
            )
            
            return {
                "status": "healthy",
                "mode": "production",
                "application_id": self.config.application_id,
                "region": self.config.region,
                "test_query_id": test_response.query_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }


# Convenience function for quick queries
def query_compliance(
    query: str,
    framework: Optional[str] = None,
    mock: bool = False
) -> ComplianceResponse:
    """Quick helper to query Amazon Q without creating a client instance.
    
    Args:
        query: The compliance question
        framework: Optional framework filter
        mock: Whether to use mock mode
    
    Returns:
        ComplianceResponse
    """
    config = AmazonQConfig.from_env()
    config.enable_mock = mock or config.enable_mock
    
    client = AmazonQClient(config)
    return client.query_compliance(query, framework=framework)
