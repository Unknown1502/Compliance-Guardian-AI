"""Unit tests for Amazon Q client."""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from src.amazon_q.client import (
    AmazonQClient,
    AmazonQConfig,
    ComplianceQuery,
    ComplianceResponse,
    query_compliance
)


class TestAmazonQConfig:
    """Tests for AmazonQConfig."""
    
    def test_config_initialization(self):
        """Test basic config initialization."""
        config = AmazonQConfig(
            application_id="test-app-id",
            region="us-west-2",
            max_results=5
        )
        
        assert config.application_id == "test-app-id"
        assert config.region == "us-west-2"
        assert config.max_results == 5
        assert config.enable_mock is False
    
    def test_config_from_env(self):
        """Test loading config from environment variables."""
        with patch.dict("os.environ", {
            "AMAZON_Q_APPLICATION_ID": "env-app-id",
            "AWS_REGION": "eu-west-1",
            "AMAZON_Q_MAX_RESULTS": "20",
            "AMAZON_Q_MOCK": "true"
        }):
            config = AmazonQConfig.from_env()
            
            assert config.application_id == "env-app-id"
            assert config.region == "eu-west-1"
            assert config.max_results == 20
            assert config.enable_mock is True
    
    def test_config_from_env_defaults(self):
        """Test default values when env vars not set."""
        with patch.dict("os.environ", {}, clear=True):
            config = AmazonQConfig.from_env()
            
            assert config.application_id == ""
            assert config.region == "us-east-1"
            assert config.max_results == 10
            assert config.enable_mock is False


class TestComplianceQuery:
    """Tests for ComplianceQuery dataclass."""
    
    def test_query_creation(self):
        """Test creating a compliance query."""
        query = ComplianceQuery(
            query="How to implement GDPR Article 17?",
            framework="GDPR",
            context={"resource": "s3_bucket"}
        )
        
        assert query.query == "How to implement GDPR Article 17?"
        assert query.framework == "GDPR"
        assert query.context == {"resource": "s3_bucket"}
    
    def test_query_to_dict(self):
        """Test converting query to dictionary."""
        query = ComplianceQuery(
            query="Test query",
            framework="HIPAA",
            filters={"category": ["technical"]}
        )
        
        result = query.to_dict()
        
        assert result["query"] == "Test query"
        assert result["framework"] == "HIPAA"
        assert result["filters"] == {"category": ["technical"]}


class TestComplianceResponse:
    """Tests for ComplianceResponse dataclass."""
    
    def test_response_creation(self):
        """Test creating a compliance response."""
        response = ComplianceResponse(
            query_id="test-123",
            results=[{"title": "Test", "score": 0.9}],
            confidence_score=0.85,
            sources=["Source 1"],
            timestamp=datetime.utcnow(),
            framework="GDPR"
        )
        
        assert response.query_id == "test-123"
        assert len(response.results) == 1
        assert response.confidence_score == 0.85
        assert response.framework == "GDPR"
    
    def test_top_result(self):
        """Test getting the top result."""
        response = ComplianceResponse(
            query_id="test",
            results=[
                {"title": "First", "score": 0.9},
                {"title": "Second", "score": 0.8}
            ],
            confidence_score=0.85,
            sources=[],
            timestamp=datetime.utcnow()
        )
        
        assert response.top_result["title"] == "First"
    
    def test_top_result_empty(self):
        """Test top result with no results."""
        response = ComplianceResponse(
            query_id="test",
            results=[],
            confidence_score=0.0,
            sources=[],
            timestamp=datetime.utcnow()
        )
        
        assert response.top_result is None
    
    def test_get_guidance(self):
        """Test extracting guidance from results."""
        response = ComplianceResponse(
            query_id="test",
            results=[
                {"excerpt": "First guidance"},
                {"text": "Second guidance"},
                {"excerpt": "Third guidance"}
            ],
            confidence_score=0.85,
            sources=[],
            timestamp=datetime.utcnow()
        )
        
        guidance = response.get_guidance()
        
        assert "First guidance" in guidance
        assert "Second guidance" in guidance
        assert "Third guidance" in guidance
    
    def test_get_guidance_empty(self):
        """Test guidance extraction with no results."""
        response = ComplianceResponse(
            query_id="test",
            results=[],
            confidence_score=0.0,
            sources=[],
            timestamp=datetime.utcnow()
        )
        
        assert response.get_guidance() == "No guidance available."


class TestAmazonQClient:
    """Tests for AmazonQClient."""
    
    def test_client_initialization_mock_mode(self):
        """Test client initialization in mock mode."""
        config = AmazonQConfig(
            application_id="test-app",
            enable_mock=True
        )
        
        client = AmazonQClient(config)
        
        assert client.config.enable_mock is True
        assert client._client is None
    
    def test_client_initialization_missing_app_id(self):
        """Test that client raises error without app ID in production mode."""
        config = AmazonQConfig(
            application_id="",
            enable_mock=False
        )
        
        with pytest.raises(ValueError, match="AMAZON_Q_APPLICATION_ID"):
            AmazonQClient(config)
    
    def test_query_compliance_mock_mode(self):
        """Test querying in mock mode."""
        config = AmazonQConfig(
            application_id="test-app",
            enable_mock=True
        )
        client = AmazonQClient(config)
        
        response = client.query_compliance(
            query="How to implement GDPR consent?",
            framework="GDPR"
        )
        
        assert isinstance(response, ComplianceResponse)
        assert response.framework == "GDPR"
        assert len(response.results) > 0
        assert response.confidence_score > 0
        assert "GDPR" in response.results[0]["title"]
    
    def test_query_compliance_empty_query(self):
        """Test that empty query raises error."""
        config = AmazonQConfig(
            application_id="test-app",
            enable_mock=True
        )
        client = AmazonQClient(config)
        
        with pytest.raises(ValueError, match="Query cannot be empty"):
            client.query_compliance("")
    
    def test_mock_query_generates_results(self):
        """Test that mock query generates appropriate results."""
        config = AmazonQConfig(
            application_id="test-app",
            enable_mock=True
        )
        client = AmazonQClient(config)
        
        response = client._mock_query(
            ComplianceQuery(
                query="Test query for HIPAA",
                framework="HIPAA"
            )
        )
        
        assert len(response.results) >= 2
        assert "HIPAA" in response.results[0]["title"]
        assert len(response.sources) >= 2
        assert response.confidence_score > 0
    
    @patch("src.amazon_q.client.boto3")
    def test_execute_query_production(self, mock_boto3):
        """Test executing a real query (mocked boto3)."""
        # Mock boto3 client
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        
        mock_client.chat_sync.return_value = {
            "conversationId": "conv-123",
            "systemMessage": "Test guidance",
            "systemMessageConfidence": 0.92,
            "sourceAttributions": [
                {
                    "title": "GDPR Article 17",
                    "snippet": "Right to erasure",
                    "url": "https://example.com/gdpr",
                    "score": 0.95,
                    "citationNumber": 1
                }
            ]
        }
        
        config = AmazonQConfig(
            application_id="test-app",
            enable_mock=False
        )
        client = AmazonQClient(config)
        
        response = client.query_compliance(
            query="Explain GDPR Article 17",
            framework="GDPR"
        )
        
        assert response.query_id == "conv-123"
        assert response.confidence_score == 0.92
        assert len(response.results) >= 1
        assert "GDPR Article 17" in str(response.results)
    
    def test_get_policy_interpretation(self):
        """Test policy interpretation."""
        config = AmazonQConfig(
            application_id="test-app",
            enable_mock=True
        )
        client = AmazonQClient(config)
        
        interpretation = client.get_policy_interpretation(
            policy_text="All data must be encrypted at rest",
            framework="HIPAA"
        )
        
        assert isinstance(interpretation, str)
        assert len(interpretation) > 0
    
    def test_check_requirement(self):
        """Test checking a compliance requirement."""
        config = AmazonQConfig(
            application_id="test-app",
            enable_mock=True
        )
        client = AmazonQClient(config)
        
        result = client.check_requirement(
            requirement="Encrypt all PHI data",
            framework="HIPAA",
            context={"resource_type": "database"}
        )
        
        assert result["requirement"] == "Encrypt all PHI data"
        assert result["framework"] == "HIPAA"
        assert "guidance" in result
        assert "confidence" in result
        assert result["confidence"] > 0
    
    def test_get_remediation_guidance(self):
        """Test getting remediation guidance."""
        config = AmazonQConfig(
            application_id="test-app",
            enable_mock=True
        )
        client = AmazonQClient(config)
        
        guidance = client.get_remediation_guidance(
            violation="S3 bucket not encrypted",
            framework="PCI-DSS"
        )
        
        assert isinstance(guidance, str)
        assert len(guidance) > 0
    
    def test_health_check_mock(self):
        """Test health check in mock mode."""
        config = AmazonQConfig(
            application_id="test-app",
            enable_mock=True
        )
        client = AmazonQClient(config)
        
        health = client.health_check()
        
        assert health["status"] == "healthy"
        assert health["mode"] == "mock"
        assert "timestamp" in health
    
    @patch("src.amazon_q.client.boto3")
    def test_health_check_production(self, mock_boto3):
        """Test health check in production mode."""
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client
        
        mock_client.chat_sync.return_value = {
            "conversationId": "health-check-123",
            "systemMessage": "OK",
            "systemMessageConfidence": 1.0,
            "sourceAttributions": []
        }
        
        config = AmazonQConfig(
            application_id="test-app",
            enable_mock=False
        )
        client = AmazonQClient(config)
        
        health = client.health_check()
        
        assert health["status"] == "healthy"
        assert health["mode"] == "production"
        assert health["application_id"] == "test-app"


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_query_compliance_function(self):
        """Test the convenience query_compliance function."""
        with patch.dict("os.environ", {
            "AMAZON_Q_APPLICATION_ID": "test-app",
            "AMAZON_Q_MOCK": "true"
        }):
            response = query_compliance(
                query="Test query",
                framework="GDPR"
            )
            
            assert isinstance(response, ComplianceResponse)
            assert response.framework == "GDPR"
    
    def test_query_compliance_function_force_mock(self):
        """Test forcing mock mode via parameter."""
        response = query_compliance(
            query="Test query",
            framework="HIPAA",
            mock=True
        )
        
        assert isinstance(response, ComplianceResponse)
        assert response.framework == "HIPAA"


# Integration-style tests (these would require actual AWS credentials in production)
class TestIntegration:
    """Integration tests (run with mock or real credentials)."""
    
    @pytest.mark.skip(reason="Requires AWS credentials and Amazon Q setup")
    def test_real_query_gdpr(self):
        """Test a real query to Amazon Q (requires credentials)."""
        client = AmazonQClient()
        
        response = client.query_compliance(
            query="What are the key requirements of GDPR Article 32?",
            framework="GDPR"
        )
        
        assert len(response.results) > 0
        assert response.confidence_score > 0
    
    @pytest.mark.skip(reason="Requires AWS credentials")
    def test_real_health_check(self):
        """Test real health check (requires credentials)."""
        client = AmazonQClient()
        health = client.health_check()
        
        assert health["status"] == "healthy"
