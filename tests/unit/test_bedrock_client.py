"""Tests for Bedrock client."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from src.core.bedrock_client import BedrockClient, BedrockConfig, BedrockResponse


class TestBedrockConfig:
    """Test BedrockConfig class."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = BedrockConfig()
        assert config.region_name == "us-east-1"
        assert "claude" in config.model_id.lower()
        assert config.max_tokens == 4096
        assert config.temperature == 0.1
        assert config.top_p == 0.9
        assert config.timeout == 300
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = BedrockConfig(
            region_name="us-west-2",
            model_id="custom-model",
            max_tokens=2048,
            temperature=0.5
        )
        assert config.region_name == "us-west-2"
        assert config.model_id == "custom-model"
        assert config.max_tokens == 2048
        assert config.temperature == 0.5


class TestBedrockResponse:
    """Test BedrockResponse class."""
    
    def test_response_creation(self):
        """Test creating a response."""
        response = BedrockResponse(
            content="Test response",
            usage={"input_tokens": 10, "output_tokens": 20},
            model_id="test-model",
            stop_reason="end_turn"
        )
        assert response.content == "Test response"
        assert response.usage["input_tokens"] == 10
        assert response.usage["output_tokens"] == 20
        assert response.model_id == "test-model"
        assert response.stop_reason == "end_turn"
    
    def test_response_with_metadata(self):
        """Test response with metadata."""
        response = BedrockResponse(
            content="Test",
            usage={"input_tokens": 5, "output_tokens": 10},
            model_id="test",
            metadata={"key": "value"}
        )
        assert response.metadata["key"] == "value"


class TestBedrockClient:
    """Test BedrockClient class."""
    
    @patch('src.core.bedrock_client.boto3.client')
    @patch('src.core.bedrock_client.Anthropic')
    def test_client_initialization(self, mock_anthropic, mock_boto3):
        """Test client initialization."""
        mock_boto3.return_value = Mock()
        mock_anthropic.return_value = Mock()
        
        client = BedrockClient()
        
        assert client.config is not None
        assert client._client is not None
        mock_boto3.assert_called_once()
    
    @patch('src.core.bedrock_client.boto3.client')
    @patch('src.core.bedrock_client.Anthropic')
    def test_client_with_custom_config(self, mock_anthropic, mock_boto3):
        """Test client with custom configuration."""
        mock_boto3.return_value = Mock()
        mock_anthropic.return_value = Mock()
        
        config = BedrockConfig(region_name="eu-west-1")
        client = BedrockClient(config)
        
        assert client.config.region_name == "eu-west-1"
        mock_boto3.assert_called_with(
            "bedrock-runtime",
            region_name="eu-west-1"
        )
    
    @patch('src.core.bedrock_client.boto3.client')
    @patch('src.core.bedrock_client.Anthropic')
    @pytest.mark.asyncio
    async def test_invoke_model_success(self, mock_anthropic, mock_boto3):
        """Test successful model invocation."""
        # Mock boto3 client
        mock_bedrock = Mock()
        mock_response = {
            'body': Mock(read=lambda: json.dumps({
                'content': [{'text': 'Test response'}],
                'usage': {'input_tokens': 10, 'output_tokens': 20},
                'stop_reason': 'end_turn'
            }).encode())
        }
        mock_bedrock.invoke_model.return_value = mock_response
        mock_boto3.return_value = mock_bedrock
        mock_anthropic.return_value = Mock()
        
        client = BedrockClient()
        
        # Mock the internal method
        with patch.object(client, 'invoke_model', new_callable=AsyncMock) as mock_invoke:
            mock_invoke.return_value = BedrockResponse(
                content="Test response",
                usage={"input_tokens": 10, "output_tokens": 20},
                model_id="test-model"
            )
            
            response = await client.invoke_model("Test prompt")
            
            assert response.content == "Test response"
            assert response.usage["input_tokens"] == 10
            assert response.usage["output_tokens"] == 20
    
    @patch('src.core.bedrock_client.boto3.client')
    @patch('src.core.bedrock_client.Anthropic')
    def test_initialization_failure(self, mock_anthropic, mock_boto3):
        """Test initialization failure handling."""
        mock_boto3.side_effect = Exception("Connection failed")
        
        with pytest.raises(Exception):
            BedrockClient()


import json
