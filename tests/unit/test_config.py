"""Tests for configuration management."""

import pytest
from src.utils.config import Config, DatabaseConfig, AWSConfig


class TestConfig:
    """Test configuration classes."""
    
    def test_database_config_defaults(self):
        """Test DatabaseConfig with default values."""
        config = DatabaseConfig()
        assert config.pool_size == 20
        assert config.max_overflow == 30
    
    def test_aws_config_defaults(self):
        """Test AWSConfig with default values."""
        config = AWSConfig()
        assert config.region == "us-east-1"
        assert "claude" in config.bedrock_model_id.lower()
    
    def test_main_config_creation(self):
        """Test main Config creation."""
        config = Config()
        assert config.app_name == "Compliance Guardian AI"
        assert config.environment in ["development", "staging", "production", "testing"]
        assert isinstance(config.database, DatabaseConfig)
        assert isinstance(config.aws, AWSConfig)
    
    def test_config_is_production(self):
        """Test production environment check."""
        config = Config(environment="production")
        assert config.is_production() is True
        assert config.is_development() is False
    
    def test_config_is_development(self):
        """Test development environment check."""
        config = Config(environment="development")
        assert config.is_development() is True
        assert config.is_production() is False
