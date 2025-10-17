"""Configuration management for Compliance Guardian AI."""

import os
import json
from typing import Any, Dict, Optional, Union, List
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, validator

# Pydantic v1 compatibility - BaseSettings is in pydantic main package
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings


class DatabaseConfig(BaseModel):
    """Database configuration."""
    url: str = Field(default="postgresql://localhost:5432/compliance_guardian")
    pool_size: int = Field(default=20)
    max_overflow: int = Field(default=30)
    pool_timeout: int = Field(default=30)
    pool_recycle: int = Field(default=3600)


class RedisConfig(BaseModel):
    """Redis configuration."""
    url: str = Field(default="redis://localhost:6379")
    max_connections: int = Field(default=20)
    retry_on_timeout: bool = Field(default=True)
    socket_keepalive: bool = Field(default=True)


class AWSConfig(BaseModel):
    """AWS service configuration."""
    region: str = Field(default="us-east-1")
    bedrock_model_id: str = Field(default="us.anthropic.claude-3-5-sonnet-20241022-v2:0")
    s3_bucket: str = Field(default="compliance-guardian-data")
    sqs_queue_url: Optional[str] = None
    sns_topic_arn: Optional[str] = None
    cloudwatch_namespace: str = Field(default="ComplianceGuardian")


class SecurityConfig(BaseModel):
    """Security configuration."""
    jwt_secret: str = Field(default="change-this-in-production")
    jwt_algorithm: str = Field(default="HS256")
    jwt_expiry_hours: int = Field(default=24)
    encryption_key: Optional[str] = None
    enable_cors: bool = Field(default=True)
    cors_origins: list = Field(default=["*"])


class ComplianceConfig(BaseModel):
    """Compliance framework configuration."""
    enabled_frameworks: list = Field(default=["GDPR", "HIPAA", "PCI_DSS"])
    default_scan_depth: int = Field(default=3)
    auto_remediation: bool = Field(default=False)
    require_approval: bool = Field(default=True)
    max_violations_per_scan: int = Field(default=1000)


class AgentConfig(BaseModel):
    """Agent system configuration."""
    max_concurrent_agents: int = Field(default=10)
    task_timeout_seconds: int = Field(default=300)
    max_retries: int = Field(default=3)
    retry_delay_seconds: int = Field(default=1)
    enable_circuit_breaker: bool = Field(default=True)


class ObservabilityConfig(BaseModel):
    """Observability configuration."""
    enable_metrics: bool = Field(default=True)
    enable_logging: bool = Field(default=True)
    enable_tracing: bool = Field(default=True)
    metrics_port: int = Field(default=8080)
    log_level: str = Field(default="INFO")
    retention_days: int = Field(default=30)


class Config(BaseSettings):
    """Main application configuration."""
    
    # Environment
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    testing: bool = Field(default=False)
    
    # Application
    app_name: str = Field(default="Compliance Guardian AI")
    app_version: str = Field(default="1.0.0")
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    cors_origins: List[str] = Field(default=["*"])
    
    # Sub-configurations
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    aws: AWSConfig = Field(default_factory=AWSConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    agents: AgentConfig = Field(default_factory=AgentConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    
    class Config:
        env_file = ".env"
        env_nested_delimiter = "__"
        case_sensitive = False
        extra = "ignore"  # Ignore extra fields from .env file
    
    @validator("environment")
    def validate_environment(cls, v):
        valid_envs = ["development", "staging", "production", "testing"]
        if v not in valid_envs:
            raise ValueError(f"Environment must be one of {valid_envs}")
        return v
    
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == "production"
    
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == "development"


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    
    if _config is None:
        _config = load_config()
    
    return _config


def load_config(config_file: Optional[str] = None) -> Config:
    """
    Load configuration from various sources.
    
    Priority order:
    1. Environment variables
    2. Config file (YAML/JSON)
    3. Default values
    
    Args:
        config_file: Optional path to config file
        
    Returns:
        Loaded configuration
    """
    config_data = {}
    
    # Load from config file if provided
    if config_file:
        config_data.update(_load_config_file(config_file))
    else:
        # Try to find config files in standard locations
        config_paths = [
            "config.yaml",
            "config.yml", 
            "config.json",
            "config/app_config.yaml",
            "config/app_config.yml",
            "config/app_config.json"
        ]
        
        for path in config_paths:
            if os.path.exists(path):
                config_data.update(_load_config_file(path))
                break
    
    # Create config with environment variable overrides
    return Config(**config_data)


def _load_config_file(file_path: str) -> Dict[str, Any]:
    """Load configuration from a file."""
    try:
        path = Path(file_path)
        
        if not path.exists():
            return {}
        
        with open(path, 'r', encoding='utf-8') as f:
            if path.suffix in ['.yaml', '.yml']:
                return yaml.safe_load(f) or {}
            elif path.suffix == '.json':
                return json.load(f) or {}
            else:
                raise ValueError(f"Unsupported config file format: {path.suffix}")
                
    except Exception as e:
        print(f"Warning: Failed to load config file {file_path}: {e}")
        return {}


def update_config(updates: Dict[str, Any]) -> None:
    """Update the global configuration."""
    global _config
    
    if _config is None:
        _config = load_config()
    
    # Create new config with updates
    current_dict = _config.dict()
    current_dict.update(updates)
    _config = Config(**current_dict)


def save_config(file_path: str, config: Optional[Config] = None) -> None:
    """Save configuration to a file."""
    config = config or get_config()
    path = Path(file_path)
    
    config_dict = config.dict()
    
    try:
        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            if path.suffix in ['.yaml', '.yml']:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            elif path.suffix == '.json':
                json.dump(config_dict, f, indent=2)
            else:
                raise ValueError(f"Unsupported config file format: {path.suffix}")
                
    except Exception as e:
        raise RuntimeError(f"Failed to save config to {file_path}: {e}")


def get_database_url() -> str:
    """Get the database URL from configuration or environment."""
    config = get_config()
    
    # Check for environment variable override
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        return db_url
    
    return config.database.url


def get_redis_url() -> str:
    """Get the Redis URL from configuration or environment."""
    config = get_config()
    
    # Check for environment variable override
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        return redis_url
    
    return config.redis.url


def get_aws_region() -> str:
    """Get the AWS region from configuration or environment."""
    config = get_config()
    
    # Check for environment variable override
    aws_region = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION"))
    if aws_region:
        return aws_region
    
    return config.aws.region


def validate_config(config: Optional[Config] = None) -> list:
    """
    Validate configuration and return list of issues.
    
    Args:
        config: Configuration to validate (uses global if None)
        
    Returns:
        List of validation issues
    """
    config = config or get_config()
    issues = []
    
    # Check critical settings for production
    if config.is_production():
        if config.security.jwt_secret == "change-this-in-production":
            issues.append("JWT secret must be changed in production")
        
        if config.debug:
            issues.append("Debug should be disabled in production")
        
        if not config.security.encryption_key:
            issues.append("Encryption key must be set in production")
    
    # Check AWS configuration
    if not config.aws.s3_bucket:
        issues.append("S3 bucket must be configured")
    
    # Check database configuration
    if "localhost" in config.database.url and config.is_production():
        issues.append("Database should not use localhost in production")
    
    # Check Redis configuration
    if "localhost" in config.redis.url and config.is_production():
        issues.append("Redis should not use localhost in production")
    
    return issues


def create_sample_config(file_path: str) -> None:
    """Create a sample configuration file."""
    config = Config()
    save_config(file_path, config)


# Configuration validation on import
def _validate_on_import():
    """Validate configuration when module is imported."""
    try:
        config = get_config()
        issues = validate_config(config)
        
        if issues:
            print("Configuration warnings:")
            for issue in issues:
                print(f"  - {issue}")
    except Exception as e:
        print(f"Warning: Configuration validation failed: {e}")


# Run validation on import
_validate_on_import()