"""Validation utilities for Compliance Guardian AI."""

import re
import json
from typing import Any, Dict, List, Optional, Union
from enum import Enum

import jsonschema
from pydantic import BaseModel, Field, validator
from email_validator import validate_email as email_validate, EmailNotValidError

from .logger import get_logger


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"
    SOX = "SOX"
    ISO_27001 = "ISO_27001"
    CCPA = "CCPA"


class SeverityLevel(Enum):
    """Violation severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ValidationError(Exception):
    """Custom validation error."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Any = None):
        self.message = message
        self.field = field
        self.value = value
        super().__init__(self.message)


def validate_email(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid email format
        
    Raises:
        ValidationError: If email is invalid
    """
    try:
        # Use email-validator library for robust validation
        valid = email_validate(email)
        return True
    except EmailNotValidError as e:
        raise ValidationError(f"Invalid email format: {str(e)}", "email", email)


def validate_json_schema(data: Dict[str, Any], schema: Dict[str, Any]) -> bool:
    """
    Validate data against JSON schema.
    
    Args:
        data: Data to validate
        schema: JSON schema to validate against
        
    Returns:
        True if data is valid
        
    Raises:
        ValidationError: If validation fails
    """
    try:
        jsonschema.validate(instance=data, schema=schema)
        return True
    except jsonschema.ValidationError as e:
        raise ValidationError(f"Schema validation failed: {e.message}", e.path, e.instance)
    except jsonschema.SchemaError as e:
        raise ValidationError(f"Invalid schema: {e.message}")


def validate_compliance_framework(framework: str) -> bool:
    """
    Validate compliance framework.
    
    Args:
        framework: Framework name to validate
        
    Returns:
        True if valid framework
        
    Raises:
        ValidationError: If framework is not supported
    """
    try:
        ComplianceFramework(framework.upper())
        return True
    except ValueError:
        valid_frameworks = [f.value for f in ComplianceFramework]
        raise ValidationError(
            f"Unsupported compliance framework: {framework}. "
            f"Supported frameworks: {valid_frameworks}",
            "framework",
            framework
        )


def validate_severity_level(severity: str) -> bool:
    """
    Validate severity level.
    
    Args:
        severity: Severity level to validate
        
    Returns:
        True if valid severity
        
    Raises:
        ValidationError: If severity is invalid
    """
    try:
        SeverityLevel(severity.upper())
        return True
    except ValueError:
        valid_severities = [s.value for s in SeverityLevel]
        raise ValidationError(
            f"Invalid severity level: {severity}. "
            f"Valid levels: {valid_severities}",
            "severity",
            severity
        )


def validate_agent_id(agent_id: str) -> bool:
    """
    Validate agent ID format.
    
    Args:
        agent_id: Agent ID to validate
        
    Returns:
        True if valid agent ID
        
    Raises:
        ValidationError: If agent ID is invalid
    """
    if not agent_id:
        raise ValidationError("Agent ID cannot be empty", "agent_id", agent_id)
    
    if not isinstance(agent_id, str):
        raise ValidationError("Agent ID must be a string", "agent_id", agent_id)
    
    # Agent ID should be alphanumeric with optional hyphens/underscores
    pattern = r'^[a-zA-Z0-9_-]+$'
    if not re.match(pattern, agent_id):
        raise ValidationError(
            "Agent ID must contain only alphanumeric characters, hyphens, and underscores",
            "agent_id",
            agent_id
        )
    
    if len(agent_id) > 50:
        raise ValidationError("Agent ID must be 50 characters or less", "agent_id", agent_id)
    
    return True


def validate_task_payload(payload: Dict[str, Any]) -> bool:
    """
    Validate task payload structure.
    
    Args:
        payload: Task payload to validate
        
    Returns:
        True if valid payload
        
    Raises:
        ValidationError: If payload is invalid
    """
    if not isinstance(payload, dict):
        raise ValidationError("Task payload must be a dictionary", "payload", payload)
    
    required_fields = ["task_type", "data"]
    for field in required_fields:
        if field not in payload:
            raise ValidationError(f"Missing required field: {field}", field, None)
    
    # Validate task_type
    valid_task_types = [
        "compliance_scan", "violation_remediation", "audit_report", 
        "risk_assessment", "policy_check"
    ]
    
    if payload["task_type"] not in valid_task_types:
        raise ValidationError(
            f"Invalid task type: {payload['task_type']}. "
            f"Valid types: {valid_task_types}",
            "task_type",
            payload["task_type"]
        )
    
    return True


def validate_code_content(code: str, max_size_mb: int = 10) -> bool:
    """
    Validate code content for scanning.
    
    Args:
        code: Code content to validate
        max_size_mb: Maximum size in MB
        
    Returns:
        True if valid code content
        
    Raises:
        ValidationError: If code content is invalid
    """
    if not isinstance(code, str):
        raise ValidationError("Code content must be a string", "code", type(code))
    
    # Check size limit
    size_mb = len(code.encode('utf-8')) / (1024 * 1024)
    if size_mb > max_size_mb:
        raise ValidationError(
            f"Code content too large: {size_mb:.2f}MB > {max_size_mb}MB",
            "code",
            f"{size_mb:.2f}MB"
        )
    
    # Check for potentially malicious content
    suspicious_patterns = [
        r'eval\s*\(',
        r'exec\s*\(',
        r'__import__\s*\(',
        r'subprocess\.',
        r'os\.system',
        r'shell=True'
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            raise ValidationError(
                f"Code contains potentially dangerous pattern: {pattern}",
                "code",
                "suspicious_content"
            )
    
    return True


def validate_file_path(file_path: str) -> bool:
    """
    Validate file path for security.
    
    Args:
        file_path: File path to validate
        
    Returns:
        True if valid file path
        
    Raises:
        ValidationError: If file path is invalid
    """
    if not isinstance(file_path, str):
        raise ValidationError("File path must be a string", "file_path", type(file_path))
    
    if not file_path.strip():
        raise ValidationError("File path cannot be empty", "file_path", file_path)
    
    # Check for path traversal attempts
    dangerous_patterns = ['../', '..\\', '/etc/', '/proc/', '/sys/', 'C:\\Windows\\']
    
    for pattern in dangerous_patterns:
        if pattern in file_path:
            raise ValidationError(
                f"File path contains dangerous pattern: {pattern}",
                "file_path",
                file_path
            )
    
    # Check for absolute paths in restricted scenarios
    if file_path.startswith('/') or (len(file_path) > 1 and file_path[1] == ':'):
        raise ValidationError(
            "Absolute file paths are not allowed",
            "file_path",
            file_path
        )
    
    return True


def validate_url(url: str, allowed_schemes: Optional[List[str]] = None) -> bool:
    """
    Validate URL format and scheme.
    
    Args:
        url: URL to validate
        allowed_schemes: List of allowed URL schemes
        
    Returns:
        True if valid URL
        
    Raises:
        ValidationError: If URL is invalid
    """
    allowed_schemes = allowed_schemes or ['http', 'https']
    
    if not isinstance(url, str):
        raise ValidationError("URL must be a string", "url", type(url))
    
    # Basic URL pattern validation
    url_pattern = re.compile(
        r'^(https?|ftp)://'  # scheme
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if not url_pattern.match(url):
        raise ValidationError("Invalid URL format", "url", url)
    
    # Check scheme
    scheme = url.split('://')[0].lower()
    if scheme not in allowed_schemes:
        raise ValidationError(
            f"URL scheme '{scheme}' not allowed. Allowed schemes: {allowed_schemes}",
            "url_scheme",
            scheme
        )
    
    return True


def validate_regex_pattern(pattern: str) -> bool:
    """
    Validate regex pattern.
    
    Args:
        pattern: Regex pattern to validate
        
    Returns:
        True if valid regex pattern
        
    Raises:
        ValidationError: If regex pattern is invalid
    """
    try:
        re.compile(pattern)
        return True
    except re.error as e:
        raise ValidationError(f"Invalid regex pattern: {str(e)}", "pattern", pattern)


def validate_json_string(json_string: str) -> bool:
    """
    Validate JSON string format.
    
    Args:
        json_string: JSON string to validate
        
    Returns:
        True if valid JSON
        
    Raises:
        ValidationError: If JSON is invalid
    """
    try:
        json.loads(json_string)
        return True
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON format: {str(e)}", "json", json_string)


def validate_pii_patterns(text: str) -> Dict[str, List[str]]:
    """
    Validate and detect PII patterns in text.
    
    Args:
        text: Text to scan for PII
        
    Returns:
        Dictionary of detected PII types and their locations
    """
    pii_patterns = {
        'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
        'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    }
    
    detected_pii = {}
    
    for pii_type, pattern in pii_patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            detected_pii[pii_type] = matches
    
    return detected_pii


class ViolationSchema(BaseModel):
    """Schema for compliance violation data."""
    
    violation_id: str = Field(..., min_length=1, max_length=100)
    framework: str = Field(..., min_length=1, max_length=50)
    severity: str = Field(..., min_length=1, max_length=20)
    description: str = Field(..., min_length=1, max_length=1000)
    file_path: Optional[str] = Field(None, max_length=500)
    line_number: Optional[int] = Field(None, ge=1)
    code_snippet: Optional[str] = Field(None, max_length=5000)
    remediation_suggestion: Optional[str] = Field(None, max_length=2000)
    
    @validator('framework')
    def validate_framework_enum(cls, v):
        validate_compliance_framework(v)
        return v.upper()
    
    @validator('severity')
    def validate_severity_enum(cls, v):
        validate_severity_level(v)
        return v.upper()
    
    @validator('file_path')
    def validate_file_path_security(cls, v):
        if v:
            validate_file_path(v)
        return v


class AgentConfigSchema(BaseModel):
    """Schema for agent configuration."""
    
    agent_id: str = Field(..., min_length=1, max_length=50)
    agent_name: str = Field(..., min_length=1, max_length=100)
    agent_type: str = Field(..., min_length=1, max_length=50)
    enabled: bool = Field(default=True)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    max_retries: int = Field(default=3, ge=0, le=10)
    config: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('agent_id')
    def validate_agent_id_format(cls, v):
        validate_agent_id(v)
        return v


def create_validation_schemas() -> Dict[str, Dict[str, Any]]:
    """Create JSON schemas for common validation tasks."""
    
    schemas = {
        "task_payload": {
            "type": "object",
            "properties": {
                "task_type": {
                    "type": "string",
                    "enum": ["compliance_scan", "violation_remediation", "audit_report", "risk_assessment", "policy_check"]
                },
                "data": {
                    "type": "object"
                },
                "priority": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "NORMAL", "LOW"]
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3600
                }
            },
            "required": ["task_type", "data"],
            "additionalProperties": False
        },
        
        "compliance_policy": {
            "type": "object",
            "properties": {
                "policy_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100
                },
                "framework": {
                    "type": "string",
                    "enum": ["GDPR", "HIPAA", "PCI_DSS", "SOX", "ISO_27001", "CCPA"]
                },
                "rules": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "rule_id": {"type": "string"},
                            "description": {"type": "string"},
                            "pattern": {"type": "string"},
                            "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
                        },
                        "required": ["rule_id", "description", "pattern", "severity"]
                    }
                }
            },
            "required": ["policy_id", "framework", "rules"],
            "additionalProperties": False
        }
    }
    
    return schemas


# Initialize validation schemas
VALIDATION_SCHEMAS = create_validation_schemas()


def validate_scan_request(request: Dict[str, Any]) -> bool:
    """
    Validate a scan request payload.
    
    Args:
        request: Scan request to validate
        
    Returns:
        True if valid, raises ValueError if invalid
    """
    required_fields = ["scan_type", "target"]
    
    for field in required_fields:
        if field not in request:
            raise ValueError(f"Missing required field: {field}")
    
    valid_scan_types = ["gdpr", "hipaa", "pci", "code", "data_flow"]
    if request["scan_type"] not in valid_scan_types:
        raise ValueError(f"Invalid scan_type. Must be one of: {valid_scan_types}")
    
    return True


def validate_remediation_request(request: Dict[str, Any]) -> bool:
    """
    Validate a remediation request payload.
    
    Args:
        request: Remediation request to validate
        
    Returns:
        True if valid, raises ValueError if invalid
    """
    required_fields = ["remediation_type", "violation_id"]
    
    for field in required_fields:
        if field not in request:
            raise ValueError(f"Missing required field: {field}")
    
    valid_remediation_types = ["consent", "encryption", "pii_masking", "policy_injection"]
    if request["remediation_type"] not in valid_remediation_types:
        raise ValueError(f"Invalid remediation_type. Must be one of: {valid_remediation_types}")
    
    return True


def validate_pii_data(data: Any) -> bool:
    """
    Validate data for PII patterns and sensitivity.
    
    Args:
        data: Data to validate for PII
        
    Returns:
        True if data is safe, raises ValueError if PII detected without proper handling
    """
    if isinstance(data, str):
        pii_patterns = validate_pii_patterns(data)
        if any(pii_patterns.values()):
            # PII detected - log warning but don't fail
            logger = get_logger(__name__)
            logger.warning(f"PII detected in data", pii_types=list(pii_patterns.keys()))
    
    return True