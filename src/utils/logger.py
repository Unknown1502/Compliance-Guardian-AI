"""Logging utilities for Compliance Guardian AI."""

import json
import logging
import logging.config
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import structlog
from pythonjsonlogger import jsonlogger

from .config import get_config


class ComplianceGuardianProcessor:
    """Custom structlog processor for Compliance Guardian AI."""
    
    def __init__(self):
        self.service_name = "compliance-guardian-ai"
    
    def __call__(self, logger, method_name, event_dict):
        """Process log events and add standard fields."""
        # Add service information
        event_dict["service"] = self.service_name
        event_dict["level"] = method_name.upper()
        
        # Add compliance-specific context
        if "agent_id" in event_dict:
            event_dict["component"] = "agent"
        
        if "violation_id" in event_dict:
            event_dict["component"] = "compliance"
        
        if "remediation_id" in event_dict:
            event_dict["component"] = "remediation"
        
        return event_dict


class SensitiveDataFilter(logging.Filter):
    """Filter to remove sensitive data from logs."""
    
    SENSITIVE_KEYS = [
        "password", "secret", "token", "key", "credential", 
        "auth", "api_key", "private_key", "jwt", "ssn", 
        "credit_card", "email"
    ]
    
    def filter(self, record):
        """Filter out sensitive data from log records."""
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            # Simple string replacement for sensitive patterns
            for key in self.SENSITIVE_KEYS:
                if key in record.msg.lower():
                    record.msg = record.msg.replace(
                        record.msg[record.msg.lower().find(key):], 
                        f"{key}=***REDACTED***"
                    )
        
        # Filter dictionary-like args
        if hasattr(record, 'args') and isinstance(record.args, (list, tuple)):
            filtered_args = []
            for arg in record.args:
                if isinstance(arg, dict):
                    filtered_arg = self._filter_dict(arg)
                    filtered_args.append(filtered_arg)
                else:
                    filtered_args.append(arg)
            record.args = tuple(filtered_args)
        
        return True
    
    def _filter_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Filter sensitive data from dictionary."""
        filtered = {}
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in self.SENSITIVE_KEYS):
                filtered[key] = "***REDACTED***"
            elif isinstance(value, dict):
                filtered[key] = self._filter_dict(value)
            elif isinstance(value, list):
                filtered[key] = [
                    self._filter_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                filtered[key] = value
        return filtered


def setup_logging(config: Optional[Dict[str, Any]] = None) -> None:
    """
    Setup logging configuration for Compliance Guardian AI.
    
    Args:
        config: Optional logging configuration override
    """
    app_config = get_config()
    
    # Default logging configuration
    default_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            },
            "json": {
                "()": jsonlogger.JsonFormatter,
                "format": "%(asctime)s %(name)s %(levelname)s %(message)s"
            },
            "detailed": {
                "format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s"
            }
        },
        "filters": {
            "sensitive_data": {
                "()": SensitiveDataFilter
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": app_config.observability.log_level,
                "formatter": "standard",
                "filters": ["sensitive_data"],
                "stream": sys.stdout
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": app_config.observability.log_level,
                "formatter": "json",
                "filters": ["sensitive_data"],
                "filename": "logs/compliance-guardian.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
                "encoding": "utf8"
            },
            "error_file": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "ERROR",
                "formatter": "detailed",
                "filters": ["sensitive_data"],
                "filename": "logs/compliance-guardian-errors.log",
                "maxBytes": 10485760,  # 10MB
                "backupCount": 3,
                "encoding": "utf8"
            }
        },
        "loggers": {
            "compliance_guardian": {
                "level": app_config.observability.log_level,
                "handlers": ["console", "file"],
                "propagate": False
            },
            "uvicorn": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False
            },
            "uvicorn.error": {
                "level": "ERROR",
                "handlers": ["console", "error_file"],
                "propagate": False
            },
            "uvicorn.access": {
                "level": "INFO",
                "handlers": ["file"],
                "propagate": False
            },
            "boto3": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False
            },
            "botocore": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False
            }
        },
        "root": {
            "level": app_config.observability.log_level,
            "handlers": ["console", "error_file"]
        }
    }
    
    # Override with provided config
    if config:
        default_config.update(config)
    
    # Ensure logs directory exists
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Configure standard logging
    logging.config.dictConfig(default_config)
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            ComplianceGuardianProcessor(),
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured logger instance
    """
    # Ensure logging is configured
    if not logging.getLogger().handlers:
        setup_logging()
    
    return structlog.get_logger(name)


def log_compliance_event(
    logger: structlog.BoundLogger,
    event_type: str,
    agent_id: str,
    details: Dict[str, Any],
    level: str = "info"
) -> None:
    """
    Log a compliance-related event with standard format.
    
    Args:
        logger: Logger instance
        event_type: Type of compliance event
        agent_id: ID of the agent involved
        details: Event details
        level: Log level
    """
    log_func = getattr(logger, level.lower(), logger.info)
    
    log_func(
        f"Compliance event: {event_type}",
        event_type=event_type,
        agent_id=agent_id,
        compliance_event=True,
        **details
    )


def log_agent_action(
    logger: structlog.BoundLogger,
    agent_id: str,
    action: str,
    task_id: Optional[str] = None,
    duration: Optional[float] = None,
    success: bool = True,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log an agent action with standard format.
    
    Args:
        logger: Logger instance
        agent_id: ID of the agent
        action: Action performed
        task_id: Optional task ID
        duration: Optional action duration in seconds
        success: Whether the action was successful
        details: Additional details
    """
    log_data = {
        "agent_id": agent_id,
        "action": action,
        "agent_action": True,
        "success": success
    }
    
    if task_id:
        log_data["task_id"] = task_id
    
    if duration is not None:
        log_data["duration_seconds"] = duration
    
    if details:
        log_data.update(details)
    
    level = "info" if success else "error"
    log_func = getattr(logger, level)
    
    log_func(
        f"Agent action: {action} ({'success' if success else 'failed'})",
        **log_data
    )


def log_security_event(
    logger: structlog.BoundLogger,
    event_type: str,
    severity: str,
    details: Dict[str, Any]
) -> None:
    """
    Log a security-related event.
    
    Args:
        logger: Logger instance
        event_type: Type of security event
        severity: Event severity (low, medium, high, critical)
        details: Event details
    """
    logger.warning(
        f"Security event: {event_type}",
        event_type=event_type,
        severity=severity,
        security_event=True,
        **details
    )


def log_performance_metric(
    logger: structlog.BoundLogger,
    metric_name: str,
    value: float,
    unit: str = "count",
    tags: Optional[Dict[str, str]] = None
) -> None:
    """
    Log a performance metric.
    
    Args:
        logger: Logger instance
        metric_name: Name of the metric
        value: Metric value
        unit: Metric unit
        tags: Optional tags
    """
    log_data = {
        "metric_name": metric_name,
        "metric_value": value,
        "metric_unit": unit,
        "performance_metric": True
    }
    
    if tags:
        log_data["metric_tags"] = tags
    
    logger.info(
        f"Performance metric: {metric_name}={value}{unit}",
        **log_data
    )


def log_api_request(
    logger: structlog.BoundLogger,
    method: str,
    path: str,
    status_code: int,
    duration: float,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None
) -> None:
    """
    Log an API request.
    
    Args:
        logger: Logger instance
        method: HTTP method
        path: Request path
        status_code: Response status code
        duration: Request duration in seconds
        user_id: Optional user ID
        ip_address: Optional client IP
    """
    log_data = {
        "http_method": method,
        "http_path": path,
        "http_status": status_code,
        "duration_seconds": duration,
        "api_request": True
    }
    
    if user_id:
        log_data["user_id"] = user_id
    
    if ip_address:
        log_data["client_ip"] = ip_address
    
    level = "info" if status_code < 400 else "warning" if status_code < 500 else "error"
    log_func = getattr(logger, level)
    
    log_func(
        f"API {method} {path} {status_code}",
        **log_data
    )


def configure_aws_logging() -> None:
    """Configure logging for AWS services."""
    # Reduce boto3/botocore logging verbosity
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    # Enable AWS SDK logging in debug mode only
    config = get_config()
    if config.debug:
        logging.getLogger('boto3.resources').setLevel(logging.INFO)
        logging.getLogger('botocore.hooks').setLevel(logging.INFO)


def get_log_context() -> Dict[str, Any]:
    """Get current log context for correlation."""
    import threading
    import time
    
    return {
        "thread_id": threading.current_thread().ident,
        "timestamp": time.time(),
        "service": "compliance-guardian-ai"
    }


# Setup logging on module import if not already configured
if not logging.getLogger().handlers:
    setup_logging()
    configure_aws_logging()