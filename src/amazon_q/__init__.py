"""Amazon Q integration package for compliance intelligence.

This package provides client wrappers and utilities for integrating Amazon Q
into the Compliance Guardian AI system for regulatory guidance and policy interpretation.
"""

from .client import (
    AmazonQClient,
    AmazonQConfig,
    ComplianceQuery,
    ComplianceResponse,
    query_compliance
)

__all__ = [
    "AmazonQClient",
    "AmazonQConfig",
    "ComplianceQuery",
    "ComplianceResponse",
    "query_compliance"
]
