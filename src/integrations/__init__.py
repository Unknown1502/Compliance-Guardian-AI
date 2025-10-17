"""External integrations for compliance scanning."""

from .github_connector import GitHubConnector
from .gitlab_connector import GitLabConnector
from .aws_connector import AWSConnector
from .database_connector import DatabaseConnector
from .regulatory_portal import RegulatoryPortalAutomator

__all__ = [
    "GitHubConnector",
    "GitLabConnector",
    "AWSConnector",
    "DatabaseConnector",
    "RegulatoryPortalAutomator"
]
