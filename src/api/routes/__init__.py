"""API routes initialization."""

from .agents import router as agents_router
from .scans import router as scans_router
from .workflows import router as workflows_router
from .reports import router as reports_router
from .remediation import router as remediation_router
from .health import router as health_router

__all__ = [
    "agents_router",
    "scans_router",
    "workflows_router",
    "reports_router",
    "remediation_router",
    "health_router"
]
