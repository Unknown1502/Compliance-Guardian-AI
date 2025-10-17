"""Health check endpoints."""

from fastapi import APIRouter, Request
from typing import Dict, Any
from datetime import datetime

from ...utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """Basic health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "compliance-guardian-ai"
    }


@router.get("/health/detailed")
async def detailed_health_check(request: Request) -> Dict[str, Any]:
    """Detailed health check with component status."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Check agent runtime
        runtime_health = await agent_runtime.health_check()
        
        # Check individual agents
        agent_statuses = {}
        for agent_id, agent in agent_runtime.agents.items():
            status = await agent.health_check()
            agent_statuses[agent_id] = status
        
        overall_healthy = runtime_health["status"] == "healthy" and all(
            status.get("status") == "healthy" for status in agent_statuses.values()
        )
        
        return {
            "status": "healthy" if overall_healthy else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "agent_runtime": runtime_health,
                "agents": agent_statuses
            }
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@router.get("/health/ready")
async def readiness_check(request: Request) -> Dict[str, Any]:
    """Readiness check for Kubernetes."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Check if all agents are initialized
        all_ready = all(
            agent.state.get("initialized", False)
            for agent in agent_runtime.agents.values()
        )
        
        if all_ready:
            return {
                "status": "ready",
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            return {
                "status": "not_ready",
                "timestamp": datetime.utcnow().isoformat(),
                "message": "Agents still initializing"
            }
        
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return {
            "status": "not_ready",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@router.get("/health/live")
async def liveness_check() -> Dict[str, Any]:
    """Liveness check for Kubernetes."""
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/metrics")
async def metrics_endpoint(request: Request) -> Dict[str, Any]:
    """Prometheus-compatible metrics endpoint."""
    try:
        observability = request.app.state.observability
        metrics = observability.get_metrics()
        
        return metrics
        
    except Exception as e:
        logger.error(f"Failed to retrieve metrics: {e}")
        return {"error": str(e)}
