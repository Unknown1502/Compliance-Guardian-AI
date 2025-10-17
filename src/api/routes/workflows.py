"""Workflow execution endpoints."""

from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime

from ...utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


class WorkflowRequest(BaseModel):
    """Workflow execution request model."""
    workflow_type: str = Field(..., description="Workflow type")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Workflow parameters")
    async_execution: bool = Field(default=True, description="Execute asynchronously")


@router.post("/workflows/execute")
async def execute_workflow(
    workflow_request: WorkflowRequest,
    request: Request,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """Execute compliance workflow."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to orchestrator agent
        task_id = await agent_runtime.submit_task(
            agent_id="orchestrator_agent",
            task_type="execute_workflow",
            parameters={
                "workflow_type": workflow_request.workflow_type,
                "parameters": workflow_request.parameters
            }
        )
        
        return {
            "workflow_id": task_id,
            "workflow_type": workflow_request.workflow_type,
            "status": "started",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to execute workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/workflows/{workflow_id}")
async def get_workflow_status(workflow_id: str, request: Request) -> Dict[str, Any]:
    """Get workflow execution status."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        status = await agent_runtime.get_task_status(workflow_id)
        
        if not status:
            raise HTTPException(status_code=404, detail=f"Workflow {workflow_id} not found")
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get workflow status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/workflows/templates")
async def list_workflow_templates(request: Request) -> Dict[str, Any]:
    """List available workflow templates."""
    try:
        # Predefined workflow templates
        templates = {
            "gdpr_compliance_check": {
                "name": "GDPR Compliance Check",
                "description": "Comprehensive GDPR compliance assessment",
                "parameters": ["resource_ids", "scope"],
                "estimated_duration": "10-30 minutes"
            },
            "hipaa_compliance_check": {
                "name": "HIPAA Compliance Check",
                "description": "HIPAA compliance verification for healthcare data",
                "parameters": ["resource_ids", "phi_locations"],
                "estimated_duration": "15-45 minutes"
            },
            "pci_compliance_check": {
                "name": "PCI DSS Compliance Check",
                "description": "Payment Card Industry compliance scan",
                "parameters": ["resource_ids", "cardholder_data_locations"],
                "estimated_duration": "20-60 minutes"
            },
            "incident_response": {
                "name": "Security Incident Response",
                "description": "Automated incident response workflow",
                "parameters": ["incident_id", "severity", "affected_resources"],
                "estimated_duration": "5-15 minutes"
            },
            "full_audit": {
                "name": "Full Compliance Audit",
                "description": "Complete multi-framework compliance audit",
                "parameters": ["frameworks", "resource_scope"],
                "estimated_duration": "1-3 hours"
            }
        }
        
        return {
            "templates": templates,
            "total": len(templates)
        }
        
    except Exception as e:
        logger.error(f"Failed to list workflow templates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/workflows/{workflow_id}")
async def cancel_workflow(workflow_id: str, request: Request) -> Dict[str, Any]:
    """Cancel running workflow."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        cancelled = await agent_runtime.cancel_task(workflow_id)
        
        if not cancelled:
            raise HTTPException(
                status_code=404,
                detail=f"Workflow {workflow_id} not found or cannot be cancelled"
            )
        
        return {
            "workflow_id": workflow_id,
            "status": "cancelled",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))
