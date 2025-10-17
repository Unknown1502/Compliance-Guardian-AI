"""Compliance scanning endpoints."""

from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime

from ...utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


class ScanRequest(BaseModel):
    """Compliance scan request model."""
    framework: str = Field(..., description="Compliance framework (gdpr, hipaa, pci, etc.)")
    resource_type: str = Field(..., description="Resource type to scan")
    resource_id: str = Field(..., description="Resource identifier")
    scan_depth: str = Field(default="standard", description="Scan depth (quick, standard, deep)")


class CodeScanRequest(BaseModel):
    """Code scan request model."""
    repository_url: Optional[str] = Field(None, description="Git repository URL")
    local_path: Optional[str] = Field(None, description="Local filesystem path")
    branch: str = Field(default="main", description="Git branch to scan")


class DataFlowScanRequest(BaseModel):
    """Data flow scan request model."""
    data_flows: List[Dict[str, Any]] = Field(..., description="List of data flows to analyze")


@router.post("/scans/compliance")
async def start_compliance_scan(
    scan_request: ScanRequest,
    request: Request,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """Start compliance scan."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to compliance agent
        task_id = await agent_runtime.submit_task(
            agent_id="compliance_agent",
            task_type="compliance_scan",
            parameters={
                "framework": scan_request.framework,
                "resource_type": scan_request.resource_type,
                "resource_id": scan_request.resource_id,
                "scan_depth": scan_request.scan_depth
            }
        )
        
        return {
            "scan_id": task_id,
            "framework": scan_request.framework,
            "resource_id": scan_request.resource_id,
            "status": "started",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to start compliance scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scans/code")
async def start_code_scan(
    scan_request: CodeScanRequest,
    request: Request,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """Start code compliance scan."""
    try:
        if not scan_request.repository_url and not scan_request.local_path:
            raise HTTPException(
                status_code=400,
                detail="Either repository_url or local_path must be provided"
            )
        
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to compliance agent
        task_id = await agent_runtime.submit_task(
            agent_id="compliance_agent",
            task_type="code_scan",
            parameters={
                "repository_url": scan_request.repository_url,
                "local_path": scan_request.local_path,
                "branch": scan_request.branch
            }
        )
        
        return {
            "scan_id": task_id,
            "status": "started",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start code scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scans/dataflow")
async def start_dataflow_scan(
    scan_request: DataFlowScanRequest,
    request: Request,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """Start data flow analysis scan."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to compliance agent
        task_id = await agent_runtime.submit_task(
            agent_id="compliance_agent",
            task_type="dataflow_scan",
            parameters={
                "data_flows": scan_request.data_flows
            }
        )
        
        return {
            "scan_id": task_id,
            "flows_count": len(scan_request.data_flows),
            "status": "started",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to start dataflow scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}")
async def get_scan_results(scan_id: str, request: Request) -> Dict[str, Any]:
    """Get scan results."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Get task status/results
        results = await agent_runtime.get_task_status(scan_id)
        
        if not results:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan results: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans")
async def list_scans(
    request: Request,
    status: Optional[str] = None,
    framework: Optional[str] = None,
    limit: int = 10
) -> Dict[str, Any]:
    """List recent scans."""
    try:
        # In production, query from database
        # For now, return mock data
        return {
            "scans": [],
            "total": 0,
            "filters": {
                "status": status,
                "framework": framework,
                "limit": limit
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/scans/{scan_id}")
async def cancel_scan(scan_id: str, request: Request) -> Dict[str, Any]:
    """Cancel running scan."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Cancel task
        cancelled = await agent_runtime.cancel_task(scan_id)
        
        if not cancelled:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found or cannot be cancelled")
        
        return {
            "scan_id": scan_id,
            "status": "cancelled",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))
