"""Reporting endpoints."""

from fastapi import APIRouter, Request, HTTPException, Response
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from ...utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


class ReportRequest(BaseModel):
    """Report generation request model."""
    report_type: str = Field(..., description="Report type (audit, compliance, executive)")
    framework: Optional[str] = Field(None, description="Compliance framework")
    resource_ids: List[str] = Field(default_factory=list, description="Resources to include")
    start_date: Optional[str] = Field(None, description="Start date (ISO format)")
    end_date: Optional[str] = Field(None, description="End date (ISO format)")
    format: str = Field(default="json", description="Report format (json, pdf, html)")


@router.post("/reports/generate")
async def generate_report(
    report_request: ReportRequest,
    request: Request
) -> Dict[str, Any]:
    """Generate compliance report."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to audit agent
        task_id = await agent_runtime.submit_task(
            agent_id="audit_agent",
            task_type="generate_report",
            parameters={
                "report_type": report_request.report_type,
                "framework": report_request.framework,
                "resource_ids": report_request.resource_ids,
                "start_date": report_request.start_date,
                "end_date": report_request.end_date,
                "format": report_request.format
            }
        )
        
        return {
            "report_id": task_id,
            "report_type": report_request.report_type,
            "status": "generating",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports/{report_id}")
async def get_report(report_id: str, request: Request) -> Dict[str, Any]:
    """Get generated report."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Get report from task results
        results = await agent_runtime.get_task_status(report_id)
        
        if not results:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    request: Request,
    format: str = "json"
) -> Response:
    """Download report in specified format."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        results = await agent_runtime.get_task_status(report_id)
        
        if not results:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        
        if results.get("status") != "completed":
            raise HTTPException(status_code=400, detail="Report not yet completed")
        
        report_data = results.get("result", {})
        
        if format == "json":
            content = json.dumps(report_data, indent=2)
            media_type = "application/json"
            filename = f"report_{report_id}.json"
        
        elif format == "html":
            # Convert to HTML (simplified)
            content = f"<html><body><pre>{json.dumps(report_data, indent=2)}</pre></body></html>"
            media_type = "text/html"
            filename = f"report_{report_id}.html"
        
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
        
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to download report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/reports")
async def list_reports(
    request: Request,
    report_type: Optional[str] = None,
    framework: Optional[str] = None,
    limit: int = 10
) -> Dict[str, Any]:
    """List generated reports."""
    try:
        # In production, query from database
        return {
            "reports": [],
            "total": 0,
            "filters": {
                "report_type": report_type,
                "framework": framework,
                "limit": limit
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to list reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/reports/{report_id}")
async def delete_report(report_id: str, request: Request) -> Dict[str, Any]:
    """Delete report."""
    try:
        # In production, delete from storage
        return {
            "report_id": report_id,
            "status": "deleted",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to delete report: {e}")
        raise HTTPException(status_code=500, detail=str(e))
