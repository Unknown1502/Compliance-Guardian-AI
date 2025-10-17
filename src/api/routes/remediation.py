"""Remediation endpoints."""

from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime

from ...utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


class RemediationRequest(BaseModel):
    """Remediation request model."""
    violation_ids: List[str] = Field(..., description="Violation IDs to remediate")
    auto_approve: bool = Field(default=False, description="Auto-approve remediation")
    dry_run: bool = Field(default=False, description="Dry run mode")


class PIIMaskingRequest(BaseModel):
    """PII masking request model."""
    data: Dict[str, Any] = Field(..., description="Data to mask")
    strategy: Optional[str] = Field(None, description="Masking strategy")


class EncryptionRequest(BaseModel):
    """Encryption enforcement request model."""
    resource_type: str = Field(..., description="Resource type (s3, ebs, rds, dynamodb)")
    resource_ids: List[str] = Field(..., description="Resource IDs to encrypt")


class ConsentRequest(BaseModel):
    """Consent management request model."""
    user_id: str = Field(..., description="User ID")
    purpose: str = Field(..., description="Processing purpose")
    scope: Optional[List[str]] = Field(None, description="Consent scope")


@router.post("/remediation/execute")
async def execute_remediation(
    remediation_request: RemediationRequest,
    request: Request,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """Execute automated remediation."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to remediation agent
        task_id = await agent_runtime.submit_task(
            agent_id="remediation_agent",
            task_type="remediate_violations",
            parameters={
                "violation_ids": remediation_request.violation_ids,
                "auto_approve": remediation_request.auto_approve,
                "dry_run": remediation_request.dry_run
            }
        )
        
        return {
            "remediation_id": task_id,
            "violation_count": len(remediation_request.violation_ids),
            "status": "started",
            "dry_run": remediation_request.dry_run,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to execute remediation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/remediation/{remediation_id}")
async def get_remediation_status(remediation_id: str, request: Request) -> Dict[str, Any]:
    """Get remediation status."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        status = await agent_runtime.get_task_status(remediation_id)
        
        if not status:
            raise HTTPException(status_code=404, detail=f"Remediation {remediation_id} not found")
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get remediation status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/remediation/pii/mask")
async def mask_pii(
    masking_request: PIIMaskingRequest,
    request: Request
) -> Dict[str, Any]:
    """Mask PII in data."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to remediation agent
        task_id = await agent_runtime.submit_task(
            agent_id="remediation_agent",
            task_type="mask_pii",
            parameters={
                "data": masking_request.data,
                "strategy": masking_request.strategy
            }
        )
        
        # For synchronous masking, wait for result
        results = await agent_runtime.get_task_status(task_id)
        
        return {
            "masked_data": results.get("result", {}).get("masked_data", {}),
            "masking_report": results.get("result", {}).get("report", {}),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to mask PII: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/remediation/encryption/enforce")
async def enforce_encryption(
    encryption_request: EncryptionRequest,
    request: Request,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """Enforce encryption on resources."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to remediation agent
        task_id = await agent_runtime.submit_task(
            agent_id="remediation_agent",
            task_type="enforce_encryption",
            parameters={
                "resource_type": encryption_request.resource_type,
                "resource_ids": encryption_request.resource_ids
            }
        )
        
        return {
            "enforcement_id": task_id,
            "resource_type": encryption_request.resource_type,
            "resource_count": len(encryption_request.resource_ids),
            "status": "started",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to enforce encryption: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/remediation/consent/grant")
async def grant_consent(consent_request: ConsentRequest, request: Request) -> Dict[str, Any]:
    """Grant user consent."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to remediation agent
        task_id = await agent_runtime.submit_task(
            agent_id="remediation_agent",
            task_type="grant_consent",
            parameters={
                "user_id": consent_request.user_id,
                "purpose": consent_request.purpose,
                "scope": consent_request.scope
            }
        )
        
        # Get result
        results = await agent_runtime.get_task_status(task_id)
        
        return {
            "consent_id": results.get("result", {}).get("consent_id"),
            "user_id": consent_request.user_id,
            "purpose": consent_request.purpose,
            "status": "granted",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to grant consent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/remediation/consent/{consent_id}")
async def withdraw_consent(consent_id: str, request: Request) -> Dict[str, Any]:
    """Withdraw user consent."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to remediation agent
        task_id = await agent_runtime.submit_task(
            agent_id="remediation_agent",
            task_type="withdraw_consent",
            parameters={
                "consent_id": consent_id
            }
        )
        
        return {
            "consent_id": consent_id,
            "status": "withdrawn",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to withdraw consent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/remediation/consent/{user_id}")
async def get_user_consents(user_id: str, request: Request) -> Dict[str, Any]:
    """Get user consents."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit to remediation agent
        task_id = await agent_runtime.submit_task(
            agent_id="remediation_agent",
            task_type="get_user_consents",
            parameters={
                "user_id": user_id
            }
        )
        
        # Get result
        results = await agent_runtime.get_task_status(task_id)
        
        return {
            "user_id": user_id,
            "consents": results.get("result", {}).get("consents", []),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get user consents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/remediation/rollback/{remediation_id}")
async def rollback_remediation(remediation_id: str, request: Request) -> Dict[str, Any]:
    """Rollback remediation actions."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        # Submit rollback task
        task_id = await agent_runtime.submit_task(
            agent_id="remediation_agent",
            task_type="rollback",
            parameters={
                "remediation_id": remediation_id
            }
        )
        
        return {
            "rollback_id": task_id,
            "remediation_id": remediation_id,
            "status": "started",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to rollback remediation: {e}")
        raise HTTPException(status_code=500, detail=str(e))
