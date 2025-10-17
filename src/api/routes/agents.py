"""Agent management endpoints."""

from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime

from ...utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()


class AgentTaskRequest(BaseModel):
    """Agent task request model."""
    task_type: str = Field(..., description="Type of task")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Task parameters")
    priority: int = Field(default=5, ge=1, le=10, description="Task priority (1-10)")


class AgentMessageRequest(BaseModel):
    """Agent message request model."""
    target_agent_id: str = Field(..., description="Target agent ID")
    message_type: str = Field(..., description="Message type")
    content: Dict[str, Any] = Field(..., description="Message content")


@router.get("/agents")
async def list_agents(request: Request) -> Dict[str, Any]:
    """List all available agents."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        agents_info = {}
        for agent_id, agent in agent_runtime.agents.items():
            agents_info[agent_id] = {
                "agent_id": agent_id,
                "type": agent.__class__.__name__,
                "description": agent.description,
                "capabilities": agent.capabilities,
                "status": await agent.health_check()
            }
        
        return {
            "agents": agents_info,
            "total": len(agents_info)
        }
        
    except Exception as e:
        logger.error(f"Failed to list agents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str, request: Request) -> Dict[str, Any]:
    """Get specific agent details."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        if agent_id not in agent_runtime.agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        agent = agent_runtime.agents[agent_id]
        
        return {
            "agent_id": agent_id,
            "type": agent.__class__.__name__,
            "description": agent.description,
            "capabilities": agent.capabilities,
            "status": await agent.health_check(),
            "memory_entries": len(agent.memory_entries)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agents/{agent_id}/tasks")
async def submit_task(
    agent_id: str,
    task: AgentTaskRequest,
    request: Request,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """Submit task to specific agent."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        if agent_id not in agent_runtime.agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        # Submit task
        task_id = await agent_runtime.submit_task(
            agent_id=agent_id,
            task_type=task.task_type,
            parameters=task.parameters,
            priority=task.priority
        )
        
        return {
            "task_id": task_id,
            "agent_id": agent_id,
            "status": "submitted",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit task to agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{agent_id}/tasks/{task_id}")
async def get_task_status(agent_id: str, task_id: str, request: Request) -> Dict[str, Any]:
    """Get task status."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        status = await agent_runtime.get_task_status(task_id)
        
        if not status:
            raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get task status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agents/{agent_id}/messages")
async def send_message(
    agent_id: str,
    message: AgentMessageRequest,
    request: Request
) -> Dict[str, Any]:
    """Send message to agent."""
    try:
        agent_runtime = request.app.state.agent_runtime
        gateway = agent_runtime.gateway
        
        # Send message through gateway
        response = await gateway.send_message(
            from_agent=agent_id,
            to_agent=message.target_agent_id,
            message_type=message.message_type,
            content=message.content
        )
        
        return {
            "status": "sent",
            "response": response,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to send message: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{agent_id}/memory")
async def get_agent_memory(
    agent_id: str,
    request: Request,
    limit: int = 10
) -> Dict[str, Any]:
    """Get agent memory entries."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        if agent_id not in agent_runtime.agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        agent = agent_runtime.agents[agent_id]
        
        # Get recent memory entries
        entries = agent.memory_entries[-limit:] if hasattr(agent, 'memory_entries') else []
        
        return {
            "agent_id": agent_id,
            "memory_entries": entries,
            "total": len(agent.memory_entries) if hasattr(agent, 'memory_entries') else 0
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get agent memory: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agents/{agent_id}/reset")
async def reset_agent(agent_id: str, request: Request) -> Dict[str, Any]:
    """Reset agent state."""
    try:
        agent_runtime = request.app.state.agent_runtime
        
        if agent_id not in agent_runtime.agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
        
        agent = agent_runtime.agents[agent_id]
        
        # Reset agent state
        agent.state = {"initialized": True}
        if hasattr(agent, 'memory_entries'):
            agent.memory_entries = []
        
        logger.info(f"Reset agent {agent_id}")
        
        return {
            "agent_id": agent_id,
            "status": "reset",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reset agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))
