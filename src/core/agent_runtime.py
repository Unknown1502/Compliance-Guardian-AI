"""Agent runtime implementation using AWS Bedrock AgentCore."""

import asyncio
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Callable
from enum import Enum
from dataclasses import dataclass, field

import boto3
from pydantic import BaseModel, Field

from ..utils.config import get_config
from ..utils.logger import get_logger
from .agent_gateway import AgentGateway
from .agent_memory import AgentMemory
from .agent_identity import AgentIdentity
from .observability import ObservabilityManager

logger = get_logger(__name__)


class AgentStatus(Enum):
    """Agent execution status."""
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class TaskPriority(Enum):
    """Task priority levels."""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4


@dataclass
class AgentTask:
    """Represents a task for agent execution."""
    
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    task_type: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    max_retries: int = 3
    retry_count: int = 0
    timeout_seconds: int = 300
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    status: AgentStatus = AgentStatus.INITIALIZING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)


class AgentExecutor:
    """Executes individual agents with proper lifecycle management."""
    
    def __init__(
        self,
        agent_id: str,
        agent_class: type,
        config: Dict[str, Any],
        memory: AgentMemory,
        gateway: AgentGateway,
        identity: AgentIdentity,
        observability: ObservabilityManager
    ):
        self.agent_id = agent_id
        self.agent_class = agent_class
        self.config = config
        self.memory = memory
        self.gateway = gateway
        self.identity = identity
        self.observability = observability
        self.agent_instance = None
        self.status = AgentStatus.INITIALIZING
        
    async def initialize(self) -> None:
        """Initialize the agent instance."""
        try:
            self.agent_instance = self.agent_class(
                agent_id=self.agent_id,
                config=self.config,
                memory=self.memory,
                gateway=self.gateway,
                identity=self.identity,
                observability=self.observability
            )
            
            await self.agent_instance.initialize()
            self.status = AgentStatus.READY
            
            logger.info(f"Agent {self.agent_id} initialized successfully")
            
        except Exception as e:
            self.status = AgentStatus.FAILED
            logger.error(f"Failed to initialize agent {self.agent_id}: {e}")
            raise
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute a task with the agent."""
        task.started_at = time.time()
        task.status = AgentStatus.RUNNING
        
        try:
            # Record task start
            await self.observability.record_agent_task_start(
                agent_id=self.agent_id,
                task_id=task.task_id,
                task_type=task.task_type
            )
            
            # Execute the task
            result = await asyncio.wait_for(
                self.agent_instance.execute_task(task),
                timeout=task.timeout_seconds
            )
            
            task.result = result
            task.status = AgentStatus.COMPLETED
            task.completed_at = time.time()
            
            # Record task completion
            await self.observability.record_agent_task_completion(
                agent_id=self.agent_id,
                task_id=task.task_id,
                result=result,
                duration=task.completed_at - task.started_at
            )
            
            logger.info(
                f"Task {task.task_id} completed successfully",
                extra={
                    "agent_id": self.agent_id,
                    "task_type": task.task_type,
                    "duration": task.completed_at - task.started_at
                }
            )
            
            return result
            
        except asyncio.TimeoutError:
            task.status = AgentStatus.FAILED
            task.error = f"Task timed out after {task.timeout_seconds} seconds"
            logger.error(f"Task {task.task_id} timed out")
            raise
            
        except Exception as e:
            task.status = AgentStatus.FAILED
            task.error = str(e)
            
            # Record task failure
            await self.observability.record_agent_task_failure(
                agent_id=self.agent_id,
                task_id=task.task_id,
                error=str(e)
            )
            
            logger.error(f"Task {task.task_id} failed: {e}")
            raise


class AgentRuntime:
    """
    Core agent runtime using AWS Bedrock AgentCore primitives.
    
    Provides:
    - Multi-agent orchestration
    - Task scheduling and execution
    - Load balancing
    - Error handling and recovery
    - Performance monitoring
    """
    
    def __init__(self):
        self.config = get_config()
        self.agents: Dict[str, AgentExecutor] = {}
        self.task_queue: List[AgentTask] = []
        self.running_tasks: Dict[str, AgentTask] = {}
        self.completed_tasks: Dict[str, AgentTask] = {}
        self.max_concurrent_tasks = self.config.get("runtime.max_concurrent_tasks", 10)
        self.is_running = False
        
        # Initialize core components
        self.memory = AgentMemory()
        self.gateway = AgentGateway()
        self.identity = AgentIdentity()
        self.observability = ObservabilityManager()
        
    async def initialize(self) -> None:
        """Initialize the runtime and all core components."""
        try:
            await self.memory.initialize()
            await self.gateway.initialize()
            await self.identity.initialize()
            await self.observability.initialize()
            
            logger.info("Agent runtime initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize agent runtime: {e}")
            raise
    
    async def register_agent(
        self,
        agent_id: str,
        agent_class: type,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        """Register a new agent with the runtime."""
        try:
            agent_config = config or {}
            
            executor = AgentExecutor(
                agent_id=agent_id,
                agent_class=agent_class,
                config=agent_config,
                memory=self.memory,
                gateway=self.gateway,
                identity=self.identity,
                observability=self.observability
            )
            
            await executor.initialize()
            self.agents[agent_id] = executor
            
            logger.info(f"Agent {agent_id} registered successfully")
            
        except Exception as e:
            logger.error(f"Failed to register agent {agent_id}: {e}")
            raise
    
    async def submit_task(
        self,
        agent_id: str,
        task_type: str,
        payload: Dict[str, Any],
        priority: TaskPriority = TaskPriority.NORMAL,
        dependencies: Optional[List[str]] = None,
        **kwargs
    ) -> str:
        """Submit a task for execution."""
        if agent_id not in self.agents:
            raise ValueError(f"Agent {agent_id} not registered")
        
        task = AgentTask(
            agent_id=agent_id,
            task_type=task_type,
            payload=payload,
            priority=priority,
            dependencies=dependencies or [],
            **kwargs
        )
        
        # Insert task based on priority
        self._insert_task_by_priority(task)
        
        logger.info(
            f"Task {task.task_id} submitted for agent {agent_id}",
            extra={
                "task_type": task_type,
                "priority": priority.name
            }
        )
        
        return task.task_id
    
    def _insert_task_by_priority(self, task: AgentTask) -> None:
        """Insert task in queue based on priority."""
        inserted = False
        for i, existing_task in enumerate(self.task_queue):
            if task.priority.value < existing_task.priority.value:
                self.task_queue.insert(i, task)
                inserted = True
                break
        
        if not inserted:
            self.task_queue.append(task)
    
    async def start(self) -> None:
        """Start the runtime task processing loop."""
        self.is_running = True
        logger.info("Agent runtime started")
        
        while self.is_running:
            try:
                await self._process_tasks()
                await asyncio.sleep(0.1)  # Small delay to prevent busy waiting
                
            except Exception as e:
                logger.error(f"Error in runtime loop: {e}")
                await asyncio.sleep(1)  # Longer delay on error
    
    async def stop(self) -> None:
        """Stop the runtime and clean up resources."""
        self.is_running = False
        
        # Wait for running tasks to complete
        if self.running_tasks:
            logger.info(f"Waiting for {len(self.running_tasks)} tasks to complete")
            await asyncio.sleep(5)  # Grace period
        
        logger.info("Agent runtime stopped")
    
    async def _process_tasks(self) -> None:
        """Process tasks from the queue."""
        # Remove completed running tasks
        completed_task_ids = []
        for task_id, task in self.running_tasks.items():
            if task.status in [AgentStatus.COMPLETED, AgentStatus.FAILED]:
                completed_task_ids.append(task_id)
                self.completed_tasks[task_id] = task
        
        for task_id in completed_task_ids:
            del self.running_tasks[task_id]
        
        # Start new tasks if we have capacity
        available_slots = self.max_concurrent_tasks - len(self.running_tasks)
        
        for _ in range(min(available_slots, len(self.task_queue))):
            if not self.task_queue:
                break
                
            task = self._get_next_ready_task()
            if task:
                await self._execute_task(task)
    
    def _get_next_ready_task(self) -> Optional[AgentTask]:
        """Get the next task that's ready to execute (dependencies met)."""
        for i, task in enumerate(self.task_queue):
            if self._are_dependencies_met(task):
                return self.task_queue.pop(i)
        return None
    
    def _are_dependencies_met(self, task: AgentTask) -> bool:
        """Check if all task dependencies are completed."""
        for dep_task_id in task.dependencies:
            if dep_task_id not in self.completed_tasks:
                return False
            
            dep_task = self.completed_tasks[dep_task_id]
            if dep_task.status != AgentStatus.COMPLETED:
                return False
        
        return True
    
    async def _execute_task(self, task: AgentTask) -> None:
        """Execute a task asynchronously."""
        self.running_tasks[task.task_id] = task
        
        try:
            agent_executor = self.agents[task.agent_id]
            
            # Execute task in background
            asyncio.create_task(
                self._safe_execute_task(agent_executor, task)
            )
            
        except Exception as e:
            task.status = AgentStatus.FAILED
            task.error = str(e)
            logger.error(f"Failed to start task {task.task_id}: {e}")
    
    async def _safe_execute_task(
        self,
        agent_executor: AgentExecutor,
        task: AgentTask
    ) -> None:
        """Safely execute a task with error handling and retries."""
        try:
            await agent_executor.execute_task(task)
            
        except Exception as e:
            task.retry_count += 1
            
            if task.retry_count <= task.max_retries:
                logger.warning(
                    f"Task {task.task_id} failed, retrying ({task.retry_count}/{task.max_retries})"
                )
                
                # Reset task status for retry
                task.status = AgentStatus.INITIALIZING
                task.started_at = None
                task.error = None
                
                # Re-queue the task
                self._insert_task_by_priority(task)
                
            else:
                task.status = AgentStatus.FAILED
                task.error = str(e)
                logger.error(f"Task {task.task_id} failed permanently after {task.retry_count} retries")
    
    async def get_task_status(self, task_id: str) -> Optional[AgentTask]:
        """Get the status of a specific task."""
        # Check running tasks
        if task_id in self.running_tasks:
            return self.running_tasks[task_id]
        
        # Check completed tasks
        if task_id in self.completed_tasks:
            return self.completed_tasks[task_id]
        
        # Check queued tasks
        for task in self.task_queue:
            if task.task_id == task_id:
                return task
        
        return None
    
    async def wait_for_task(
        self,
        task_id: str,
        timeout: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """Wait for a task to complete and return its result."""
        start_time = time.time()
        
        while True:
            task = await self.get_task_status(task_id)
            
            if not task:
                raise ValueError(f"Task {task_id} not found")
            
            if task.status == AgentStatus.COMPLETED:
                return task.result
            
            if task.status == AgentStatus.FAILED:
                raise RuntimeError(f"Task {task_id} failed: {task.error}")
            
            if timeout and (time.time() - start_time) > timeout:
                raise TimeoutError(f"Task {task_id} did not complete within {timeout} seconds")
            
            await asyncio.sleep(0.1)
    
    def get_runtime_metrics(self) -> Dict[str, Any]:
        """Get runtime performance metrics."""
        return {
            "registered_agents": len(self.agents),
            "queued_tasks": len(self.task_queue),
            "running_tasks": len(self.running_tasks),
            "completed_tasks": len(self.completed_tasks),
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "is_running": self.is_running,
            "agent_status": {
                agent_id: executor.status.value 
                for agent_id, executor in self.agents.items()
            }
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on the runtime."""
        try:
            metrics = self.get_runtime_metrics()
            
            # Check if any agents are in failed state
            failed_agents = [
                agent_id for agent_id, executor in self.agents.items()
                if executor.status == AgentStatus.FAILED
            ]
            
            # Check task queue size
            queue_size_warning = len(self.task_queue) > 100
            
            status = "healthy"
            if failed_agents:
                status = "degraded"
            if not self.is_running:
                status = "stopped"
            
            return {
                "status": status,
                "metrics": metrics,
                "warnings": {
                    "failed_agents": failed_agents,
                    "large_queue": queue_size_warning
                }
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }