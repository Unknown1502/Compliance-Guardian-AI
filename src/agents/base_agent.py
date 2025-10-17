"""Base agent class with common functionality for all agents."""

import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from ..core.bedrock_client import BedrockClient, BedrockResponse
from ..core.agent_memory import AgentMemory
from ..core.agent_gateway import AgentGateway, MessageType, MessagePriority
from ..core.agent_identity import AgentIdentityManager, Permission
from ..core.observability import ObservabilityManager, LogLevel
from ..utils.config import get_config
from ..utils.logger import get_logger
from ..utils.validators import validate_agent_id, validate_task_payload

logger = get_logger(__name__)


class AgentStatus(Enum):
    """Agent operational status."""
    INITIALIZING = "initializing"
    READY = "ready"
    BUSY = "busy"
    ERROR = "error"
    SHUTDOWN = "shutdown"


class AgentCapability(Enum):
    """Agent capabilities for service discovery."""
    COMPLIANCE_SCANNING = "compliance_scanning"
    VIOLATION_REMEDIATION = "violation_remediation"
    AUDIT_REPORTING = "audit_reporting"
    RISK_ASSESSMENT = "risk_assessment"
    ORCHESTRATION = "orchestration"
    EXPLAINABILITY = "explainability"
    POLICY_INTERPRETATION = "policy_interpretation"
    DATA_ANALYSIS = "data_analysis"


@dataclass
class AgentTask:
    """Represents a task for agent execution."""
    
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_type: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5  # 1-10, lower is higher priority
    timeout_seconds: int = 300
    max_retries: int = 3
    retry_count: int = 0
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    requester_agent: Optional[str] = None
    correlation_id: Optional[str] = None


@dataclass
class AgentMetrics:
    """Agent performance metrics."""
    
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_execution_time: float = 0.0
    average_execution_time: float = 0.0
    uptime_seconds: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    last_heartbeat: float = field(default_factory=time.time)


class BaseAgent(ABC):
    """
    Base class for all Compliance Guardian AI agents.
    
    Provides common functionality:
    - Bedrock LLM integration
    - Memory management
    - Inter-agent communication
    - Task execution framework
    - Observability and monitoring
    - Security and authentication
    """
    
    def __init__(
        self,
        agent_id: str,
        config: Dict[str, Any],
        memory: AgentMemory,
        gateway: AgentGateway,
        identity: AgentIdentityManager,
        observability: ObservabilityManager
    ):
        """
        Initialize base agent.
        
        Args:
            agent_id: Unique agent identifier
            config: Agent configuration
            memory: Memory management system
            gateway: Communication gateway
            identity: Identity management system
            observability: Observability system
        """
        # Validate agent ID
        validate_agent_id(agent_id)
        
        self.agent_id = agent_id
        self.config = config
        self.memory = memory
        self.gateway = gateway
        self.identity = identity
        self.observability = observability
        
        # Core components
        self.bedrock_client = BedrockClient()
        
        # Agent state
        self.status = AgentStatus.INITIALIZING
        self.capabilities: Set[AgentCapability] = set()
        self.metrics = AgentMetrics()
        self.session_id = str(uuid.uuid4())
        
        # Task management
        self.current_task: Optional[AgentTask] = None
        self.task_queue: List[AgentTask] = []
        
        # Configuration
        self.max_concurrent_tasks = config.get("max_concurrent_tasks", 1)
        self.heartbeat_interval = config.get("heartbeat_interval", 30)
        
        # Initialize derived class capabilities
        self._initialize_capabilities()
        
    @abstractmethod
    def _initialize_capabilities(self) -> None:
        """Initialize agent-specific capabilities."""
        pass
    
    @abstractmethod
    async def _execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """
        Execute agent-specific task.
        
        Args:
            task: Task to execute
            
        Returns:
            Task execution result
        """
        pass
    
    async def initialize(self) -> None:
        """Initialize the agent and all dependencies."""
        try:
            logger.info(f"Initializing agent {self.agent_id}")
            
            # Authenticate with identity system
            token = await self.identity.authenticate_agent(self.agent_id)
            if not token:
                raise RuntimeError(f"Failed to authenticate agent {self.agent_id}")
            
            # Register with gateway
            await self.gateway.register_agent(
                agent_id=self.agent_id,
                agent_endpoint=f"agent://{self.agent_id}",
                agent_capabilities=[cap.value for cap in self.capabilities],
                metadata={
                    "agent_type": self.__class__.__name__,
                    "session_id": self.session_id,
                    "config": self.config
                }
            )
            
            # Register message handler
            await self.gateway.register_message_handler(
                self.agent_id,
                self._handle_message
            )
            
            # Store initialization in memory
            await self.memory.store_memory(
                agent_id=self.agent_id,
                content={
                    "event": "agent_initialized",
                    "capabilities": [cap.value for cap in self.capabilities],
                    "config": self.config
                },
                memory_type="context",
                session_id=self.session_id,
                importance_score=0.8
            )
            
            self.status = AgentStatus.READY
            self.metrics.last_heartbeat = time.time()
            
            await self.observability.log_event(
                level=LogLevel.INFO,
                message=f"Agent {self.agent_id} initialized successfully",
                agent_id=self.agent_id,
                metadata={
                    "capabilities": [cap.value for cap in self.capabilities],
                    "session_id": self.session_id
                }
            )
            
            logger.info(f"Agent {self.agent_id} initialized successfully")
            
        except Exception as e:
            self.status = AgentStatus.ERROR
            logger.error(f"Failed to initialize agent {self.agent_id}: {e}")
            raise
    
    async def shutdown(self) -> None:
        """Shutdown the agent gracefully."""
        try:
            logger.info(f"Shutting down agent {self.agent_id}")
            
            self.status = AgentStatus.SHUTDOWN
            
            # Complete current task if any
            if self.current_task:
                logger.warning(f"Agent {self.agent_id} shutting down with active task")
            
            # Unregister from gateway
            await self.gateway.unregister_agent(self.agent_id)
            
            # Store shutdown event
            await self.memory.store_memory(
                agent_id=self.agent_id,
                content={
                    "event": "agent_shutdown",
                    "metrics": self.metrics.__dict__,
                    "uptime": time.time() - self.metrics.last_heartbeat
                },
                memory_type="context",
                session_id=self.session_id,
                importance_score=0.6
            )
            
            await self.observability.log_event(
                level=LogLevel.INFO,
                message=f"Agent {self.agent_id} shutdown completed",
                agent_id=self.agent_id
            )
            
        except Exception as e:
            logger.error(f"Error during agent shutdown: {e}")
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """
        Execute a task with full lifecycle management.
        
        Args:
            task: Task to execute
            
        Returns:
            Task execution result
        """
        try:
            # Validate task
            validate_task_payload(task.payload)
            
            # Check permissions
            required_permission = self._get_required_permission(task.task_type)
            if required_permission:
                has_permission = await self.identity.check_permission(
                    self.agent_id,
                    required_permission
                )
                if not has_permission:
                    raise PermissionError(f"Agent {self.agent_id} lacks permission for {task.task_type}")
            
            # Update task status
            task.started_at = time.time()
            task.status = "running"
            self.current_task = task
            self.status = AgentStatus.BUSY
            
            # Record task start
            trace_id = await self.observability.record_agent_task_start(
                agent_id=self.agent_id,
                task_id=task.task_id,
                task_type=task.task_type,
                metadata={
                    "requester": task.requester_agent,
                    "correlation_id": task.correlation_id
                }
            )
            
            # Store task in memory
            await self.memory.store_memory(
                agent_id=self.agent_id,
                content={
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "status": "started",
                    "payload": task.payload
                },
                memory_type="working",
                session_id=self.session_id,
                importance_score=0.7
            )
            
            # Execute task with timeout
            result = await asyncio.wait_for(
                self._execute_task(task),
                timeout=task.timeout_seconds
            )
            
            # Update metrics
            execution_time = time.time() - task.started_at
            self.metrics.tasks_completed += 1
            self.metrics.total_execution_time += execution_time
            self.metrics.average_execution_time = (
                self.metrics.total_execution_time / 
                max(1, self.metrics.tasks_completed)
            )
            
            # Update task status
            task.completed_at = time.time()
            task.status = "completed"
            task.result = result
            
            # Record task completion
            await self.observability.record_agent_task_completion(
                agent_id=self.agent_id,
                task_id=task.task_id,
                result=result,
                duration=execution_time,
                trace_id=trace_id
            )
            
            # Store result in memory
            await self.memory.store_memory(
                agent_id=self.agent_id,
                content={
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "status": "completed",
                    "result": result,
                    "execution_time": execution_time
                },
                memory_type="working",
                session_id=self.session_id,
                importance_score=0.8
            )
            
            self.current_task = None
            self.status = AgentStatus.READY
            
            return result
            
        except asyncio.TimeoutError:
            self.metrics.tasks_failed += 1
            task.status = "timeout"
            task.error = f"Task timed out after {task.timeout_seconds} seconds"
            
            await self.observability.record_agent_task_failure(
                agent_id=self.agent_id,
                task_id=task.task_id,
                error=task.error
            )
            
            self.current_task = None
            self.status = AgentStatus.READY
            
            raise
            
        except Exception as e:
            self.metrics.tasks_failed += 1
            task.status = "failed"
            task.error = str(e)
            
            await self.observability.record_agent_task_failure(
                agent_id=self.agent_id,
                task_id=task.task_id,
                error=str(e)
            )
            
            self.current_task = None
            self.status = AgentStatus.READY
            
            raise
    
    def _get_required_permission(self, task_type: str) -> Optional[Permission]:
        """Get required permission for a task type."""
        permission_map = {
            "compliance_scan": Permission.EXECUTE_SCAN,
            "violation_remediation": Permission.APPLY_REMEDIATION,
            "audit_report": Permission.GENERATE_REPORT,
            "risk_assessment": Permission.VIEW_AUDIT_LOGS,
            "memory_read": Permission.READ_MEMORY,
            "memory_write": Permission.WRITE_MEMORY
        }
        
        return permission_map.get(task_type)
    
    async def _handle_message(self, message) -> None:
        """Handle incoming messages from other agents."""
        try:
            if message.message_type == MessageType.REQUEST:
                # Convert message to task
                task = AgentTask(
                    task_id=message.correlation_id or str(uuid.uuid4()),
                    task_type=message.payload.get("task_type", "unknown"),
                    payload=message.payload.get("data", {}),
                    requester_agent=message.from_agent,
                    correlation_id=message.correlation_id
                )
                
                # Execute task
                result = await self.execute_task(task)
                
                # Send response
                await self.gateway.send_message(
                    from_agent=self.agent_id,
                    to_agent=message.from_agent,
                    message_type=MessageType.RESPONSE,
                    payload={"result": result, "status": "success"},
                    correlation_id=message.correlation_id
                )
                
            elif message.message_type == MessageType.NOTIFICATION:
                # Handle notification
                await self._handle_notification(message.payload)
                
        except Exception as e:
            logger.error(f"Failed to handle message: {e}")
            
            # Send error response if it was a request
            if message.message_type == MessageType.REQUEST:
                await self.gateway.send_message(
                    from_agent=self.agent_id,
                    to_agent=message.from_agent,
                    message_type=MessageType.ERROR,
                    payload={"error": str(e), "status": "failed"},
                    correlation_id=message.correlation_id
                )
    
    async def _handle_notification(self, payload: Dict[str, Any]) -> None:
        """Handle notification messages."""
        notification_type = payload.get("type", "unknown")
        
        logger.info(
            f"Agent {self.agent_id} received notification: {notification_type}",
            extra={"payload": payload}
        )
        
        # Store notification in memory
        await self.memory.store_memory(
            agent_id=self.agent_id,
            content={
                "event": "notification_received",
                "type": notification_type,
                "payload": payload
            },
            memory_type="context",
            session_id=self.session_id,
            importance_score=0.4
        )
    
    async def send_request(
        self,
        target_agent: str,
        task_type: str,
        data: Dict[str, Any],
        timeout_seconds: int = 30
    ) -> Dict[str, Any]:
        """
        Send a request to another agent and wait for response.
        
        Args:
            target_agent: Target agent ID
            task_type: Type of task to request
            data: Task data
            timeout_seconds: Request timeout
            
        Returns:
            Response from target agent
        """
        try:
            response = await self.gateway.send_request_response(
                from_agent=self.agent_id,
                to_agent=target_agent,
                request_payload={
                    "task_type": task_type,
                    "data": data
                },
                timeout_seconds=timeout_seconds
            )
            
            return response.get("result", {})
            
        except Exception as e:
            logger.error(f"Failed to send request to {target_agent}: {e}")
            raise
    
    async def broadcast_notification(
        self,
        notification_type: str,
        data: Dict[str, Any],
        target_capabilities: Optional[List[str]] = None
    ) -> None:
        """
        Broadcast a notification to other agents.
        
        Args:
            notification_type: Type of notification
            data: Notification data
            target_capabilities: Target agents with specific capabilities
        """
        try:
            await self.gateway.broadcast_message(
                from_agent=self.agent_id,
                payload={
                    "type": notification_type,
                    "data": data,
                    "timestamp": time.time()
                },
                target_capabilities=target_capabilities
            )
            
        except Exception as e:
            logger.error(f"Failed to broadcast notification: {e}")
            raise
    
    async def invoke_llm(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> BedrockResponse:
        """
        Invoke Bedrock LLM with observability tracking.
        
        Args:
            prompt: User prompt
            system_prompt: System prompt
            tools: Available tools
            **kwargs: Additional LLM parameters
            
        Returns:
            LLM response
        """
        try:
            start_time = time.time()
            
            response = await self.bedrock_client.invoke_model(
                prompt=prompt,
                system_prompt=system_prompt,
                tools=tools,
                **kwargs
            )
            
            duration = time.time() - start_time
            
            # Record metrics
            await self.observability.record_bedrock_request(
                model_id=self.bedrock_client.config.model_id,
                agent_id=self.agent_id,
                duration=duration,
                input_tokens=response.usage.get("input_tokens", 0),
                output_tokens=response.usage.get("output_tokens", 0),
                status="success"
            )
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            
            await self.observability.record_bedrock_request(
                model_id=self.bedrock_client.config.model_id,
                agent_id=self.agent_id,
                duration=duration,
                input_tokens=0,
                output_tokens=0,
                status="failed"
            )
            
            raise
    
    async def store_memory(
        self,
        content: Dict[str, Any],
        memory_type: str = "working",
        importance_score: float = 0.5,
        tags: Optional[List[str]] = None
    ) -> str:
        """Store content in agent memory."""
        return await self.memory.store_memory(
            agent_id=self.agent_id,
            content=content,
            memory_type=memory_type,
            session_id=self.session_id,
            importance_score=importance_score,
            tags=tags or []
        )
    
    async def retrieve_memories(
        self,
        memory_type: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List:
        """Retrieve agent memories."""
        return await self.memory.retrieve_agent_memories(
            agent_id=self.agent_id,
            memory_type=memory_type,
            limit=limit
        )
    
    async def search_memories(
        self,
        query: str,
        limit: int = 10
    ) -> List:
        """Search agent memories."""
        return await self.memory.search_memories(
            query=query,
            agent_id=self.agent_id,
            limit=limit
        )
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        return {
            "agent_id": self.agent_id,
            "status": self.status.value,
            "capabilities": [cap.value for cap in self.capabilities],
            "current_task": self.current_task.task_id if self.current_task else None,
            "metrics": self.metrics.__dict__,
            "session_id": self.session_id,
            "uptime": time.time() - self.metrics.last_heartbeat
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Perform agent health check."""
        try:
            # Update heartbeat
            self.metrics.last_heartbeat = time.time()
            
            # Basic health indicators
            is_healthy = (
                self.status in [AgentStatus.READY, AgentStatus.BUSY] and
                self.metrics.last_heartbeat > time.time() - 60  # Active within last minute
            )
            
            return {
                "status": "healthy" if is_healthy else "unhealthy",
                "agent_id": self.agent_id,
                "agent_status": self.status.value,
                "last_heartbeat": self.metrics.last_heartbeat,
                "uptime": time.time() - self.metrics.last_heartbeat,
                "task_success_rate": (
                    self.metrics.tasks_completed / 
                    max(1, self.metrics.tasks_completed + self.metrics.tasks_failed)
                ) * 100
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "agent_id": self.agent_id
            }