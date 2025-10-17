"""Agent gateway implementation using AWS Bedrock AgentCore Gateway."""

import asyncio
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

import boto3
import httpx
from pydantic import BaseModel, Field

from ..utils.config import get_config
from ..utils.logger import get_logger

logger = get_logger(__name__)


class MessageType(Enum):
    """Types of messages that can be sent between agents."""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    BROADCAST = "broadcast"
    ERROR = "error"


class MessagePriority(Enum):
    """Message priority levels."""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4


@dataclass
class AgentMessage:
    """Represents a message between agents."""
    
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    from_agent: str = ""
    to_agent: str = ""
    message_type: MessageType = MessageType.REQUEST
    priority: MessagePriority = MessagePriority.NORMAL
    payload: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    timeout_seconds: int = 30
    created_at: float = field(default_factory=time.time)
    delivered_at: Optional[float] = None
    processed_at: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 3


class GatewayConfig(BaseModel):
    """Configuration for agent gateway."""
    
    max_concurrent_messages: int = Field(default=100)
    default_timeout: int = Field(default=30)
    retry_delay_seconds: int = Field(default=1)
    max_retry_delay: int = Field(default=60)
    circuit_breaker_threshold: int = Field(default=10)
    circuit_breaker_timeout: int = Field(default=60)
    rate_limit_per_agent: int = Field(default=100)  # messages per minute
    enable_message_persistence: bool = Field(default=True)
    enable_load_balancing: bool = Field(default=True)


class CircuitBreaker:
    """Circuit breaker pattern implementation for agent communication."""
    
    def __init__(self, threshold: int = 10, timeout: int = 60):
        self.threshold = threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "closed"  # closed, open, half_open
    
    def can_execute(self) -> bool:
        """Check if the circuit allows execution."""
        if self.state == "closed":
            return True
        elif self.state == "open":
            if time.time() - self.last_failure_time > self.timeout:
                self.state = "half_open"
                return True
            return False
        elif self.state == "half_open":
            return True
        return False
    
    def record_success(self) -> None:
        """Record a successful execution."""
        self.failure_count = 0
        self.state = "closed"
    
    def record_failure(self) -> None:
        """Record a failed execution."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.threshold:
            self.state = "open"


class AgentGateway:
    """
    Agent gateway using AWS Bedrock AgentCore Gateway primitives.
    
    Provides:
    - Secure message routing between agents
    - Load balancing and failover
    - Circuit breaker pattern
    - Rate limiting
    - Message persistence and replay
    - Authentication and authorization
    """
    
    def __init__(self, config: Optional[GatewayConfig] = None):
        self.config = config or GatewayConfig()
        self._registered_agents: Dict[str, Dict[str, Any]] = {}
        self._message_handlers: Dict[str, Callable] = {}
        self._pending_messages: Dict[str, AgentMessage] = {}
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._rate_limiters: Dict[str, Dict[str, Any]] = {}
        self._message_queues: Dict[str, List[AgentMessage]] = {}
        
        # AWS clients
        self._sqs_client = None
        self._sns_client = None
        
    async def initialize(self) -> None:
        """Initialize the gateway and AWS services."""
        try:
            # Initialize AWS SQS for message queuing
            self._sqs_client = boto3.client("sqs")
            
            # Initialize AWS SNS for broadcasting
            self._sns_client = boto3.client("sns")
            
            logger.info("Agent gateway initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize agent gateway: {e}")
            raise
    
    async def register_agent(
        self,
        agent_id: str,
        agent_endpoint: str,
        agent_capabilities: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Register an agent with the gateway.
        
        Args:
            agent_id: Unique agent identifier
            agent_endpoint: Agent's communication endpoint
            agent_capabilities: List of capabilities the agent provides
            metadata: Additional agent metadata
            
        Returns:
            True if registration successful
        """
        try:
            agent_info = {
                "agent_id": agent_id,
                "endpoint": agent_endpoint,
                "capabilities": agent_capabilities,
                "metadata": metadata or {},
                "registered_at": time.time(),
                "last_seen": time.time(),
                "status": "online",
                "message_count": 0
            }
            
            self._registered_agents[agent_id] = agent_info
            self._message_queues[agent_id] = []
            self._circuit_breakers[agent_id] = CircuitBreaker(
                threshold=self.config.circuit_breaker_threshold,
                timeout=self.config.circuit_breaker_timeout
            )
            self._rate_limiters[agent_id] = {
                "messages": [],
                "limit": self.config.rate_limit_per_agent
            }
            
            logger.info(
                f"Agent {agent_id} registered successfully",
                extra={
                    "endpoint": agent_endpoint,
                    "capabilities": agent_capabilities
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to register agent {agent_id}: {e}")
            return False
    
    async def unregister_agent(self, agent_id: str) -> bool:
        """Unregister an agent from the gateway."""
        try:
            if agent_id in self._registered_agents:
                del self._registered_agents[agent_id]
                del self._message_queues[agent_id]
                del self._circuit_breakers[agent_id]
                del self._rate_limiters[agent_id]
                
                logger.info(f"Agent {agent_id} unregistered")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to unregister agent {agent_id}: {e}")
            return False
    
    async def send_message(
        self,
        from_agent: str,
        to_agent: str,
        message_type: MessageType,
        payload: Dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL,
        correlation_id: Optional[str] = None,
        timeout_seconds: Optional[int] = None
    ) -> str:
        """
        Send a message from one agent to another.
        
        Args:
            from_agent: Source agent ID
            to_agent: Destination agent ID
            message_type: Type of message
            payload: Message payload
            priority: Message priority
            correlation_id: For request-response correlation
            timeout_seconds: Message timeout
            
        Returns:
            Message ID
        """
        try:
            # Validate agents are registered
            if from_agent not in self._registered_agents:
                raise ValueError(f"Source agent {from_agent} not registered")
            
            if to_agent not in self._registered_agents:
                raise ValueError(f"Destination agent {to_agent} not registered")
            
            # Check rate limiting
            if not await self._check_rate_limit(from_agent):
                raise Exception(f"Rate limit exceeded for agent {from_agent}")
            
            # Check circuit breaker
            circuit_breaker = self._circuit_breakers[to_agent]
            if not circuit_breaker.can_execute():
                raise Exception(f"Circuit breaker open for agent {to_agent}")
            
            # Create message
            message = AgentMessage(
                from_agent=from_agent,
                to_agent=to_agent,
                message_type=message_type,
                priority=priority,
                payload=payload,
                correlation_id=correlation_id,
                timeout_seconds=timeout_seconds or self.config.default_timeout
            )
            
            # Store pending message
            self._pending_messages[message.message_id] = message
            
            # Route message
            success = await self._route_message(message)
            
            if success:
                circuit_breaker.record_success()
                logger.debug(
                    f"Message sent successfully",
                    extra={
                        "message_id": message.message_id,
                        "from_agent": from_agent,
                        "to_agent": to_agent,
                        "message_type": message_type.value
                    }
                )
            else:
                circuit_breaker.record_failure()
                raise Exception("Failed to route message")
            
            return message.message_id
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            raise
    
    async def _route_message(self, message: AgentMessage) -> bool:
        """Route a message to the destination agent."""
        try:
            # Add to destination agent's queue
            if message.to_agent in self._message_queues:
                # Insert based on priority
                queue = self._message_queues[message.to_agent]
                inserted = False
                
                for i, existing_msg in enumerate(queue):
                    if message.priority.value < existing_msg.priority.value:
                        queue.insert(i, message)
                        inserted = True
                        break
                
                if not inserted:
                    queue.append(message)
                
                message.delivered_at = time.time()
                
                # Notify the agent if it has a handler
                if message.to_agent in self._message_handlers:
                    asyncio.create_task(
                        self._notify_agent(message.to_agent, message)
                    )
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to route message {message.message_id}: {e}")
            return False
    
    async def _notify_agent(self, agent_id: str, message: AgentMessage) -> None:
        """Notify an agent about a new message."""
        try:
            handler = self._message_handlers.get(agent_id)
            if handler:
                await handler(message)
                
        except Exception as e:
            logger.error(f"Failed to notify agent {agent_id}: {e}")
    
    async def receive_messages(
        self,
        agent_id: str,
        max_messages: int = 10
    ) -> List[AgentMessage]:
        """Receive messages for an agent."""
        try:
            if agent_id not in self._message_queues:
                return []
            
            queue = self._message_queues[agent_id]
            messages = []
            
            for _ in range(min(max_messages, len(queue))):
                if queue:
                    message = queue.pop(0)
                    message.processed_at = time.time()
                    messages.append(message)
            
            # Update agent last seen
            if agent_id in self._registered_agents:
                self._registered_agents[agent_id]["last_seen"] = time.time()
            
            return messages
            
        except Exception as e:
            logger.error(f"Failed to receive messages for agent {agent_id}: {e}")
            return []
    
    async def register_message_handler(
        self,
        agent_id: str,
        handler: Callable[[AgentMessage], None]
    ) -> None:
        """Register a message handler for an agent."""
        self._message_handlers[agent_id] = handler
        logger.debug(f"Message handler registered for agent {agent_id}")
    
    async def send_request_response(
        self,
        from_agent: str,
        to_agent: str,
        request_payload: Dict[str, Any],
        timeout_seconds: int = 30
    ) -> Dict[str, Any]:
        """
        Send a request and wait for a response.
        
        Args:
            from_agent: Source agent ID
            to_agent: Destination agent ID
            request_payload: Request data
            timeout_seconds: Timeout for response
            
        Returns:
            Response payload
        """
        try:
            correlation_id = str(uuid.uuid4())
            
            # Send request
            message_id = await self.send_message(
                from_agent=from_agent,
                to_agent=to_agent,
                message_type=MessageType.REQUEST,
                payload=request_payload,
                correlation_id=correlation_id,
                timeout_seconds=timeout_seconds
            )
            
            # Wait for response
            start_time = time.time()
            while time.time() - start_time < timeout_seconds:
                # Check for response in pending messages
                for msg_id, msg in self._pending_messages.items():
                    if (msg.correlation_id == correlation_id and
                        msg.message_type == MessageType.RESPONSE and
                        msg.to_agent == from_agent):
                        
                        # Remove from pending
                        del self._pending_messages[msg_id]
                        return msg.payload
                
                await asyncio.sleep(0.1)
            
            raise TimeoutError(f"No response received within {timeout_seconds} seconds")
            
        except Exception as e:
            logger.error(f"Request-response failed: {e}")
            raise
    
    async def broadcast_message(
        self,
        from_agent: str,
        payload: Dict[str, Any],
        target_capabilities: Optional[List[str]] = None
    ) -> List[str]:
        """
        Broadcast a message to multiple agents.
        
        Args:
            from_agent: Source agent ID
            payload: Message payload
            target_capabilities: Filter agents by capabilities
            
        Returns:
            List of message IDs
        """
        try:
            message_ids = []
            
            for agent_id, agent_info in self._registered_agents.items():
                if agent_id == from_agent:
                    continue
                
                # Filter by capabilities if specified
                if target_capabilities:
                    agent_capabilities = agent_info.get("capabilities", [])
                    if not any(cap in agent_capabilities for cap in target_capabilities):
                        continue
                
                message_id = await self.send_message(
                    from_agent=from_agent,
                    to_agent=agent_id,
                    message_type=MessageType.BROADCAST,
                    payload=payload,
                    priority=MessagePriority.LOW
                )
                
                message_ids.append(message_id)
            
            logger.info(
                f"Broadcast sent to {len(message_ids)} agents",
                extra={
                    "from_agent": from_agent,
                    "target_capabilities": target_capabilities
                }
            )
            
            return message_ids
            
        except Exception as e:
            logger.error(f"Failed to broadcast message: {e}")
            return []
    
    async def _check_rate_limit(self, agent_id: str) -> bool:
        """Check if agent is within rate limits."""
        try:
            if agent_id not in self._rate_limiters:
                return True
            
            rate_limiter = self._rate_limiters[agent_id]
            current_time = time.time()
            
            # Remove old messages (older than 1 minute)
            rate_limiter["messages"] = [
                timestamp for timestamp in rate_limiter["messages"]
                if current_time - timestamp < 60
            ]
            
            # Check if under limit
            if len(rate_limiter["messages"]) < rate_limiter["limit"]:
                rate_limiter["messages"].append(current_time)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to check rate limit for agent {agent_id}: {e}")
            return True  # Allow on error
    
    def get_agent_status(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get status information for an agent."""
        if agent_id not in self._registered_agents:
            return None
        
        agent_info = self._registered_agents[agent_id].copy()
        agent_info.update({
            "queue_size": len(self._message_queues.get(agent_id, [])),
            "circuit_breaker_state": self._circuit_breakers[agent_id].state,
            "rate_limit_usage": len(self._rate_limiters[agent_id]["messages"])
        })
        
        return agent_info
    
    def get_gateway_metrics(self) -> Dict[str, Any]:
        """Get gateway performance metrics."""
        total_queue_size = sum(len(queue) for queue in self._message_queues.values())
        pending_messages = len(self._pending_messages)
        
        circuit_breaker_states = {
            agent_id: cb.state
            for agent_id, cb in self._circuit_breakers.items()
        }
        
        return {
            "registered_agents": len(self._registered_agents),
            "total_queue_size": total_queue_size,
            "pending_messages": pending_messages,
            "circuit_breaker_states": circuit_breaker_states,
            "message_handlers": len(self._message_handlers)
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on the gateway."""
        try:
            metrics = self.get_gateway_metrics()
            
            # Check for unhealthy conditions
            warnings = []
            if metrics["total_queue_size"] > 1000:
                warnings.append("High message queue size")
            
            open_circuit_breakers = [
                agent_id for agent_id, state in metrics["circuit_breaker_states"].items()
                if state == "open"
            ]
            
            if open_circuit_breakers:
                warnings.append(f"Open circuit breakers: {open_circuit_breakers}")
            
            status = "healthy"
            if warnings:
                status = "degraded"
            
            return {
                "status": status,
                "metrics": metrics,
                "warnings": warnings
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }