"""Core module initialization for Compliance Guardian AI."""

__version__ = "1.0.0"
__author__ = "Compliance Guardian Team"
__email__ = "contact@compliance-guardian.ai"

from .bedrock_client import BedrockClient
from .agent_runtime import AgentRuntime
from .agent_memory import AgentMemory
from .agent_gateway import AgentGateway
from .agent_identity import AgentIdentity
from .observability import ObservabilityManager

__all__ = [
    "BedrockClient",
    "AgentRuntime", 
    "AgentMemory",
    "AgentGateway",
    "AgentIdentity",
    "ObservabilityManager",
]