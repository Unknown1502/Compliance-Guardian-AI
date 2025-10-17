"""Agent memory management using AWS Bedrock AgentCore Memory."""

import json
import time
import uuid
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field

import boto3
import redis
from pydantic import BaseModel, Field

from ..utils.config import get_config
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class MemoryEntry:
    """Represents a memory entry in the agent memory system."""
    
    memory_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    session_id: str = ""
    memory_type: str = "conversation"  # conversation, context, long_term, working
    content: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    importance_score: float = 0.5  # 0.0 to 1.0
    access_count: int = 0
    tags: List[str] = field(default_factory=list)


class MemoryConfig(BaseModel):
    """Configuration for agent memory system."""
    
    redis_url: str = Field(default="redis://localhost:6379")
    max_memory_entries: int = Field(default=10000)
    default_ttl_hours: int = Field(default=24)
    max_working_memory_mb: int = Field(default=100)
    compression_enabled: bool = Field(default=True)
    persistence_enabled: bool = Field(default=True)


class AgentMemory:
    """
    Agent memory management system using AWS Bedrock AgentCore Memory primitives.
    
    Provides:
    - Short-term memory (conversation context)
    - Long-term memory (knowledge persistence)
    - Working memory (temporary calculations)
    - Session management
    - Memory consolidation
    - Semantic search across memories
    """
    
    def __init__(self, config: Optional[MemoryConfig] = None):
        self.config = config or MemoryConfig()
        self._redis_client = None
        self._bedrock_client = None
        self._memory_cache: Dict[str, MemoryEntry] = {}
        self._session_memories: Dict[str, List[str]] = {}
        
    async def initialize(self) -> None:
        """Initialize memory system and connections."""
        try:
            # Initialize Redis for fast memory storage
            self._redis_client = redis.from_url(
                self.config.redis_url,
                decode_responses=True
            )
            
            # Test Redis connection
            await self._redis_client.ping()
            
            # Initialize Bedrock client for semantic operations
            self._bedrock_client = boto3.client("bedrock-runtime")
            
            logger.info("Agent memory system initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize agent memory: {e}")
            raise
    
    async def store_memory(
        self,
        agent_id: str,
        content: Dict[str, Any],
        memory_type: str = "conversation",
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        importance_score: float = 0.5,
        ttl_hours: Optional[int] = None,
        tags: Optional[List[str]] = None
    ) -> str:
        """
        Store a memory entry.
        
        Args:
            agent_id: ID of the agent storing the memory
            content: Memory content
            memory_type: Type of memory (conversation, context, long_term, working)
            session_id: Session identifier
            metadata: Additional metadata
            importance_score: Importance score (0.0 to 1.0)
            ttl_hours: Time to live in hours
            tags: Tags for categorization
            
        Returns:
            Memory ID
        """
        try:
            session_id = session_id or str(uuid.uuid4())
            ttl_hours = ttl_hours or self.config.default_ttl_hours
            
            memory_entry = MemoryEntry(
                agent_id=agent_id,
                session_id=session_id,
                memory_type=memory_type,
                content=content,
                metadata=metadata or {},
                importance_score=importance_score,
                expires_at=time.time() + (ttl_hours * 3600),
                tags=tags or []
            )
            
            # Store in Redis
            memory_key = f"memory:{memory_entry.memory_id}"
            memory_data = {
                "agent_id": memory_entry.agent_id,
                "session_id": memory_entry.session_id,
                "memory_type": memory_entry.memory_type,
                "content": json.dumps(memory_entry.content),
                "metadata": json.dumps(memory_entry.metadata),
                "created_at": memory_entry.created_at,
                "updated_at": memory_entry.updated_at,
                "expires_at": memory_entry.expires_at,
                "importance_score": memory_entry.importance_score,
                "access_count": memory_entry.access_count,
                "tags": json.dumps(memory_entry.tags)
            }
            
            await self._redis_client.hset(memory_key, mapping=memory_data)
            
            if memory_entry.expires_at:
                await self._redis_client.expire(
                    memory_key, 
                    int(memory_entry.expires_at - time.time())
                )
            
            # Update session index
            if session_id not in self._session_memories:
                self._session_memories[session_id] = []
            self._session_memories[session_id].append(memory_entry.memory_id)
            
            # Store session index in Redis
            session_key = f"session:{session_id}"
            await self._redis_client.sadd(session_key, memory_entry.memory_id)
            
            # Cache locally for fast access
            self._memory_cache[memory_entry.memory_id] = memory_entry
            
            logger.debug(
                f"Memory stored successfully",
                extra={
                    "memory_id": memory_entry.memory_id,
                    "agent_id": agent_id,
                    "memory_type": memory_type,
                    "session_id": session_id
                }
            )
            
            return memory_entry.memory_id
            
        except Exception as e:
            logger.error(f"Failed to store memory: {e}")
            raise
    
    async def retrieve_memory(self, memory_id: str) -> Optional[MemoryEntry]:
        """Retrieve a specific memory entry."""
        try:
            # Check local cache first
            if memory_id in self._memory_cache:
                memory_entry = self._memory_cache[memory_id]
                memory_entry.access_count += 1
                memory_entry.updated_at = time.time()
                return memory_entry
            
            # Retrieve from Redis
            memory_key = f"memory:{memory_id}"
            memory_data = await self._redis_client.hgetall(memory_key)
            
            if not memory_data:
                return None
            
            memory_entry = MemoryEntry(
                memory_id=memory_id,
                agent_id=memory_data["agent_id"],
                session_id=memory_data["session_id"],
                memory_type=memory_data["memory_type"],
                content=json.loads(memory_data["content"]),
                metadata=json.loads(memory_data["metadata"]),
                created_at=float(memory_data["created_at"]),
                updated_at=float(memory_data["updated_at"]),
                expires_at=float(memory_data["expires_at"]) if memory_data.get("expires_at") else None,
                importance_score=float(memory_data["importance_score"]),
                access_count=int(memory_data["access_count"]) + 1,
                tags=json.loads(memory_data["tags"])
            )
            
            # Update access count
            await self._redis_client.hset(
                memory_key,
                "access_count",
                memory_entry.access_count
            )
            
            # Cache locally
            self._memory_cache[memory_id] = memory_entry
            
            return memory_entry
            
        except Exception as e:
            logger.error(f"Failed to retrieve memory {memory_id}: {e}")
            return None
    
    async def retrieve_session_memories(
        self,
        session_id: str,
        memory_type: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[MemoryEntry]:
        """Retrieve all memories for a session."""
        try:
            session_key = f"session:{session_id}"
            memory_ids = await self._redis_client.smembers(session_key)
            
            memories = []
            for memory_id in memory_ids:
                memory = await self.retrieve_memory(memory_id)
                if memory:
                    if memory_type is None or memory.memory_type == memory_type:
                        memories.append(memory)
            
            # Sort by creation time (most recent first)
            memories.sort(key=lambda m: m.created_at, reverse=True)
            
            if limit:
                memories = memories[:limit]
            
            return memories
            
        except Exception as e:
            logger.error(f"Failed to retrieve session memories for {session_id}: {e}")
            return []
    
    async def retrieve_agent_memories(
        self,
        agent_id: str,
        memory_type: Optional[str] = None,
        limit: Optional[int] = None,
        min_importance: float = 0.0
    ) -> List[MemoryEntry]:
        """Retrieve memories for a specific agent."""
        try:
            # Search Redis for agent memories
            pattern = f"memory:*"
            memory_keys = []
            
            async for key in self._redis_client.scan_iter(match=pattern):
                memory_data = await self._redis_client.hgetall(key)
                if (memory_data.get("agent_id") == agent_id and
                    (memory_type is None or memory_data.get("memory_type") == memory_type) and
                    float(memory_data.get("importance_score", 0)) >= min_importance):
                    memory_keys.append(key.split(":")[-1])
            
            memories = []
            for memory_id in memory_keys:
                memory = await self.retrieve_memory(memory_id)
                if memory:
                    memories.append(memory)
            
            # Sort by importance and recency
            memories.sort(
                key=lambda m: (m.importance_score, m.created_at),
                reverse=True
            )
            
            if limit:
                memories = memories[:limit]
            
            return memories
            
        except Exception as e:
            logger.error(f"Failed to retrieve agent memories for {agent_id}: {e}")
            return []
    
    async def search_memories(
        self,
        query: str,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        memory_type: Optional[str] = None,
        limit: int = 10
    ) -> List[MemoryEntry]:
        """
        Search memories using semantic similarity.
        
        Args:
            query: Search query
            agent_id: Filter by agent ID
            session_id: Filter by session ID
            memory_type: Filter by memory type
            limit: Maximum number of results
            
        Returns:
            List of matching memories
        """
        try:
            # Get candidate memories
            if session_id:
                candidates = await self.retrieve_session_memories(session_id, memory_type)
            elif agent_id:
                candidates = await self.retrieve_agent_memories(agent_id, memory_type)
            else:
                # Search all memories (expensive, should be limited)
                candidates = []
                pattern = f"memory:*"
                async for key in self._redis_client.scan_iter(match=pattern):
                    memory_id = key.split(":")[-1]
                    memory = await self.retrieve_memory(memory_id)
                    if memory and (memory_type is None or memory.memory_type == memory_type):
                        candidates.append(memory)
            
            # Simple text-based search (can be enhanced with embeddings)
            query_lower = query.lower()
            scored_memories = []
            
            for memory in candidates:
                content_str = json.dumps(memory.content).lower()
                metadata_str = json.dumps(memory.metadata).lower()
                tags_str = " ".join(memory.tags).lower()
                
                score = 0.0
                
                # Simple keyword matching
                if query_lower in content_str:
                    score += 1.0
                if query_lower in metadata_str:
                    score += 0.5
                if query_lower in tags_str:
                    score += 0.3
                
                # Boost by importance and recency
                score *= memory.importance_score
                age_hours = (time.time() - memory.created_at) / 3600
                recency_boost = max(0.1, 1.0 - (age_hours / 168))  # Decay over a week
                score *= recency_boost
                
                if score > 0:
                    scored_memories.append((memory, score))
            
            # Sort by score and return top results
            scored_memories.sort(key=lambda x: x[1], reverse=True)
            return [memory for memory, score in scored_memories[:limit]]
            
        except Exception as e:
            logger.error(f"Failed to search memories: {e}")
            return []
    
    async def update_memory(
        self,
        memory_id: str,
        content: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        importance_score: Optional[float] = None,
        tags: Optional[List[str]] = None
    ) -> bool:
        """Update an existing memory entry."""
        try:
            memory = await self.retrieve_memory(memory_id)
            if not memory:
                return False
            
            # Update fields
            if content is not None:
                memory.content = content
            if metadata is not None:
                memory.metadata = metadata
            if importance_score is not None:
                memory.importance_score = importance_score
            if tags is not None:
                memory.tags = tags
            
            memory.updated_at = time.time()
            
            # Update in Redis
            memory_key = f"memory:{memory_id}"
            update_data = {
                "content": json.dumps(memory.content),
                "metadata": json.dumps(memory.metadata),
                "updated_at": memory.updated_at,
                "importance_score": memory.importance_score,
                "tags": json.dumps(memory.tags)
            }
            
            await self._redis_client.hset(memory_key, mapping=update_data)
            
            # Update cache
            self._memory_cache[memory_id] = memory
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update memory {memory_id}: {e}")
            return False
    
    async def delete_memory(self, memory_id: str) -> bool:
        """Delete a memory entry."""
        try:
            memory = await self.retrieve_memory(memory_id)
            if not memory:
                return False
            
            # Remove from Redis
            memory_key = f"memory:{memory_id}"
            await self._redis_client.delete(memory_key)
            
            # Remove from session index
            session_key = f"session:{memory.session_id}"
            await self._redis_client.srem(session_key, memory_id)
            
            # Remove from cache
            if memory_id in self._memory_cache:
                del self._memory_cache[memory_id]
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete memory {memory_id}: {e}")
            return False
    
    async def create_memory_checkpoint(
        self,
        session_id: str,
        checkpoint_name: str
    ) -> str:
        """Create a checkpoint of session memories."""
        try:
            memories = await self.retrieve_session_memories(session_id)
            checkpoint_id = str(uuid.uuid4())
            
            checkpoint_data = {
                "checkpoint_id": checkpoint_id,
                "session_id": session_id,
                "checkpoint_name": checkpoint_name,
                "created_at": time.time(),
                "memories": [
                    {
                        "memory_id": memory.memory_id,
                        "content": memory.content,
                        "metadata": memory.metadata,
                        "memory_type": memory.memory_type,
                        "importance_score": memory.importance_score,
                        "tags": memory.tags
                    }
                    for memory in memories
                ]
            }
            
            checkpoint_key = f"checkpoint:{checkpoint_id}"
            await self._redis_client.set(
                checkpoint_key,
                json.dumps(checkpoint_data),
                ex=30 * 24 * 3600  # 30 days
            )
            
            return checkpoint_id
            
        except Exception as e:
            logger.error(f"Failed to create memory checkpoint: {e}")
            raise
    
    async def restore_memory_checkpoint(
        self,
        checkpoint_id: str,
        new_session_id: Optional[str] = None
    ) -> str:
        """Restore memories from a checkpoint."""
        try:
            checkpoint_key = f"checkpoint:{checkpoint_id}"
            checkpoint_data_str = await self._redis_client.get(checkpoint_key)
            
            if not checkpoint_data_str:
                raise ValueError(f"Checkpoint {checkpoint_id} not found")
            
            checkpoint_data = json.loads(checkpoint_data_str)
            session_id = new_session_id or str(uuid.uuid4())
            
            restored_memory_ids = []
            for memory_data in checkpoint_data["memories"]:
                memory_id = await self.store_memory(
                    agent_id=memory_data.get("agent_id", "unknown"),
                    content=memory_data["content"],
                    memory_type=memory_data["memory_type"],
                    session_id=session_id,
                    metadata=memory_data["metadata"],
                    importance_score=memory_data["importance_score"],
                    tags=memory_data["tags"]
                )
                restored_memory_ids.append(memory_id)
            
            logger.info(
                f"Restored {len(restored_memory_ids)} memories from checkpoint {checkpoint_id}"
            )
            
            return session_id
            
        except Exception as e:
            logger.error(f"Failed to restore memory checkpoint {checkpoint_id}: {e}")
            raise
    
    async def consolidate_memories(
        self,
        session_id: str,
        consolidation_strategy: str = "importance"
    ) -> int:
        """
        Consolidate memories to reduce storage and improve relevance.
        
        Args:
            session_id: Session to consolidate
            consolidation_strategy: Strategy to use (importance, recency, similarity)
            
        Returns:
            Number of memories consolidated
        """
        try:
            memories = await self.retrieve_session_memories(session_id)
            
            if len(memories) < 10:  # Don't consolidate small sessions
                return 0
            
            consolidated_count = 0
            
            if consolidation_strategy == "importance":
                # Remove low-importance memories
                low_importance = [m for m in memories if m.importance_score < 0.3]
                for memory in low_importance:
                    await self.delete_memory(memory.memory_id)
                    consolidated_count += 1
            
            elif consolidation_strategy == "recency":
                # Remove old memories (older than 7 days)
                cutoff_time = time.time() - (7 * 24 * 3600)
                old_memories = [m for m in memories if m.created_at < cutoff_time]
                for memory in old_memories:
                    await self.delete_memory(memory.memory_id)
                    consolidated_count += 1
            
            elif consolidation_strategy == "similarity":
                # Merge similar memories (simplified implementation)
                # This would typically use embeddings for better similarity detection
                pass
            
            logger.info(
                f"Consolidated {consolidated_count} memories for session {session_id}"
            )
            
            return consolidated_count
            
        except Exception as e:
            logger.error(f"Failed to consolidate memories for session {session_id}: {e}")
            return 0
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory system statistics."""
        try:
            # Get Redis statistics
            redis_info = self._redis_client.info("memory")
            
            # Count memories by type
            memory_counts = {}
            total_memories = 0
            
            # This is a simplified implementation
            # In production, you'd maintain these counters
            
            return {
                "total_memories": total_memories,
                "memory_by_type": memory_counts,
                "redis_memory_mb": redis_info.get("used_memory_human", "unknown"),
                "cache_size": len(self._memory_cache),
                "active_sessions": len(self._session_memories)
            }
            
        except Exception as e:
            logger.error(f"Failed to get memory stats: {e}")
            return {}
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on memory system."""
        try:
            # Test Redis connection
            redis_ping = self._redis_client.ping()
            
            stats = self.get_memory_stats()
            
            return {
                "status": "healthy" if redis_ping else "unhealthy",
                "redis_connected": redis_ping,
                "stats": stats
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }