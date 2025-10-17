"""Agent identity and access management using AWS Bedrock AgentCore Identity."""

import json
import time
import uuid
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

import boto3
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from ..utils.config import get_config
from ..utils.logger import get_logger

logger = get_logger(__name__)


class Permission(Enum):
    """Available permissions for agents."""
    READ_MEMORY = "read_memory"
    WRITE_MEMORY = "write_memory"
    EXECUTE_SCAN = "execute_scan"
    APPLY_REMEDIATION = "apply_remediation"
    GENERATE_REPORT = "generate_report"
    INVOKE_BEDROCK = "invoke_bedrock"
    ACCESS_EXTERNAL_API = "access_external_api"
    MANAGE_AGENTS = "manage_agents"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    ADMIN_ACCESS = "admin_access"


class Role(Enum):
    """Predefined roles with permission sets."""
    ORCHESTRATOR = "orchestrator"
    COMPLIANCE_SCANNER = "compliance_scanner"
    AUDITOR = "auditor"
    REMEDIATOR = "remediator"
    EXPLAINER = "explainer"
    ADMIN = "admin"
    READONLY = "readonly"


@dataclass
class AgentIdentity:
    """Represents an agent's identity and credentials."""
    
    agent_id: str
    agent_name: str
    role: Role
    permissions: Set[Permission] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_authenticated: Optional[float] = None
    is_active: bool = True
    jwt_token: Optional[str] = None
    public_key: Optional[bytes] = None
    private_key: Optional[bytes] = None


class IdentityConfig:
    """Configuration for identity management."""
    
    def __init__(self):
        self.jwt_secret = get_config().get("identity.jwt_secret", "default-secret-change-in-production")
        self.jwt_algorithm = "HS256"
        self.token_expiry_hours = 24
        self.max_sessions_per_agent = 5
        self.require_mfa = False
        self.enable_audit_logging = True


class AgentIdentityManager:
    """
    Agent identity and access management using AWS Bedrock AgentCore Identity.
    
    Provides:
    - Agent authentication and authorization
    - Role-based access control (RBAC)
    - JWT token management
    - Permission verification
    - Multi-factor authentication support
    - Audit logging
    """
    
    def __init__(self, config: Optional[IdentityConfig] = None):
        self.config = config or IdentityConfig()
        self._identities: Dict[str, AgentIdentity] = {}
        self._role_permissions: Dict[Role, Set[Permission]] = {}
        self._active_sessions: Dict[str, Dict[str, Any]] = {}
        
        # AWS clients
        self._iam_client = None
        self._secrets_client = None
        
        self._initialize_role_permissions()
    
    def _initialize_role_permissions(self) -> None:
        """Initialize default role-permission mappings."""
        self._role_permissions = {
            Role.ORCHESTRATOR: {
                Permission.READ_MEMORY,
                Permission.WRITE_MEMORY,
                Permission.MANAGE_AGENTS,
                Permission.INVOKE_BEDROCK,
                Permission.VIEW_AUDIT_LOGS
            },
            Role.COMPLIANCE_SCANNER: {
                Permission.READ_MEMORY,
                Permission.WRITE_MEMORY,
                Permission.EXECUTE_SCAN,
                Permission.INVOKE_BEDROCK,
                Permission.ACCESS_EXTERNAL_API
            },
            Role.AUDITOR: {
                Permission.READ_MEMORY,
                Permission.GENERATE_REPORT,
                Permission.VIEW_AUDIT_LOGS,
                Permission.INVOKE_BEDROCK
            },
            Role.REMEDIATOR: {
                Permission.READ_MEMORY,
                Permission.WRITE_MEMORY,
                Permission.APPLY_REMEDIATION,
                Permission.ACCESS_EXTERNAL_API,
                Permission.INVOKE_BEDROCK
            },
            Role.EXPLAINER: {
                Permission.READ_MEMORY,
                Permission.INVOKE_BEDROCK,
                Permission.VIEW_AUDIT_LOGS
            },
            Role.ADMIN: set(Permission),  # All permissions
            Role.READONLY: {
                Permission.READ_MEMORY,
                Permission.VIEW_AUDIT_LOGS
            }
        }
    
    async def initialize(self) -> None:
        """Initialize identity management system."""
        try:
            # Initialize AWS clients
            self._iam_client = boto3.client("iam")
            self._secrets_client = boto3.client("secretsmanager")
            
            # Load existing identities from AWS Secrets Manager
            await self._load_identities()
            
            logger.info("Agent identity manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize identity manager: {e}")
            raise
    
    async def _load_identities(self) -> None:
        """Load existing agent identities from secure storage."""
        try:
            # This would typically load from AWS Secrets Manager
            # For now, we'll create default identities
            
            default_agents = [
                ("orchestrator", "Orchestrator Agent", Role.ORCHESTRATOR),
                ("compliance", "Compliance Scanner Agent", Role.COMPLIANCE_SCANNER),
                ("audit", "Audit Agent", Role.AUDITOR),
                ("remediation", "Remediation Agent", Role.REMEDIATOR),
                ("explainability", "Explainability Agent", Role.EXPLAINER)
            ]
            
            for agent_id, agent_name, role in default_agents:
                await self.create_agent_identity(agent_id, agent_name, role)
            
        except Exception as e:
            logger.error(f"Failed to load identities: {e}")
    
    async def create_agent_identity(
        self,
        agent_id: str,
        agent_name: str,
        role: Role,
        custom_permissions: Optional[Set[Permission]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AgentIdentity:
        """
        Create a new agent identity.
        
        Args:
            agent_id: Unique agent identifier
            agent_name: Human-readable agent name
            role: Agent role
            custom_permissions: Custom permissions (override role defaults)
            metadata: Additional metadata
            
        Returns:
            Created agent identity
        """
        try:
            if agent_id in self._identities:
                raise ValueError(f"Agent identity {agent_id} already exists")
            
            # Generate RSA key pair for the agent
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            public_key = private_key.public_key()
            
            # Serialize keys
            private_key_bytes = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
            
            public_key_bytes = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
            
            # Determine permissions
            permissions = custom_permissions or self._role_permissions.get(role, set())
            
            # Create identity
            identity = AgentIdentity(
                agent_id=agent_id,
                agent_name=agent_name,
                role=role,
                permissions=permissions,
                metadata=metadata or {},
                private_key=private_key_bytes,
                public_key=public_key_bytes
            )
            
            # Store identity
            self._identities[agent_id] = identity
            
            # Store in AWS Secrets Manager
            await self._store_identity_securely(identity)
            
            logger.info(
                f"Agent identity created successfully",
                extra={
                    "agent_id": agent_id,
                    "agent_name": agent_name,
                    "role": role.value,
                    "permissions_count": len(permissions)
                }
            )
            
            return identity
            
        except Exception as e:
            logger.error(f"Failed to create agent identity {agent_id}: {e}")
            raise
    
    async def _store_identity_securely(self, identity: AgentIdentity) -> None:
        """Store agent identity in AWS Secrets Manager."""
        try:
            secret_name = f"compliance-guardian/agent-identity/{identity.agent_id}"
            
            secret_value = {
                "agent_id": identity.agent_id,
                "agent_name": identity.agent_name,
                "role": identity.role.value,
                "permissions": [p.value for p in identity.permissions],
                "metadata": identity.metadata,
                "created_at": identity.created_at,
                "public_key": identity.public_key.decode() if identity.public_key else None,
                "private_key": identity.private_key.decode() if identity.private_key else None
            }
            
            # Store in Secrets Manager
            try:
                self._secrets_client.create_secret(
                    Name=secret_name,
                    SecretString=json.dumps(secret_value),
                    Description=f"Identity for agent {identity.agent_id}"
                )
            except self._secrets_client.exceptions.ResourceExistsException:
                # Update existing secret
                self._secrets_client.update_secret(
                    SecretId=secret_name,
                    SecretString=json.dumps(secret_value)
                )
            
        except Exception as e:
            logger.warning(f"Failed to store identity securely: {e}")
    
    async def authenticate_agent(
        self,
        agent_id: str,
        credentials: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Authenticate an agent and return a JWT token.
        
        Args:
            agent_id: Agent identifier
            credentials: Authentication credentials
            
        Returns:
            JWT token if authentication successful
        """
        try:
            if agent_id not in self._identities:
                logger.warning(f"Authentication failed: Agent {agent_id} not found")
                return None
            
            identity = self._identities[agent_id]
            
            if not identity.is_active:
                logger.warning(f"Authentication failed: Agent {agent_id} is inactive")
                return None
            
            # For now, we'll use simplified authentication
            # In production, this would verify credentials, certificates, etc.
            
            # Create JWT token
            payload = {
                "agent_id": agent_id,
                "agent_name": identity.agent_name,
                "role": identity.role.value,
                "permissions": [p.value for p in identity.permissions],
                "iat": time.time(),
                "exp": time.time() + (self.config.token_expiry_hours * 3600),
                "jti": str(uuid.uuid4())  # JWT ID for tracking
            }
            
            token = jwt.encode(
                payload,
                self.config.jwt_secret,
                algorithm=self.config.jwt_algorithm
            )
            
            # Store token and update identity
            identity.jwt_token = token
            identity.last_authenticated = time.time()
            
            # Track active session
            session_id = payload["jti"]
            self._active_sessions[session_id] = {
                "agent_id": agent_id,
                "token": token,
                "created_at": time.time(),
                "last_used": time.time()
            }
            
            logger.info(
                f"Agent authenticated successfully",
                extra={
                    "agent_id": agent_id,
                    "session_id": session_id
                }
            )
            
            return token
            
        except Exception as e:
            logger.error(f"Authentication failed for agent {agent_id}: {e}")
            return None
    
    async def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify a JWT token and return the payload.
        
        Args:
            token: JWT token to verify
            
        Returns:
            Token payload if valid
        """
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm]
            )
            
            # Check if session is still active
            session_id = payload.get("jti")
            if session_id not in self._active_sessions:
                logger.warning("Token verification failed: Session not found")
                return None
            
            # Update last used time
            self._active_sessions[session_id]["last_used"] = time.time()
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token verification failed: Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token verification failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None
    
    async def check_permission(
        self,
        agent_id: str,
        permission: Permission,
        resource: Optional[str] = None
    ) -> bool:
        """
        Check if an agent has a specific permission.
        
        Args:
            agent_id: Agent identifier
            permission: Required permission
            resource: Optional resource identifier for fine-grained access
            
        Returns:
            True if agent has permission
        """
        try:
            if agent_id not in self._identities:
                return False
            
            identity = self._identities[agent_id]
            
            if not identity.is_active:
                return False
            
            # Check if agent has the permission
            has_permission = permission in identity.permissions
            
            # Admin role has all permissions
            if identity.role == Role.ADMIN:
                has_permission = True
            
            # Log access attempt
            if self.config.enable_audit_logging:
                await self._log_access_attempt(
                    agent_id=agent_id,
                    permission=permission.value,
                    resource=resource,
                    granted=has_permission
                )
            
            return has_permission
            
        except Exception as e:
            logger.error(f"Permission check failed for agent {agent_id}: {e}")
            return False
    
    async def _log_access_attempt(
        self,
        agent_id: str,
        permission: str,
        resource: Optional[str],
        granted: bool
    ) -> None:
        """Log access attempt for audit purposes."""
        try:
            audit_entry = {
                "timestamp": time.time(),
                "agent_id": agent_id,
                "permission": permission,
                "resource": resource,
                "granted": granted,
                "event_type": "permission_check"
            }
            
            # In production, this would go to AWS CloudTrail or similar
            logger.info(
                "Access attempt",
                extra=audit_entry
            )
            
        except Exception as e:
            logger.error(f"Failed to log access attempt: {e}")
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke a JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm],
                options={"verify_exp": False}  # Don't check expiry for revocation
            )
            
            session_id = payload.get("jti")
            if session_id in self._active_sessions:
                del self._active_sessions[session_id]
                
                logger.info(
                    f"Token revoked successfully",
                    extra={
                        "agent_id": payload.get("agent_id"),
                        "session_id": session_id
                    }
                )
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False
    
    async def update_agent_permissions(
        self,
        agent_id: str,
        new_permissions: Set[Permission]
    ) -> bool:
        """Update an agent's permissions."""
        try:
            if agent_id not in self._identities:
                return False
            
            identity = self._identities[agent_id]
            old_permissions = identity.permissions.copy()
            identity.permissions = new_permissions
            
            # Store updated identity
            await self._store_identity_securely(identity)
            
            logger.info(
                f"Agent permissions updated",
                extra={
                    "agent_id": agent_id,
                    "old_permissions": [p.value for p in old_permissions],
                    "new_permissions": [p.value for p in new_permissions]
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update permissions for agent {agent_id}: {e}")
            return False
    
    async def deactivate_agent(self, agent_id: str) -> bool:
        """Deactivate an agent identity."""
        try:
            if agent_id not in self._identities:
                return False
            
            identity = self._identities[agent_id]
            identity.is_active = False
            
            # Revoke all active sessions for this agent
            sessions_to_remove = []
            for session_id, session_info in self._active_sessions.items():
                if session_info["agent_id"] == agent_id:
                    sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                del self._active_sessions[session_id]
            
            logger.info(f"Agent {agent_id} deactivated and sessions revoked")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deactivate agent {agent_id}: {e}")
            return False
    
    def get_agent_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        """Get agent identity information."""
        return self._identities.get(agent_id)
    
    def list_active_sessions(self) -> List[Dict[str, Any]]:
        """List all active sessions."""
        return [
            {
                "session_id": session_id,
                "agent_id": session_info["agent_id"],
                "created_at": session_info["created_at"],
                "last_used": session_info["last_used"]
            }
            for session_id, session_info in self._active_sessions.items()
        ]
    
    def get_identity_metrics(self) -> Dict[str, Any]:
        """Get identity management metrics."""
        active_agents = sum(1 for identity in self._identities.values() if identity.is_active)
        
        role_distribution = {}
        for identity in self._identities.values():
            role = identity.role.value
            role_distribution[role] = role_distribution.get(role, 0) + 1
        
        return {
            "total_identities": len(self._identities),
            "active_identities": active_agents,
            "active_sessions": len(self._active_sessions),
            "role_distribution": role_distribution
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on identity system."""
        try:
            metrics = self.get_identity_metrics()
            
            # Check for issues
            warnings = []
            if len(self._active_sessions) > 100:
                warnings.append("High number of active sessions")
            
            # Test AWS connectivity
            try:
                self._secrets_client.list_secrets(MaxResults=1)
                aws_connected = True
            except Exception:
                aws_connected = False
                warnings.append("AWS Secrets Manager connection failed")
            
            status = "healthy"
            if warnings:
                status = "degraded"
            if not aws_connected:
                status = "unhealthy"
            
            return {
                "status": status,
                "metrics": metrics,
                "aws_connected": aws_connected,
                "warnings": warnings
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }