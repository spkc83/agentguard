"""AgentGuard core security runtime.

Public API:
    from agentguard.core import AgentRegistry, RBACEngine, AppendOnlyAuditLog
    from agentguard.core import CircuitBreaker, TokenBucketRateLimiter
    from agentguard.core import NoOpSandboxBackend, DockerSandboxBackend, SandboxConfig
"""

from agentguard.core.audit import (
    AppendOnlyAuditLog,
    AuditKeyEpoch,
    AuditKeyring,
    AuditLog,
    FileAuditBackend,
)
from agentguard.core.audit_collector import AuditCollectorServer, SigningAuditBackend
from agentguard.core.authentication import (
    AgentAuthenticator,
    AgentCredentialProvider,
    AuthenticatedAgentPrincipal,
    AuthenticationAttempt,
    AuthenticationError,
    AuthenticationFailure,
    ControlPlaneAuthenticator,
    ControlPlanePrincipal,
)
from agentguard.core.circuit_breaker import CircuitBreaker, CircuitState, TokenBucketRateLimiter
from agentguard.core.identity import AgentRegistry, FileBackedRegistry
from agentguard.core.jwt_authentication import (
    CredentialUseDisposition,
    CredentialUseStore,
    InMemoryCredentialUseStore,
    InMemoryJwtKeySetProvider,
    JwtAgentAuthenticator,
    JwtKeySetProvider,
    JwtKeySetSnapshot,
    JwtTrustPolicy,
)
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.core.registry import (
    AgentIdentityResolver,
    AgentRegistryRecord,
    AgentRegistrySnapshot,
    AgentStatus,
    AuthoritativeAgentRegistry,
    RegistryError,
    RegistryFailure,
)
from agentguard.core.registry_control_plane import AgentRegistryControlPlane, RoleGrantPolicy
from agentguard.core.registry_state import (
    InMemoryAuthoritativeAgentRegistry,
    RegisterAgentCommand,
    RegistryMutationCommand,
    RegistryOperation,
    RegistryOperationState,
    ReplaceAgentRolesCommand,
    RevokeAgentCommand,
    RotateAgentCredentialsCommand,
    SignedAuditReference,
)
from agentguard.core.registry_store import SignedFileAuthoritativeAgentRegistry
from agentguard.core.sandbox import (
    SANDBOX_BACKEND_REQUIRED,
    DockerSandboxBackend,
    NoOpSandboxBackend,
    SandboxBackend,
    SandboxConfig,
    SandboxObligation,
)

__all__ = [
    "AgentRegistry",
    "AgentRegistryControlPlane",
    "AgentIdentityResolver",
    "AgentRegistryRecord",
    "AgentRegistrySnapshot",
    "AgentStatus",
    "AgentAuthenticator",
    "AgentCredentialProvider",
    "AppendOnlyAuditLog",
    "AuthenticatedAgentPrincipal",
    "AuthenticationAttempt",
    "AuthenticationError",
    "AuthenticationFailure",
    "AuthoritativeAgentRegistry",
    "AuditCollectorServer",
    "AuditKeyEpoch",
    "AuditKeyring",
    "AuditLog",
    "CircuitBreaker",
    "CircuitState",
    "ControlPlaneAuthenticator",
    "ControlPlanePrincipal",
    "CredentialUseDisposition",
    "CredentialUseStore",
    "DockerSandboxBackend",
    "FileAuditBackend",
    "FileBackedRegistry",
    "InMemoryAuthoritativeAgentRegistry",
    "InMemoryCredentialUseStore",
    "InMemoryJwtKeySetProvider",
    "JwtAgentAuthenticator",
    "JwtKeySetProvider",
    "JwtKeySetSnapshot",
    "JwtTrustPolicy",
    "NoOpSandboxBackend",
    "Permission",
    "RBACEngine",
    "RegistryError",
    "RegistryFailure",
    "RegistryMutationCommand",
    "RegistryOperation",
    "RegistryOperationState",
    "RegisterAgentCommand",
    "ReplaceAgentRolesCommand",
    "RevokeAgentCommand",
    "Role",
    "RoleGrantPolicy",
    "RotateAgentCredentialsCommand",
    "SandboxConfig",
    "SandboxBackend",
    "SANDBOX_BACKEND_REQUIRED",
    "SandboxObligation",
    "SigningAuditBackend",
    "SignedAuditReference",
    "SignedFileAuthoritativeAgentRegistry",
    "TokenBucketRateLimiter",
]
