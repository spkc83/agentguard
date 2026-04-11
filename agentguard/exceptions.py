"""AgentGuard exception hierarchy.

All custom exceptions inherit from AgentGuardError so callers can
catch the base class for broad error handling.
"""

from __future__ import annotations


class AgentGuardError(Exception):
    """Base exception for all AgentGuard errors."""


class PermissionDeniedError(AgentGuardError):
    """Raised when an agent lacks permission for the requested action."""

    def __init__(self, agent_id: str, action: str, resource: str, reason: str = "") -> None:
        self.agent_id = agent_id
        self.action = action
        self.resource = resource
        self.reason = reason
        msg = f"Permission denied: agent={agent_id} action={action} resource={resource}"
        if reason:
            msg += f" reason={reason}"
        super().__init__(msg)


class PolicyViolationError(AgentGuardError):
    """Raised when a policy evaluation finds a critical violation."""

    def __init__(self, rule_id: str, rule_name: str, remediation: str = "") -> None:
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.remediation = remediation
        super().__init__(f"Policy violation: {rule_id} ({rule_name})")


class AuditError(AgentGuardError):
    """Raised when the audit log cannot be written. Blocks action execution."""


class AuditKeyMissingError(AuditError):
    """Raised when AGENTGUARD_AUDIT_KEY env var is not set."""

    def __init__(self) -> None:
        super().__init__(
            "AGENTGUARD_AUDIT_KEY environment variable is required but not set. "
            'Generate a key with: python -c "import secrets; print(secrets.token_hex(32))"'
        )


class AuditTamperDetectedError(AuditError):
    """Raised when HMAC chain verification detects log tampering."""

    def __init__(self, event_index: int, event_id: str) -> None:
        self.event_index = event_index
        self.event_id = event_id
        super().__init__(f"Audit log tamper detected at index={event_index} event_id={event_id}")


class IdentityNotFoundError(AgentGuardError):
    """Raised when an agent identity cannot be resolved."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        super().__init__(f"Agent identity not found: {agent_id}")


class SandboxError(AgentGuardError):
    """Raised when sandboxed tool execution fails."""


class CircuitOpenError(AgentGuardError):
    """Raised when a circuit breaker is in OPEN state and rejects the call."""

    def __init__(self, breaker_name: str) -> None:
        self.breaker_name = breaker_name
        super().__init__(f"Circuit breaker open: {breaker_name}")
