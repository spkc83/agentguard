"""AgentGuard exception hierarchy.

All custom exceptions inherit from AgentGuardError so callers can
catch the base class for broad error handling.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


class AgentGuardError(Exception):
    """Base exception for all AgentGuard errors."""


class AuthenticationFailure(StrEnum):
    """Safe, machine-stable authentication failure classifications."""

    CREDENTIAL_MISSING = "AUTH.CREDENTIAL_MISSING"
    CREDENTIAL_INVALID = "AUTH.CREDENTIAL_INVALID"
    CREDENTIAL_EXPIRED = "AUTH.CREDENTIAL_EXPIRED"
    CREDENTIAL_NOT_YET_VALID = "AUTH.CREDENTIAL_NOT_YET_VALID"
    CREDENTIAL_REPLAYED = "AUTH.CREDENTIAL_REPLAYED"
    CREDENTIAL_REVOKED = "AUTH.CREDENTIAL_REVOKED"
    PRINCIPAL_MISMATCH = "AUTH.PRINCIPAL_MISMATCH"
    IDENTITY_INACTIVE = "AUTH.IDENTITY_INACTIVE"
    PROVIDER_FAILURE = "AUTH.PROVIDER_FAILURE"
    INTERNAL_ERROR = "AUTH.INTERNAL_ERROR"


class AuthenticationError(AgentGuardError):
    """Raised with a safe classification and no credential/provider detail."""

    def __init__(self, failure: AuthenticationFailure) -> None:
        if not isinstance(failure, AuthenticationFailure):
            raise TypeError("failure must be an AuthenticationFailure")
        self.failure = failure
        self.reason_code = failure.value
        super().__init__(f"Authentication failed: {failure.value}")


class RegistryFailure(StrEnum):
    """Safe, machine-stable authoritative-registry failure classifications."""

    CAPABILITY_DENIED = "REGISTRY.CAPABILITY_DENIED"
    UNKNOWN_ROLE = "REGISTRY.UNKNOWN_ROLE"
    REVISION_CONFLICT = "REGISTRY.REVISION_CONFLICT"
    OPERATION_CONFLICT = "REGISTRY.OPERATION_CONFLICT"
    IDENTITY_NOT_FOUND = "REGISTRY.IDENTITY_NOT_FOUND"
    IDENTITY_INACTIVE = "REGISTRY.IDENTITY_INACTIVE"
    TAMPER_DETECTED = "REGISTRY.TAMPER_DETECTED"


class RegistryError(AgentGuardError):
    """Raised with a safe registry classification and no sensitive detail."""

    def __init__(self, failure: RegistryFailure) -> None:
        if not isinstance(failure, RegistryFailure):
            raise TypeError("failure must be a RegistryFailure")
        self.failure = failure
        self.reason_code = failure.value
        super().__init__(f"Registry operation failed: {failure.value}")


class AdverseActionFailure(StrEnum):
    """Safe, machine-stable adverse-action failure classifications."""

    NO_TRUE_FACTORS = "AA.NO_TRUE_FACTORS"
    UNMAPPED_FEATURES = "AA.UNMAPPED_FEATURES"
    INVALID_ATTRIBUTION = "AA.INVALID_ATTRIBUTION"
    TAXONOMY_MISMATCH = "AA.TAXONOMY_MISMATCH"
    NO_REASON_CODES = "AA.NO_REASON_CODES"
    UNKNOWN_CODE = "AA.UNKNOWN_CODE"
    CODE_NOT_ATTRIBUTED = "AA.CODE_NOT_ATTRIBUTED"
    ATTRIBUTION_MODEL_MISMATCH = "AA.ATTRIBUTION_MODEL_MISMATCH"
    UNRESOLVED_DECLINE = "AA.UNRESOLVED_DECLINE"
    NOTICE_INCOMPLETE = "AA.NOTICE_INCOMPLETE"
    NOTICE_WINDOW_EXCEEDED = "AA.NOTICE_WINDOW_EXCEEDED"


class AdverseActionError(AgentGuardError):
    """Raised when an adverse-action artifact cannot be produced truthfully."""

    def __init__(self, failure: AdverseActionFailure) -> None:
        if not isinstance(failure, AdverseActionFailure):
            raise TypeError("failure must be an AdverseActionFailure")
        self.failure = failure
        self.reason_code = failure.value
        super().__init__(f"Adverse action failed: {failure.value}")


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


class EscalationRequiredError(AgentGuardError):
    """Raised when execution or delivery requires human approval."""

    def __init__(
        self,
        agent_id: str,
        action: str,
        resource: str,
        reason_codes: tuple[str, ...],
        *,
        escalation_id: str = "",
        approval_token: str = "",
        expires_at: datetime | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.action = action
        self.resource = resource
        self.reason_codes = reason_codes
        self.escalation_id = escalation_id
        self.approval_token = approval_token
        self.expires_at = expires_at
        super().__init__(
            "Escalation required: "
            f"agent={agent_id} action={action} resource={resource} "
            f"reason_codes={','.join(reason_codes)}"
        )


class PolicyLoadError(AgentGuardError):
    """Raised when a policy file cannot be loaded safely.

    Fail-safe over fail-open: a rule the engine cannot evaluate (for example
    an unknown or misspelled ``check.type``) must stop startup rather than
    silently degrade into a rule that always passes.
    """

    def __init__(self, file: str, rule_id: str, detail: str) -> None:
        self.file = file
        self.rule_id = rule_id
        self.detail = detail
        super().__init__(f"Policy file {file}: rule {rule_id}: {detail}")


class AuditError(AgentGuardError):
    """Raised when the audit log cannot be written. Blocks action execution."""


class AuditEventConflictError(AuditError):
    """Raised when a stable event ID is reused for different unsigned content."""

    def __init__(self, event_id: str) -> None:
        self.event_id = event_id
        super().__init__(f"Audit event ID conflicts with committed content: {event_id}")


class AuditKeyMissingError(AuditError):
    """Raised when AGENTGUARD_AUDIT_KEY env var is not set."""

    def __init__(self) -> None:
        super().__init__(
            "AGENTGUARD_AUDIT_KEY environment variable is required but not set. "
            'Generate a key with: python -c "import secrets; print(secrets.token_hex(32))"'
        )


class AuditKeyWeakError(AuditError):
    """Raised when AGENTGUARD_AUDIT_KEY is shorter than the minimum key length."""

    def __init__(self, minimum_bytes: int) -> None:
        self.minimum_bytes = minimum_bytes
        super().__init__(
            f"AGENTGUARD_AUDIT_KEY must be at least {minimum_bytes} bytes. "
            'Generate a strong key with: python -c "import secrets; print(secrets.token_hex(32))"'
        )


class AuditKeyEnvironmentError(AuditError):
    """Raised when AGENTGUARD_AUDIT_KEYS cannot be parsed into signing epochs.

    The detail describes the structural problem only. Key material and any
    prefix of it never reach this message.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"AGENTGUARD_AUDIT_KEYS is invalid: {detail}")


class AuditKeyRotationRefusedError(AuditError):
    """Raised when a rotation would leave the log unverifiable after a restart.

    An environment-sourced keyring can only be rebuilt from the environment, so
    an epoch that AGENTGUARD_AUDIT_KEYS does not declare would be lost on the
    next start. The refusal names the epoch, never its key material.
    """

    def __init__(self, key_id: str) -> None:
        self.key_id = key_id
        super().__init__(
            f"Audit key rotation to epoch {key_id!r} is refused: AGENTGUARD_AUDIT_KEYS must "
            "declare this epoch (key and activation_sequence) before it can be activated, "
            "otherwise a restart cannot verify events signed under it."
        )


class AuditKeyUnavailableError(AuditError):
    """Raised when an audit record references an unavailable verification key."""

    def __init__(self, key_id: str) -> None:
        self.key_id = key_id
        super().__init__(f"Audit verification key is unavailable: key_id={key_id}")


class AuditCollectorUnavailableError(AuditError):
    """Raised when the out-of-process audit collector cannot be reached."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"Audit collector unavailable: {detail}")


class AuditCollectorProtocolError(AuditError):
    """Raised when an audit collector request or response violates the protocol."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"Audit collector protocol error: code={code} detail={detail}")


class AuditCollectorOwnershipError(AuditError):
    """Raised when collector socket or process ownership cannot be established safely."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"Audit collector ownership error: {detail}")


class AuditTamperDetectedError(AuditError):
    """Raised when HMAC chain verification detects log tampering."""

    def __init__(self, event_index: int, event_id: str, *, detail: str = "") -> None:
        self.event_index = event_index
        self.event_id = event_id
        self.detail = detail
        super().__init__(
            detail or f"Audit log tamper detected at index={event_index} event_id={event_id}"
        )


class AuditRollbackDetectedError(AuditTamperDetectedError):
    """Raised when the local chain head is behind a trusted external checkpoint.

    This is the specific signal that the audit directory was rolled back to an
    earlier state while an off-host witness survived. It subclasses
    :class:`AuditTamperDetectedError` so existing fail-closed handlers keep
    blocking, while operators can distinguish rollback from in-place edits.
    """

    def __init__(self, *, trusted_head_sequence: int, local_head_sequence: int) -> None:
        self.trusted_head_sequence = trusted_head_sequence
        self.local_head_sequence = local_head_sequence
        super().__init__(
            max(local_head_sequence - 1, 0),
            "<trusted-checkpoint>",
            detail=(
                "Audit log rollback detected: local head sequence "
                f"{local_head_sequence} is behind trusted checkpoint head "
                f"{trusted_head_sequence}"
            ),
        )


class AuditAttestationError(AuditError):
    """Raised when evidence is readable but cannot support a clean attestation."""

    def __init__(self, status: str) -> None:
        self.status = status
        super().__init__(f"Audit evidence is not attestable: checkpoint_status={status}")


class IdentityNotFoundError(AgentGuardError):
    """Raised when an agent identity cannot be resolved."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        super().__init__(f"Agent identity not found: {agent_id}")


class DuplicateAgentError(AgentGuardError):
    """Raised when registering an agent with an ID that already exists."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        super().__init__(f"Agent already registered: {agent_id}")


class SandboxError(AgentGuardError):
    """Raised when sandboxed tool execution fails with a stable classification."""

    def __init__(
        self,
        detail: str,
        *,
        reason_code: str = "SANDBOX.INTERNAL_ERROR",
        result: object | None = None,
    ) -> None:
        self.reason_code = reason_code
        self.result = result
        super().__init__(f"{reason_code}: {detail}")


class CircuitOpenError(AgentGuardError):
    """Raised when a circuit breaker is in OPEN state and rejects the call."""

    def __init__(self, breaker_name: str) -> None:
        self.breaker_name = breaker_name
        super().__init__(f"Circuit breaker open: {breaker_name}")


class RateLimitExceededError(AgentGuardError):
    """Raised when an agent exceeds its rate limit."""

    def __init__(self, agent_id: str, limit: float, action: str | None = None) -> None:
        self.agent_id = agent_id
        self.limit = limit
        self.action = action
        action_text = f" action={action}" if action is not None else ""
        super().__init__(
            f"Rate limit exceeded: agent={agent_id}{action_text} limit={limit} tokens/sec"
        )
