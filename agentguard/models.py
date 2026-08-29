"""Shared Pydantic models — the API contracts between AgentGuard layers.

These models are locked contracts. Breaking changes require a major version bump.
See AGENTS.md "Shared Contracts" section for the design rationale.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 — Pydantic needs this at runtime
from math import isfinite
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.exceptions import (  # noqa: TC001 — Pydantic runtime types
    AuthenticationFailure,
    RegistryFailure,
)

PolicyEffect = Literal["allow", "deny", "escalate", "warn"]
AuditEventType = Literal[
    "legacy",
    "admission",
    "execution_completed",
    "execution_post_processing_claimed",
    "delivery_completed",
    "delivery_denied",
    "delivery_escalated",
    "denial",
    "rejection",
    "escalation",
    "escalation_requested",
    "approval_granted",
    "approval_denied",
    "approval_expired",
    "escalation_resumed",
    "execution_in_doubt",
    "execution_reconciliation_resumed",
    "execution_reconciled",
    "authentication_succeeded",
    "authentication_rejected",
    "registry_mutation_authorized",
    "registry_mutation_rejected",
]
ChainMode = Literal["enforce", "shadow", "off"]
GuardrailStage = Literal[
    "input",
    "pre_tool",
    "post_tool",
    "pre_message",
    "post_message",
    "on_decision",
    "attestation",
]
GuardrailEffect = Literal["allow", "deny", "escalate", "warn", "transform"]
UNAUTHENTICATED_AGENT_ID = "__unauthenticated__"
UNAUTHENTICATED_AGENT_NAME = "Unauthenticated"


class EvidenceRef(BaseModel):
    """Opaque, non-authorizing reference used only to correlate evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    namespace: str
    value: str


class AuditLink(BaseModel):
    """Typed relationship from one evidence event to another governed subject."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    relation: Literal["subject", "decision", "notice", "model", "parent"]
    target: EvidenceRef


class AgentIdentity(BaseModel):
    """An agent's identity as registered with AgentGuard.

    Args:
        agent_id: Stable UUID assigned at registration.
        name: Human-readable agent name.
        roles: List of role names assigned to this agent.
        metadata: Arbitrary key-value metadata (framework, version, owner, etc.).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str
    name: str
    roles: list[str]
    metadata: dict[str, str] = Field(default_factory=dict)


class PermissionContext(BaseModel):
    """Result of an RBAC permission check.

    Args:
        agent: The agent requesting the action.
        requested_action: Action pattern (e.g. "tool:web_search", "data:read:pii").
        resource: Target resource (file path, URL, agent ID, etc.).
        context: Additional context for condition-based permission checks.
        granted: Whether the action was allowed.
        reason: Human-readable explanation of the decision.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent: AgentIdentity
    requested_action: str
    resource: str
    context: dict[str, Any] = Field(default_factory=dict)
    granted: bool = False
    reason: str = ""


class PolicyResult(BaseModel):
    """Result of evaluating a single compliance policy rule.

    Args:
        rule_id: Unique rule identifier (e.g. "OWASP-AGENT-01", "AG-FINOS-012").
        rule_name: Human-readable rule name.
        passed: Whether the rule check passed.
        severity: Rule severity — critical, high, medium, or low.
        evidence: Data collected during evaluation (matched patterns, values, etc.).
        remediation: Recommended action if the rule failed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    rule_name: str
    passed: bool
    severity: Literal["critical", "high", "medium", "low"]
    evidence: dict[str, Any]
    remediation: str
    effect: PolicyEffect | None = None


class GuardrailEvaluation(BaseModel):
    """Signed evidence for one guardrail evaluation in a governed lifecycle."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    guardrail_id: str = Field(min_length=1)
    guardrail_version: str = Field(min_length=1)
    stage: GuardrailStage
    effect: GuardrailEffect
    reason_codes: tuple[str, ...]
    duration_ms: float
    enforced: bool

    @field_validator("duration_ms")
    @classmethod
    def _validate_duration(cls, value: float) -> float:
        if value < 0 or not isfinite(value):
            raise ValueError("duration_ms must be finite and nonnegative")
        return value

    @model_validator(mode="after")
    def _validate_reason_contract(self) -> GuardrailEvaluation:
        if self.effect in {"deny", "escalate"} and not self.reason_codes:
            raise ValueError(f"{self.effect} evaluations require reason codes")
        return self


class HitlEvidence(BaseModel):
    """Signed, redacted evidence for one durable HITL lifecycle transition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    escalation_id: str = Field(min_length=1)
    decision_id: str = ""
    state: Literal["requested", "approved", "denied", "expired"]
    approver_id: str = ""
    reason_redacted: str = ""
    decided_at: datetime | None = None
    expires_at: datetime | None = None

    @field_validator("decided_at", "expires_at")
    @classmethod
    def _validate_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("HITL timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _validate_state_contract(self) -> HitlEvidence:
        if self.state == "requested":
            if self.decision_id or self.approver_id or self.decided_at is not None:
                raise ValueError("requested HITL evidence cannot contain decision fields")
            if self.expires_at is None:
                raise ValueError("requested HITL evidence requires expires_at")
            return self

        if not self.decision_id or self.decided_at is None:
            raise ValueError(f"{self.state} HITL evidence requires a decision")
        if self.state in {"approved", "denied"} and not self.approver_id:
            raise ValueError(f"{self.state} HITL evidence requires approver_id")
        if self.state == "expired":
            if self.approver_id:
                raise ValueError("expired HITL evidence cannot contain approver_id")
            if self.expires_at is None:
                raise ValueError("expired HITL evidence requires expires_at")
            if self.decided_at < self.expires_at:
                raise ValueError("expired HITL evidence cannot predate expires_at")
        return self


class ReconciliationEvidence(BaseModel):
    """Signed, redacted evidence for execution-outcome reconciliation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    escalation_id: str = Field(min_length=1)
    claim_id: str = Field(min_length=1)
    reconciliation_id: str = Field(min_length=1)
    classification: Literal[
        "claimed_without_terminal",
        "admission_without_completion",
        "completion_without_protected_result",
        "protected_result_available",
        "reconciled_denied",
    ]
    state: Literal["in_doubt", "resumed", "reconciled"]
    reconciler_id: str = Field(min_length=1)
    reason_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessed_at: datetime
    audit_chain_id: str = Field(min_length=1)
    audit_head_sequence: int = Field(ge=0)
    audit_head_event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    journal_revision: int = Field(ge=0)
    journal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("assessed_at")
    @classmethod
    def _validate_assessed_at(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("reconciliation assessed_at must be timezone-aware")
        return value


class AuthenticationEvidence(BaseModel):
    """Signed, secret-free evidence for one agent-authentication attempt."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    state: Literal["verified", "rejected"]
    method: str = Field(min_length=1, max_length=256)
    authority: str = Field(default="", max_length=2048)
    agent_id: str = Field(default="", max_length=256)
    credential_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authenticated_at: datetime
    issued_at: datetime | None = None
    not_before: datetime | None = None
    expires_at: datetime | None = None
    registry_revision: int | None = Field(default=None, ge=0)
    failure_reason: AuthenticationFailure | None = None

    @field_validator("authenticated_at", "issued_at", "not_before", "expires_at")
    @classmethod
    def _validate_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("authentication timestamps must be timezone-aware")
        return value

    @field_validator("method", "authority", "agent_id")
    @classmethod
    def _validate_descriptor(cls, value: str) -> str:
        if value and (value != value.strip() or not value.isprintable()):
            raise ValueError("authentication identifiers must be canonical printable text")
        return value

    @model_validator(mode="after")
    def _validate_state_contract(self) -> AuthenticationEvidence:
        credential_times = (self.issued_at, self.not_before, self.expires_at)
        if self.state == "rejected":
            if self.agent_id or self.authority:
                raise ValueError("rejected authentication cannot contain trusted identity fields")
            if any(value is not None for value in credential_times):
                raise ValueError("rejected authentication cannot contain credential timestamps")
            if self.registry_revision is not None:
                raise ValueError("rejected authentication cannot contain registry metadata")
            if self.failure_reason is None:
                raise ValueError("rejected authentication requires a failure reason")
            return self

        if not self.agent_id or not self.authority:
            raise ValueError("verified authentication requires trusted identity fields")
        if any(value is None for value in credential_times):
            raise ValueError("verified authentication requires credential timestamps")
        if self.failure_reason is not None:
            raise ValueError("verified authentication cannot contain a failure reason")
        assert self.issued_at is not None
        assert self.not_before is not None
        assert self.expires_at is not None
        if not self.issued_at <= self.not_before <= self.authenticated_at < self.expires_at:
            raise ValueError(
                "authentication timestamps must satisfy "
                "issued_at <= not_before <= authenticated_at < expires_at"
            )
        return self


class RegistryMutationEvidence(BaseModel):
    """Signed prepare/audit/commit evidence for one registry mutation decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    state: Literal["authorized", "rejected"]
    operation_id: str = Field(min_length=1, max_length=256)
    registry_id: str = Field(min_length=1, max_length=256)
    mutation: Literal["register", "replace_roles", "rotate_credentials", "revoke"]
    principal_id: str = Field(min_length=1, max_length=256)
    authentication_method: str = Field(min_length=1, max_length=256)
    authentication_authority: str = Field(min_length=1, max_length=2048)
    credential_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    capabilities_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_agent_id: str = Field(min_length=1, max_length=256)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    base_registry_revision: int | None = Field(default=None, ge=0)
    target_registry_revision: int | None = Field(default=None, ge=1)
    requested_registry_revision: int | None = Field(default=None, ge=0)
    observed_registry_revision: int | None = Field(default=None, ge=0)
    before_record_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    after_record_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    base_credential_epoch: int | None = Field(default=None, ge=1)
    target_credential_epoch: int | None = Field(default=None, ge=1)
    prepared_at: datetime
    failure_reason: RegistryFailure | None = None

    @field_validator(
        "operation_id",
        "registry_id",
        "principal_id",
        "authentication_method",
        "authentication_authority",
        "target_agent_id",
    )
    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        if value != value.strip() or not value.isprintable():
            raise ValueError("registry identifiers must be canonical printable text")
        return value

    @field_validator("prepared_at")
    @classmethod
    def _validate_prepared_at(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("registry prepared_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _validate_state_contract(self) -> RegistryMutationEvidence:
        if self.state == "rejected":
            if self.failure_reason is None:
                raise ValueError("rejected registry mutation requires a failure reason")
            if any(
                value is not None
                for value in (
                    self.base_registry_revision,
                    self.target_registry_revision,
                    self.before_record_digest,
                    self.after_record_digest,
                    self.base_credential_epoch,
                    self.target_credential_epoch,
                )
            ):
                raise ValueError("rejected registry mutation cannot assert prepared registry state")
            revisions = (
                self.requested_registry_revision,
                self.observed_registry_revision,
            )
            if self.failure_reason is RegistryFailure.REVISION_CONFLICT:
                if any(value is None for value in revisions) or len(set(revisions)) != 2:
                    raise ValueError(
                        "revision conflicts require distinct requested and observed revisions"
                    )
            elif any(value is not None for value in revisions):
                raise ValueError("only revision conflicts can contain observed revision facts")
            return self
        if self.failure_reason is not None:
            raise ValueError("authorized registry mutation cannot contain a failure reason")
        if (
            self.requested_registry_revision is not None
            or self.observed_registry_revision is not None
        ):
            raise ValueError("authorized registry mutation cannot contain conflict revisions")
        if (
            self.base_registry_revision is None
            or self.target_registry_revision is None
            or self.after_record_digest is None
            or self.target_credential_epoch is None
        ):
            raise ValueError("authorized registry mutation requires complete proposed target state")
        if self.target_registry_revision != self.base_registry_revision + 1:
            raise ValueError("authorized mutation must advance registry revision exactly once")
        if self.mutation == "register":
            if self.before_record_digest is not None or self.base_credential_epoch is not None:
                raise ValueError("register cannot claim prior record state")
            if self.target_credential_epoch != 1:
                raise ValueError("register starts at credential epoch 1")
            return self
        if self.before_record_digest is None or self.base_credential_epoch is None:
            raise ValueError("updates require prior record state")
        expected_epoch = (
            self.base_credential_epoch + 1
            if self.mutation in {"rotate_credentials", "revoke"}
            else self.base_credential_epoch
        )
        if self.target_credential_epoch != expected_epoch:
            raise ValueError("credential epoch conflicts with registry operation")
        return self


class AuditEvent(BaseModel):
    """A single entry in the immutable audit log.

    Frozen after creation — use model_copy(update={...}) to create modified copies.
    Every tool call, permission check, and policy evaluation produces an AuditEvent.
    Events are written BEFORE execution (log-first, act-second).

    Args:
        event_id: UUID for this event.
        timestamp: UTC timestamp.
        agent_id: The acting agent's ID.
        action: The action being performed.
        resource: The target resource.
        permission_context: Full RBAC decision context.
        result: Outcome — allowed, denied, escalated, rejected, or error.
        policy_results: Results from compliance policy evaluation.
        guardrail_evaluations: Signed per-stage guardrail decisions. Schema v4
            commits these records into the event HMAC envelope.
        hitl_evidence: Signed redacted HITL lifecycle evidence. Schema v5 commits
            this record into the event HMAC envelope.
        reconciliation_evidence: Signed redacted reconciliation evidence. Schema
            v6 commits this record into the event HMAC envelope.
        authentication_evidence: Signed secret-free authentication evidence.
            Schema v7 commits this record into the event HMAC envelope.
        duration_ms: Time taken for the governed action (0 if pre-execution log).
        trace_id: OpenTelemetry trace ID for correlation.
        event_hash: HMAC-SHA256 hash of this event (set by audit logger).
        prev_hash: HMAC-SHA256 hash of the previous event in the chain.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    timestamp: datetime
    agent_id: str
    action: str
    resource: str
    permission_context: PermissionContext
    result: Literal["allowed", "denied", "escalated", "rejected", "error"]
    policy_results: list[PolicyResult] = Field(default_factory=list)
    guardrail_evaluations: tuple[GuardrailEvaluation, ...] = ()
    hitl_evidence: HitlEvidence | None = None
    reconciliation_evidence: ReconciliationEvidence | None = None
    authentication_evidence: AuthenticationEvidence | None = None
    registry_mutation_evidence: RegistryMutationEvidence | None = None
    duration_ms: float
    trace_id: str
    invocation_id: str = ""
    event_type: AuditEventType = "legacy"
    reason_codes: tuple[str, ...] = ()
    payload_digest: str = ""
    payload_redacted: dict[str, Any] = Field(default_factory=dict)
    subject_ref: EvidenceRef | None = None
    policy_bundle_version: str = ""
    chain_mode: ChainMode = "enforce"
    links: tuple[AuditLink, ...] = ()
    sequence: int | None = None
    key_id: str = ""
    chain_id: str = ""
    hash_schema_version: Literal[1, 2, 3, 4, 5, 6, 7, 8] = 8
    event_hash: str = ""
    prev_hash: str = ""

    @model_validator(mode="before")
    @classmethod
    def _classify_unversioned_hash_schema(cls, data: Any) -> Any:
        """Classify historical records independently of their audit backend.

        Persisted v1 records predate ``hash_schema_version`` and already carry
        a hash. New in-memory events are unhashed and use v8. Keeping this
        distinction here prevents a custom backend from reinterpreting old
        signed bytes as the new event shape.
        """
        if not isinstance(data, dict) or "hash_schema_version" in data:
            return data
        classified = dict(data)
        classified["hash_schema_version"] = (
            1 if data.get("event_hash") or data.get("prev_hash") else 8
        )
        return classified

    @model_validator(mode="after")
    def _validate_guardrail_mode(self) -> AuditEvent:
        if self.chain_mode == "off" and self.guardrail_evaluations:
            raise ValueError("off-mode events cannot contain guardrail evaluations")
        expected = self.chain_mode == "enforce"
        if any(evaluation.enforced is not expected for evaluation in self.guardrail_evaluations):
            raise ValueError(
                f"guardrail evaluation enforcement conflicts with {self.chain_mode} mode"
            )
        return self

    @model_validator(mode="after")
    def _validate_hitl_event(self) -> AuditEvent:
        expected_states: dict[str, str] = {
            "escalation_requested": "requested",
            "approval_granted": "approved",
            "approval_denied": "denied",
            "approval_expired": "expired",
            "escalation_resumed": "approved",
        }
        expected = expected_states.get(self.event_type)
        if expected is None:
            if self.hitl_evidence is not None:
                raise ValueError("HITL evidence requires a HITL lifecycle event type")
        elif self.hitl_evidence is None or self.hitl_evidence.state != expected:
            raise ValueError(f"{self.event_type} requires {expected} HITL evidence")
        return self

    @model_validator(mode="after")
    def _validate_reconciliation_event(self) -> AuditEvent:
        expected_states: dict[str, str] = {
            "execution_in_doubt": "in_doubt",
            "execution_reconciliation_resumed": "resumed",
            "execution_reconciled": "reconciled",
        }
        expected = expected_states.get(self.event_type)
        if expected is None:
            if self.reconciliation_evidence is not None:
                raise ValueError("reconciliation evidence requires a reconciliation event type")
        elif self.reconciliation_evidence is None or self.reconciliation_evidence.state != expected:
            raise ValueError(f"{self.event_type} requires {expected} reconciliation evidence")
        return self

    @model_validator(mode="after")
    def _validate_authentication_event(self) -> AuditEvent:
        expected_states: dict[str, str] = {
            "authentication_succeeded": "verified",
            "authentication_rejected": "rejected",
        }
        expected = expected_states.get(self.event_type)
        if expected is None:
            if self.authentication_evidence is not None:
                raise ValueError("authentication evidence requires an authentication event type")
        elif self.authentication_evidence is None or self.authentication_evidence.state != expected:
            raise ValueError(f"{self.event_type} requires {expected} authentication evidence")
        else:
            evidence = self.authentication_evidence
            if self.action != "authenticate" or self.resource != "agent":
                raise ValueError("authentication lifecycle events use only generic action/resource")
            if (
                self.permission_context.requested_action != "authenticate"
                or self.permission_context.resource != "agent"
                or self.permission_context.context
                or self.policy_results
                or self.guardrail_evaluations
                or self.payload_digest
                or self.payload_redacted
                or self.subject_ref is not None
                or self.policy_bundle_version
                or self.links
            ):
                raise ValueError("authentication lifecycle events cannot carry request data")
            if expected == "rejected":
                assert evidence.failure_reason is not None
                reserved = self.permission_context.agent
                if (
                    self.result != "rejected"
                    or self.agent_id != UNAUTHENTICATED_AGENT_ID
                    or reserved.agent_id != UNAUTHENTICATED_AGENT_ID
                    or reserved.name != UNAUTHENTICATED_AGENT_NAME
                    or reserved.roles
                    or reserved.metadata
                    or self.permission_context.granted
                    or self.permission_context.reason != evidence.failure_reason.value
                    or self.reason_codes != (evidence.failure_reason.value,)
                ):
                    raise ValueError(
                        "rejected authentication must use the reserved secret-free actor"
                    )
            elif (
                self.result != "allowed"
                or self.agent_id != evidence.agent_id
                or self.permission_context.agent.agent_id != evidence.agent_id
                or not self.permission_context.granted
                or self.permission_context.reason
                or self.reason_codes
            ):
                raise ValueError("verified authentication identity fields must agree")
        return self

    @model_validator(mode="after")
    def _validate_registry_mutation_event(self) -> AuditEvent:
        expected_states = {
            "registry_mutation_authorized": "authorized",
            "registry_mutation_rejected": "rejected",
        }
        expected = expected_states.get(self.event_type)
        if expected is None:
            if self.registry_mutation_evidence is not None:
                raise ValueError("registry mutation evidence requires a registry event type")
            return self
        evidence = self.registry_mutation_evidence
        if evidence is None or evidence.state != expected:
            raise ValueError(f"{self.event_type} requires {expected} registry evidence")
        action = f"registry.{evidence.mutation}"
        resource = f"agent_registry:{evidence.registry_id}"
        if self.action != action or self.resource != resource:
            raise ValueError("registry lifecycle event action/resource mismatch")
        if (
            self.agent_id != evidence.principal_id
            or self.permission_context.agent.agent_id != evidence.principal_id
            or self.permission_context.agent.name != evidence.principal_id
            or self.permission_context.agent.roles
            or self.permission_context.agent.metadata
            or self.permission_context.requested_action != action
            or self.permission_context.resource != resource
            or self.permission_context.context
            or self.policy_results
            or self.guardrail_evaluations
            or self.hitl_evidence is not None
            or self.reconciliation_evidence is not None
            or self.authentication_evidence is not None
            or self.payload_digest
            or self.payload_redacted
            or self.subject_ref is not None
            or self.policy_bundle_version
            or self.links
        ):
            raise ValueError("registry lifecycle events cannot carry request data")
        if expected == "authorized":
            if (
                self.result != "allowed"
                or not self.permission_context.granted
                or self.permission_context.reason
                or self.reason_codes
            ):
                raise ValueError("authorized registry mutation envelope is inconsistent")
        else:
            assert evidence.failure_reason is not None
            if (
                self.result != "rejected"
                or self.permission_context.granted
                or self.permission_context.reason != evidence.failure_reason.value
                or self.reason_codes != (evidence.failure_reason.value,)
            ):
                raise ValueError("rejected registry mutation envelope is inconsistent")
        return self


class SandboxResult(BaseModel):
    """Result from sandboxed tool execution.

    Args:
        stdout: Standard output from the tool.
        stderr: Standard error from the tool.
        exit_code: Process exit code (0 = success).
        duration_ms: Execution time in milliseconds.
        backend: Sandbox backend used — "docker", "wasm", or "none".
    """

    model_config = ConfigDict(frozen=True)

    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    backend: Literal["docker", "wasm", "none"]
    failure_reason: str | None = None

    @property
    def success(self) -> bool:
        """True if exit_code is 0."""
        return self.exit_code == 0

    @property
    def reason_code(self) -> str:
        """Return a stable failure classification without parsing stderr."""

        if self.success:
            return ""
        return self.failure_reason or "SANDBOX.PROCESS_EXIT_NONZERO"
