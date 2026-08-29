"""Injected authentication and protection contracts for resumable HITL work."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import Enum
from math import isfinite
from typing import Annotated, Any, Literal, Protocol, TypeAlias, runtime_checkable

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    TypeAdapter,
    field_serializer,
    field_validator,
    model_serializer,
    model_validator,
)

from agentguard.core.authentication import AuthenticatedAgentPrincipal
from agentguard.core.registry_state import SignedAuditReference
from agentguard.guardrails.chain import ChainCursor, EvaluatedDecision
from agentguard.guardrails.contracts import (
    DecisionPayload,
    GuardrailOutcome,
    GuardrailPayload,
    GuardrailStage,
    ToolResultPayload,
)
from agentguard.guardrails.executors import ExecutorRef
from agentguard.guardrails.normalization import (
    canonical_json_bytes,
    normalize_payload,
    thaw_payload,
)
from agentguard.models import AuditLink, EvidenceRef, PermissionContext, PolicyResult

from .engine import PolicyBundleSnapshot

ContinuationKind: TypeAlias = Literal["pre_execution_continuation", "post_execution_continuation"]
_PRE_CONTINUATION_KIND: Literal["pre_execution_continuation"] = "pre_execution_continuation"


class ApprovalDisposition(str, Enum):  # noqa: UP042 - preserve public enum string semantics
    """An authenticated human's requested escalation disposition."""

    APPROVE = "approve"
    DENY = "deny"


ApproverCapability: TypeAlias = Literal[
    "hitl:approve",
    "hitl:deny",
    "hitl:reconcile",
]


class ApproverPrincipal(BaseModel):
    """Identity established by an injected credential authenticator."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    approver_id: str = Field(min_length=1, max_length=256)
    capabilities: frozenset[ApproverCapability] = frozenset()


@runtime_checkable
class ApproverAuthenticator(Protocol):
    """Authenticate opaque caller credentials without trusting request identity fields."""

    async def authenticate(self, credential: object) -> ApproverPrincipal: ...


class SealedContinuation(BaseModel):
    """Opaque output of an application-injected authenticated-encryption provider."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    kind: Literal["sealed_continuation"] = "sealed_continuation"
    algorithm: str = Field(min_length=1, max_length=128)
    key_id: str = Field(min_length=1, max_length=256)
    nonce: bytes = Field(min_length=1)
    ciphertext: bytes = Field(min_length=1)


@runtime_checkable
class ContinuationProtector(Protocol):
    """Seal and open continuation bytes using authenticated encryption and explicit AAD."""

    async def seal(self, plaintext: bytes, *, aad: bytes) -> SealedContinuation: ...

    async def open(self, sealed: SealedContinuation, *, aad: bytes) -> bytes: ...


class WorkloadAuthenticationBinding(BaseModel):
    """Authoritative authentication and registry state pinned into resumable work."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    principal: AuthenticatedAgentPrincipal
    registry_id: str = Field(min_length=1, max_length=256)
    registry_revision: int = Field(ge=0)
    record_revision: int = Field(ge=1)
    credential_epoch: int = Field(ge=1)
    audit_reference: SignedAuditReference

    @field_validator("registry_id")
    @classmethod
    def _validate_registry_id(cls, value: str) -> str:
        if value != value.strip() or not value.isprintable():
            raise ValueError("registry_id must be canonical printable text")
        return value


class PreExecutionContinuation(BaseModel):
    """Exact protected state needed to resume before an executor is invoked."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1, 2, 3] = 1
    kind: Literal["pre_execution_continuation"] = "pre_execution_continuation"
    escalation_id: str = Field(min_length=1, max_length=256)
    invocation_id: str = Field(min_length=1, max_length=256)
    trace_id: str = Field(min_length=1, max_length=256)
    agent_id: str = Field(min_length=1, max_length=256)
    authentication_binding: WorkloadAuthenticationBinding | None = None
    subject_ref: EvidenceRef | None = None
    links: tuple[AuditLink, ...] = ()
    redacted_evidence: Any = None
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    permission_context: PermissionContext
    stage: GuardrailStage
    payload: GuardrailPayload
    payload_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_bundle_version: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_bundle_snapshot: PolicyBundleSnapshot | None = None
    policy_results: tuple[PolicyResult, ...] = ()
    input_decisions: tuple[EvaluatedDecision, ...] = ()
    pre_runtime_outcomes: tuple[GuardrailOutcome, ...] = ()
    guardrail_cursor: ChainCursor
    executor_ref: ExecutorRef
    created_at: datetime
    expires_at: datetime

    @field_validator("stage")
    @classmethod
    def _validate_stage(cls, value: GuardrailStage) -> GuardrailStage:
        if value not in {GuardrailStage.PRE_TOOL, GuardrailStage.PRE_MESSAGE}:
            raise ValueError("continuations support only pre_tool and pre_message stages")
        return value

    @field_validator("created_at", "expires_at")
    @classmethod
    def _normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("continuation timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_bound_state(self) -> PreExecutionContinuation:
        self._validate_authentication_binding()
        self._validate_evidence_links()
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        if self.guardrail_cursor.stage is not self.stage:
            raise ValueError("cursor stage does not match continuation stage")
        if self.guardrail_cursor.payload != self.payload:
            raise ValueError("cursor payload does not match continuation payload")
        if isinstance(self.payload, ToolResultPayload):
            raise ValueError("pre-execution continuations cannot contain tool results")
        if (
            self.permission_context.agent.agent_id != self.agent_id
            or self.permission_context.requested_action != self.action
            or self.permission_context.resource != self.resource
        ):
            raise ValueError("permission context does not match continuation subject")
        if (
            self.policy_bundle_snapshot is not None
            and self.policy_bundle_snapshot.version != self.policy_bundle_version
        ):
            raise ValueError("policy bundle snapshot does not match the pinned version")
        digest = hashlib.sha256(
            canonical_json_bytes(self.payload.model_dump(mode="json"))
        ).hexdigest()
        if digest != self.payload_digest:
            raise ValueError("payload_digest does not match continuation payload")
        return self

    @model_serializer(mode="wrap")
    def _serialize_versioned_fields(self, handler: SerializerFunctionWrapHandler) -> Any:
        serialized = handler(self)
        if isinstance(serialized, dict):
            if self.schema_version == 1:
                serialized.pop("authentication_binding", None)
            if self.schema_version in {1, 2}:
                serialized.pop("subject_ref", None)
                serialized.pop("links", None)
                serialized.pop("redacted_evidence", None)
        return serialized

    @field_validator("redacted_evidence", mode="before")
    @classmethod
    def _normalize_redacted_evidence(cls, value: Any) -> Any:
        return None if value is None else normalize_payload(value)

    @field_serializer("redacted_evidence", when_used="json")
    def _serialize_redacted_evidence(self, value: Any) -> Any:
        return None if value is None else thaw_payload(value)

    def _validate_authentication_binding(self) -> None:
        if self.schema_version == 1:
            if self.authentication_binding is not None:
                raise ValueError("schema v1 continuation cannot contain authentication binding")
            return
        if self.schema_version == 2 and self.authentication_binding is None:
            raise ValueError("schema v2 continuation requires authentication binding")
        if (
            self.authentication_binding is not None
            and self.authentication_binding.principal.agent_id != self.agent_id
        ):
            raise ValueError("authentication binding does not match continuation agent")

    def _validate_evidence_links(self) -> None:
        _validate_continuation_evidence_links(
            schema_version=self.schema_version,
            subject_ref=self.subject_ref,
            links=self.links,
            redacted_evidence=self.redacted_evidence,
        )


class PostExecutionContinuation(BaseModel):
    """Exact protected result and state needed to resume post-processing only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1, 2, 3] = 1
    kind: Literal["post_execution_continuation"] = "post_execution_continuation"
    escalation_id: str = Field(min_length=1, max_length=256)
    invocation_id: str = Field(min_length=1, max_length=256)
    trace_id: str = Field(min_length=1, max_length=256)
    agent_id: str = Field(min_length=1, max_length=256)
    authentication_binding: WorkloadAuthenticationBinding | None = None
    subject_ref: EvidenceRef | None = None
    links: tuple[AuditLink, ...] = ()
    redacted_evidence: Any = None
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    permission_context: PermissionContext
    stage: GuardrailStage
    payload: ToolResultPayload | DecisionPayload
    payload_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_bundle_version: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    policy_bundle_snapshot: PolicyBundleSnapshot
    policy_results: tuple[PolicyResult, ...] = ()
    prior_outcomes: tuple[GuardrailOutcome, ...] = ()
    prior_guardrail_decisions: tuple[EvaluatedDecision, ...] = ()
    guardrail_cursor: ChainCursor | None = None
    chain_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_duration_ms: float
    execution_completed_at: datetime
    created_at: datetime
    expires_at: datetime

    @field_validator("stage")
    @classmethod
    def _validate_stage(cls, value: GuardrailStage) -> GuardrailStage:
        if value not in {
            GuardrailStage.POST_TOOL,
            GuardrailStage.POST_MESSAGE,
            GuardrailStage.ON_DECISION,
        }:
            raise ValueError(
                "continuations support only post_tool, post_message, and on_decision stages"
            )
        return value

    @field_validator("execution_duration_ms")
    @classmethod
    def _validate_execution_duration(cls, value: float) -> float:
        if value < 0 or not isfinite(value):
            raise ValueError("execution_duration_ms must be finite and nonnegative")
        return value

    @field_validator("execution_completed_at", "created_at", "expires_at")
    @classmethod
    def _normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("continuation timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_bound_state(self) -> PostExecutionContinuation:
        self._validate_authentication_binding()
        self._validate_evidence_links()
        if self.execution_completed_at > self.created_at:
            raise ValueError("execution_completed_at cannot be later than created_at")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        if (
            self.permission_context.agent.agent_id != self.agent_id
            or self.permission_context.requested_action != self.action
            or self.permission_context.resource != self.resource
        ):
            raise ValueError("permission context does not match continuation subject")
        if self.policy_bundle_snapshot.version != self.policy_bundle_version:
            raise ValueError("policy bundle snapshot does not match the pinned version")
        if self.stage is GuardrailStage.ON_DECISION:
            if not isinstance(self.payload, DecisionPayload):
                raise ValueError("on_decision continuations require a decision payload")
        elif not isinstance(self.payload, ToolResultPayload):
            raise ValueError("tool/message continuations require a tool result payload")
        digest = hashlib.sha256(
            canonical_json_bytes(self.payload.model_dump(mode="json"))
        ).hexdigest()
        if digest != self.payload_digest:
            raise ValueError("payload_digest does not match continuation payload")
        if self.guardrail_cursor is not None:
            if self.guardrail_cursor.stage is not self.stage:
                raise ValueError("cursor stage does not match continuation stage")
            if self.guardrail_cursor.payload != self.payload:
                raise ValueError("cursor payload does not match continuation payload")
            if self.guardrail_cursor.chain_fingerprint != self.chain_fingerprint:
                raise ValueError("cursor chain fingerprint does not match continuation")
        return self

    @model_serializer(mode="wrap")
    def _serialize_versioned_fields(self, handler: SerializerFunctionWrapHandler) -> Any:
        serialized = handler(self)
        if isinstance(serialized, dict):
            if self.schema_version == 1:
                serialized.pop("authentication_binding", None)
            if self.schema_version in {1, 2}:
                serialized.pop("subject_ref", None)
                serialized.pop("links", None)
                serialized.pop("redacted_evidence", None)
        return serialized

    @field_validator("redacted_evidence", mode="before")
    @classmethod
    def _normalize_redacted_evidence(cls, value: Any) -> Any:
        return None if value is None else normalize_payload(value)

    @field_serializer("redacted_evidence", when_used="json")
    def _serialize_redacted_evidence(self, value: Any) -> Any:
        return None if value is None else thaw_payload(value)

    def _validate_authentication_binding(self) -> None:
        if self.schema_version == 1:
            if self.authentication_binding is not None:
                raise ValueError("schema v1 continuation cannot contain authentication binding")
            return
        if self.schema_version == 2 and self.authentication_binding is None:
            raise ValueError("schema v2 continuation requires authentication binding")
        if (
            self.authentication_binding is not None
            and self.authentication_binding.principal.agent_id != self.agent_id
        ):
            raise ValueError("authentication binding does not match continuation agent")

    def _validate_evidence_links(self) -> None:
        _validate_continuation_evidence_links(
            schema_version=self.schema_version,
            subject_ref=self.subject_ref,
            links=self.links,
            redacted_evidence=self.redacted_evidence,
        )


def _validate_continuation_evidence_links(
    *,
    schema_version: Literal[1, 2, 3],
    subject_ref: EvidenceRef | None,
    links: tuple[AuditLink, ...],
    redacted_evidence: Any,
) -> None:
    has_extended_evidence = subject_ref is not None or bool(links) or redacted_evidence is not None
    if schema_version in {1, 2} and has_extended_evidence:
        raise ValueError("continuation evidence fields require schema v3")
    if schema_version == 3 and not has_extended_evidence:
        raise ValueError("schema v3 continuation requires evidence fields")
    refs = ([subject_ref] if subject_ref is not None else []) + [link.target for link in links]
    for ref in refs:
        for field_name, text in (("namespace", ref.namespace), ("value", ref.value)):
            if not text or text != text.strip() or not text.isprintable():
                raise ValueError(
                    f"continuation evidence {field_name} must be canonical printable text"
                )
    seen: set[tuple[str, str, str]] = set()
    for link in links:
        key = (link.relation, link.target.namespace, link.target.value)
        if key in seen:
            raise ValueError("continuation audit links must be unique")
        seen.add(key)


ProtectedContinuation: TypeAlias = Annotated[
    PreExecutionContinuation | PostExecutionContinuation,
    Field(discriminator="kind"),
]
_PROTECTED_CONTINUATION_ADAPTER: TypeAdapter[ProtectedContinuation] = TypeAdapter(
    ProtectedContinuation
)


def parse_protected_continuation(value: bytes | str) -> ProtectedContinuation:
    """Parse protected plaintext without allowing PRE/POST kind substitution."""

    return _PROTECTED_CONTINUATION_ADAPTER.validate_json(value)


def canonical_continuation_aad(
    escalation_id: str,
    *,
    kind: ContinuationKind = _PRE_CONTINUATION_KIND,
    schema_version: Literal[1, 2, 3] = 1,
) -> bytes:
    """Return canonical AAD binding a sealed blob to its exact schema and request."""

    if not escalation_id or len(escalation_id) > 256:
        raise ValueError("escalation_id must contain between 1 and 256 characters")
    if kind not in {_PRE_CONTINUATION_KIND, "post_execution_continuation"}:
        raise ValueError("unsupported continuation kind")
    if schema_version not in {1, 2, 3}:
        raise ValueError("unsupported continuation schema version")
    return canonical_json_bytes(
        {
            "schema_version": schema_version,
            "kind": kind,
            "escalation_id": escalation_id,
        }
    )
