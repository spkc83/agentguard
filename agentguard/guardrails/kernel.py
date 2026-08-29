"""Framework-independent fail-closed governance kernel.

The trusted call path is intentionally ordered:

    immutable input -> input transforms -> derive action/resource -> RBAC
    -> staged policy/guardrails -> limits -> admission audit -> execute
    -> execution audit -> post policy/guardrails -> delivery audit

Raw runtime payloads never enter persisted evidence. Audit events carry only a
bounded redacted snapshot and digest. Input transforms run before action and
resource derivation so the object authorized by RBAC is the object executed.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import math
import posixpath
import threading
import time
import unicodedata
import uuid
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal, NoReturn, cast

import structlog

from agentguard.compliance.continuation import (
    ApprovalDisposition,
    ApproverAuthenticator,
    ApproverPrincipal,
    ContinuationProtector,
    PostExecutionContinuation,
    PreExecutionContinuation,
    ProtectedContinuation,
    WorkloadAuthenticationBinding,
    canonical_continuation_aad,
    parse_protected_continuation,
)
from agentguard.compliance.continuation import (
    ContinuationKind as ProtectedContinuationKind,
)
from agentguard.compliance.engine import PolicyBundle, PolicyEngine
from agentguard.compliance.escalation_store import (
    ApprovedEscalation,
    DecisionDisposition,
    EscalationExpiredError,
    EscalationRecord,
    EscalationStateError,
    EscalationStore,
)
from agentguard.compliance.escalation_store import (
    ContinuationKind as StoreContinuationKind,
)
from agentguard.compliance.execution_journal import (
    ExecutionJournal,
    ExecutionJournalError,
    ExecutionJournalNotFoundError,
    ExecutionJournalRecord,
    ExecutionJournalStatus,
    InDoubtClassification,
    ProtectedExecutionOutcome,
)
from agentguard.core.authentication import (
    AgentAuthenticator,
    AgentCredentialProvider,
    AuthenticatedAgentPrincipal,
    AuthenticationAttempt,
)
from agentguard.core.registry import (
    AgentRegistryRecord,
    AgentStatus,
    AuthoritativeAgentRegistry,
)
from agentguard.core.registry_state import SignedAuditReference
from agentguard.core.sandbox import (
    SANDBOX_BACKEND_REQUIRED,
    SANDBOX_COMMAND_INVALID,
    SANDBOX_INTERNAL_ERROR,
    SANDBOX_OBLIGATION_CONFLICT,
    SANDBOX_REQUIRED,
    DockerSandboxBackend,
    SandboxObligation,
    validate_sandbox_command,
)
from agentguard.exceptions import (
    AuthenticationError,
    AuthenticationFailure,
    CircuitOpenError,
    EscalationRequiredError,
    PermissionDeniedError,
    RateLimitExceededError,
    SandboxError,
)
from agentguard.models import (
    UNAUTHENTICATED_AGENT_ID,
    UNAUTHENTICATED_AGENT_NAME,
    AgentIdentity,
    AuditEvent,
    AuditLink,
    AuthenticationEvidence,
    EvidenceRef,
    GuardrailEvaluation,
    HitlEvidence,
    PermissionContext,
    PolicyResult,
    ReconciliationEvidence,
)

from .chain import ChainCursor, ChainMode, ChainResult, EvaluatedDecision, GuardrailChain
from .content import (
    EvidenceSnapshot,
    PiiEgressGuardrail,
    PiiInputGuardrail,
    SecretEgressGuardrail,
)
from .contracts import (
    DecisionPayload,
    Guardrail,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailPayload,
    GuardrailStage,
    IdentitySnapshot,
    MessagePayload,
    ToolCallPayload,
    ToolResultPayload,
)
from .normalization import (
    canonical_json_bytes,
    normalize_payload,
    thaw_payload,
)
from .reason_codes import (
    CIRCUIT_BREAKER_OPEN,
    DELIVERY_CANCELLED,
    EXECUTION_ADMISSION_WITHOUT_COMPLETION,
    EXECUTION_CANCELLED,
    EXECUTION_CLAIMED_WITHOUT_TERMINAL,
    EXECUTION_COMPLETION_WITHOUT_PROTECTED_RESULT,
    EXECUTION_FAILED,
    EXECUTION_PROTECTED_RESULT_AVAILABLE,
    EXECUTION_RECONCILED_DENY,
    GUARDRAIL_INTERNAL_ERROR,
    GUARDRAIL_TIMEOUT,
    INPUT_INVALID,
    OUTPUT_SCHEMA_INVALID,
    RATE_LIMIT_EXCEEDED,
    RBAC_PERMISSION_DENIED,
    RESOURCE_UNRESOLVED,
    RUNTIME_REASON_CODES,
)

if TYPE_CHECKING:
    from agentguard.compliance.escalation_store import CreatedEscalation
    from agentguard.core.audit import AuditLog
    from agentguard.core.circuit_breaker import CircuitBreaker, TokenBucketRateLimiter
    from agentguard.core.identity import AgentRegistry
    from agentguard.core.rbac import RBACEngine
    from agentguard.observability.tracer import AgentTracer

    from .executors import ExecutorRef, ExecutorResolver

logger = structlog.get_logger()
_ACTIVE_TRACER: ContextVar[AgentTracer | None] = ContextVar(
    "agentguard_active_tracer", default=None
)
_ACTIVE_SUBJECT_REF: ContextVar[EvidenceRef | None] = ContextVar(
    "agentguard_active_subject_ref", default=None
)
_ACTIVE_AUDIT_LINKS: ContextVar[tuple[AuditLink, ...]] = ContextVar(
    "agentguard_active_audit_links", default=()
)

UNRESOLVED_RESOURCE = "<unresolved>"
UNRESOLVED_ACTION = "<unresolved>"

ResourceResolver = str | Callable[[Any], "str | Awaitable[str]"]
ActionResolver = str | Callable[[Any], "str | Awaitable[str]"]

_FNMATCH_METACHARS = frozenset("*?[]")
_RESERVED_CHARS = frozenset("<>")
_DEFAULT_RESOLVER_TIMEOUT = 1.0
_DEFAULT_GUARDRAIL_TIMEOUT = 1.0
_DEFAULT_ESCALATION_TTL = timedelta(minutes=15)


@dataclass(frozen=True, slots=True)
class ReconciliationAssessment:
    """Authenticated classification of one claimed protected execution."""

    escalation_id: str
    claim_id: str
    invocation_id: str
    status: ExecutionJournalStatus
    classification: InDoubtClassification | None
    protected_result_available: bool


@dataclass(frozen=True, slots=True)
class _AuthenticatedWorkload:
    """Registry-owned runtime identity plus the exact resumable trust binding."""

    identity: AgentIdentity
    binding: WorkloadAuthenticationBinding


class _WorkloadBindingError(EscalationStateError):
    """Safe sticky-binding denial raised during credential-free resumption."""

    def __init__(self, failure: AuthenticationFailure) -> None:
        self.failure = failure
        self.reason_code = failure.value
        super().__init__(failure.value)


@dataclass(frozen=True, slots=True)
class AdapterToolCall:
    """Deferred caller-supplied executor request observed only after authentication."""

    action: ActionResolver
    resource: ResourceResolver | None
    executor: Callable[[GuardrailPayload], Awaitable[Any]]
    payload: ToolCallPayload | MessagePayload | None = None
    fallback_action: str | None = None


@dataclass(frozen=True, slots=True)
class AdapterRegisteredToolCall:
    """Deferred trusted-executor request observed only after authentication."""

    action: ActionResolver
    resource: ResourceResolver | None
    executor_id: str
    payload: ToolCallPayload | MessagePayload | None = None
    fallback_action: str | None = None


@dataclass(frozen=True, slots=True)
class GovernedAdapterCaller:
    """Mode-neutral adapter boundary bound to exactly one identity source."""

    _kernel: GovernanceKernel
    _agent_id: str | None
    _credential_provider: AgentCredentialProvider | None

    async def guarded_tool_call(self, factory: Callable[[], AdapterToolCall]) -> Any:
        invocation_id, trace_id, authenticated = await self._prepare_call()
        request = factory()
        if not isinstance(request, AdapterToolCall):
            raise TypeError("adapter request factory must return AdapterToolCall")
        return await self._kernel._guarded_tool_call(
            agent_id=self._agent_id,
            credential=None,
            action=request.action,
            resource=request.resource,
            executor=request.executor,
            payload=request.payload,
            fallback_action=request.fallback_action,
            executor_ref=None,
            invocation_id=invocation_id,
            trace_id=trace_id,
            authenticated_override=authenticated,
        )

    async def guarded_registered_tool_call(
        self,
        factory: Callable[[], AdapterRegisteredToolCall],
    ) -> Any:
        invocation_id, trace_id, authenticated = await self._prepare_call()
        request = factory()
        if not isinstance(request, AdapterRegisteredToolCall):
            raise TypeError("adapter request factory must return AdapterRegisteredToolCall")
        return await self._kernel._guarded_tool_call(
            agent_id=self._agent_id,
            credential=None,
            action=request.action,
            resource=request.resource,
            executor=None,
            payload=request.payload,
            fallback_action=request.fallback_action,
            executor_ref=None,
            executor_id=request.executor_id,
            invocation_id=invocation_id,
            trace_id=trace_id,
            authenticated_override=authenticated,
        )

    async def _prepare_call(
        self,
    ) -> tuple[str, str, _AuthenticatedWorkload | None]:
        invocation_id = str(uuid.uuid4())
        trace_id = str(uuid.uuid4())
        provider = self._credential_provider
        if provider is None:
            return invocation_id, trace_id, None

        provider_failed = False
        credential: object | None = None
        try:
            credential = await provider.get_credential()
        except asyncio.CancelledError:
            raise
        except Exception:
            provider_failed = True
        if provider_failed or credential is None:
            await self._kernel._reject_authentication(
                AuthenticationFailure.PROVIDER_FAILURE,
                AuthenticationAttempt.for_provider_failure(),
                invocation_id=invocation_id,
                trace_id=trace_id,
            )
        authenticated = await self._kernel._authenticate_workload(
            credential,
            invocation_id=invocation_id,
            trace_id=trace_id,
        )
        return invocation_id, trace_id, authenticated


class _ResumingGuardrailChain:
    """Replay protected INPUT evidence and continue one PRE-stage cursor."""

    def __init__(
        self,
        base: GuardrailChain,
        continuation: PreExecutionContinuation,
    ) -> None:
        self._base = base
        self._continuation = continuation

    @property
    def mode(self) -> ChainMode:
        return self._base.mode

    @property
    def approved_cursor(self) -> ChainCursor:
        return self._continuation.guardrail_cursor

    @property
    def approved_escalations(self) -> frozenset[tuple[str, str]]:
        cursor = self._continuation.guardrail_cursor
        indexes = (*cursor.approved_escalation_indexes, cursor.next_entry_index - 1)
        descriptors = self._base.descriptor.guardrails
        return frozenset(
            (
                descriptors[index].guardrail_id,
                descriptors[index].guardrail_version,
            )
            for index in indexes
        )

    @property
    def resumable(self) -> bool:
        return self._base.resumable

    @property
    def fingerprint(self) -> str:
        return self._base.fingerprint

    async def run(self, context: GuardrailContext) -> ChainResult:
        if context.stage is GuardrailStage.INPUT:
            return ChainResult(
                mode=self.mode,
                decisions=self._continuation.input_decisions,
                payload=self._continuation.payload,
            )
        if context.stage is self._continuation.stage:
            return await self._base.resume(context, self._continuation.guardrail_cursor)
        return await self._base.run(context)


def _approved_escalations(
    chain: GuardrailChain,
    cursor: ChainCursor,
) -> frozenset[tuple[str, str]]:
    """Return guardrail identities whose authenticated escalations are approved."""

    indexes = (*cursor.approved_escalation_indexes, cursor.next_entry_index - 1)
    descriptors = chain.descriptor.guardrails
    return frozenset(
        (
            descriptors[index].guardrail_id,
            descriptors[index].guardrail_version,
        )
        for index in indexes
    )


def _continuation_reason_codes(
    continuation: ProtectedContinuation,
) -> tuple[str, ...]:
    """Extract the triggering codes without assuming a PRE-only cursor."""

    cursor = continuation.guardrail_cursor
    if cursor is not None and cursor.decisions:
        return cursor.decisions[-1].decision.reason_codes
    if isinstance(continuation, PostExecutionContinuation):
        codes = _reason_codes(continuation.prior_outcomes, continuation.policy_results)
        if codes:
            return codes
    return (GUARDRAIL_INTERNAL_ERROR,)


def _continuation_schema_kind(
    kind: StoreContinuationKind | None,
) -> ProtectedContinuationKind:
    """Map signed store metadata to the continuation schema discriminator."""

    if kind is StoreContinuationKind.POST_DELIVERY:
        return "post_execution_continuation"
    return "pre_execution_continuation"


def _set_span_attribute(span: Any, key: str, value: Any) -> None:
    setter = getattr(span, "set_attribute", None)
    if callable(setter):
        try:
            setter(key, value)
        except BaseException:
            logger.debug("otel_attribute_write_failed", exc_info=True)


@contextmanager
def _safe_span(
    tracer: AgentTracer | None,
    name: str,
    attributes: dict[str, Any],
) -> Any:
    if tracer is None:
        yield None
        return
    try:
        manager = tracer.span(name, attributes=attributes)
        span = manager.__enter__()
    except BaseException:
        logger.debug("otel_span_creation_failed", span_name=name, exc_info=True)
        yield None
        return
    try:
        yield span
    except BaseException as exc:
        try:
            manager.__exit__(type(exc), exc, exc.__traceback__)
        except BaseException:
            logger.debug("otel_span_end_failed", span_name=name, exc_info=True)
        raise
    else:
        try:
            manager.__exit__(None, None, None)
        except BaseException:
            logger.debug("otel_span_end_failed", span_name=name, exc_info=True)


class _ResolverExecutor:
    """Bound synchronous resolver work without orphan-queue growth."""

    def __init__(self, max_workers: int = 4) -> None:
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="agentguard-resolver",
        )
        self._capacity = threading.BoundedSemaphore(max_workers)

    async def call(
        self,
        resolver: Callable[[Any], str | Awaitable[str]],
        call_input: Any,
        timeout: float,
    ) -> Any:
        if inspect.iscoroutinefunction(resolver):
            return await asyncio.wait_for(resolver(call_input), timeout=timeout)

        if not self._capacity.acquire(blocking=False):
            raise TimeoutError("resolver capacity exhausted")
        try:
            future = self._pool.submit(resolver, call_input)
        except BaseException:
            self._capacity.release()
            raise
        future.add_done_callback(lambda _future: self._capacity.release())

        wrapped = asyncio.wrap_future(future)
        result = await asyncio.wait_for(asyncio.shield(wrapped), timeout=timeout)
        if inspect.isawaitable(result):
            return await asyncio.wait_for(result, timeout=timeout)
        return result


_RESOLVER_EXECUTOR = _ResolverExecutor()


@lru_cache(maxsize=1)
def default_policy_engine() -> PolicyEngine:
    """Return the process-wide immutable built-in policy bundle."""
    return PolicyEngine()


def default_guardrails() -> tuple[Guardrail, ...]:
    """Return the default input and egress content controls."""
    return (PiiInputGuardrail(), PiiEgressGuardrail(), SecretEgressGuardrail())


def _has_unsafe_char(text: str) -> bool:
    """Reject characters that do not render but change matching or the audit trail.

    C0/DEL, C1 controls, and format characters (soft hyphen, zero-width
    space/joiner, word joiner, BOM, bidi overrides) are invisible to a policy
    author and to anyone reading an audit event, yet ``fnmatchcase`` treats
    ``admin​/keys`` and ``admin/keys`` as different resources — a
    deny-override bypass. Combining marks (Mn/Me) are attached to a base
    character and can likewise hide a distinct byte sequence.
    """
    for ch in text:
        if ch < " " or ch == "\x7f":
            return True
        if unicodedata.category(ch) in {"Cc", "Cf", "Mn", "Me"}:
            return True
    return False


def canonicalize_action(raw: str) -> str | None:
    """Canonicalize a derived action or reject attacker-controlled patterns."""
    normalized = unicodedata.normalize("NFKC", raw).strip()
    if not normalized:
        return None
    if any(ch in _FNMATCH_METACHARS or ch in _RESERVED_CHARS for ch in normalized):
        return None
    if _has_unsafe_char(normalized):
        return None
    return normalized.casefold()


def canonicalize_resource(raw: str) -> str | None:
    """Canonicalize a derived RBAC resource or reject unsafe values."""
    stripped = unicodedata.normalize("NFKC", raw).strip()
    if not stripped:
        return None
    if any(ch in _FNMATCH_METACHARS or ch in _RESERVED_CHARS for ch in stripped):
        return None
    if _has_unsafe_char(stripped):
        return None
    if stripped.startswith("/") or ".." in stripped.split("/"):
        return None

    normalized = posixpath.normpath(stripped)
    if normalized in {"", "."} or normalized.startswith("/"):
        return None
    if any(segment == ".." for segment in normalized.split("/")):
        return None
    return normalized.casefold()


async def _resolve(
    resolver: ResourceResolver | ActionResolver | None,
    call_input: Any,
    *,
    timeout: float,
    kind: str,
) -> str | None:
    if resolver is None:
        return None
    if isinstance(resolver, str):
        derived: Any = resolver
    else:
        try:
            derived = await _RESOLVER_EXECUTOR.call(resolver, call_input, timeout)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning(
                "invocation_resolver_failed",
                resolver_kind=kind,
                error_type=type(exc).__name__,
            )
            return None
    if not isinstance(derived, str):
        logger.warning(
            "invocation_resolver_returned_non_str",
            resolver_kind=kind,
            result_type=type(derived).__name__,
        )
        return None
    canonical = canonicalize_action(derived) if kind == "action" else canonicalize_resource(derived)
    if canonical is None:
        logger.warning("invocation_resolver_returned_uncanonical_value", resolver_kind=kind)
    return canonical


async def resolve_resource(
    resolver: ResourceResolver | None,
    call_input: Any,
    *,
    timeout: float = _DEFAULT_RESOLVER_TIMEOUT,
) -> str | None:
    """Resolve a resource through the bounded resolver executor."""
    return await _resolve(resolver, call_input, timeout=timeout, kind="resource")


async def resolve_action(
    resolver: ActionResolver | None,
    call_input: Any,
    *,
    timeout: float = _DEFAULT_RESOLVER_TIMEOUT,
) -> str | None:
    """Resolve an action through the bounded resolver executor."""
    return await _resolve(resolver, call_input, timeout=timeout, kind="action")


def _identity_snapshot(identity: AgentIdentity) -> IdentitySnapshot:
    return IdentitySnapshot(
        agent_id=identity.agent_id,
        name=identity.name,
        roles=tuple(identity.roles),
        metadata=cast("Any", dict(identity.metadata)),
    )


def _native_input(payload: ToolCallPayload | MessagePayload) -> Any:
    if isinstance(payload, ToolCallPayload):
        return thaw_payload(payload.arguments)
    return {
        "target": payload.target,
        "message": thaw_payload(cast("Any", payload.message)),
    }


async def _evaluate_guardrails(
    chain: GuardrailChain | _ResumingGuardrailChain,
    context: GuardrailContext,
) -> ChainResult:
    return await chain.run(context)


def _guardrail_evaluations(
    result: ChainResult,
    stage: GuardrailStage,
) -> tuple[GuardrailEvaluation, ...]:
    return tuple(
        GuardrailEvaluation(
            guardrail_id=record.guardrail_id,
            guardrail_version=record.guardrail_version,
            stage=stage.value,
            effect=record.decision.effect.value,
            reason_codes=record.decision.reason_codes,
            duration_ms=record.duration_ms,
            enforced=record.enforced,
        )
        for record in result.decisions
    )


def _outcome_effect(
    outcomes: Sequence[GuardrailOutcome], effect: GuardrailEffect
) -> GuardrailOutcome | None:
    return next((outcome for outcome in outcomes if outcome.effect is effect), None)


def _reason_codes(
    outcomes: Sequence[GuardrailOutcome], policy_results: Sequence[PolicyResult]
) -> tuple[str, ...]:
    codes = [code for outcome in outcomes for code in outcome.reason_codes]
    codes.extend(
        result.rule_id
        for result in policy_results
        if not result.passed and result.effect in {"deny", "escalate", "warn"}
    )
    return tuple(dict.fromkeys(codes))


def _sanitize_policy_results(results: Sequence[PolicyResult]) -> list[PolicyResult]:
    sanitized: list[PolicyResult] = []
    for result in results:
        snapshot = EvidenceSnapshot.capture(result.evidence)
        evidence = thaw_payload(cast("Any", snapshot.value))
        if not isinstance(evidence, dict):
            raise TypeError("policy evidence must be a mapping")
        sanitized.append(result.model_copy(update={"evidence": evidence}))
    return sanitized


def _permission_evidence(
    permission: PermissionContext,
    snapshot: EvidenceSnapshot | None,
) -> PermissionContext:
    context = {"payload_digest": snapshot.digest} if snapshot is not None else {}
    return permission.model_copy(update={"context": context})


def _validate_evidence_ref(value: EvidenceRef) -> EvidenceRef:
    """Reject ambiguous correlation data before it reaches signed evidence."""

    validated = EvidenceRef.model_validate(value.model_dump(mode="python"))
    for field_name, text in (
        ("namespace", validated.namespace),
        ("value", validated.value),
    ):
        if not text or text != text.strip() or not text.isprintable():
            raise ValueError(f"evidence {field_name} must be canonical printable text")
    return validated


def _validate_evidence_links(
    subject_ref: EvidenceRef | None,
    links: Sequence[AuditLink],
) -> tuple[EvidenceRef | None, tuple[AuditLink, ...]]:
    subject = _validate_evidence_ref(subject_ref) if subject_ref is not None else None
    validated_links: list[AuditLink] = []
    seen: set[tuple[str, str, str]] = set()
    for value in links:
        link = AuditLink.model_validate(value.model_dump(mode="python"))
        target = _validate_evidence_ref(link.target)
        link = link.model_copy(update={"target": target})
        key = (link.relation, target.namespace, target.value)
        if key in seen:
            raise ValueError("audit links must be unique")
        seen.add(key)
        validated_links.append(link)
    return subject, tuple(validated_links)


def _active_evidence_links(
    subject_ref: EvidenceRef | None,
    links: Sequence[AuditLink],
) -> tuple[EvidenceRef | None, tuple[AuditLink, ...]]:
    subject = subject_ref or _ACTIVE_SUBJECT_REF.get()
    combined = (*_ACTIVE_AUDIT_LINKS.get(), *links)
    return _validate_evidence_links(subject, combined)


def _continuation_schema_version(
    authentication_binding: WorkloadAuthenticationBinding | None,
    subject_ref: EvidenceRef | None,
    links: Sequence[AuditLink],
    redacted_evidence: object | None,
) -> Literal[1, 2, 3]:
    if subject_ref is not None or links or redacted_evidence is not None:
        return 3
    return 2 if authentication_binding is not None else 1


def _capture_result_evidence(
    value: object,
    redacted_evidence: object | None,
) -> EvidenceSnapshot:
    if redacted_evidence is None:
        return EvidenceSnapshot.capture(value)
    return EvidenceSnapshot.capture_redacted(value, redacted_evidence)


def _capture_unvalidated_result_evidence(value: object) -> EvidenceSnapshot:
    """Retain only the result digest until post-execution validation succeeds."""

    return EvidenceSnapshot.capture_redacted(value, {})


def _redacted_evidence_attributes(redacted_evidence: object | None) -> Any:
    """Expose the proposed audit projection to POST guardrails, never to audit implicitly."""

    return {} if redacted_evidence is None else {"redacted_evidence": redacted_evidence}


def _new_event(
    *,
    invocation_id: str,
    trace_id: str,
    identity: AgentIdentity,
    action: str,
    resource: str,
    permission: PermissionContext,
    result: str,
    event_type: str,
    policy_results: Sequence[PolicyResult] = (),
    reason_codes: Sequence[str] = (),
    duration_ms: float = 0.0,
    snapshot: EvidenceSnapshot | None = None,
    policy_bundle_version: str = "",
    chain_mode: ChainMode = ChainMode.ENFORCE,
    guardrail_evaluations: Sequence[GuardrailEvaluation] = (),
    hitl_evidence: HitlEvidence | None = None,
    reconciliation_evidence: ReconciliationEvidence | None = None,
    authentication_evidence: AuthenticationEvidence | None = None,
    subject_ref: EvidenceRef | None = None,
    links: Sequence[AuditLink] = (),
    event_id: str | None = None,
    timestamp: datetime | None = None,
) -> AuditEvent:
    subject_ref, links = _validate_evidence_links(subject_ref, links)
    redacted = {"value": thaw_payload(cast("Any", snapshot.value))} if snapshot is not None else {}
    return AuditEvent(
        event_id=event_id or str(uuid.uuid4()),
        timestamp=timestamp or datetime.now(UTC),
        agent_id=identity.agent_id,
        action=action,
        resource=resource,
        permission_context=_permission_evidence(permission, snapshot),
        result=cast("Any", result),
        policy_results=list(policy_results),
        duration_ms=duration_ms,
        trace_id=trace_id,
        invocation_id=invocation_id,
        event_type=cast("Any", event_type),
        reason_codes=tuple(reason_codes),
        payload_digest=snapshot.digest if snapshot is not None else "",
        payload_redacted=redacted,
        policy_bundle_version=policy_bundle_version,
        chain_mode=chain_mode.value,
        guardrail_evaluations=tuple(guardrail_evaluations),
        hitl_evidence=hitl_evidence,
        reconciliation_evidence=reconciliation_evidence,
        authentication_evidence=authentication_evidence,
        subject_ref=subject_ref,
        links=tuple(links),
        hash_schema_version=(
            7
            if authentication_evidence is not None
            else 6
            if reconciliation_evidence is not None
            else 5
            if hitl_evidence is not None
            else 4
        ),
    )


async def _audit_decision(
    audit_log: AuditLog,
    *,
    invocation_id: str,
    trace_id: str,
    identity: AgentIdentity,
    action: str,
    resource: str,
    permission: PermissionContext,
    result: str,
    event_type: str,
    reason_codes: Sequence[str],
    policy_results: Sequence[PolicyResult] = (),
    duration_ms: float = 0.0,
    snapshot: EvidenceSnapshot | None = None,
    policy_bundle_version: str = "",
    chain_mode: ChainMode = ChainMode.ENFORCE,
    guardrail_evaluations: Sequence[GuardrailEvaluation] = (),
    hitl_evidence: HitlEvidence | None = None,
    reconciliation_evidence: ReconciliationEvidence | None = None,
    authentication_evidence: AuthenticationEvidence | None = None,
    subject_ref: EvidenceRef | None = None,
    links: Sequence[AuditLink] = (),
    event_id: str | None = None,
    timestamp: datetime | None = None,
    tracer: AgentTracer | None = None,
) -> None:
    subject_ref, links = _active_evidence_links(subject_ref, links)
    active_tracer = tracer or _ACTIVE_TRACER.get()
    span_cm = _safe_span(
        active_tracer,
        "agentguard.audit_write",
        {
            "audit.event_type": event_type,
            "audit.result": result,
            "invocation.id": invocation_id,
        },
    )
    started = time.monotonic()
    with span_cm as span:
        try:
            event = _new_event(
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=action,
                resource=resource,
                permission=permission,
                result=result,
                event_type=event_type,
                reason_codes=reason_codes,
                policy_results=policy_results,
                duration_ms=duration_ms,
                snapshot=snapshot,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                guardrail_evaluations=guardrail_evaluations,
                hitl_evidence=hitl_evidence,
                reconciliation_evidence=reconciliation_evidence,
                authentication_evidence=authentication_evidence,
                subject_ref=subject_ref,
                links=links,
                event_id=event_id,
                timestamp=timestamp,
            )
            writer = audit_log.write_once if event_id is not None else audit_log.write
            await writer(event)
        finally:
            if active_tracer is not None:
                _set_span_attribute(
                    span,
                    "agentguard.audit.duration_ms",
                    (time.monotonic() - started) * 1000.0,
                )


async def _persist_escalation(
    escalation_store: EscalationStore | None,
    *,
    ttl: timedelta,
) -> CreatedEscalation | None:
    """Create control-plane state before any approval token can escape."""

    if escalation_store is None:
        return None
    return await escalation_store.create(str(uuid.uuid4()), ttl=ttl)


async def _persist_pre_execution_escalation(
    *,
    escalation_store: EscalationStore,
    continuation_protector: ContinuationProtector,
    executor_ref: ExecutorRef,
    policy_engine: PolicyEngine,
    policy_bundle: PolicyBundle,
    ttl: timedelta,
    invocation_id: str,
    trace_id: str,
    identity: AgentIdentity,
    action: str,
    resource: str,
    permission: PermissionContext,
    stage: GuardrailStage,
    payload: GuardrailPayload,
    policy_results: Sequence[PolicyResult],
    input_decisions: Sequence[EvaluatedDecision],
    pre_runtime_outcomes: Sequence[GuardrailOutcome],
    cursor: ChainCursor,
    authentication_binding: WorkloadAuthenticationBinding | None,
    subject_ref: EvidenceRef | None,
    links: tuple[AuditLink, ...],
    redacted_evidence: object | None,
) -> CreatedEscalation:
    """Reserve, protect, and attach a restart-safe PRE-stage continuation."""

    escalation_id = str(uuid.uuid4())
    created = await escalation_store.create(escalation_id, ttl=ttl)
    continuation = PreExecutionContinuation(
        schema_version=_continuation_schema_version(
            authentication_binding, subject_ref, links, redacted_evidence
        ),
        escalation_id=escalation_id,
        invocation_id=invocation_id,
        trace_id=trace_id,
        agent_id=identity.agent_id,
        authentication_binding=authentication_binding,
        subject_ref=subject_ref,
        links=links,
        redacted_evidence=redacted_evidence,
        action=action,
        resource=resource,
        permission_context=permission,
        stage=stage,
        payload=payload,
        payload_digest=hashlib.sha256(
            canonical_json_bytes(payload.model_dump(mode="json"))
        ).hexdigest(),
        policy_bundle_version=policy_bundle.version,
        policy_bundle_snapshot=policy_engine.export_bundle(policy_bundle),
        policy_results=tuple(policy_results),
        input_decisions=tuple(input_decisions),
        pre_runtime_outcomes=tuple(pre_runtime_outcomes),
        guardrail_cursor=cursor,
        executor_ref=executor_ref,
        created_at=created.record.created_at,
        expires_at=created.record.expires_at,
    )
    sealed = await continuation_protector.seal(
        continuation.model_dump_json().encode("utf-8"),
        aad=canonical_continuation_aad(
            escalation_id,
            schema_version=continuation.schema_version,
        ),
    )
    attached = await escalation_store.attach_continuation(
        escalation_id,
        token=created.token,
        sealed_continuation=sealed,
    )
    return created.model_copy(update={"record": attached})


async def _persist_post_execution_escalation(
    *,
    escalation_store: EscalationStore,
    continuation_protector: ContinuationProtector,
    policy_engine: PolicyEngine,
    policy_bundle: PolicyBundle,
    ttl: timedelta,
    invocation_id: str,
    trace_id: str,
    identity: AgentIdentity,
    action: str,
    resource: str,
    permission: PermissionContext,
    stage: GuardrailStage,
    payload: ToolResultPayload | DecisionPayload,
    policy_results: Sequence[PolicyResult],
    prior_outcomes: Sequence[GuardrailOutcome],
    prior_guardrail_decisions: Sequence[EvaluatedDecision],
    cursor: ChainCursor,
    chain_fingerprint: str,
    execution_duration_ms: float,
    execution_completed_at: datetime,
    authentication_binding: WorkloadAuthenticationBinding | None,
    subject_ref: EvidenceRef | None,
    links: tuple[AuditLink, ...],
    redacted_evidence: object | None,
) -> CreatedEscalation:
    """Seal an executed result and exact POST cursor without executor authority."""

    escalation_id = str(uuid.uuid4())
    created = await escalation_store.create(escalation_id, ttl=ttl)
    continuation = PostExecutionContinuation(
        schema_version=_continuation_schema_version(
            authentication_binding, subject_ref, links, redacted_evidence
        ),
        escalation_id=escalation_id,
        invocation_id=invocation_id,
        trace_id=trace_id,
        agent_id=identity.agent_id,
        authentication_binding=authentication_binding,
        subject_ref=subject_ref,
        links=links,
        redacted_evidence=redacted_evidence,
        action=action,
        resource=resource,
        permission_context=permission,
        stage=stage,
        payload=payload,
        payload_digest=hashlib.sha256(
            canonical_json_bytes(payload.model_dump(mode="json"))
        ).hexdigest(),
        policy_bundle_version=policy_bundle.version,
        policy_bundle_snapshot=policy_engine.export_bundle(policy_bundle),
        policy_results=tuple(policy_results),
        prior_outcomes=tuple(prior_outcomes),
        prior_guardrail_decisions=tuple(prior_guardrail_decisions),
        guardrail_cursor=cursor,
        chain_fingerprint=chain_fingerprint,
        execution_duration_ms=execution_duration_ms,
        execution_completed_at=execution_completed_at,
        created_at=created.record.created_at,
        expires_at=created.record.expires_at,
    )
    sealed = await continuation_protector.seal(
        continuation.model_dump_json().encode("utf-8"),
        aad=canonical_continuation_aad(
            escalation_id,
            kind="post_execution_continuation",
            schema_version=continuation.schema_version,
        ),
    )
    attached = await escalation_store.attach_continuation(
        escalation_id,
        token=created.token,
        sealed_continuation=sealed,
        continuation_kind=StoreContinuationKind.POST_DELIVERY,
    )
    return created.model_copy(update={"record": attached})


def _post_payload_value(payload: ToolResultPayload | DecisionPayload) -> object:
    """Return the externally deliverable value represented by a POST payload."""

    if isinstance(payload, DecisionPayload):
        return payload
    return thaw_payload(cast("Any", payload.result))


def _post_payload_matches_stage(
    payload: GuardrailPayload,
    stage: GuardrailStage,
) -> bool:
    """Keep protected POST state and delivery payload kinds stage-consistent."""

    if stage is GuardrailStage.ON_DECISION:
        return isinstance(payload, DecisionPayload)
    if stage in {GuardrailStage.POST_TOOL, GuardrailStage.POST_MESSAGE}:
        return isinstance(payload, ToolResultPayload)
    return False


async def _finish_audit_write_on_cancellation(
    write: Coroutine[Any, Any, None],
) -> None:
    """Let an in-flight terminal write finish before propagating cancellation."""

    task: asyncio.Task[None] = asyncio.create_task(write)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.cancelled():
                raise
            cancelled = True
        except Exception:
            if not cancelled:
                raise
            logger.exception("audit_terminal_write_failed_during_cancellation")
            break
    if cancelled:
        if task.done() and not task.cancelled():
            error = task.exception()
            if error is not None:
                logger.error(
                    "audit_terminal_write_failed_during_cancellation",
                    error_type=type(error).__name__,
                )
        raise asyncio.CancelledError
    task.result()


async def _audit_failed_execution_lifecycle(
    audit_log: AuditLog,
    *,
    invocation_id: str,
    trace_id: str,
    identity: AgentIdentity,
    action: str,
    resource: str,
    permission: PermissionContext,
    reason_codes: Sequence[str],
    policy_results: Sequence[PolicyResult],
    duration_ms: float,
    policy_bundle_version: str,
    chain_mode: ChainMode,
    execution_journal: ExecutionJournal | None = None,
    execution_journal_record: ExecutionJournalRecord | None = None,
) -> None:
    """Best-effort completion and terminal evidence without masking execution failure."""

    try:
        await _audit_decision(
            audit_log,
            invocation_id=invocation_id,
            trace_id=trace_id,
            identity=identity,
            action=action,
            resource=resource,
            permission=permission,
            result="error",
            event_type="execution_completed",
            reason_codes=reason_codes,
            policy_results=policy_results,
            duration_ms=duration_ms,
            policy_bundle_version=policy_bundle_version,
            chain_mode=chain_mode,
            event_id=f"invocation:{invocation_id}:execution-completed",
        )
    except Exception:
        logger.exception("audit_failed_execution_write_failed", trace_id=trace_id)
        return

    try:
        await _audit_decision(
            audit_log,
            invocation_id=invocation_id,
            trace_id=trace_id,
            identity=identity,
            action=action,
            resource=resource,
            permission=permission,
            result="denied",
            event_type="delivery_denied",
            reason_codes=reason_codes,
            policy_results=policy_results,
            duration_ms=duration_ms,
            policy_bundle_version=policy_bundle_version,
            chain_mode=chain_mode,
            event_id=(
                f"invocation:{invocation_id}:delivery"
                if execution_journal_record is not None
                else None
            ),
        )
    except Exception:
        logger.exception("audit_failed_delivery_write_failed", trace_id=trace_id)
        return

    if execution_journal is not None and execution_journal_record is not None:
        try:
            await execution_journal.commit_execution_denied(
                execution_journal_record.escalation_id,
                claim_id=execution_journal_record.claim_id,
                invocation_id=execution_journal_record.invocation_id,
            )
        except Exception:
            logger.exception("execution_journal_failed_terminal_commit", trace_id=trace_id)


async def _audit_cancelled_delivery(
    audit_log: AuditLog,
    *,
    invocation_id: str,
    trace_id: str,
    identity: AgentIdentity,
    action: str,
    resource: str,
    permission: PermissionContext,
    policy_results: Sequence[PolicyResult],
    duration_ms: float,
    snapshot: EvidenceSnapshot,
    policy_bundle_version: str,
    chain_mode: ChainMode,
    guardrail_evaluations: Sequence[GuardrailEvaluation] = (),
    event_id: str | None = None,
) -> None:
    """Commit the required delivery terminal without masking cancellation."""

    try:
        await _finish_audit_write_on_cancellation(
            _audit_decision(
                audit_log,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=action,
                resource=resource,
                permission=permission,
                result="denied",
                event_type="delivery_denied",
                reason_codes=(DELIVERY_CANCELLED,),
                policy_results=policy_results,
                duration_ms=duration_ms,
                snapshot=snapshot,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                guardrail_evaluations=guardrail_evaluations,
                event_id=event_id,
            )
        )
    except Exception:
        logger.exception("audit_cancelled_delivery_write_failed", trace_id=trace_id)


def _transient_policy_event(
    *,
    invocation_id: str,
    trace_id: str,
    identity: AgentIdentity,
    action: str,
    resource: str,
    permission: PermissionContext,
    context: dict[str, Any],
) -> AuditEvent:
    return AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC),
        agent_id=identity.agent_id,
        action=action,
        resource=resource,
        permission_context=permission.model_copy(update={"context": context}),
        result="allowed",
        duration_ms=0.0,
        trace_id=trace_id,
        invocation_id=invocation_id,
        event_type="legacy",
    )


async def _evaluate_policy_stage(
    policy_engine: PolicyEngine,
    event: AuditEvent,
    stage: GuardrailStage,
    tracer: AgentTracer | None,
    bundle: PolicyBundle | None = None,
) -> list[PolicyResult]:
    bundle_version = (
        bundle.version if bundle is not None else str(getattr(policy_engine, "bundle_version", ""))
    )
    span_cm = _safe_span(
        tracer,
        "agentguard.policy_eval",
        {
            "policy.stage": stage.value,
            "policy.bundle_version": bundle_version,
        },
    )
    with span_cm as span:
        if bundle is None:
            evaluated = await policy_engine.evaluate_stage(event, cast("Any", stage.value))
        else:
            evaluated = await policy_engine.evaluate_stage(
                event,
                cast("Any", stage.value),
                bundle=bundle,
            )
        results = _sanitize_policy_results(evaluated)
        if tracer is not None:
            violations = [result for result in results if not result.passed]
            _set_span_attribute(span, "agentguard.policy.result_count", len(results))
            _set_span_attribute(span, "agentguard.policy.violation_count", len(violations))
            _set_span_attribute(
                span,
                "agentguard.policy.critical",
                any(result.severity == "critical" for result in violations),
            )
        return results


async def _run_governed_impl(
    *,
    agent_id: str,
    action: ActionResolver,
    resource: ResourceResolver | None,
    registry: AgentRegistry | None,
    rbac_engine: RBACEngine,
    audit_log: AuditLog,
    executor: Callable[[GuardrailPayload], Awaitable[Any]] | None,
    payload: ToolCallPayload | MessagePayload | None = None,
    policy_engine: PolicyEngine | None = None,
    guardrail_chain: GuardrailChain | _ResumingGuardrailChain,
    rate_limiter: TokenBucketRateLimiter | None = None,
    circuit_breaker: CircuitBreaker | None = None,
    tracer: AgentTracer | None = None,
    root_span: Any = None,
    resolver_timeout: float = _DEFAULT_RESOLVER_TIMEOUT,
    fallback_action: str | None = None,
    escalation_store: EscalationStore | None = None,
    escalation_ttl: timedelta = _DEFAULT_ESCALATION_TTL,
    continuation_protector: ContinuationProtector | None = None,
    executor_ref: ExecutorRef | None = None,
    executor_id: str | None = None,
    executor_resolver: ExecutorResolver | None = None,
    invocation_id: str | None = None,
    trace_id: str | None = None,
    policy_bundle_override: PolicyBundle | None = None,
    identity_override: AgentIdentity | None = None,
    permission_override: PermissionContext | None = None,
    resumed_escalation_id: str | None = None,
    lifecycle_observer: Callable[[], None] | None = None,
    execution_journal: ExecutionJournal | None = None,
    execution_journal_record: ExecutionJournalRecord | None = None,
    authentication_binding: WorkloadAuthenticationBinding | None = None,
    subject_ref: EvidenceRef | None = None,
    links: tuple[AuditLink, ...] = (),
    redacted_evidence: object | None = None,
    sandbox_backend: DockerSandboxBackend | None = None,
) -> Any:
    """Execute one immutable payload through the full governance lifecycle."""
    invocation_id = invocation_id or str(uuid.uuid4())
    trace_id = trace_id or str(uuid.uuid4())
    policy_bundle = policy_bundle_override or (
        policy_engine.snapshot()
        if policy_engine is not None and isinstance(policy_engine, PolicyEngine)
        else None
    )
    policy_bundle_version = (
        policy_bundle.version
        if policy_bundle is not None
        else str(getattr(policy_engine, "bundle_version", ""))
        if policy_engine is not None
        else ""
    )
    chain_mode = guardrail_chain.mode
    resumed_terminal_id = (
        f"hitl:{resumed_escalation_id}:delivery-denied"
        if resumed_escalation_id is not None
        else None
    )
    call_payload: ToolCallPayload | MessagePayload = payload or ToolCallPayload(
        arguments=cast("Any", {})
    )

    async def commit_journal_delivery_denied() -> None:
        if execution_journal is not None and execution_journal_record is not None:
            await execution_journal.commit_delivery_denied(
                execution_journal_record.escalation_id,
                claim_id=execution_journal_record.claim_id,
                invocation_id=execution_journal_record.invocation_id,
            )

    if identity_override is None:
        if registry is None:
            raise EscalationStateError("legacy identity registry is not configured")
        identity = await registry.resolve(agent_id)
    else:
        identity = identity_override
    if identity.agent_id != agent_id:
        raise EscalationStateError("pinned identity does not match resumed agent")
    identity_view = _identity_snapshot(identity)

    resolved_executor = executor
    resolved_executor_ref = executor_ref

    def resolve_registered_executor() -> None:
        nonlocal resolved_executor, resolved_executor_ref
        if resolved_executor is not None:
            return
        if executor_id is None or executor_resolver is None:
            raise EscalationStateError("trusted executor resolution is not configured")
        registered = executor_resolver.resolve(executor_id)
        resolved_executor = registered.executor
        resolved_executor_ref = registered.ref

    base_action = action if isinstance(action, str) else (fallback_action or UNRESOLVED_ACTION)

    input_context = GuardrailContext(
        trace_id=trace_id,
        invocation_id=invocation_id,
        stage=GuardrailStage.INPUT,
        identity=identity_view,
        action=base_action,
        resource=UNRESOLVED_RESOURCE,
        payload=call_payload,
    )
    input_chain_result = await _evaluate_guardrails(
        guardrail_chain,
        input_context,
    )
    transformed = input_chain_result.payload
    input_guardrail_outcomes = [record.decision for record in input_chain_result.decisions]
    input_runtime_outcomes: list[GuardrailOutcome] = []
    input_evaluations = _guardrail_evaluations(
        input_chain_result,
        GuardrailStage.INPUT,
    )
    if not isinstance(transformed, ToolCallPayload | MessagePayload):
        input_runtime_outcomes.append(
            GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(INPUT_INVALID,),
            )
        )
    else:
        call_payload = transformed

    native_input = _native_input(call_payload)
    try:
        input_snapshot = EvidenceSnapshot.capture(native_input)
    except (TypeError, ValueError):
        input_snapshot = None
        input_runtime_outcomes.append(
            GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(INPUT_INVALID,),
            )
        )

    enforced_input_guardrails = input_guardrail_outcomes if input_chain_result.enforced else []
    actual_input_outcomes = [
        *input_runtime_outcomes,
        *enforced_input_guardrails,
    ]
    input_deny = _outcome_effect(actual_input_outcomes, GuardrailEffect.DENY)
    input_escalate = _outcome_effect(actual_input_outcomes, GuardrailEffect.ESCALATE)
    if input_deny is not None or input_escalate is not None:
        early_action = (
            fallback_action
            or (canonicalize_action(base_action) if base_action != UNRESOLVED_ACTION else None)
            or UNRESOLVED_ACTION
        )
        early_permission = PermissionContext(
            agent=identity,
            requested_action=early_action,
            resource=UNRESOLVED_RESOURCE,
            granted=False,
            reason="input guardrail stopped resolution",
        )
        codes = _reason_codes(actual_input_outcomes, ()) or (GUARDRAIL_INTERNAL_ERROR,)
        escalated = input_escalate is not None
        created = (
            await _persist_escalation(escalation_store, ttl=escalation_ttl) if escalated else None
        )
        hitl_evidence = (
            HitlEvidence(
                escalation_id=created.record.escalation_id,
                state="requested",
                expires_at=created.record.expires_at,
            )
            if created is not None
            else None
        )
        await _audit_decision(
            audit_log,
            invocation_id=invocation_id,
            trace_id=trace_id,
            identity=identity,
            action=early_action,
            resource=UNRESOLVED_RESOURCE,
            permission=early_permission,
            result="escalated" if escalated else "denied",
            event_type=(
                "escalation_requested"
                if created is not None
                else "escalation"
                if escalated
                else "delivery_denied"
                if resumed_escalation_id is not None
                else "denial"
            ),
            reason_codes=codes,
            snapshot=input_snapshot,
            policy_bundle_version=policy_bundle_version,
            chain_mode=chain_mode,
            guardrail_evaluations=input_evaluations,
            hitl_evidence=hitl_evidence,
            event_id=(
                f"hitl:{created.record.escalation_id}:requested"
                if created is not None
                else resumed_terminal_id
            ),
        )
        if escalated:
            raise EscalationRequiredError(
                agent_id,
                early_action,
                UNRESOLVED_RESOURCE,
                codes,
                escalation_id=created.record.escalation_id if created is not None else "",
                approval_token=created.token if created is not None else "",
                expires_at=created.record.expires_at if created is not None else None,
            )
        raise PermissionDeniedError(
            agent_id, early_action, UNRESOLVED_RESOURCE, reason=",".join(codes)
        )

    resolved_action, resolved_resource = await asyncio.gather(
        resolve_action(action, native_input, timeout=resolver_timeout),
        resolve_resource(resource, native_input, timeout=resolver_timeout),
    )
    if resolved_resource is None and fallback_action is not None:
        audit_action = fallback_action
    else:
        audit_action = (
            resolved_action
            or fallback_action
            or (canonicalize_action(base_action) if base_action != UNRESOLVED_ACTION else None)
            or UNRESOLVED_ACTION
        )
    audit_resource = resolved_resource or UNRESOLVED_RESOURCE
    _set_span_attribute(root_span, "agentguard.tool.action", audit_action)
    _set_span_attribute(root_span, "agentguard.tool.resource", audit_resource)

    provisional_permission = PermissionContext(
        agent=identity,
        requested_action=audit_action,
        resource=audit_resource,
        granted=False,
        reason="governance evaluation pending",
    )

    if resolved_action is None or resolved_resource is None:
        reason = RESOURCE_UNRESOLVED
        unresolved_permission = provisional_permission.model_copy(
            update={"reason": "resource_unresolvable: resource could not be derived from the call"}
        )
        await _audit_decision(
            audit_log,
            invocation_id=invocation_id,
            trace_id=trace_id,
            identity=identity,
            action=audit_action,
            resource=UNRESOLVED_RESOURCE,
            permission=unresolved_permission,
            result="denied",
            event_type=("delivery_denied" if resumed_escalation_id is not None else "denial"),
            reason_codes=(reason,),
            snapshot=input_snapshot,
            policy_bundle_version=policy_bundle_version,
            chain_mode=chain_mode,
            guardrail_evaluations=input_evaluations,
            event_id=resumed_terminal_id,
        )
        raise PermissionDeniedError(
            agent_id,
            audit_action,
            UNRESOLVED_RESOURCE,
            reason="resource_unresolvable: resource could not be derived from the call",
        )

    rbac_span_cm = _safe_span(
        tracer,
        "agentguard.rbac_check",
        {
            "agent.id": agent_id,
            "permission.action": resolved_action,
            "permission.resource": resolved_resource,
        },
    )
    with rbac_span_cm as rbac_span:
        if permission_override is None:
            permission = await rbac_engine.check_permission(
                identity, resolved_action, resolved_resource
            )
        else:
            permission = permission_override
            if (
                permission.agent != identity
                or permission.requested_action != resolved_action
                or permission.resource != resolved_resource
                or not permission.granted
            ):
                raise EscalationStateError("pinned permission does not match resumed call")
        if tracer is not None:
            _set_span_attribute(rbac_span, "agentguard.permission.granted", permission.granted)
            _set_span_attribute(rbac_span, "agentguard.permission.reason", permission.reason)
    if not permission.granted:
        await _audit_decision(
            audit_log,
            invocation_id=invocation_id,
            trace_id=trace_id,
            identity=identity,
            action=resolved_action,
            resource=resolved_resource,
            permission=permission,
            result="denied",
            event_type=("delivery_denied" if resumed_escalation_id is not None else "denial"),
            reason_codes=(RBAC_PERMISSION_DENIED,),
            snapshot=input_snapshot,
            policy_bundle_version=policy_bundle_version,
            chain_mode=chain_mode,
            guardrail_evaluations=input_evaluations,
            event_id=resumed_terminal_id,
        )
        raise PermissionDeniedError(
            agent_id, resolved_action, resolved_resource, reason=permission.reason
        )

    is_message = isinstance(call_payload, MessagePayload)
    pre_stage = GuardrailStage.PRE_MESSAGE if is_message else GuardrailStage.PRE_TOOL
    pre_policy_results: list[PolicyResult] = []
    pre_runtime_outcomes: list[GuardrailOutcome] = []
    try:
        if policy_engine is not None:
            transient = _transient_policy_event(
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                context={"tool_args": native_input},
            )
            pre_policy_results = await _evaluate_policy_stage(
                policy_engine,
                transient,
                pre_stage,
                tracer,
                policy_bundle,
            )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("policy_evaluation_failed", error_type=type(exc).__name__)
        pre_policy_results = []
        pre_runtime_outcomes.append(
            GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(
                    GUARDRAIL_TIMEOUT
                    if isinstance(exc, TimeoutError)
                    else GUARDRAIL_INTERNAL_ERROR,
                ),
            )
        )

    pre_context = GuardrailContext(
        trace_id=trace_id,
        invocation_id=invocation_id,
        stage=pre_stage,
        identity=identity_view,
        action=resolved_action,
        resource=resolved_resource,
        payload=call_payload,
        prior=(
            *input_guardrail_outcomes,
            *input_runtime_outcomes,
            *pre_runtime_outcomes,
        ),
    )
    pre_chain_result = await _evaluate_guardrails(
        guardrail_chain,
        pre_context,
    )
    pre_guardrail_records = list(pre_chain_result.decisions)
    pre_guardrail_outcomes = [record.decision for record in pre_guardrail_records]
    if isinstance(guardrail_chain, _ResumingGuardrailChain):
        approved = guardrail_chain.approved_escalations
        pre_guardrail_outcomes = [
            record.decision
            for record in pre_guardrail_records
            if (
                (record.guardrail_id, record.guardrail_version) not in approved
                or record.decision.effect is not GuardrailEffect.ESCALATE
            )
        ]
    pre_evaluations = (
        *input_evaluations,
        *_guardrail_evaluations(pre_chain_result, pre_stage),
    )
    sandbox_obligation: SandboxObligation | None = None
    sandbox_command: list[str] | None = None
    if pre_chain_result.enforced:
        obligations = tuple(
            obligation
            for record in pre_guardrail_records
            for obligation in record.decision.obligations
        )
        distinct_obligations = tuple(dict.fromkeys(obligations))
        if len(distinct_obligations) > 1:
            pre_runtime_outcomes.append(
                GuardrailOutcome(
                    effect=GuardrailEffect.DENY,
                    reason_codes=(SANDBOX_OBLIGATION_CONFLICT,),
                )
            )
        elif distinct_obligations:
            sandbox_obligation = distinct_obligations[0]
            if sandbox_backend is None:
                pre_runtime_outcomes.append(
                    GuardrailOutcome(
                        effect=GuardrailEffect.DENY,
                        reason_codes=(SANDBOX_BACKEND_REQUIRED,),
                    )
                )
            elif not isinstance(call_payload, ToolCallPayload):
                pre_runtime_outcomes.append(
                    GuardrailOutcome(
                        effect=GuardrailEffect.DENY,
                        reason_codes=(SANDBOX_COMMAND_INVALID,),
                    )
                )
            else:
                try:
                    sandbox_command = validate_sandbox_command(
                        call_payload.arguments.get("command")
                    )
                    pre_runtime_outcomes.append(
                        GuardrailOutcome(
                            effect=GuardrailEffect.WARN,
                            reason_codes=(SANDBOX_REQUIRED,),
                        )
                    )
                except SandboxError as exc:
                    pre_runtime_outcomes.append(
                        GuardrailOutcome(
                            effect=GuardrailEffect.DENY,
                            reason_codes=(exc.reason_code,),
                        )
                    )
        if obligations and input_snapshot is not None:
            input_snapshot = EvidenceSnapshot.capture_redacted(
                native_input,
                {"sandbox_command": "[redacted]"},
            )
    all_pre_outcomes = [
        *input_guardrail_outcomes,
        *input_runtime_outcomes,
        *pre_runtime_outcomes,
        *pre_guardrail_outcomes,
    ]
    actual_pre_outcomes = [
        *input_runtime_outcomes,
        *pre_runtime_outcomes,
        *(
            [*input_guardrail_outcomes, *pre_guardrail_outcomes]
            if pre_chain_result.enforced
            else []
        ),
    ]
    pre_codes = _reason_codes(actual_pre_outcomes, pre_policy_results)
    policy_deny = next(
        (result for result in pre_policy_results if not result.passed and result.effect == "deny"),
        None,
    )
    policy_escalate = next(
        (
            result
            for result in pre_policy_results
            if not result.passed and result.effect == "escalate"
        ),
        None,
    )
    guard_deny = _outcome_effect(actual_pre_outcomes, GuardrailEffect.DENY)
    guard_escalate = _outcome_effect(actual_pre_outcomes, GuardrailEffect.ESCALATE)
    if policy_deny is not None or guard_deny is not None:
        codes = pre_codes or (GUARDRAIL_INTERNAL_ERROR,)
        await _audit_decision(
            audit_log,
            invocation_id=invocation_id,
            trace_id=trace_id,
            identity=identity,
            action=resolved_action,
            resource=resolved_resource,
            permission=permission,
            result="denied",
            event_type=("delivery_denied" if resumed_escalation_id is not None else "denial"),
            reason_codes=codes,
            policy_results=pre_policy_results,
            snapshot=input_snapshot,
            policy_bundle_version=policy_bundle_version,
            chain_mode=chain_mode,
            guardrail_evaluations=pre_evaluations,
            event_id=resumed_terminal_id,
        )
        raise PermissionDeniedError(
            agent_id, resolved_action, resolved_resource, reason=",".join(codes)
        )
    if policy_escalate is not None or guard_escalate is not None:
        codes = pre_codes or (GUARDRAIL_INTERNAL_ERROR,)
        restart_safe = executor_ref is not None or (
            executor_id is not None and executor_resolver is not None
        )
        resumable = (
            escalation_store is not None
            and continuation_protector is not None
            and restart_safe
            and isinstance(policy_engine, PolicyEngine)
            and policy_bundle is not None
            and policy_escalate is None
            and guard_escalate is not None
            and pre_chain_result.cursor is not None
            and guardrail_chain.resumable
            and sandbox_obligation is None
        )
        if resumable:
            resolve_registered_executor()
            assert escalation_store is not None
            assert continuation_protector is not None
            assert resolved_executor_ref is not None
            assert isinstance(policy_engine, PolicyEngine)
            assert policy_bundle is not None
            assert pre_chain_result.cursor is not None
            created = await _persist_pre_execution_escalation(
                escalation_store=escalation_store,
                continuation_protector=continuation_protector,
                executor_ref=resolved_executor_ref,
                policy_engine=policy_engine,
                policy_bundle=policy_bundle,
                ttl=escalation_ttl,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                stage=pre_stage,
                payload=pre_chain_result.payload,
                policy_results=pre_policy_results,
                input_decisions=input_chain_result.decisions,
                pre_runtime_outcomes=pre_runtime_outcomes,
                cursor=pre_chain_result.cursor,
                authentication_binding=authentication_binding,
                subject_ref=subject_ref,
                links=links,
                redacted_evidence=redacted_evidence,
            )
        else:
            created = await _persist_escalation(escalation_store, ttl=escalation_ttl)
        hitl_evidence = (
            HitlEvidence(
                escalation_id=created.record.escalation_id,
                state="requested",
                expires_at=created.record.expires_at,
            )
            if created is not None
            else None
        )
        await _audit_decision(
            audit_log,
            invocation_id=invocation_id,
            trace_id=trace_id,
            identity=identity,
            action=resolved_action,
            resource=resolved_resource,
            permission=permission,
            result="escalated",
            event_type="escalation_requested" if created is not None else "escalation",
            reason_codes=codes,
            policy_results=pre_policy_results,
            snapshot=input_snapshot,
            policy_bundle_version=policy_bundle_version,
            chain_mode=chain_mode,
            guardrail_evaluations=pre_evaluations,
            hitl_evidence=hitl_evidence,
            event_id=(
                f"hitl:{created.record.escalation_id}:requested" if created is not None else None
            ),
        )
        raise EscalationRequiredError(
            agent_id,
            resolved_action,
            resolved_resource,
            codes,
            escalation_id=created.record.escalation_id if created is not None else "",
            approval_token=created.token if created is not None else "",
            expires_at=created.record.expires_at if created is not None else None,
        )

    if rate_limiter is not None:
        try:
            await rate_limiter.acquire(agent_id, resolved_action)
        except RateLimitExceededError:
            await _audit_decision(
                audit_log,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                result="denied" if resumed_escalation_id is not None else "rejected",
                event_type=(
                    "delivery_denied" if resumed_escalation_id is not None else "rejection"
                ),
                reason_codes=(RATE_LIMIT_EXCEEDED,),
                policy_results=pre_policy_results,
                snapshot=input_snapshot,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                guardrail_evaluations=pre_evaluations,
                event_id=resumed_terminal_id,
            )
            raise

    if sandbox_obligation is None:
        resolve_registered_executor()
        assert resolved_executor is not None
    else:
        assert sandbox_backend is not None
        assert sandbox_command is not None

    span_cm = nullcontext()
    started = time.monotonic()
    execution_started = False
    with span_cm:

        async def _write_admission() -> None:
            await _audit_decision(
                audit_log,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                result="allowed",
                event_type="admission",
                reason_codes=pre_codes,
                policy_results=pre_policy_results,
                snapshot=input_snapshot,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                guardrail_evaluations=pre_evaluations,
                event_id=f"invocation:{invocation_id}:admission",
            )
            if execution_journal is not None and execution_journal_record is not None:
                await execution_journal.mark_admitted(
                    execution_journal_record.escalation_id,
                    claim_id=execution_journal_record.claim_id,
                    invocation_id=execution_journal_record.invocation_id,
                )
            if lifecycle_observer is not None:
                lifecycle_observer()

        async def _execute() -> Any:
            nonlocal execution_started
            execution_started = True
            with _safe_span(
                tracer,
                "agentguard.tool_execution",
                {
                    "agent.id": agent_id,
                    "tool.action": resolved_action,
                    "tool.resource": resolved_resource,
                    "trace.id": trace_id,
                    "invocation.id": invocation_id,
                },
            ):
                if sandbox_obligation is None:
                    assert resolved_executor is not None
                    return await resolved_executor(call_payload)
                assert sandbox_backend is not None
                assert sandbox_command is not None
                sandbox_result = await sandbox_backend.run(
                    sandbox_command,
                    sandbox_obligation.config,
                )
                if not sandbox_result.success:
                    reason_code = sandbox_result.reason_code
                    if reason_code not in RUNTIME_REASON_CODES or not reason_code.startswith(
                        "SANDBOX."
                    ):
                        reason_code = SANDBOX_INTERNAL_ERROR
                    raise SandboxError(
                        "sandboxed process exited unsuccessfully",
                        reason_code=reason_code,
                        result=sandbox_result,
                    )
                return sandbox_result

        try:
            if circuit_breaker is not None:
                result = await circuit_breaker.call(_execute, before_execute=_write_admission)
            else:
                await _write_admission()
                result = await _execute()
        except CircuitOpenError:
            await _audit_decision(
                audit_log,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                result="denied" if resumed_escalation_id is not None else "rejected",
                event_type=(
                    "delivery_denied" if resumed_escalation_id is not None else "rejection"
                ),
                reason_codes=(CIRCUIT_BREAKER_OPEN,),
                policy_results=pre_policy_results,
                snapshot=input_snapshot,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                guardrail_evaluations=pre_evaluations,
                event_id=resumed_terminal_id,
            )
            raise
        except asyncio.CancelledError:
            if execution_started:
                duration_ms = (time.monotonic() - started) * 1000.0
                codes = tuple(dict.fromkeys((*pre_codes, EXECUTION_CANCELLED)))
                await _finish_audit_write_on_cancellation(
                    _audit_failed_execution_lifecycle(
                        audit_log,
                        invocation_id=invocation_id,
                        trace_id=trace_id,
                        identity=identity,
                        action=resolved_action,
                        resource=resolved_resource,
                        permission=permission,
                        reason_codes=codes,
                        policy_results=pre_policy_results,
                        duration_ms=duration_ms,
                        policy_bundle_version=policy_bundle_version,
                        chain_mode=chain_mode,
                        execution_journal=execution_journal,
                        execution_journal_record=execution_journal_record,
                    )
                )
            elif resumed_escalation_id is not None:
                await asyncio.shield(
                    _audit_decision(
                        audit_log,
                        invocation_id=invocation_id,
                        trace_id=trace_id,
                        identity=identity,
                        action=resolved_action,
                        resource=resolved_resource,
                        permission=permission,
                        result="denied",
                        event_type="delivery_denied",
                        reason_codes=tuple(dict.fromkeys((*pre_codes, DELIVERY_CANCELLED))),
                        policy_results=pre_policy_results,
                        snapshot=input_snapshot,
                        policy_bundle_version=policy_bundle_version,
                        chain_mode=chain_mode,
                        guardrail_evaluations=pre_evaluations,
                        event_id=resumed_terminal_id,
                    )
                )
            raise
        except Exception as exc:
            if not execution_started:
                raise
            duration_ms = (time.monotonic() - started) * 1000.0
            execution_reason = (
                exc.reason_code if isinstance(exc, SandboxError) else EXECUTION_FAILED
            )
            codes = tuple(dict.fromkeys((*pre_codes, execution_reason)))
            await _audit_failed_execution_lifecycle(
                audit_log,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                reason_codes=codes,
                policy_results=pre_policy_results,
                duration_ms=duration_ms,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                execution_journal=execution_journal,
                execution_journal_record=execution_journal_record,
            )
            logger.warning(
                "governed_execution_failed",
                agent_id=agent_id,
                action=resolved_action,
                resource=resolved_resource,
                trace_id=trace_id,
                error_type=type(exc).__name__,
            )
            raise

        duration_ms = (time.monotonic() - started) * 1000.0
        execution_completed_at = datetime.now(UTC)
        try:
            result_payload = (
                result if isinstance(result, DecisionPayload) else ToolResultPayload(result=result)
            )
            native_result = _post_payload_value(result_payload)
            unvalidated_result_snapshot = _capture_unvalidated_result_evidence(native_result)
        except (TypeError, ValueError):
            codes = (OUTPUT_SCHEMA_INVALID,)
            await _audit_decision(
                audit_log,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                result="allowed",
                event_type="execution_completed",
                reason_codes=pre_codes,
                policy_results=pre_policy_results,
                duration_ms=duration_ms,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                timestamp=execution_completed_at,
                event_id=f"invocation:{invocation_id}:execution-completed",
            )
            await _finish_audit_write_on_cancellation(
                _audit_decision(
                    audit_log,
                    invocation_id=invocation_id,
                    trace_id=trace_id,
                    identity=identity,
                    action=resolved_action,
                    resource=resolved_resource,
                    permission=permission,
                    result="denied",
                    event_type="delivery_denied",
                    reason_codes=codes,
                    policy_results=pre_policy_results,
                    duration_ms=duration_ms,
                    policy_bundle_version=policy_bundle_version,
                    chain_mode=chain_mode,
                    event_id=f"invocation:{invocation_id}:delivery",
                )
            )
            if execution_journal is not None and execution_journal_record is not None:
                await execution_journal.commit_execution_denied(
                    execution_journal_record.escalation_id,
                    claim_id=execution_journal_record.claim_id,
                    invocation_id=execution_journal_record.invocation_id,
                )
            raise PermissionDeniedError(
                agent_id, resolved_action, resolved_resource, reason=",".join(codes)
            ) from None

        post_stage = (
            GuardrailStage.ON_DECISION
            if isinstance(result_payload, DecisionPayload)
            else GuardrailStage.POST_MESSAGE
            if is_message
            else GuardrailStage.POST_TOOL
        )
        if execution_journal is not None and execution_journal_record is not None:
            if not isinstance(policy_engine, PolicyEngine) or policy_bundle is None:
                raise EscalationStateError("execution journaling requires a pinned policy bundle")
            protected_continuation = PostExecutionContinuation(
                schema_version=_continuation_schema_version(
                    authentication_binding, subject_ref, links, redacted_evidence
                ),
                escalation_id=execution_journal_record.escalation_id,
                invocation_id=invocation_id,
                trace_id=trace_id,
                agent_id=identity.agent_id,
                authentication_binding=authentication_binding,
                subject_ref=subject_ref,
                links=links,
                redacted_evidence=redacted_evidence,
                action=resolved_action,
                resource=resolved_resource,
                permission_context=permission,
                stage=post_stage,
                payload=result_payload,
                payload_digest=hashlib.sha256(
                    canonical_json_bytes(result_payload.model_dump(mode="json"))
                ).hexdigest(),
                policy_bundle_version=policy_bundle.version,
                policy_bundle_snapshot=policy_engine.export_bundle(policy_bundle),
                policy_results=tuple(pre_policy_results),
                prior_outcomes=tuple(all_pre_outcomes),
                prior_guardrail_decisions=(
                    *input_chain_result.decisions,
                    *pre_chain_result.decisions,
                ),
                guardrail_cursor=None,
                chain_fingerprint=guardrail_chain.fingerprint,
                execution_duration_ms=duration_ms,
                execution_completed_at=execution_completed_at,
                created_at=execution_completed_at,
                expires_at=execution_completed_at + escalation_ttl,
            )
            await execution_journal.protect_outcome(
                execution_journal_record.escalation_id,
                claim_id=execution_journal_record.claim_id,
                invocation_id=invocation_id,
                outcome=ProtectedExecutionOutcome(
                    escalation_id=execution_journal_record.escalation_id,
                    claim_id=execution_journal_record.claim_id,
                    invocation_id=invocation_id,
                    admission_payload_digest=execution_journal_record.payload_digest,
                    policy_bundle_version=execution_journal_record.policy_bundle_version,
                    chain_fingerprint=execution_journal_record.chain_fingerprint,
                    continuation=protected_continuation,
                ),
            )

        await _audit_decision(
            audit_log,
            invocation_id=invocation_id,
            trace_id=trace_id,
            identity=identity,
            action=resolved_action,
            resource=resolved_resource,
            permission=permission,
            result="allowed",
            event_type="execution_completed",
            reason_codes=pre_codes,
            policy_results=pre_policy_results,
            duration_ms=duration_ms,
            policy_bundle_version=policy_bundle_version,
            chain_mode=chain_mode,
            timestamp=execution_completed_at,
            event_id=f"invocation:{invocation_id}:execution-completed",
        )
        if execution_journal is not None and execution_journal_record is not None:
            await execution_journal.mark_completion_audited(
                execution_journal_record.escalation_id,
                claim_id=execution_journal_record.claim_id,
                invocation_id=invocation_id,
            )
            claimed_post = await execution_journal.claim_post_processing(
                execution_journal_record.escalation_id,
                claim_id=execution_journal_record.claim_id,
                invocation_id=invocation_id,
            )
            await _audit_decision(
                audit_log,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                result="allowed",
                event_type="execution_post_processing_claimed",
                reason_codes=pre_codes,
                policy_results=pre_policy_results,
                duration_ms=duration_ms,
                snapshot=unvalidated_result_snapshot,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                links=(
                    AuditLink(
                        relation="subject",
                        target=EvidenceRef(
                            namespace="execution-journal",
                            value=(
                                f"{claimed_post.escalation_id}:"
                                f"{claimed_post.claim_id}:{claimed_post.invocation_id}"
                            ),
                        ),
                    ),
                ),
                event_id=f"invocation:{invocation_id}:post-processing-claimed",
            )

        post_policy_results: list[PolicyResult] = []
        post_runtime_outcomes: list[GuardrailOutcome] = []
        try:
            if policy_engine is not None:
                transient = _transient_policy_event(
                    invocation_id=invocation_id,
                    trace_id=trace_id,
                    identity=identity,
                    action=resolved_action,
                    resource=resolved_resource,
                    permission=permission,
                    context={"tool_result": native_result},
                )
                post_policy_results = await _evaluate_policy_stage(
                    policy_engine,
                    transient,
                    post_stage,
                    tracer,
                    policy_bundle,
                )
        except asyncio.CancelledError:
            await _audit_cancelled_delivery(
                audit_log,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                policy_results=pre_policy_results,
                duration_ms=(time.monotonic() - started) * 1000.0,
                snapshot=unvalidated_result_snapshot,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                event_id=(
                    f"invocation:{invocation_id}:delivery"
                    if execution_journal_record is not None
                    else None
                ),
            )
            await commit_journal_delivery_denied()
            raise
        except Exception as exc:
            logger.warning("policy_evaluation_failed", error_type=type(exc).__name__)
            post_policy_results = []
            post_runtime_outcomes.append(
                GuardrailOutcome(
                    effect=GuardrailEffect.DENY,
                    reason_codes=(
                        GUARDRAIL_TIMEOUT
                        if isinstance(exc, TimeoutError)
                        else GUARDRAIL_INTERNAL_ERROR,
                    ),
                )
            )

        post_context = GuardrailContext(
            trace_id=trace_id,
            invocation_id=invocation_id,
            stage=post_stage,
            identity=identity_view,
            action=resolved_action,
            resource=resolved_resource,
            payload=result_payload,
            attributes=_redacted_evidence_attributes(redacted_evidence),
            prior=tuple(all_pre_outcomes),
        )
        try:
            post_chain_result = await _evaluate_guardrails(
                guardrail_chain,
                post_context,
            )
        except BaseException:
            # GuardrailChain._evaluate converts a POST-stage Exception into a
            # DENY, so only a BaseException subclass (CancelledError,
            # KeyboardInterrupt, ...) reaches here. The result is already
            # withheld; write the delivery terminal so the evidence trail ends
            # on a committed terminal rather than leaving reconciliation to
            # infer an in-doubt window, then re-raise.
            await _audit_cancelled_delivery(
                audit_log,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                policy_results=[*pre_policy_results, *post_policy_results],
                duration_ms=(time.monotonic() - started) * 1000.0,
                snapshot=unvalidated_result_snapshot,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                event_id=(
                    f"invocation:{invocation_id}:delivery"
                    if execution_journal_record is not None
                    else None
                ),
            )
            await commit_journal_delivery_denied()
            raise
        delivered_payload = post_chain_result.payload
        post_guardrail_outcomes = [record.decision for record in post_chain_result.decisions]
        post_evaluations = _guardrail_evaluations(post_chain_result, post_stage)
        actual_post_outcomes = [
            *post_runtime_outcomes,
            *(post_guardrail_outcomes if post_chain_result.enforced else []),
        ]
        combined_policy = [*pre_policy_results, *post_policy_results]
        combined_actual_outcomes = [*actual_pre_outcomes, *actual_post_outcomes]
        post_codes = _reason_codes(combined_actual_outcomes, combined_policy)
        policy_deny = next(
            (
                result
                for result in post_policy_results
                if not result.passed and result.effect == "deny"
            ),
            None,
        )
        policy_escalate = next(
            (
                result
                for result in post_policy_results
                if not result.passed and result.effect == "escalate"
            ),
            None,
        )
        guard_deny = _outcome_effect(actual_post_outcomes, GuardrailEffect.DENY)
        guard_escalate = _outcome_effect(actual_post_outcomes, GuardrailEffect.ESCALATE)
        if policy_deny is not None or guard_deny is not None:
            codes = post_codes or (GUARDRAIL_INTERNAL_ERROR,)
            await _finish_audit_write_on_cancellation(
                _audit_decision(
                    audit_log,
                    invocation_id=invocation_id,
                    trace_id=trace_id,
                    identity=identity,
                    action=resolved_action,
                    resource=resolved_resource,
                    permission=permission,
                    result="denied",
                    event_type="delivery_denied",
                    reason_codes=codes,
                    policy_results=combined_policy,
                    duration_ms=duration_ms,
                    snapshot=unvalidated_result_snapshot,
                    policy_bundle_version=policy_bundle_version,
                    chain_mode=chain_mode,
                    guardrail_evaluations=post_evaluations,
                    event_id=(
                        f"invocation:{invocation_id}:delivery"
                        if execution_journal_record is not None
                        else None
                    ),
                )
            )
            await commit_journal_delivery_denied()
            raise PermissionDeniedError(
                agent_id, resolved_action, resolved_resource, reason=",".join(codes)
            )
        accepted_result_snapshot = _capture_result_evidence(native_result, redacted_evidence)
        if policy_escalate is not None or guard_escalate is not None:
            codes = post_codes or (GUARDRAIL_INTERNAL_ERROR,)
            if escalation_store is None:
                await _finish_audit_write_on_cancellation(
                    _audit_decision(
                        audit_log,
                        invocation_id=invocation_id,
                        trace_id=trace_id,
                        identity=identity,
                        action=resolved_action,
                        resource=resolved_resource,
                        permission=permission,
                        result="escalated",
                        event_type="delivery_escalated",
                        reason_codes=codes,
                        policy_results=combined_policy,
                        duration_ms=duration_ms,
                        snapshot=accepted_result_snapshot,
                        policy_bundle_version=policy_bundle_version,
                        chain_mode=chain_mode,
                        guardrail_evaluations=post_evaluations,
                    )
                )
                raise EscalationRequiredError(
                    agent_id,
                    resolved_action,
                    resolved_resource,
                    codes,
                )

            post_resumable = (
                continuation_protector is not None
                and isinstance(policy_engine, PolicyEngine)
                and policy_bundle is not None
                and policy_escalate is None
                and guard_escalate is not None
                and post_chain_result.cursor is not None
                and guardrail_chain.resumable
            )

            async def commit_durable_request() -> CreatedEscalation:
                if post_resumable:
                    assert continuation_protector is not None
                    assert isinstance(policy_engine, PolicyEngine)
                    assert policy_bundle is not None
                    assert post_chain_result.cursor is not None
                    if not _post_payload_matches_stage(post_chain_result.payload, post_stage):
                        raise EscalationStateError(
                            "post-delivery continuation payload does not match its stage"
                        )
                    resumable_payload = cast(
                        "ToolResultPayload | DecisionPayload", post_chain_result.payload
                    )
                    created = await _persist_post_execution_escalation(
                        escalation_store=escalation_store,
                        continuation_protector=continuation_protector,
                        policy_engine=policy_engine,
                        policy_bundle=policy_bundle,
                        ttl=escalation_ttl,
                        invocation_id=invocation_id,
                        trace_id=trace_id,
                        identity=identity,
                        action=resolved_action,
                        resource=resolved_resource,
                        permission=permission,
                        stage=post_stage,
                        payload=resumable_payload,
                        policy_results=combined_policy,
                        prior_outcomes=(*all_pre_outcomes, *post_runtime_outcomes),
                        prior_guardrail_decisions=post_chain_result.decisions,
                        cursor=post_chain_result.cursor,
                        chain_fingerprint=guardrail_chain.fingerprint,
                        execution_duration_ms=duration_ms,
                        execution_completed_at=execution_completed_at,
                        authentication_binding=authentication_binding,
                        subject_ref=subject_ref,
                        links=links,
                        redacted_evidence=redacted_evidence,
                    )
                else:
                    persisted = await _persist_escalation(
                        escalation_store,
                        ttl=escalation_ttl,
                    )
                    assert persisted is not None
                    created = persisted
                await _audit_decision(
                    audit_log,
                    invocation_id=invocation_id,
                    trace_id=trace_id,
                    identity=identity,
                    action=resolved_action,
                    resource=resolved_resource,
                    permission=permission,
                    result="escalated",
                    event_type="escalation_requested",
                    reason_codes=codes,
                    policy_results=combined_policy,
                    duration_ms=duration_ms,
                    snapshot=accepted_result_snapshot,
                    policy_bundle_version=policy_bundle_version,
                    chain_mode=chain_mode,
                    guardrail_evaluations=post_evaluations,
                    hitl_evidence=HitlEvidence(
                        escalation_id=created.record.escalation_id,
                        state="requested",
                        expires_at=created.record.expires_at,
                    ),
                    event_id=f"hitl:{created.record.escalation_id}:requested",
                )
                return created

            request_task = asyncio.create_task(commit_durable_request())
            cancellation_observed = False
            try:
                while not request_task.done():
                    try:
                        await asyncio.shield(request_task)
                    except asyncio.CancelledError:
                        cancellation_observed = True
                if cancellation_observed:
                    if not request_task.cancelled():
                        request_task.exception()
                    await _audit_cancelled_delivery(
                        audit_log,
                        invocation_id=invocation_id,
                        trace_id=trace_id,
                        identity=identity,
                        action=resolved_action,
                        resource=resolved_resource,
                        permission=permission,
                        policy_results=combined_policy,
                        duration_ms=duration_ms,
                        snapshot=accepted_result_snapshot,
                        policy_bundle_version=policy_bundle_version,
                        chain_mode=chain_mode,
                        guardrail_evaluations=post_evaluations,
                        event_id=(
                            f"invocation:{invocation_id}:delivery"
                            if execution_journal_record is not None
                            else None
                        ),
                    )
                    await commit_journal_delivery_denied()
                    raise asyncio.CancelledError
                created = request_task.result()
            except Exception:
                try:
                    await _finish_audit_write_on_cancellation(
                        _audit_decision(
                            audit_log,
                            invocation_id=invocation_id,
                            trace_id=trace_id,
                            identity=identity,
                            action=resolved_action,
                            resource=resolved_resource,
                            permission=permission,
                            result="denied",
                            event_type="delivery_denied",
                            reason_codes=(GUARDRAIL_INTERNAL_ERROR,),
                            policy_results=combined_policy,
                            duration_ms=duration_ms,
                            snapshot=accepted_result_snapshot,
                            policy_bundle_version=policy_bundle_version,
                            chain_mode=chain_mode,
                            guardrail_evaluations=post_evaluations,
                            event_id=(
                                f"invocation:{invocation_id}:delivery"
                                if execution_journal_record is not None
                                else None
                            ),
                        )
                    )
                    await commit_journal_delivery_denied()
                except Exception:
                    logger.exception(
                        "audit_failed_escalation_delivery_write_failed",
                        trace_id=trace_id,
                    )
                raise
            if execution_journal is not None and execution_journal_record is not None:
                await execution_journal.commit_handoff(
                    execution_journal_record.escalation_id,
                    claim_id=execution_journal_record.claim_id,
                    invocation_id=execution_journal_record.invocation_id,
                )
            raise EscalationRequiredError(
                agent_id,
                resolved_action,
                resolved_resource,
                codes,
                escalation_id=created.record.escalation_id,
                approval_token=created.token,
                expires_at=created.record.expires_at,
            )

        if not _post_payload_matches_stage(delivered_payload, post_stage):
            codes = (OUTPUT_SCHEMA_INVALID,)
            await _finish_audit_write_on_cancellation(
                _audit_decision(
                    audit_log,
                    invocation_id=invocation_id,
                    trace_id=trace_id,
                    identity=identity,
                    action=resolved_action,
                    resource=resolved_resource,
                    permission=permission,
                    result="denied",
                    event_type="delivery_denied",
                    reason_codes=codes,
                    policy_results=combined_policy,
                    duration_ms=duration_ms,
                    policy_bundle_version=policy_bundle_version,
                    chain_mode=chain_mode,
                    guardrail_evaluations=post_evaluations,
                    event_id=(
                        f"invocation:{invocation_id}:delivery"
                        if execution_journal_record is not None
                        else None
                    ),
                )
            )
            await commit_journal_delivery_denied()
            raise PermissionDeniedError(
                agent_id, resolved_action, resolved_resource, reason=",".join(codes)
            )

        transformed_result = any(
            outcome.effect is GuardrailEffect.TRANSFORM for outcome in actual_post_outcomes
        )
        typed_delivered_payload = cast("ToolResultPayload | DecisionPayload", delivered_payload)
        delivered = _post_payload_value(typed_delivered_payload) if transformed_result else result
        delivery_snapshot = _capture_result_evidence(
            _post_payload_value(typed_delivered_payload), redacted_evidence
        )
        await _finish_audit_write_on_cancellation(
            _audit_decision(
                audit_log,
                invocation_id=invocation_id,
                trace_id=trace_id,
                identity=identity,
                action=resolved_action,
                resource=resolved_resource,
                permission=permission,
                result="allowed",
                event_type="delivery_completed",
                reason_codes=post_codes,
                policy_results=combined_policy,
                duration_ms=(time.monotonic() - started) * 1000.0,
                snapshot=delivery_snapshot,
                policy_bundle_version=policy_bundle_version,
                chain_mode=chain_mode,
                guardrail_evaluations=post_evaluations,
                event_id=f"invocation:{invocation_id}:delivery",
            )
        )
        if execution_journal is not None and execution_journal_record is not None:
            await execution_journal.commit_delivered(
                execution_journal_record.escalation_id,
                claim_id=execution_journal_record.claim_id,
                invocation_id=invocation_id,
            )
        logger.info(
            "governed_execution_completed",
            agent_id=agent_id,
            action=resolved_action,
            trace_id=trace_id,
            invocation_id=invocation_id,
        )
        return delivered


class GovernanceKernel:
    """Own the complete governance lifecycle for framework adapters.

    ``chain_mode`` applies only to the content guardrail chain. RBAC, policy,
    rate-limit, circuit-breaker, audit, and execution controls remain active in
    every mode. Shadow mode signs observed decisions without blocking or
    applying transforms; off mode skips content guardrail evaluation.
    """

    def __init__(
        self,
        *,
        registry: AgentRegistry | None = None,
        authoritative_registry: AuthoritativeAgentRegistry | None = None,
        agent_authenticator: AgentAuthenticator | None = None,
        rbac_engine: RBACEngine,
        audit_log: AuditLog,
        policy_engine: PolicyEngine | None,
        guardrails: Sequence[Guardrail],
        chain_mode: ChainMode | str = ChainMode.ENFORCE,
        rate_limiter: TokenBucketRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        tracer: AgentTracer | None = None,
        resolver_timeout: float = _DEFAULT_RESOLVER_TIMEOUT,
        guardrail_timeout: float = _DEFAULT_GUARDRAIL_TIMEOUT,
        escalation_store: EscalationStore | None = None,
        escalation_ttl: timedelta = _DEFAULT_ESCALATION_TTL,
        approver_authenticator: ApproverAuthenticator | None = None,
        continuation_protector: ContinuationProtector | None = None,
        executor_resolver: ExecutorResolver | None = None,
        execution_journal: ExecutionJournal | None = None,
        sandbox_backend: DockerSandboxBackend | None = None,
    ) -> None:
        legacy_mode = (
            registry is not None and authoritative_registry is None and agent_authenticator is None
        )
        secure_mode = (
            registry is None
            and authoritative_registry is not None
            and agent_authenticator is not None
        )
        if not (legacy_mode or secure_mode):
            raise ValueError(
                "configure exactly legacy registry or secure authoritative_registry "
                "with agent_authenticator"
            )
        if not math.isfinite(resolver_timeout) or resolver_timeout <= 0:
            raise ValueError("resolver_timeout must be a positive finite number")
        if not math.isfinite(guardrail_timeout) or guardrail_timeout <= 0:
            raise ValueError("guardrail_timeout must be a positive finite number")
        if escalation_ttl <= timedelta(0):
            raise ValueError("escalation_ttl must be positive")
        if sandbox_backend is not None and type(sandbox_backend) is not DockerSandboxBackend:
            raise TypeError(
                "sandbox_backend must be the hardened DockerSandboxBackend; "
                "host subprocess backends and subclass overrides are not valid for "
                "enforced obligations"
            )
        self._registry = registry
        self._authoritative_registry = authoritative_registry
        self._agent_authenticator = agent_authenticator
        self._secure_mode = secure_mode
        self._rbac_engine = rbac_engine
        self._audit_log = audit_log
        self._policy_engine = policy_engine
        self._guardrail_chain = GuardrailChain(
            guardrails,
            mode=ChainMode(chain_mode),
            timeout_ms=math.ceil(guardrail_timeout * 1_000),
        )
        self._rate_limiter = rate_limiter
        self._circuit_breaker = circuit_breaker
        self._tracer = tracer
        self._resolver_timeout = resolver_timeout
        self._escalation_store = escalation_store
        self._escalation_ttl = escalation_ttl
        self._approver_authenticator = approver_authenticator
        self._continuation_protector = continuation_protector
        self._executor_resolver = executor_resolver
        self._execution_journal = execution_journal
        self._sandbox_backend = sandbox_backend
        self._reconciliation_lock = asyncio.Lock()

    @property
    def chain_mode(self) -> ChainMode:
        """Return the configured guardrail-chain enforcement mode."""

        return self._guardrail_chain.mode

    def bind_adapter(
        self,
        *,
        agent_id: str | None = None,
        credential_provider: AgentCredentialProvider | None = None,
    ) -> GovernedAdapterCaller:
        """Bind one mode-neutral adapter caller to the configured trust mode."""

        if self._secure_mode:
            if agent_id is not None or credential_provider is None:
                raise ValueError(
                    "secure adapter binding requires credential_provider and forbids agent_id"
                )
        elif agent_id is None or credential_provider is not None:
            raise ValueError("legacy adapter binding requires agent_id and forbids provider")
        return GovernedAdapterCaller(
            _kernel=self,
            _agent_id=agent_id,
            _credential_provider=credential_provider,
        )

    async def _write_authentication_event(
        self,
        *,
        invocation_id: str,
        trace_id: str,
        evidence: AuthenticationEvidence,
    ) -> AuditEvent:
        rejected = evidence.state == "rejected"
        identity = AgentIdentity(
            agent_id=(UNAUTHENTICATED_AGENT_ID if rejected else evidence.agent_id),
            name=(UNAUTHENTICATED_AGENT_NAME if rejected else "Authenticated agent"),
            roles=[],
        )
        permission = PermissionContext(
            agent=identity,
            requested_action="authenticate",
            resource="agent",
            granted=not rejected,
            reason=(evidence.failure_reason.value if evidence.failure_reason else ""),
        )
        event_id = hashlib.sha256(
            canonical_json_bytes(
                {
                    "domain": "agentguard.authentication.event.v1",
                    "invocation_id": invocation_id,
                    "state": evidence.state,
                }
            )
        ).hexdigest()
        event = _new_event(
            invocation_id=invocation_id,
            trace_id=trace_id,
            identity=identity,
            action="authenticate",
            resource="agent",
            permission=permission,
            result="rejected" if rejected else "allowed",
            event_type=("authentication_rejected" if rejected else "authentication_succeeded"),
            reason_codes=(evidence.failure_reason.value,) if evidence.failure_reason else (),
            authentication_evidence=evidence,
            event_id=event_id,
            timestamp=evidence.authenticated_at,
        )
        signed = await self._audit_log.write_once(event)
        if (
            signed.event_id != event.event_id
            or signed.invocation_id != invocation_id
            or signed.trace_id != trace_id
            or signed.authentication_evidence != evidence
            or signed.event_type != event.event_type
            or signed.action != "authenticate"
            or signed.resource != "agent"
        ):
            raise EscalationStateError("authentication audit evidence changed during write")
        if (
            not signed.event_hash
            or not signed.chain_id
            or signed.sequence is None
            or not signed.key_id
            or signed.hash_schema_version < 7
        ):
            raise EscalationStateError("authentication audit evidence is not signed")
        return signed

    async def _reject_authentication(
        self,
        failure: AuthenticationFailure,
        attempt: AuthenticationAttempt,
        *,
        invocation_id: str,
        trace_id: str,
    ) -> NoReturn:
        evidence = AuthenticationEvidence(
            state="rejected",
            method=attempt.method,
            credential_digest=attempt.credential_digest,
            authenticated_at=datetime.now(UTC),
            failure_reason=failure,
        )
        await self._write_authentication_event(
            invocation_id=invocation_id,
            trace_id=trace_id,
            evidence=evidence,
        )
        raise AuthenticationError(failure)

    async def _authenticate_workload(
        self,
        credential: object | None,
        *,
        invocation_id: str,
        trace_id: str,
    ) -> _AuthenticatedWorkload:
        """Authenticate and audit before observing any governed request data."""

        authenticator = self._agent_authenticator
        registry = self._authoritative_registry
        if authenticator is None or registry is None:
            raise EscalationStateError("secure workload authentication is not configured")
        fallback_attempt = AuthenticationAttempt(
            method="unknown",
            credential_digest=hashlib.sha256(b"").hexdigest(),
        )
        if credential is None:
            await self._reject_authentication(
                AuthenticationFailure.CREDENTIAL_MISSING,
                fallback_attempt,
                invocation_id=invocation_id,
                trace_id=trace_id,
            )
        describe_failure: AuthenticationFailure | None = None
        attempt: AuthenticationAttempt | None = None
        try:
            attempt = AuthenticationAttempt.model_validate(
                await authenticator.describe_attempt(credential)
            )
        except asyncio.CancelledError:
            raise
        except AuthenticationError as exc:
            describe_failure = exc.failure
        except Exception:
            describe_failure = AuthenticationFailure.INTERNAL_ERROR
        if describe_failure is not None:
            await self._reject_authentication(
                describe_failure,
                fallback_attempt,
                invocation_id=invocation_id,
                trace_id=trace_id,
            )
        assert attempt is not None

        authentication_failure: AuthenticationFailure | None = None
        principal: AuthenticatedAgentPrincipal | None = None
        try:
            principal = AuthenticatedAgentPrincipal.model_validate(
                await authenticator.authenticate(credential)
            )
        except asyncio.CancelledError:
            raise
        except AuthenticationError as exc:
            authentication_failure = exc.failure
        except Exception:
            authentication_failure = AuthenticationFailure.INTERNAL_ERROR
        if authentication_failure is not None:
            await self._reject_authentication(
                authentication_failure,
                attempt,
                invocation_id=invocation_id,
                trace_id=trace_id,
            )
        assert principal is not None

        now = datetime.now(UTC)
        failure: AuthenticationFailure | None = None
        if (
            principal.method != attempt.method
            or principal.credential_digest != attempt.credential_digest
        ):
            failure = AuthenticationFailure.PRINCIPAL_MISMATCH
        elif now < principal.not_before or now < principal.authenticated_at:
            failure = AuthenticationFailure.CREDENTIAL_NOT_YET_VALID
        elif now >= principal.expires_at:
            failure = AuthenticationFailure.CREDENTIAL_EXPIRED
        if failure is not None:
            await self._reject_authentication(
                failure,
                attempt,
                invocation_id=invocation_id,
                trace_id=trace_id,
            )

        registry_failed = False
        registry_snapshot = None
        record = None
        try:
            registry_snapshot = await registry.snapshot()
            record = next(
                (
                    candidate
                    for candidate in registry_snapshot.records
                    if candidate.agent_id == principal.agent_id
                ),
                None,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            registry_failed = True
        if registry_failed:
            await self._reject_authentication(
                AuthenticationFailure.INTERNAL_ERROR,
                attempt,
                invocation_id=invocation_id,
                trace_id=trace_id,
            )
        assert registry_snapshot is not None
        if record is None or record.status is not AgentStatus.ACTIVE:
            await self._reject_authentication(
                AuthenticationFailure.IDENTITY_INACTIVE,
                attempt,
                invocation_id=invocation_id,
                trace_id=trace_id,
            )

        identity = self._identity_from_registry_record(record)
        evidence = AuthenticationEvidence(
            state="verified",
            method=principal.method,
            authority=principal.authority,
            agent_id=principal.agent_id,
            credential_digest=principal.credential_digest,
            authenticated_at=principal.authenticated_at,
            issued_at=principal.issued_at,
            not_before=principal.not_before,
            expires_at=principal.expires_at,
            registry_revision=registry_snapshot.registry_revision,
        )
        signed = await self._write_authentication_event(
            invocation_id=invocation_id,
            trace_id=trace_id,
            evidence=evidence,
        )
        assert signed.sequence is not None
        reference = SignedAuditReference(
            event_id=signed.event_id,
            event_hash=signed.event_hash,
            chain_id=signed.chain_id,
            sequence=signed.sequence,
            key_id=signed.key_id,
        )
        return _AuthenticatedWorkload(
            identity=identity,
            binding=WorkloadAuthenticationBinding(
                principal=principal,
                registry_id=registry_snapshot.registry_id,
                registry_revision=registry_snapshot.registry_revision,
                record_revision=record.record_revision,
                credential_epoch=record.credential_epoch,
                audit_reference=reference,
            ),
        )

    @staticmethod
    def _identity_from_registry_record(record: AgentRegistryRecord) -> AgentIdentity:
        return AgentIdentity(
            agent_id=record.agent_id,
            name=record.name,
            roles=list(record.roles),
            metadata=dict(record.metadata),
        )

    async def guarded_tool_call(
        self,
        *,
        agent_id: str | None = None,
        credential: object | None = None,
        action: ActionResolver,
        resource: ResourceResolver | None,
        executor: Callable[[GuardrailPayload], Awaitable[Any]],
        payload: ToolCallPayload | MessagePayload | None = None,
        fallback_action: str | None = None,
        subject_ref: EvidenceRef | None = None,
        links: Sequence[AuditLink] = (),
        redacted_evidence: object | None = None,
    ) -> Any:
        """Execute a legacy caller-supplied executor without restart resumption."""

        return await self._guarded_tool_call(
            agent_id=agent_id,
            credential=credential,
            action=action,
            resource=resource,
            executor=executor,
            payload=payload,
            fallback_action=fallback_action,
            executor_ref=None,
            subject_ref=subject_ref,
            links=links,
            redacted_evidence=redacted_evidence,
        )

    async def guarded_registered_tool_call(
        self,
        *,
        agent_id: str | None = None,
        credential: object | None = None,
        action: ActionResolver,
        resource: ResourceResolver | None,
        executor_id: str,
        payload: ToolCallPayload | MessagePayload | None = None,
        fallback_action: str | None = None,
        subject_ref: EvidenceRef | None = None,
        links: Sequence[AuditLink] = (),
        redacted_evidence: object | None = None,
    ) -> Any:
        """Execute an application-registered executor eligible for PRE-stage resume."""

        return await self._guarded_tool_call(
            agent_id=agent_id,
            credential=credential,
            action=action,
            resource=resource,
            executor=None,
            payload=payload,
            fallback_action=fallback_action,
            executor_ref=None,
            executor_id=executor_id,
            subject_ref=subject_ref,
            links=links,
            redacted_evidence=redacted_evidence,
        )

    async def _guarded_tool_call(
        self,
        *,
        agent_id: str | None,
        credential: object | None,
        action: ActionResolver,
        resource: ResourceResolver | None,
        executor: Callable[[GuardrailPayload], Awaitable[Any]] | None,
        payload: ToolCallPayload | MessagePayload | None = None,
        fallback_action: str | None = None,
        executor_ref: ExecutorRef | None,
        executor_id: str | None = None,
        invocation_id: str | None = None,
        trace_id: str | None = None,
        authenticated_override: _AuthenticatedWorkload | None = None,
        subject_ref: EvidenceRef | None = None,
        links: Sequence[AuditLink] = (),
        redacted_evidence: object | None = None,
    ) -> Any:
        """Execute one call while keeping every outcome inside one root span."""

        subject_ref, validated_links = _validate_evidence_links(subject_ref, links)
        normalized_redacted_evidence = (
            None
            if redacted_evidence is None
            else thaw_payload(normalize_payload(redacted_evidence))
        )

        invocation_id = invocation_id or str(uuid.uuid4())
        trace_id = trace_id or str(uuid.uuid4())
        authenticated: _AuthenticatedWorkload | None = None
        if self._secure_mode:
            if agent_id is not None:
                raise ValueError("secure governed calls accept credential but not agent_id")
            if authenticated_override is None:
                authenticated = await self._authenticate_workload(
                    credential,
                    invocation_id=invocation_id,
                    trace_id=trace_id,
                )
            else:
                if credential is not None:
                    raise ValueError("preauthenticated governed calls cannot accept credential")
                authenticated = authenticated_override
            effective_agent_id = authenticated.identity.agent_id
        else:
            if authenticated_override is not None:
                raise ValueError("legacy governed calls cannot use authenticated identity")
            if agent_id is None:
                raise ValueError("legacy governed calls require agent_id")
            if credential is not None:
                raise ValueError("legacy governed calls do not accept workload credentials")
            effective_agent_id = agent_id

        span_action = action if isinstance(action, str) else (fallback_action or UNRESOLVED_ACTION)
        span_resource = resource if isinstance(resource, str) else UNRESOLVED_RESOURCE
        span_cm = _safe_span(
            self._tracer,
            "agentguard.tool_call",
            {
                "agent.id": effective_agent_id,
                "tool.action": span_action,
                "tool.resource": canonicalize_resource(span_resource) or UNRESOLVED_RESOURCE,
            },
        )
        started = time.monotonic()
        outcome = "error"
        token = _ACTIVE_TRACER.set(self._tracer)
        subject_token = _ACTIVE_SUBJECT_REF.set(subject_ref)
        links_token = _ACTIVE_AUDIT_LINKS.set(validated_links)
        try:
            with span_cm as root_span:
                try:
                    result = await _run_governed_impl(
                        agent_id=effective_agent_id,
                        action=action,
                        resource=resource,
                        registry=self._registry,
                        rbac_engine=self._rbac_engine,
                        audit_log=self._audit_log,
                        executor=executor,
                        payload=payload,
                        policy_engine=self._policy_engine,
                        guardrail_chain=self._guardrail_chain,
                        rate_limiter=self._rate_limiter,
                        circuit_breaker=self._circuit_breaker,
                        tracer=self._tracer,
                        root_span=root_span,
                        resolver_timeout=self._resolver_timeout,
                        fallback_action=fallback_action,
                        escalation_store=self._escalation_store,
                        escalation_ttl=self._escalation_ttl,
                        continuation_protector=self._continuation_protector,
                        executor_ref=executor_ref,
                        executor_id=executor_id,
                        executor_resolver=self._executor_resolver,
                        invocation_id=invocation_id,
                        trace_id=trace_id,
                        identity_override=(authenticated.identity if authenticated else None),
                        authentication_binding=(authenticated.binding if authenticated else None),
                        execution_journal=self._execution_journal,
                        subject_ref=subject_ref,
                        links=validated_links,
                        redacted_evidence=normalized_redacted_evidence,
                        sandbox_backend=self._sandbox_backend,
                    )
                except EscalationRequiredError as exc:
                    outcome = "escalated"
                    if self._tracer is not None:
                        _set_span_attribute(root_span, "agentguard.result", outcome)
                        _set_span_attribute(
                            root_span,
                            "agentguard.reason_codes",
                            exc.reason_codes,
                        )
                    raise
                except PermissionDeniedError as exc:
                    outcome = "denied"
                    if self._tracer is not None:
                        _set_span_attribute(root_span, "agentguard.result", outcome)
                        _set_span_attribute(
                            root_span,
                            "agentguard.denial.reason",
                            exc.reason,
                        )
                    raise
                except (RateLimitExceededError, CircuitOpenError):
                    outcome = "rejected"
                    if self._tracer is not None:
                        _set_span_attribute(root_span, "agentguard.result", outcome)
                    raise
                except BaseException:
                    if self._tracer is not None:
                        _set_span_attribute(root_span, "agentguard.result", outcome)
                    raise
                outcome = "allowed"
                if self._tracer is not None:
                    _set_span_attribute(root_span, "agentguard.result", outcome)
                return result
        finally:
            _ACTIVE_AUDIT_LINKS.reset(links_token)
            _ACTIVE_SUBJECT_REF.reset(subject_token)
            _ACTIVE_TRACER.reset(token)
            if self._tracer is not None:
                record_outcome = getattr(self._tracer, "record_outcome", None)
                if callable(record_outcome):
                    try:
                        record_outcome(
                            outcome,
                            (time.monotonic() - started) * 1000.0,
                        )
                    except BaseException:
                        logger.debug("otel_metric_write_failed", exc_info=True)

    async def decide_escalation(
        self,
        *,
        escalation_id: str,
        approval_token: str,
        credential: object,
        decision_id: str,
        disposition: ApprovalDisposition,
        reason: str = "",
    ) -> EscalationRecord:
        """Authenticate and durably record one approval decision.

        The approver identity comes only from the injected authenticator. The
        prepared store transition remains ineffective until its stable audit
        event has been committed with ``write_once``.
        """

        store = self._require_escalation_store()
        if self._approver_authenticator is None:
            raise EscalationStateError("approver authentication is not configured")
        principal = await self._approver_authenticator.authenticate(credential)
        disposition = ApprovalDisposition(disposition)
        required_capability = (
            "hitl:approve" if disposition is ApprovalDisposition.APPROVE else "hitl:deny"
        )
        if required_capability not in principal.capabilities:
            raise EscalationStateError("approver is not authorized for this decision")

        store_disposition = (
            DecisionDisposition.APPROVE
            if disposition is ApprovalDisposition.APPROVE
            else DecisionDisposition.DENY
        )
        reason_digest = hashlib.sha256(reason.encode("utf-8")).hexdigest()
        try:
            prepared = await store.prepare_decision(
                escalation_id,
                token=approval_token,
                decision_id=decision_id,
                disposition=store_disposition,
                approver_id=principal.approver_id,
                reason_digest=reason_digest,
            )
        except EscalationExpiredError:
            await self.expire_escalation(escalation_id=escalation_id)
            raise

        continuation = await self._open_continuation(
            escalation_id,
            prepared.sealed_continuation,
            prepared.record.continuation_kind,
        )
        reason_codes = _continuation_reason_codes(continuation)
        event_type = (
            "approval_granted" if disposition is ApprovalDisposition.APPROVE else "approval_denied"
        )
        hitl_evidence = HitlEvidence(
            escalation_id=escalation_id,
            decision_id=prepared.decision_id,
            state=("approved" if disposition is ApprovalDisposition.APPROVE else "denied"),
            approver_id=prepared.approver_id,
            reason_redacted="[provided]" if reason else "",
            decided_at=prepared.decided_at,
            expires_at=prepared.record.expires_at,
        )
        await _audit_decision(
            self._audit_log,
            invocation_id=continuation.invocation_id,
            trace_id=continuation.trace_id,
            identity=continuation.permission_context.agent,
            action=continuation.action,
            resource=continuation.resource,
            permission=continuation.permission_context,
            result="allowed" if disposition is ApprovalDisposition.APPROVE else "denied",
            event_type=event_type,
            reason_codes=reason_codes,
            policy_results=continuation.policy_results,
            policy_bundle_version=continuation.policy_bundle_version,
            chain_mode=ChainMode.ENFORCE,
            subject_ref=continuation.subject_ref,
            links=continuation.links,
            hitl_evidence=hitl_evidence,
            event_id=f"hitl:{escalation_id}:decision:{decision_id}",
            timestamp=prepared.decided_at,
            tracer=self._tracer,
        )
        if disposition is ApprovalDisposition.DENY:
            await _audit_decision(
                self._audit_log,
                invocation_id=continuation.invocation_id,
                trace_id=continuation.trace_id,
                identity=continuation.permission_context.agent,
                action=continuation.action,
                resource=continuation.resource,
                permission=continuation.permission_context,
                result="denied",
                event_type="delivery_denied",
                reason_codes=reason_codes,
                policy_results=continuation.policy_results,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_mode=ChainMode.ENFORCE,
                subject_ref=continuation.subject_ref,
                links=continuation.links,
                event_id=f"hitl:{escalation_id}:delivery-denied:{decision_id}",
                timestamp=prepared.decided_at,
                tracer=self._tracer,
            )
        return await store.commit_decision(escalation_id, decision_id=decision_id)

    async def expire_escalation(self, *, escalation_id: str) -> EscalationRecord:
        """Materialize one expired resumable request with signed evidence."""

        store = self._require_escalation_store()
        prepared = await store.prepare_expiry(escalation_id)
        sealed = await store.get_sealed_continuation(escalation_id)
        continuation = await self._open_continuation(
            escalation_id,
            sealed,
            prepared.continuation_kind,
        )
        reason_codes = _continuation_reason_codes(continuation)
        decided_at = prepared.expires_at
        hitl_evidence = HitlEvidence(
            escalation_id=escalation_id,
            decision_id="expiry",
            state="expired",
            decided_at=decided_at,
            expires_at=prepared.expires_at,
        )
        await _audit_decision(
            self._audit_log,
            invocation_id=continuation.invocation_id,
            trace_id=continuation.trace_id,
            identity=continuation.permission_context.agent,
            action=continuation.action,
            resource=continuation.resource,
            permission=continuation.permission_context,
            result="denied",
            event_type="approval_expired",
            reason_codes=reason_codes,
            policy_results=continuation.policy_results,
            policy_bundle_version=continuation.policy_bundle_version,
            chain_mode=ChainMode.ENFORCE,
            subject_ref=continuation.subject_ref,
            links=continuation.links,
            hitl_evidence=hitl_evidence,
            event_id=f"hitl:{escalation_id}:expired",
            timestamp=decided_at,
            tracer=self._tracer,
        )
        await _audit_decision(
            self._audit_log,
            invocation_id=continuation.invocation_id,
            trace_id=continuation.trace_id,
            identity=continuation.permission_context.agent,
            action=continuation.action,
            resource=continuation.resource,
            permission=continuation.permission_context,
            result="denied",
            event_type="delivery_denied",
            reason_codes=reason_codes,
            policy_results=continuation.policy_results,
            policy_bundle_version=continuation.policy_bundle_version,
            chain_mode=ChainMode.ENFORCE,
            subject_ref=continuation.subject_ref,
            links=continuation.links,
            event_id=f"hitl:{escalation_id}:delivery-denied:expiry",
            timestamp=decided_at,
            tracer=self._tracer,
        )
        return await store.commit_expiry(escalation_id)

    async def assess_execution(
        self,
        escalation_id: str,
        *,
        credential: object,
    ) -> ReconciliationAssessment:
        """Classify claimed protected work from authenticated, checkpointed evidence."""

        principal = await self._authenticate_reconciler(credential)
        snapshot = await self._audit_log.read_verified(require_checkpoint=True)
        record, claimed, continuation = await self._load_execution_journal_context(escalation_id)
        events = tuple(
            event for event in snapshot.events if event.invocation_id == record.invocation_id
        )
        terminal = await self._converge_verified_journal_terminal(record, events)
        if terminal is not None:
            return self._reconciliation_assessment(terminal)

        if self._post_processing_claim_audited(events) and record.status in {
            ExecutionJournalStatus.OUTCOME_PROTECTED,
            ExecutionJournalStatus.COMPLETION_AUDITED,
        }:
            record = await self._restore_post_processing_claim(record)

        if record.status in {
            ExecutionJournalStatus.OUTCOME_PROTECTED,
            ExecutionJournalStatus.COMPLETION_AUDITED,
        }:
            return self._reconciliation_assessment(record)
        if record.status in {
            ExecutionJournalStatus.IN_DOUBT,
            ExecutionJournalStatus.RECONCILIATION_PREPARED,
            ExecutionJournalStatus.RECONCILED_DENIED,
            ExecutionJournalStatus.DELIVERED,
            ExecutionJournalStatus.DELIVERY_DENIED,
            ExecutionJournalStatus.HANDED_OFF,
        }:
            return self._reconciliation_assessment(record)

        admission = next(
            (event for event in events if event.event_type == "admission"),
            None,
        )
        completion = next(
            (event for event in events if event.event_type == "execution_completed"),
            None,
        )
        if completion is not None and admission is None:
            raise EscalationStateError("execution completion without admission is contradictory")
        if isinstance(continuation, PostExecutionContinuation) or (
            record.status is ExecutionJournalStatus.POST_PROCESSING_CLAIMED
        ):
            classification = InDoubtClassification.CLAIMED_WITHOUT_TERMINAL
        elif completion is not None:
            classification = InDoubtClassification.COMPLETION_WITHOUT_PROTECTED_RESULT
        elif admission is not None or record.status is ExecutionJournalStatus.ADMITTED:
            classification = InDoubtClassification.ADMISSION_WITHOUT_COMPLETION
        else:
            classification = InDoubtClassification.CLAIMED_WITHOUT_TERMINAL

        stable_id = f"invocation:{record.invocation_id}:in-doubt"
        existing = next((event for event in events if event.event_id == stable_id), None)
        if existing is not None:
            if (
                existing.reconciliation_evidence is None
                or existing.reconciliation_evidence.classification != classification.value
            ):
                raise EscalationStateError("conflicting in-doubt evidence")
            record = await self._require_execution_journal().commit_in_doubt(
                escalation_id,
                claim_id=record.claim_id,
                invocation_id=record.invocation_id,
                classification=classification,
            )
            return self._reconciliation_assessment(record)

        prepared = await self._require_execution_journal().prepare_in_doubt(
            escalation_id,
            claim_id=record.claim_id,
            invocation_id=record.invocation_id,
            classification=classification,
        )
        evidence = self._reconciliation_evidence(
            prepared,
            principal=principal,
            reconciliation_id=f"assessment:{escalation_id}",
            classification=classification.value,
            state="in_doubt",
            reason_digest=hashlib.sha256(b"").hexdigest(),
            snapshot=snapshot,
        )
        await _audit_decision(
            self._audit_log,
            invocation_id=record.invocation_id,
            trace_id=continuation.trace_id,
            identity=continuation.permission_context.agent,
            action=continuation.action,
            resource=continuation.resource,
            permission=continuation.permission_context,
            result="error",
            event_type="execution_in_doubt",
            reason_codes=(
                {
                    InDoubtClassification.CLAIMED_WITHOUT_TERMINAL: (
                        EXECUTION_CLAIMED_WITHOUT_TERMINAL
                    ),
                    InDoubtClassification.ADMISSION_WITHOUT_COMPLETION: (
                        EXECUTION_ADMISSION_WITHOUT_COMPLETION
                    ),
                    InDoubtClassification.COMPLETION_WITHOUT_PROTECTED_RESULT: (
                        EXECUTION_COMPLETION_WITHOUT_PROTECTED_RESULT
                    ),
                }[classification],
            ),
            policy_results=continuation.policy_results,
            policy_bundle_version=continuation.policy_bundle_version,
            chain_mode=ChainMode.ENFORCE,
            reconciliation_evidence=evidence,
            subject_ref=continuation.subject_ref,
            links=(*continuation.links, *self._reconciliation_links(record)),
            event_id=stable_id,
            timestamp=prepared.in_doubt_at,
            tracer=self._tracer,
        )
        committed = await self._require_execution_journal().commit_in_doubt(
            escalation_id,
            claim_id=record.claim_id,
            invocation_id=record.invocation_id,
            classification=classification,
        )
        return self._reconciliation_assessment(committed)

    async def deny_in_doubt(
        self,
        escalation_id: str,
        *,
        credential: object,
        reconciliation_id: str,
        reason: str = "",
    ) -> ExecutionJournalRecord:
        """Apply the sole generic resolution: authenticated delivery denial."""

        async with self._reconciliation_lock:
            return await self._deny_in_doubt_locked(
                escalation_id,
                credential=credential,
                reconciliation_id=reconciliation_id,
                reason=reason,
            )

    async def _deny_in_doubt_locked(
        self,
        escalation_id: str,
        *,
        credential: object,
        reconciliation_id: str,
        reason: str,
    ) -> ExecutionJournalRecord:
        """Serialize one deny-only transition inside this kernel instance."""

        principal = await self._authenticate_reconciler(credential)
        assessment = await self.assess_execution(escalation_id, credential=credential)
        if assessment.protected_result_available:
            raise EscalationStateError("a protected result requires known-outcome reconciliation")
        journal = self._require_execution_journal()
        reason_digest = hashlib.sha256(reason.encode("utf-8")).hexdigest()
        try:
            prepared = await journal.prepare_reconciliation(
                escalation_id,
                claim_id=assessment.claim_id,
                invocation_id=assessment.invocation_id,
                reconciliation_id=reconciliation_id,
                reconciler_id=principal.approver_id,
                reason_digest=reason_digest,
            )
        except ExecutionJournalError as exc:
            raise EscalationStateError("conflicting execution reconciliation") from exc
        claimed = await self._require_escalation_store().inspect_claimed(escalation_id)
        continuation = await self._open_continuation(
            escalation_id,
            claimed.sealed_continuation,
            claimed.record.continuation_kind,
        )
        snapshot = await self._audit_log.read_verified(require_checkpoint=True)
        reconcile_event_id = f"invocation:{assessment.invocation_id}:reconcile:{reconciliation_id}"
        existing_ids = {event.event_id for event in snapshot.events}
        if reconcile_event_id not in existing_ids:
            evidence = self._reconciliation_evidence(
                prepared,
                principal=principal,
                reconciliation_id=reconciliation_id,
                classification="reconciled_denied",
                state="reconciled",
                reason_digest=reason_digest,
                snapshot=snapshot,
            )
            await _audit_decision(
                self._audit_log,
                invocation_id=assessment.invocation_id,
                trace_id=continuation.trace_id,
                identity=continuation.permission_context.agent,
                action=continuation.action,
                resource=continuation.resource,
                permission=continuation.permission_context,
                result="denied",
                event_type="execution_reconciled",
                reason_codes=(EXECUTION_RECONCILED_DENY,),
                policy_results=continuation.policy_results,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_mode=ChainMode.ENFORCE,
                reconciliation_evidence=evidence,
                subject_ref=continuation.subject_ref,
                links=(*continuation.links, *self._reconciliation_links(prepared)),
                event_id=reconcile_event_id,
                tracer=self._tracer,
            )
        terminal_id = f"invocation:{assessment.invocation_id}:delivery"
        refreshed = await self._audit_log.read_verified(require_checkpoint=True)
        if terminal_id not in {event.event_id for event in refreshed.events}:
            await _audit_decision(
                self._audit_log,
                invocation_id=assessment.invocation_id,
                trace_id=continuation.trace_id,
                identity=continuation.permission_context.agent,
                action=continuation.action,
                resource=continuation.resource,
                permission=continuation.permission_context,
                result="denied",
                event_type="delivery_denied",
                reason_codes=(EXECUTION_RECONCILED_DENY,),
                policy_results=continuation.policy_results,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_mode=ChainMode.ENFORCE,
                subject_ref=continuation.subject_ref,
                links=continuation.links,
                event_id=terminal_id,
                tracer=self._tracer,
            )
        committed = await journal.commit_reconciled_denied(
            escalation_id,
            claim_id=assessment.claim_id,
            invocation_id=assessment.invocation_id,
            reconciliation_id=reconciliation_id,
        )
        if claimed.record.continuation_kind is StoreContinuationKind.POST_DELIVERY:
            assert claimed.claim_id is not None
            await self._require_escalation_store().commit_delivery_denied(
                escalation_id,
                claim_id=claimed.claim_id,
            )
        return committed

    async def reconcile_known_outcome(
        self,
        escalation_id: str,
        *,
        credential: object,
        reconciliation_id: str,
        reason: str = "",
    ) -> Any:
        """Resume post-processing from a sealed result without resolving an executor."""

        async with self._reconciliation_lock:
            return await self._reconcile_known_outcome_locked(
                escalation_id,
                credential=credential,
                reconciliation_id=reconciliation_id,
                reason=reason,
            )

    async def _reconcile_known_outcome_locked(
        self,
        escalation_id: str,
        *,
        credential: object,
        reconciliation_id: str,
        reason: str,
    ) -> Any:
        """Serialize one protected-result post-processing claim per kernel."""

        principal = await self._authenticate_reconciler(credential)
        record, _, _ = await self._load_execution_journal_context(escalation_id)
        snapshot = await self._audit_log.read_verified(require_checkpoint=False)
        events = tuple(
            event for event in snapshot.events if event.invocation_id == record.invocation_id
        )
        terminal = await self._converge_verified_journal_terminal(record, events)
        if terminal is not None:
            raise EscalationStateError("execution already has an audited delivery terminal")
        if self._post_processing_claim_audited(events):
            if record.status in {
                ExecutionJournalStatus.OUTCOME_PROTECTED,
                ExecutionJournalStatus.COMPLETION_AUDITED,
            }:
                await self._restore_post_processing_claim(record)
            raise EscalationStateError("post-processing was already durably claimed")
        if record.status not in {
            ExecutionJournalStatus.OUTCOME_PROTECTED,
            ExecutionJournalStatus.COMPLETION_AUDITED,
        }:
            raise EscalationStateError("protected outcome is not recoverable")
        journal = self._require_execution_journal()
        outcome = await journal.open_outcome(
            escalation_id,
            claim_id=record.claim_id,
            invocation_id=record.invocation_id,
        )
        continuation = outcome.continuation
        policy_bundle = self._validate_journal_outcome_runtime(continuation)
        identity = continuation.permission_context.agent
        permission = continuation.permission_context.model_copy(
            update={"granted": False, "reason": "secure resume validation pending"}
        )
        if not self._secure_mode:
            identity = await self._resolve_continuation_identity(continuation)
            permission = await self._rbac_engine.check_permission(
                identity,
                continuation.action,
                continuation.resource,
            )
        else:
            if record.status is ExecutionJournalStatus.OUTCOME_PROTECTED:
                await _audit_decision(
                    self._audit_log,
                    invocation_id=record.invocation_id,
                    trace_id=continuation.trace_id,
                    identity=continuation.permission_context.agent,
                    action=continuation.action,
                    resource=continuation.resource,
                    permission=continuation.permission_context,
                    result="allowed",
                    event_type="execution_completed",
                    reason_codes=_continuation_reason_codes(continuation),
                    policy_results=continuation.policy_results,
                    duration_ms=continuation.execution_duration_ms,
                    policy_bundle_version=continuation.policy_bundle_version,
                    chain_mode=ChainMode.ENFORCE,
                    event_id=f"invocation:{record.invocation_id}:execution-completed",
                    timestamp=continuation.execution_completed_at,
                    tracer=self._tracer,
                )
                record = await journal.mark_completion_audited(
                    escalation_id,
                    claim_id=record.claim_id,
                    invocation_id=record.invocation_id,
                )
            claim_task = asyncio.create_task(
                journal.claim_post_processing(
                    escalation_id,
                    claim_id=record.claim_id,
                    invocation_id=record.invocation_id,
                )
            )
            claim_cancelled = False
            while not claim_task.done():
                try:
                    await asyncio.shield(claim_task)
                except asyncio.CancelledError:
                    claim_cancelled = True
                except Exception:
                    break
            record = claim_task.result()
            if claim_cancelled:
                with suppress(asyncio.CancelledError):
                    await _finish_audit_write_on_cancellation(
                        self._finish_journal_binding_denied(
                            outcome,
                            identity=identity,
                            permission=permission.model_copy(update={"reason": DELIVERY_CANCELLED}),
                            reason_codes=(DELIVERY_CANCELLED,),
                        )
                    )
                raise asyncio.CancelledError
            try:
                identity = await self._resolve_continuation_identity(continuation)
                permission = await self._rbac_engine.check_permission(
                    identity,
                    continuation.action,
                    continuation.resource,
                )
            except asyncio.CancelledError:
                with suppress(asyncio.CancelledError):
                    await _finish_audit_write_on_cancellation(
                        self._finish_journal_binding_denied(
                            outcome,
                            identity=identity,
                            permission=permission.model_copy(update={"reason": DELIVERY_CANCELLED}),
                            reason_codes=(DELIVERY_CANCELLED,),
                        )
                    )
                raise
            except _WorkloadBindingError as exc:
                await self._finish_journal_binding_denied(
                    outcome,
                    identity=identity,
                    permission=permission.model_copy(update={"reason": exc.reason_code}),
                    reason_codes=(exc.reason_code,),
                )
                raise AuthenticationError(exc.failure) from None
            except Exception:
                await self._finish_journal_binding_denied(
                    outcome,
                    identity=identity,
                    permission=permission.model_copy(update={"reason": GUARDRAIL_INTERNAL_ERROR}),
                    reason_codes=(GUARDRAIL_INTERNAL_ERROR,),
                )
                raise
        if not permission.granted:
            if self._secure_mode:
                await self._finish_journal_binding_denied(
                    outcome,
                    identity=identity,
                    permission=permission,
                    reason_codes=(RBAC_PERMISSION_DENIED,),
                )
            raise PermissionDeniedError(
                continuation.agent_id,
                continuation.action,
                continuation.resource,
                reason=permission.reason,
            )
        if not self._secure_mode and record.status is ExecutionJournalStatus.OUTCOME_PROTECTED:
            await _audit_decision(
                self._audit_log,
                invocation_id=record.invocation_id,
                trace_id=continuation.trace_id,
                identity=identity,
                action=continuation.action,
                resource=continuation.resource,
                permission=permission,
                result="allowed",
                event_type="execution_completed",
                reason_codes=_continuation_reason_codes(continuation),
                policy_results=continuation.policy_results,
                duration_ms=continuation.execution_duration_ms,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_mode=ChainMode.ENFORCE,
                event_id=f"invocation:{record.invocation_id}:execution-completed",
                timestamp=continuation.execution_completed_at,
                tracer=self._tracer,
            )
            record = await journal.mark_completion_audited(
                escalation_id,
                claim_id=record.claim_id,
                invocation_id=record.invocation_id,
            )
        if not self._secure_mode:
            record = await journal.claim_post_processing(
                escalation_id,
                claim_id=record.claim_id,
                invocation_id=record.invocation_id,
            )
        snapshot = await self._audit_log.read_verified(require_checkpoint=False)
        resume_event_id = f"invocation:{record.invocation_id}:reconcile:{reconciliation_id}"
        evidence = self._reconciliation_evidence(
            record,
            principal=principal,
            reconciliation_id=reconciliation_id,
            classification="protected_result_available",
            state="resumed",
            reason_digest=hashlib.sha256(reason.encode("utf-8")).hexdigest(),
            snapshot=snapshot,
        )
        await _audit_decision(
            self._audit_log,
            invocation_id=record.invocation_id,
            trace_id=continuation.trace_id,
            identity=identity,
            action=continuation.action,
            resource=continuation.resource,
            permission=permission,
            result="allowed",
            event_type="execution_reconciliation_resumed",
            reason_codes=(EXECUTION_PROTECTED_RESULT_AVAILABLE,),
            policy_results=continuation.policy_results,
            policy_bundle_version=continuation.policy_bundle_version,
            chain_mode=ChainMode.ENFORCE,
            reconciliation_evidence=evidence,
            links=self._reconciliation_links(record),
            event_id=resume_event_id,
            tracer=self._tracer,
        )
        return await self._deliver_journal_outcome(
            outcome,
            identity=identity,
            permission=permission,
            policy_bundle=policy_bundle,
        )

    async def resume_tool_call(
        self,
        *,
        escalation_id: str,
        approval_token: str,
    ) -> Any:
        """Resume protected work with its signed evidence correlations active."""

        store = self._require_escalation_store()
        try:
            approved = await store.inspect_approved(escalation_id, token=approval_token)
        except EscalationExpiredError:
            await self.expire_escalation(escalation_id=escalation_id)
            raise
        continuation = await self._open_continuation(
            escalation_id,
            approved.sealed_continuation,
            approved.record.continuation_kind,
        )
        subject_token = _ACTIVE_SUBJECT_REF.set(continuation.subject_ref)
        links_token = _ACTIVE_AUDIT_LINKS.set(continuation.links)
        try:
            return await self._resume_tool_call_impl(
                escalation_id=escalation_id,
                approval_token=approval_token,
            )
        finally:
            _ACTIVE_AUDIT_LINKS.reset(links_token)
            _ACTIVE_SUBJECT_REF.reset(subject_token)

    async def _resume_tool_call_impl(
        self,
        *,
        escalation_id: str,
        approval_token: str,
    ) -> Any:
        """Resume approved PRE execution or POST delivery from protected state."""

        store = self._require_escalation_store()
        try:
            approved = await store.inspect_approved(escalation_id, token=approval_token)
        except EscalationExpiredError:
            await self.expire_escalation(escalation_id=escalation_id)
            raise
        continuation = await self._open_continuation(
            escalation_id,
            approved.sealed_continuation,
            approved.record.continuation_kind,
        )
        if isinstance(continuation, PostExecutionContinuation):
            return await self._resume_post_delivery(
                continuation=continuation,
                approval_token=approval_token,
            )
        policy_bundle = self._validate_continuation_runtime(continuation)
        identity = continuation.permission_context.agent
        permission = continuation.permission_context.model_copy(
            update={"granted": False, "reason": "secure resume validation pending"}
        )
        if not self._secure_mode:
            identity = await self._resolve_continuation_identity(continuation)
            permission = await self._rbac_engine.check_permission(
                identity,
                continuation.action,
                continuation.resource,
            )
        call_payload = cast(
            "ToolCallPayload | MessagePayload",
            continuation.payload,
        )
        snapshot = EvidenceSnapshot.capture(_native_input(call_payload))
        claim_task = asyncio.create_task(store.claim_approved(escalation_id, token=approval_token))
        claim_cancelled = False
        while not claim_task.done():
            try:
                await asyncio.shield(claim_task)
            except asyncio.CancelledError:
                claim_cancelled = True
            except Exception:
                break
        try:
            claimed = claim_task.result()
        except EscalationExpiredError:
            await self.expire_escalation(escalation_id=escalation_id)
            raise
        if claim_cancelled:
            with suppress(asyncio.CancelledError):
                await _finish_audit_write_on_cancellation(
                    self._audit_claimed_delivery_denied(
                        continuation=continuation,
                        claimed=claimed,
                        identity=identity,
                        permission=permission,
                        snapshot=snapshot,
                        reason_codes=(DELIVERY_CANCELLED,),
                    )
                )
            raise asyncio.CancelledError
        if self._secure_mode:
            try:
                identity = await self._resolve_continuation_identity(continuation)
                permission = await self._rbac_engine.check_permission(
                    identity,
                    continuation.action,
                    continuation.resource,
                )
            except asyncio.CancelledError:
                with suppress(asyncio.CancelledError):
                    await _finish_audit_write_on_cancellation(
                        self._audit_claimed_delivery_denied(
                            continuation=continuation,
                            claimed=claimed,
                            identity=identity,
                            permission=permission.model_copy(update={"reason": DELIVERY_CANCELLED}),
                            snapshot=snapshot,
                            reason_codes=(DELIVERY_CANCELLED,),
                        )
                    )
                raise
            except _WorkloadBindingError as exc:
                await self._audit_claimed_delivery_denied(
                    continuation=continuation,
                    claimed=claimed,
                    identity=identity,
                    permission=permission.model_copy(update={"reason": exc.reason_code}),
                    snapshot=snapshot,
                    reason_codes=(exc.reason_code,),
                )
                raise AuthenticationError(exc.failure) from None
            except Exception:
                await self._audit_claimed_delivery_denied(
                    continuation=continuation,
                    claimed=claimed,
                    identity=identity,
                    permission=permission.model_copy(update={"reason": GUARDRAIL_INTERNAL_ERROR}),
                    snapshot=snapshot,
                    reason_codes=(GUARDRAIL_INTERNAL_ERROR,),
                )
                raise
        if not permission.granted:
            await self._audit_claimed_delivery_denied(
                continuation=continuation,
                claimed=claimed,
                identity=identity,
                permission=permission,
                snapshot=snapshot,
                reason_codes=(RBAC_PERMISSION_DENIED,),
            )
            raise PermissionDeniedError(
                continuation.agent_id,
                continuation.action,
                continuation.resource,
                reason=permission.reason,
            )

        if self._executor_resolver is None:
            raise EscalationStateError("trusted executor resolution is not configured")
        registered = self._executor_resolver.resolve(continuation.executor_ref.executor_id)
        if registered.ref != continuation.executor_ref:
            raise EscalationStateError("trusted executor reference changed")

        journal_record: ExecutionJournalRecord | None = None
        if self._execution_journal is not None:
            if claimed.claim_id is None:
                raise EscalationStateError("execution claim metadata is missing")
            journal_record = await self._execution_journal.create_claim(
                escalation_id,
                claim_id=claimed.claim_id,
                invocation_id=continuation.invocation_id,
                payload_digest=continuation.payload_digest,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_fingerprint=continuation.guardrail_cursor.chain_fingerprint,
            )

        try:
            await _audit_decision(
                self._audit_log,
                invocation_id=continuation.invocation_id,
                trace_id=continuation.trace_id,
                identity=identity,
                action=continuation.action,
                resource=continuation.resource,
                permission=permission,
                result="allowed",
                event_type="escalation_resumed",
                reason_codes=(continuation.guardrail_cursor.decisions[-1].decision.reason_codes),
                policy_results=continuation.policy_results,
                snapshot=snapshot,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_mode=ChainMode.ENFORCE,
                hitl_evidence=HitlEvidence(
                    escalation_id=escalation_id,
                    decision_id=claimed.decision_id,
                    state="approved",
                    approver_id=claimed.approver_id,
                    reason_redacted=(
                        "[provided]"
                        if claimed.reason_digest != hashlib.sha256(b"").hexdigest()
                        else ""
                    ),
                    decided_at=claimed.decided_at,
                    expires_at=claimed.record.expires_at,
                ),
                event_id=f"hitl:{escalation_id}:resumed:{claimed.decision_id}",
                timestamp=claimed.claimed_at,
                tracer=self._tracer,
            )
        except asyncio.CancelledError:
            with suppress(asyncio.CancelledError):
                await _finish_audit_write_on_cancellation(
                    self._audit_claimed_delivery_denied(
                        continuation=continuation,
                        claimed=claimed,
                        identity=identity,
                        permission=permission,
                        snapshot=snapshot,
                        reason_codes=(DELIVERY_CANCELLED,),
                    )
                )
            raise
        except Exception:
            await self._audit_claimed_delivery_denied(
                continuation=continuation,
                claimed=claimed,
                identity=identity,
                permission=permission,
                snapshot=snapshot,
                reason_codes=(GUARDRAIL_INTERNAL_ERROR,),
            )
            raise

        resume_chain = _ResumingGuardrailChain(self._guardrail_chain, continuation)
        lifecycle_owned = False

        def _mark_lifecycle_owned() -> None:
            nonlocal lifecycle_owned
            lifecycle_owned = True

        try:
            return await _run_governed_impl(
                agent_id=continuation.agent_id,
                action=continuation.action,
                resource=continuation.resource,
                registry=self._registry,
                rbac_engine=self._rbac_engine,
                audit_log=self._audit_log,
                executor=registered.executor,
                payload=call_payload,
                policy_engine=self._policy_engine,
                guardrail_chain=resume_chain,
                rate_limiter=self._rate_limiter,
                circuit_breaker=self._circuit_breaker,
                tracer=self._tracer,
                resolver_timeout=self._resolver_timeout,
                escalation_store=self._escalation_store,
                escalation_ttl=self._escalation_ttl,
                continuation_protector=self._continuation_protector,
                executor_ref=registered.ref,
                invocation_id=continuation.invocation_id,
                trace_id=continuation.trace_id,
                policy_bundle_override=policy_bundle,
                identity_override=identity,
                permission_override=permission,
                resumed_escalation_id=escalation_id,
                lifecycle_observer=_mark_lifecycle_owned,
                execution_journal=self._execution_journal,
                execution_journal_record=journal_record,
                authentication_binding=continuation.authentication_binding,
                # Forward the integrator's minimised projection across the
                # resume boundary. Without it, result-evidence capture falls
                # back to snapshotting the whole tool result, silently
                # inverting the minimisation contract on the human-approved
                # path. subject_ref/links are also active via contextvars, but
                # are threaded explicitly here so the impl does not depend on
                # the caller's contextvar scope.
                subject_ref=continuation.subject_ref,
                links=continuation.links,
                redacted_evidence=continuation.redacted_evidence,
                sandbox_backend=self._sandbox_backend,
            )
        except (EscalationRequiredError, PermissionDeniedError):
            raise
        except (RateLimitExceededError, CircuitOpenError):
            raise
        except asyncio.CancelledError:
            if not lifecycle_owned:
                with suppress(asyncio.CancelledError):
                    await _finish_audit_write_on_cancellation(
                        self._audit_claimed_delivery_denied(
                            continuation=continuation,
                            claimed=claimed,
                            identity=identity,
                            permission=permission,
                            snapshot=snapshot,
                            reason_codes=(DELIVERY_CANCELLED,),
                        )
                    )
            raise
        except BaseException:
            if not lifecycle_owned:
                await self._audit_claimed_delivery_denied(
                    continuation=continuation,
                    claimed=claimed,
                    identity=identity,
                    permission=permission,
                    snapshot=snapshot,
                    reason_codes=(GUARDRAIL_INTERNAL_ERROR,),
                )
            raise

    async def _resume_post_delivery(
        self,
        *,
        continuation: PostExecutionContinuation,
        approval_token: str,
    ) -> Any:
        """Resume only protected POST processing; never resolve or run an executor."""

        store = self._require_escalation_store()
        policy_bundle = self._validate_post_continuation_runtime(continuation)
        identity = continuation.permission_context.agent
        permission = continuation.permission_context.model_copy(
            update={"granted": False, "reason": "secure resume validation pending"}
        )
        if not self._secure_mode:
            identity = await self._resolve_continuation_identity(continuation)
            permission = await self._rbac_engine.check_permission(
                identity,
                continuation.action,
                continuation.resource,
            )
        unvalidated_result_snapshot = _capture_unvalidated_result_evidence(
            _post_payload_value(continuation.payload)
        )
        claim_task = asyncio.create_task(
            store.claim_post_delivery(
                continuation.escalation_id,
                token=approval_token,
            )
        )
        claim_cancelled = False
        while not claim_task.done():
            try:
                await asyncio.shield(claim_task)
            except asyncio.CancelledError:
                claim_cancelled = True
            except Exception:
                break
        try:
            claimed = claim_task.result()
        except EscalationExpiredError:
            await self.expire_escalation(escalation_id=continuation.escalation_id)
            raise
        if claim_cancelled:
            with suppress(asyncio.CancelledError):
                await _finish_audit_write_on_cancellation(
                    self._finish_post_delivery_denied(
                        continuation=continuation,
                        claimed=claimed,
                        identity=identity,
                        permission=permission,
                        snapshot=unvalidated_result_snapshot,
                        reason_codes=(DELIVERY_CANCELLED,),
                    )
                )
            raise asyncio.CancelledError
        if self._secure_mode:
            try:
                identity = await self._resolve_continuation_identity(continuation)
                permission = await self._rbac_engine.check_permission(
                    identity,
                    continuation.action,
                    continuation.resource,
                )
            except asyncio.CancelledError:
                with suppress(asyncio.CancelledError):
                    await _finish_audit_write_on_cancellation(
                        self._finish_post_delivery_denied(
                            continuation=continuation,
                            claimed=claimed,
                            identity=identity,
                            permission=permission.model_copy(update={"reason": DELIVERY_CANCELLED}),
                            snapshot=unvalidated_result_snapshot,
                            reason_codes=(DELIVERY_CANCELLED,),
                        )
                    )
                raise
            except _WorkloadBindingError as exc:
                await _finish_audit_write_on_cancellation(
                    self._finish_post_delivery_denied(
                        continuation=continuation,
                        claimed=claimed,
                        identity=identity,
                        permission=permission.model_copy(update={"reason": exc.reason_code}),
                        snapshot=unvalidated_result_snapshot,
                        reason_codes=(exc.reason_code,),
                    )
                )
                raise AuthenticationError(exc.failure) from None
            except Exception:
                await _finish_audit_write_on_cancellation(
                    self._finish_post_delivery_denied(
                        continuation=continuation,
                        claimed=claimed,
                        identity=identity,
                        permission=permission.model_copy(
                            update={"reason": GUARDRAIL_INTERNAL_ERROR}
                        ),
                        snapshot=unvalidated_result_snapshot,
                        reason_codes=(GUARDRAIL_INTERNAL_ERROR,),
                    )
                )
                raise
        if not permission.granted:
            await _finish_audit_write_on_cancellation(
                self._finish_post_delivery_denied(
                    continuation=continuation,
                    claimed=claimed,
                    identity=identity,
                    permission=permission,
                    snapshot=unvalidated_result_snapshot,
                    reason_codes=(RBAC_PERMISSION_DENIED,),
                )
            )
            raise PermissionDeniedError(
                continuation.agent_id,
                continuation.action,
                continuation.resource,
                reason=permission.reason,
            )

        reason_codes = _continuation_reason_codes(continuation)
        try:
            await _audit_decision(
                self._audit_log,
                invocation_id=continuation.invocation_id,
                trace_id=continuation.trace_id,
                identity=identity,
                action=continuation.action,
                resource=continuation.resource,
                permission=permission,
                result="allowed",
                event_type="escalation_resumed",
                reason_codes=reason_codes,
                policy_results=continuation.policy_results,
                snapshot=unvalidated_result_snapshot,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_mode=ChainMode.ENFORCE,
                hitl_evidence=HitlEvidence(
                    escalation_id=continuation.escalation_id,
                    decision_id=claimed.decision_id,
                    state="approved",
                    approver_id=claimed.approver_id,
                    reason_redacted=(
                        "[provided]"
                        if claimed.reason_digest != hashlib.sha256(b"").hexdigest()
                        else ""
                    ),
                    decided_at=claimed.decided_at,
                    expires_at=claimed.record.expires_at,
                ),
                event_id=(f"hitl:{continuation.escalation_id}:resumed:{claimed.decision_id}"),
                timestamp=claimed.claimed_at,
                tracer=self._tracer,
            )
        except asyncio.CancelledError:
            with suppress(asyncio.CancelledError):
                await _finish_audit_write_on_cancellation(
                    self._finish_post_delivery_denied(
                        continuation=continuation,
                        claimed=claimed,
                        identity=identity,
                        permission=permission,
                        snapshot=unvalidated_result_snapshot,
                        reason_codes=(DELIVERY_CANCELLED,),
                    )
                )
            raise
        except Exception:
            await _finish_audit_write_on_cancellation(
                self._finish_post_delivery_denied(
                    continuation=continuation,
                    claimed=claimed,
                    identity=identity,
                    permission=permission,
                    snapshot=unvalidated_result_snapshot,
                    reason_codes=(GUARDRAIL_INTERNAL_ERROR,),
                )
            )
            raise

        assert continuation.guardrail_cursor is not None
        context = GuardrailContext(
            trace_id=continuation.trace_id,
            invocation_id=continuation.invocation_id,
            stage=continuation.stage,
            identity=_identity_snapshot(identity),
            action=continuation.action,
            resource=continuation.resource,
            payload=continuation.payload,
            attributes=_redacted_evidence_attributes(continuation.redacted_evidence),
            prior=continuation.prior_outcomes,
        )
        try:
            chain_result = await self._guardrail_chain.resume(
                context,
                continuation.guardrail_cursor,
            )
        except asyncio.CancelledError:
            with suppress(asyncio.CancelledError):
                await _finish_audit_write_on_cancellation(
                    self._finish_post_delivery_denied(
                        continuation=continuation,
                        claimed=claimed,
                        identity=identity,
                        permission=permission,
                        snapshot=unvalidated_result_snapshot,
                        reason_codes=(DELIVERY_CANCELLED,),
                    )
                )
            raise
        except Exception:
            await _finish_audit_write_on_cancellation(
                self._finish_post_delivery_denied(
                    continuation=continuation,
                    claimed=claimed,
                    identity=identity,
                    permission=permission,
                    snapshot=unvalidated_result_snapshot,
                    reason_codes=(GUARDRAIL_INTERNAL_ERROR,),
                )
            )
            raise

        approved_guardrails = _approved_escalations(
            self._guardrail_chain,
            continuation.guardrail_cursor,
        )
        effective_decisions = [
            record
            for record in chain_result.decisions
            if (
                (record.guardrail_id, record.guardrail_version) not in approved_guardrails
                or record.decision.effect is not GuardrailEffect.ESCALATE
            )
        ]
        outcomes = (
            [record.decision for record in effective_decisions] if chain_result.enforced else []
        )
        codes = _reason_codes(outcomes, continuation.policy_results)
        evaluations = _guardrail_evaluations(chain_result, continuation.stage)
        denied = _outcome_effect(outcomes, GuardrailEffect.DENY)
        escalated = _outcome_effect(outcomes, GuardrailEffect.ESCALATE)
        if denied is not None:
            denial_codes = codes or (GUARDRAIL_INTERNAL_ERROR,)
            await _finish_audit_write_on_cancellation(
                self._finish_post_delivery_denied(
                    continuation=continuation,
                    claimed=claimed,
                    identity=identity,
                    permission=permission,
                    snapshot=unvalidated_result_snapshot,
                    reason_codes=denial_codes,
                    guardrail_evaluations=evaluations,
                )
            )
            raise PermissionDeniedError(
                continuation.agent_id,
                continuation.action,
                continuation.resource,
                reason=",".join(denial_codes),
            )

        if escalated is not None:
            if claimed.claim_id is None:
                raise EscalationStateError("post-delivery claim metadata is missing")
            claim_id: str = claimed.claim_id

            async def commit_handoff() -> CreatedEscalation:
                child_request = await self._persist_post_handoff(
                    continuation=continuation,
                    policy_bundle=policy_bundle,
                    identity=identity,
                    permission=permission,
                    chain_result=chain_result,
                    policy_results=continuation.policy_results,
                    prior_outcomes=continuation.prior_outcomes,
                    reason_codes=codes or (GUARDRAIL_INTERNAL_ERROR,),
                    guardrail_evaluations=evaluations,
                )
                await store.commit_handoff(
                    continuation.escalation_id,
                    claim_id=claim_id,
                )
                return child_request

            handoff_task = asyncio.create_task(commit_handoff())
            cancellation_observed = False
            while not handoff_task.done():
                try:
                    await asyncio.shield(handoff_task)
                except asyncio.CancelledError:
                    cancellation_observed = True
                except Exception:
                    break
            child = handoff_task.result()
            if cancellation_observed:
                logger.info(
                    "post_delivery_handoff_completed_after_cancellation",
                    escalation_id=continuation.escalation_id,
                    child_escalation_id=child.record.escalation_id,
                )
            raise EscalationRequiredError(
                continuation.agent_id,
                continuation.action,
                continuation.resource,
                codes or (GUARDRAIL_INTERNAL_ERROR,),
                escalation_id=child.record.escalation_id,
                approval_token=child.token,
                expires_at=child.record.expires_at,
            )

        if not _post_payload_matches_stage(chain_result.payload, continuation.stage):
            await _finish_audit_write_on_cancellation(
                self._finish_post_delivery_denied(
                    continuation=continuation,
                    claimed=claimed,
                    identity=identity,
                    permission=permission,
                    snapshot=unvalidated_result_snapshot,
                    reason_codes=(OUTPUT_SCHEMA_INVALID,),
                    guardrail_evaluations=evaluations,
                )
            )
            raise PermissionDeniedError(
                continuation.agent_id,
                continuation.action,
                continuation.resource,
                reason=OUTPUT_SCHEMA_INVALID,
            )

        delivered = _post_payload_value(
            cast("ToolResultPayload | DecisionPayload", chain_result.payload)
        )
        delivery_snapshot = _capture_result_evidence(delivered, continuation.redacted_evidence)
        delivery_claim_id = claimed.claim_id
        assert delivery_claim_id is not None

        async def commit_delivery() -> None:
            await _audit_decision(
                self._audit_log,
                invocation_id=continuation.invocation_id,
                trace_id=continuation.trace_id,
                identity=identity,
                action=continuation.action,
                resource=continuation.resource,
                permission=permission,
                result="allowed",
                event_type="delivery_completed",
                reason_codes=codes,
                policy_results=continuation.policy_results,
                duration_ms=continuation.execution_duration_ms,
                snapshot=delivery_snapshot,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_mode=ChainMode.ENFORCE,
                guardrail_evaluations=evaluations,
                event_id=f"hitl:{continuation.escalation_id}:delivery",
                tracer=self._tracer,
            )
            await store.commit_delivered(
                continuation.escalation_id,
                claim_id=delivery_claim_id,
            )

        await _finish_audit_write_on_cancellation(commit_delivery())
        return delivered

    async def _persist_post_handoff(
        self,
        *,
        continuation: PostExecutionContinuation,
        policy_bundle: PolicyBundle,
        identity: AgentIdentity,
        permission: PermissionContext,
        chain_result: ChainResult,
        policy_results: Sequence[PolicyResult],
        prior_outcomes: Sequence[GuardrailOutcome],
        reason_codes: tuple[str, ...],
        guardrail_evaluations: Sequence[GuardrailEvaluation],
    ) -> CreatedEscalation:
        """Create and audit a child POST request before handing off its parent."""

        store = self._require_escalation_store()
        if self._continuation_protector is None or not isinstance(
            self._policy_engine, PolicyEngine
        ):
            raise EscalationStateError("post-delivery continuation is not configured")
        if chain_result.cursor is None or not _post_payload_matches_stage(
            chain_result.payload, continuation.stage
        ):
            raise EscalationStateError("downstream escalation has no resumable POST cursor")
        resumable_payload = cast("ToolResultPayload | DecisionPayload", chain_result.payload)
        child = await _persist_post_execution_escalation(
            escalation_store=store,
            continuation_protector=self._continuation_protector,
            policy_engine=self._policy_engine,
            policy_bundle=policy_bundle,
            ttl=self._escalation_ttl,
            invocation_id=continuation.invocation_id,
            trace_id=continuation.trace_id,
            identity=identity,
            action=continuation.action,
            resource=continuation.resource,
            permission=permission,
            stage=continuation.stage,
            payload=resumable_payload,
            policy_results=policy_results,
            prior_outcomes=prior_outcomes,
            prior_guardrail_decisions=chain_result.decisions,
            cursor=chain_result.cursor,
            chain_fingerprint=continuation.chain_fingerprint,
            execution_duration_ms=continuation.execution_duration_ms,
            execution_completed_at=continuation.execution_completed_at,
            authentication_binding=continuation.authentication_binding,
            subject_ref=continuation.subject_ref,
            links=continuation.links,
            redacted_evidence=continuation.redacted_evidence,
        )
        child_snapshot = _capture_result_evidence(
            _post_payload_value(resumable_payload), continuation.redacted_evidence
        )
        await _audit_decision(
            self._audit_log,
            invocation_id=continuation.invocation_id,
            trace_id=continuation.trace_id,
            identity=identity,
            action=continuation.action,
            resource=continuation.resource,
            permission=permission,
            result="escalated",
            event_type="escalation_requested",
            reason_codes=reason_codes,
            policy_results=policy_results,
            duration_ms=continuation.execution_duration_ms,
            snapshot=child_snapshot,
            policy_bundle_version=continuation.policy_bundle_version,
            chain_mode=ChainMode.ENFORCE,
            guardrail_evaluations=guardrail_evaluations,
            hitl_evidence=HitlEvidence(
                escalation_id=child.record.escalation_id,
                state="requested",
                expires_at=child.record.expires_at,
            ),
            links=(
                AuditLink(
                    relation="parent",
                    target=EvidenceRef(
                        namespace="hitl-escalation",
                        value=continuation.escalation_id,
                    ),
                ),
            ),
            event_id=f"hitl:{child.record.escalation_id}:requested",
            tracer=self._tracer,
        )
        return child

    async def _finish_post_delivery_denied(
        self,
        *,
        continuation: PostExecutionContinuation,
        claimed: ApprovedEscalation,
        identity: AgentIdentity,
        permission: PermissionContext,
        snapshot: EvidenceSnapshot,
        reason_codes: tuple[str, ...],
        guardrail_evaluations: Sequence[GuardrailEvaluation] = (),
    ) -> None:
        """Audit then commit the sole denial terminal for claimed POST delivery."""

        assert claimed.claim_id is not None
        await _audit_decision(
            self._audit_log,
            invocation_id=continuation.invocation_id,
            trace_id=continuation.trace_id,
            identity=identity,
            action=continuation.action,
            resource=continuation.resource,
            permission=permission,
            result="denied",
            event_type="delivery_denied",
            reason_codes=reason_codes,
            policy_results=continuation.policy_results,
            duration_ms=continuation.execution_duration_ms,
            snapshot=snapshot,
            policy_bundle_version=continuation.policy_bundle_version,
            chain_mode=ChainMode.ENFORCE,
            guardrail_evaluations=guardrail_evaluations,
            event_id=f"hitl:{continuation.escalation_id}:delivery",
            timestamp=claimed.claimed_at,
            tracer=self._tracer,
        )
        await self._require_escalation_store().commit_delivery_denied(
            continuation.escalation_id,
            claim_id=claimed.claim_id,
        )

    async def _audit_claimed_delivery_denied(
        self,
        *,
        continuation: PreExecutionContinuation,
        claimed: ApprovedEscalation,
        identity: AgentIdentity,
        permission: PermissionContext,
        snapshot: EvidenceSnapshot,
        reason_codes: tuple[str, ...],
    ) -> None:
        await _audit_decision(
            self._audit_log,
            invocation_id=continuation.invocation_id,
            trace_id=continuation.trace_id,
            identity=identity,
            action=continuation.action,
            resource=continuation.resource,
            permission=permission,
            result="denied",
            event_type="delivery_denied",
            reason_codes=reason_codes,
            policy_results=continuation.policy_results,
            snapshot=snapshot,
            policy_bundle_version=continuation.policy_bundle_version,
            chain_mode=ChainMode.ENFORCE,
            event_id=f"hitl:{continuation.escalation_id}:delivery-denied",
            timestamp=claimed.claimed_at,
            tracer=self._tracer,
        )

    async def _authenticate_reconciler(self, credential: object) -> ApproverPrincipal:
        if self._approver_authenticator is None:
            raise EscalationStateError("approver authentication is not configured")
        principal = await self._approver_authenticator.authenticate(credential)
        if "hitl:reconcile" not in principal.capabilities:
            raise EscalationStateError("approver is not authorized for reconciliation")
        return principal

    async def _load_execution_journal_context(
        self,
        escalation_id: str,
    ) -> tuple[ExecutionJournalRecord, ApprovedEscalation, ProtectedContinuation]:
        journal = self._require_execution_journal()
        store = self._require_escalation_store()
        claimed = await store.inspect_claimed(escalation_id)
        if claimed.claim_id is None:
            raise EscalationStateError("claimed escalation has no claim ID")
        continuation = await self._open_continuation(
            escalation_id,
            claimed.sealed_continuation,
            claimed.record.continuation_kind,
        )
        try:
            record = await journal.find(escalation_id)
        except ExecutionJournalNotFoundError:
            chain_fingerprint = (
                continuation.chain_fingerprint
                if isinstance(continuation, PostExecutionContinuation)
                else continuation.guardrail_cursor.chain_fingerprint
            )
            record = await journal.create_claim(
                escalation_id,
                claim_id=claimed.claim_id,
                invocation_id=continuation.invocation_id,
                payload_digest=continuation.payload_digest,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_fingerprint=chain_fingerprint,
            )
        if (
            record.claim_id != claimed.claim_id
            or record.invocation_id != continuation.invocation_id
        ):
            raise EscalationStateError("journal claim does not match escalation state")
        return record, claimed, continuation

    @staticmethod
    def _reconciliation_assessment(
        record: ExecutionJournalRecord,
    ) -> ReconciliationAssessment:
        return ReconciliationAssessment(
            escalation_id=record.escalation_id,
            claim_id=record.claim_id,
            invocation_id=record.invocation_id,
            status=record.status,
            classification=record.in_doubt_classification,
            protected_result_available=record.status
            in {
                ExecutionJournalStatus.OUTCOME_PROTECTED,
                ExecutionJournalStatus.COMPLETION_AUDITED,
            },
        )

    @staticmethod
    def _reconciliation_links(record: ExecutionJournalRecord) -> tuple[AuditLink, ...]:
        return (
            AuditLink(
                relation="subject",
                target=EvidenceRef(namespace="hitl-escalation", value=record.escalation_id),
            ),
            AuditLink(
                relation="subject",
                target=EvidenceRef(
                    namespace="execution-journal",
                    value=f"{record.escalation_id}:{record.claim_id}",
                ),
            ),
        )

    @staticmethod
    def _reconciliation_evidence(
        record: ExecutionJournalRecord,
        *,
        principal: ApproverPrincipal,
        reconciliation_id: str,
        classification: Literal[
            "claimed_without_terminal",
            "admission_without_completion",
            "completion_without_protected_result",
            "protected_result_available",
            "reconciled_denied",
        ],
        state: Literal["in_doubt", "resumed", "reconciled"],
        reason_digest: str,
        snapshot: Any,
    ) -> ReconciliationEvidence:
        verification = snapshot.verification
        if (
            not verification.chain_id
            or verification.head_sequence is None
            or not verification.head_event_hash
        ):
            raise EscalationStateError("verified audit snapshot has no committed head")
        return ReconciliationEvidence(
            escalation_id=record.escalation_id,
            claim_id=record.claim_id,
            reconciliation_id=reconciliation_id,
            classification=classification,
            state=state,
            reconciler_id=principal.approver_id,
            reason_digest=reason_digest,
            assessed_at=record.in_doubt_at or datetime.now(UTC),
            audit_chain_id=verification.chain_id,
            audit_head_sequence=verification.head_sequence,
            audit_head_event_hash=verification.head_event_hash,
            journal_revision=record.revision,
            journal_digest=hashlib.sha256(
                canonical_json_bytes(record.model_dump(mode="json"))
            ).hexdigest(),
        )

    def _validate_journal_outcome_runtime(
        self,
        continuation: PostExecutionContinuation,
    ) -> PolicyBundle:
        if continuation.guardrail_cursor is not None:
            raise EscalationStateError("journal outcome unexpectedly contains a POST cursor")
        if continuation.chain_fingerprint != self._guardrail_chain.fingerprint:
            raise EscalationStateError("guardrail chain fingerprint changed")
        if not self._guardrail_chain.is_resumable(continuation.stage):
            raise EscalationStateError("post guardrail chain is not restart-resumable")
        if not isinstance(self._policy_engine, PolicyEngine):
            raise EscalationStateError("restart-safe policy resolution is not configured")
        restored = self._policy_engine.restore_bundle(continuation.policy_bundle_snapshot)
        active = self._policy_engine.snapshot()
        if (
            restored.version != continuation.policy_bundle_version
            or active.version != continuation.policy_bundle_version
        ):
            raise EscalationStateError("active policy bundle changed after execution")
        return restored

    async def _converge_verified_journal_terminal(
        self,
        record: ExecutionJournalRecord,
        events: Sequence[AuditEvent],
    ) -> ExecutionJournalRecord | None:
        """Repair journal state only from its stable verified delivery boundary."""

        terminal_id = f"invocation:{record.invocation_id}:delivery"
        terminals = tuple(event for event in events if event.event_id == terminal_id)
        terminal_types = {event.event_type for event in terminals}
        if len(terminal_types) > 1:
            raise EscalationStateError("conflicting delivery terminals block reconciliation")
        if not terminals:
            return None
        terminal_type = terminals[-1].event_type
        if terminal_type not in {"delivery_completed", "delivery_denied"}:
            raise EscalationStateError("stable delivery event has an invalid lifecycle type")
        if terminal_type == "delivery_denied" and record.status in {
            ExecutionJournalStatus.RECONCILIATION_PREPARED,
            ExecutionJournalStatus.RECONCILED_DENIED,
        }:
            return record
        try:
            return await self._require_execution_journal().converge_audited_terminal(
                record.escalation_id,
                claim_id=record.claim_id,
                invocation_id=record.invocation_id,
                delivered=terminal_type == "delivery_completed",
            )
        except ExecutionJournalError as exc:
            raise EscalationStateError("audited terminal conflicts with journal state") from exc

    @staticmethod
    def _post_processing_claim_audited(events: Sequence[AuditEvent]) -> bool:
        return any(
            event.event_type
            in {
                "execution_post_processing_claimed",
                "execution_reconciliation_resumed",
            }
            for event in events
        )

    async def _restore_post_processing_claim(
        self,
        record: ExecutionJournalRecord,
    ) -> ExecutionJournalRecord:
        """Converge a rolled-back pre-claim record without rerunning POST callbacks."""

        journal = self._require_execution_journal()
        try:
            if record.status is ExecutionJournalStatus.OUTCOME_PROTECTED:
                record = await journal.mark_completion_audited(
                    record.escalation_id,
                    claim_id=record.claim_id,
                    invocation_id=record.invocation_id,
                )
            if record.status is ExecutionJournalStatus.COMPLETION_AUDITED:
                record = await journal.claim_post_processing(
                    record.escalation_id,
                    claim_id=record.claim_id,
                    invocation_id=record.invocation_id,
                )
        except ExecutionJournalError as exc:
            raise EscalationStateError("audited POST claim conflicts with journal state") from exc
        if record.status is not ExecutionJournalStatus.POST_PROCESSING_CLAIMED:
            raise EscalationStateError("audited POST claim conflicts with journal state")
        return record

    async def _deliver_journal_outcome(
        self,
        outcome: ProtectedExecutionOutcome,
        *,
        identity: AgentIdentity,
        permission: PermissionContext,
        policy_bundle: PolicyBundle,
    ) -> Any:
        continuation = outcome.continuation
        native_result = _post_payload_value(continuation.payload)
        unvalidated_result_snapshot = _capture_unvalidated_result_evidence(native_result)
        policy_results: list[PolicyResult] = []
        runtime_outcomes: list[GuardrailOutcome] = []
        journal = self._require_execution_journal()

        async def deny_cancelled() -> None:
            await _audit_decision(
                self._audit_log,
                invocation_id=continuation.invocation_id,
                trace_id=continuation.trace_id,
                identity=identity,
                action=continuation.action,
                resource=continuation.resource,
                permission=permission,
                result="denied",
                event_type="delivery_denied",
                reason_codes=(DELIVERY_CANCELLED,),
                policy_results=[*continuation.policy_results, *policy_results],
                duration_ms=continuation.execution_duration_ms,
                snapshot=unvalidated_result_snapshot,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_mode=ChainMode.ENFORCE,
                subject_ref=continuation.subject_ref,
                links=continuation.links,
                event_id=f"invocation:{continuation.invocation_id}:delivery",
                tracer=self._tracer,
            )
            await journal.commit_delivery_denied(
                outcome.escalation_id,
                claim_id=outcome.claim_id,
                invocation_id=outcome.invocation_id,
            )

        try:
            if isinstance(self._policy_engine, PolicyEngine):
                transient = _transient_policy_event(
                    invocation_id=continuation.invocation_id,
                    trace_id=continuation.trace_id,
                    identity=identity,
                    action=continuation.action,
                    resource=continuation.resource,
                    permission=permission,
                    context={"tool_result": native_result},
                )
                policy_results = await _evaluate_policy_stage(
                    self._policy_engine,
                    transient,
                    continuation.stage,
                    self._tracer,
                    policy_bundle,
                )
        except asyncio.CancelledError:
            with suppress(asyncio.CancelledError):
                await _finish_audit_write_on_cancellation(deny_cancelled())
            raise
        except Exception as exc:
            runtime_outcomes.append(
                GuardrailOutcome(
                    effect=GuardrailEffect.DENY,
                    reason_codes=(
                        GUARDRAIL_TIMEOUT
                        if isinstance(exc, TimeoutError)
                        else GUARDRAIL_INTERNAL_ERROR,
                    ),
                )
            )
        context = GuardrailContext(
            trace_id=continuation.trace_id,
            invocation_id=continuation.invocation_id,
            stage=continuation.stage,
            identity=_identity_snapshot(identity),
            action=continuation.action,
            resource=continuation.resource,
            payload=continuation.payload,
            attributes=_redacted_evidence_attributes(continuation.redacted_evidence),
            prior=continuation.prior_outcomes,
        )
        try:
            chain_result = await self._guardrail_chain.run(context)
        except asyncio.CancelledError:
            with suppress(asyncio.CancelledError):
                await _finish_audit_write_on_cancellation(deny_cancelled())
            raise
        decisions = [record.decision for record in chain_result.decisions]
        effective = decisions if chain_result.enforced else []
        combined_policy = [*continuation.policy_results, *policy_results]
        actual = [*runtime_outcomes, *effective]
        reason_codes = _reason_codes(actual, combined_policy)
        evaluations = _guardrail_evaluations(chain_result, continuation.stage)
        policy_deny = any(
            not result.passed and result.effect == "deny" for result in policy_results
        )
        policy_escalate = any(
            not result.passed and result.effect == "escalate" for result in policy_results
        )
        denied = policy_deny or _outcome_effect(actual, GuardrailEffect.DENY) is not None
        guardrail_escalated = _outcome_effect(actual, GuardrailEffect.ESCALATE) is not None
        payload_mismatch = not _post_payload_matches_stage(chain_result.payload, continuation.stage)
        if denied or policy_escalate or payload_mismatch:
            codes = reason_codes or (
                OUTPUT_SCHEMA_INVALID if payload_mismatch else GUARDRAIL_INTERNAL_ERROR,
            )
            await _audit_decision(
                self._audit_log,
                invocation_id=continuation.invocation_id,
                trace_id=continuation.trace_id,
                identity=identity,
                action=continuation.action,
                resource=continuation.resource,
                permission=permission,
                result="denied",
                event_type="delivery_denied",
                reason_codes=codes,
                policy_results=combined_policy,
                duration_ms=continuation.execution_duration_ms,
                snapshot=unvalidated_result_snapshot,
                policy_bundle_version=continuation.policy_bundle_version,
                chain_mode=ChainMode.ENFORCE,
                guardrail_evaluations=evaluations,
                subject_ref=continuation.subject_ref,
                links=continuation.links,
                event_id=f"invocation:{continuation.invocation_id}:delivery",
                tracer=self._tracer,
            )
            await journal.commit_delivery_denied(
                outcome.escalation_id,
                claim_id=outcome.claim_id,
                invocation_id=outcome.invocation_id,
            )
            raise PermissionDeniedError(
                continuation.agent_id,
                continuation.action,
                continuation.resource,
                reason=",".join(codes),
            )
        if guardrail_escalated:

            async def commit_handoff() -> CreatedEscalation:
                child_request = await self._persist_post_handoff(
                    continuation=continuation,
                    policy_bundle=policy_bundle,
                    identity=identity,
                    permission=permission,
                    chain_result=chain_result,
                    policy_results=combined_policy,
                    prior_outcomes=(*continuation.prior_outcomes, *runtime_outcomes),
                    reason_codes=reason_codes or (GUARDRAIL_INTERNAL_ERROR,),
                    guardrail_evaluations=evaluations,
                )
                await journal.commit_handoff(
                    outcome.escalation_id,
                    claim_id=outcome.claim_id,
                    invocation_id=outcome.invocation_id,
                )
                return child_request

            handoff_task = asyncio.create_task(commit_handoff())
            cancellation_observed = False
            while not handoff_task.done():
                try:
                    await asyncio.shield(handoff_task)
                except asyncio.CancelledError:
                    cancellation_observed = True
                except Exception:
                    break
            child = handoff_task.result()
            if cancellation_observed:
                logger.info(
                    "journal_post_delivery_handoff_completed_after_cancellation",
                    escalation_id=outcome.escalation_id,
                    child_escalation_id=child.record.escalation_id,
                )
            raise EscalationRequiredError(
                continuation.agent_id,
                continuation.action,
                continuation.resource,
                reason_codes or (GUARDRAIL_INTERNAL_ERROR,),
                escalation_id=child.record.escalation_id,
                approval_token=child.token,
                expires_at=child.record.expires_at,
            )
        delivered = _post_payload_value(
            cast("ToolResultPayload | DecisionPayload", chain_result.payload)
        )
        delivery_snapshot = _capture_result_evidence(delivered, continuation.redacted_evidence)
        await _audit_decision(
            self._audit_log,
            invocation_id=continuation.invocation_id,
            trace_id=continuation.trace_id,
            identity=identity,
            action=continuation.action,
            resource=continuation.resource,
            permission=permission,
            result="allowed",
            event_type="delivery_completed",
            reason_codes=reason_codes,
            policy_results=combined_policy,
            duration_ms=continuation.execution_duration_ms,
            snapshot=delivery_snapshot,
            policy_bundle_version=continuation.policy_bundle_version,
            chain_mode=ChainMode.ENFORCE,
            guardrail_evaluations=evaluations,
            subject_ref=continuation.subject_ref,
            links=continuation.links,
            event_id=f"invocation:{continuation.invocation_id}:delivery",
            tracer=self._tracer,
        )
        await journal.commit_delivered(
            outcome.escalation_id,
            claim_id=outcome.claim_id,
            invocation_id=outcome.invocation_id,
        )
        return delivered

    async def _finish_journal_binding_denied(
        self,
        outcome: ProtectedExecutionOutcome,
        *,
        identity: AgentIdentity,
        permission: PermissionContext,
        reason_codes: tuple[str, ...],
    ) -> None:
        """Audit and terminalize secure protected work before any POST callback."""

        continuation = outcome.continuation
        await _audit_decision(
            self._audit_log,
            invocation_id=continuation.invocation_id,
            trace_id=continuation.trace_id,
            identity=identity,
            action=continuation.action,
            resource=continuation.resource,
            permission=permission,
            result="denied",
            event_type="delivery_denied",
            reason_codes=reason_codes,
            policy_results=continuation.policy_results,
            duration_ms=continuation.execution_duration_ms,
            policy_bundle_version=continuation.policy_bundle_version,
            chain_mode=ChainMode.ENFORCE,
            subject_ref=continuation.subject_ref,
            links=continuation.links,
            event_id=f"invocation:{continuation.invocation_id}:delivery",
            tracer=self._tracer,
        )
        await self._require_execution_journal().commit_delivery_denied(
            outcome.escalation_id,
            claim_id=outcome.claim_id,
            invocation_id=outcome.invocation_id,
        )

    def _require_execution_journal(self) -> ExecutionJournal:
        if self._execution_journal is None:
            raise EscalationStateError("execution journaling is not configured")
        return self._execution_journal

    def _require_escalation_store(self) -> EscalationStore:
        if self._escalation_store is None:
            raise EscalationStateError("durable escalation state is not configured")
        return self._escalation_store

    async def _open_continuation(
        self,
        escalation_id: str,
        sealed: Any,
        continuation_kind: StoreContinuationKind | None,
    ) -> ProtectedContinuation:
        if self._continuation_protector is None:
            raise EscalationStateError("continuation protection is not configured")
        schema_kind = _continuation_schema_kind(continuation_kind)
        legacy_schema_version: Literal[1, 2] = 2 if self._secure_mode else 1
        continuation: ProtectedContinuation | None = None
        last_error: Exception | None = None
        for expected_schema_version in (3, legacy_schema_version):
            try:
                plaintext = await self._continuation_protector.open(
                    sealed,
                    aad=canonical_continuation_aad(
                        escalation_id,
                        kind=schema_kind,
                        schema_version=expected_schema_version,
                    ),
                )
                parsed = parse_protected_continuation(plaintext)
                if parsed.schema_version != expected_schema_version:
                    raise ValueError("continuation schema does not match authenticated AAD")
                continuation = parsed
                break
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last_error = exc
        if continuation is None:
            raise EscalationStateError("protected continuation validation failed") from last_error
        if continuation.escalation_id != escalation_id or continuation.kind != schema_kind:
            raise EscalationStateError("protected continuation identity mismatch")
        return continuation

    async def _resolve_continuation_identity(
        self,
        continuation: ProtectedContinuation,
    ) -> AgentIdentity:
        """Revalidate sticky secure-mode registry state without the old credential."""

        if not self._secure_mode:
            if (
                continuation.schema_version not in {1, 3}
                or continuation.authentication_binding is not None
            ):
                raise EscalationStateError("legacy kernel rejects authenticated continuation")
            if self._registry is None:
                raise EscalationStateError("legacy identity registry is not configured")
            return await self._registry.resolve(continuation.agent_id)

        binding = continuation.authentication_binding
        registry = self._authoritative_registry
        if continuation.schema_version not in {2, 3} or binding is None or registry is None:
            raise EscalationStateError("secure kernel requires authenticated continuation")
        audit_snapshot = await self._audit_log.read_verified(require_checkpoint=False)
        authentication_event = next(
            (
                event
                for event in audit_snapshot.events
                if event.event_id == binding.audit_reference.event_id
            ),
            None,
        )
        evidence = (
            authentication_event.authentication_evidence
            if authentication_event is not None
            else None
        )
        if (
            authentication_event is None
            or authentication_event.event_type != "authentication_succeeded"
            or authentication_event.event_hash != binding.audit_reference.event_hash
            or authentication_event.chain_id != binding.audit_reference.chain_id
            or authentication_event.sequence != binding.audit_reference.sequence
            or authentication_event.key_id != binding.audit_reference.key_id
            or evidence is None
            or evidence.state != "verified"
            or evidence.agent_id != binding.principal.agent_id
            or evidence.method != binding.principal.method
            or evidence.authority != binding.principal.authority
            or evidence.credential_digest != binding.principal.credential_digest
            or evidence.issued_at != binding.principal.issued_at
            or evidence.not_before != binding.principal.not_before
            or evidence.authenticated_at != binding.principal.authenticated_at
            or evidence.expires_at != binding.principal.expires_at
            or evidence.registry_revision != binding.registry_revision
        ):
            raise EscalationStateError("authenticated continuation audit binding is invalid")
        snapshot = await registry.snapshot()
        if snapshot.registry_id != binding.registry_id:
            raise EscalationStateError("authoritative registry identity changed")
        if snapshot.registry_revision < binding.registry_revision:
            raise EscalationStateError("authoritative registry revision regressed")
        record = next(
            (
                candidate
                for candidate in snapshot.records
                if candidate.agent_id == binding.principal.agent_id
            ),
            None,
        )
        if record is None or record.status is not AgentStatus.ACTIVE:
            raise _WorkloadBindingError(AuthenticationFailure.IDENTITY_INACTIVE)
        if record.agent_id != continuation.agent_id:
            raise EscalationStateError("authenticated continuation principal changed")
        if record.credential_epoch != binding.credential_epoch:
            raise _WorkloadBindingError(AuthenticationFailure.CREDENTIAL_REVOKED)
        if record.record_revision < binding.record_revision:
            raise EscalationStateError("authoritative agent record revision regressed")
        return self._identity_from_registry_record(record)

    def _validate_continuation_runtime(
        self,
        continuation: PreExecutionContinuation,
    ) -> PolicyBundle:
        if continuation.guardrail_cursor.chain_fingerprint != self._guardrail_chain.fingerprint:
            raise EscalationStateError("guardrail chain fingerprint changed")
        if not self._guardrail_chain.resumable:
            raise EscalationStateError("guardrail chain is not restart-resumable")
        cursor_context = GuardrailContext(
            trace_id=continuation.trace_id,
            invocation_id=continuation.invocation_id,
            stage=continuation.stage,
            identity=_identity_snapshot(continuation.permission_context.agent),
            action=continuation.action,
            resource=continuation.resource,
            payload=continuation.payload,
        )
        try:
            self._guardrail_chain.validate_cursor(
                cursor_context,
                continuation.guardrail_cursor,
            )
        except ValueError as exc:
            raise EscalationStateError("guardrail continuation cursor is invalid") from exc
        if not isinstance(self._policy_engine, PolicyEngine):
            raise EscalationStateError("restart-safe policy resolution is not configured")
        snapshot = continuation.policy_bundle_snapshot
        if snapshot is None:
            raise EscalationStateError("protected policy bundle snapshot is unavailable")
        restored = self._policy_engine.restore_bundle(snapshot)
        active = self._policy_engine.snapshot()
        if (
            restored.version != continuation.policy_bundle_version
            or active.version != continuation.policy_bundle_version
        ):
            raise EscalationStateError("active policy bundle changed after approval request")
        return restored

    def _validate_post_continuation_runtime(
        self,
        continuation: PostExecutionContinuation,
    ) -> PolicyBundle:
        """Validate every restart-sensitive POST dependency before delivery claim."""

        if continuation.chain_fingerprint != self._guardrail_chain.fingerprint:
            raise EscalationStateError("guardrail chain fingerprint changed")
        if not self._guardrail_chain.resumable:
            raise EscalationStateError("guardrail chain is not restart-resumable")
        cursor = continuation.guardrail_cursor
        if cursor is None:
            raise EscalationStateError("protected post-delivery cursor is unavailable")
        cursor_context = GuardrailContext(
            trace_id=continuation.trace_id,
            invocation_id=continuation.invocation_id,
            stage=continuation.stage,
            identity=_identity_snapshot(continuation.permission_context.agent),
            action=continuation.action,
            resource=continuation.resource,
            payload=continuation.payload,
            prior=continuation.prior_outcomes,
        )
        try:
            self._guardrail_chain.validate_cursor(cursor_context, cursor)
        except ValueError as exc:
            raise EscalationStateError("guardrail continuation cursor is invalid") from exc
        if not isinstance(self._policy_engine, PolicyEngine):
            raise EscalationStateError("restart-safe policy resolution is not configured")
        restored = self._policy_engine.restore_bundle(continuation.policy_bundle_snapshot)
        active = self._policy_engine.snapshot()
        if (
            restored.version != continuation.policy_bundle_version
            or active.version != continuation.policy_bundle_version
        ):
            raise EscalationStateError("active policy bundle changed after approval request")
        return restored
