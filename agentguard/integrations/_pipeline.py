"""Shared governance pipeline for integration adapters.

All framework adapters (MCP, LangGraph, CrewAI, ADK, A2A) route tool calls
through this pipeline to ensure consistent behavior:

    derive resource -> resolve identity -> RBAC check -> audit (pre)
                    -> breaker -> execute -> audit (on error, if it raises)

The log-first, act-second contract holds in both directions: an ``allowed``
pre-event is written before execution; an ``error`` post-event is written
if execution raises (per ADR-004).

Resource derivation is a trust boundary
---------------------------------------
The RBAC ``resource`` is the *subject* of the permission decision. It MUST be
derived by the integrator — from the tool identity and, where appropriate, the
call arguments — and it must NEVER be accepted from the governed agent as a
free-form value. An agent that can name its own resource can name one that its
policy allows, which makes deny rules decorative.

Adapters therefore take resource *resolvers* at construction time (see
:data:`ResourceResolver`) rather than a resource argument at call time. Direct
callers of :func:`run_governed` are inside the trust boundary by definition and
own that derivation themselves.

Whatever the derivation produces is canonicalised by
:func:`canonicalize_resource` before it reaches RBAC, because the derived value
may still contain attacker-influenced substrings. Canonicalisation rejects
``fnmatch`` metacharacters (an agent must not be able to self-grant ``*``),
path traversal, absolute paths, reserved sentinel characters, and control
characters; it then case-folds. Any rejection — like any failure to derive a
resource at all — is a fail-closed, audited denial against the
:data:`UNRESOLVED_RESOURCE` sentinel.
"""

from __future__ import annotations

import inspect
import posixpath
import time
import uuid
from collections.abc import Awaitable, Callable
from contextlib import nullcontext
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog

from agentguard.exceptions import PermissionDeniedError
from agentguard.models import AuditEvent, PermissionContext

if TYPE_CHECKING:
    from agentguard.core.audit import AppendOnlyAuditLog
    from agentguard.core.circuit_breaker import CircuitBreaker
    from agentguard.core.identity import AgentRegistry
    from agentguard.core.rbac import RBACEngine
    from agentguard.observability.tracer import AgentTracer

logger = structlog.get_logger()

UNRESOLVED_RESOURCE = "<unresolved>"
"""Sentinel recorded when a call's RBAC resource could not be derived.

Never passed to RBAC — a call with an unresolved resource is denied outright.
The angle brackets are rejected by :func:`canonicalize_resource`, so a derived
resource can never impersonate this sentinel.
"""

ResourceResolver = str | Callable[[Any], "str | Awaitable[str]"]
"""How an adapter derives the RBAC resource for a call.

Either a static resource string, or a sync/async callable that receives the
adapter-specific call input (tool arguments, message payload, ...) and returns
the resource string.
"""

_FNMATCH_METACHARS = frozenset("*?[]")
_RESERVED_CHARS = frozenset("<>")


def canonicalize_resource(raw: str) -> str | None:
    """Canonicalise a derived RBAC resource, or reject it.

    Rejection (``None``) is a security decision, not an error: the caller must
    treat it as "resource unresolvable" and deny the call.

    Rejects:
        * empty or whitespace-only strings (``fnmatch("", "*")`` is ``True``,
          so the empty string is not a safe sentinel);
        * any string containing an ``fnmatch`` metacharacter (``*?[]``) — an
          agent-influenced resource must not be able to widen itself into a
          pattern;
        * any string containing the reserved sentinel characters ``<>`` or an
          ASCII control character;
        * absolute paths (leading ``/``);
        * paths that traverse upward (any ``..`` segment) or normalise away to
          nothing (``.``, ``./``).

    Otherwise normalises redundant separators and ``.`` segments via
    :func:`posixpath.normpath`, strips a trailing slash, and case-folds — RBAC
    resource matching is case-insensitive so that ``Admin/keys`` cannot evade a
    ``deny admin/*`` rule.

    Args:
        raw: The derived resource string.

    Returns:
        The canonical resource, or ``None`` if the value must be rejected.
    """
    stripped = raw.strip()
    if not stripped:
        return None
    if any(ch in _FNMATCH_METACHARS or ch in _RESERVED_CHARS for ch in stripped):
        return None
    if any(ch < " " or ch == "\x7f" for ch in stripped):
        return None
    if stripped.startswith("/"):
        return None

    normalized = posixpath.normpath(stripped)
    if normalized in {"", "."} or normalized.startswith("/"):
        return None
    if any(segment == ".." for segment in normalized.split("/")):
        return None

    return normalized.casefold()


async def resolve_resource(resolver: ResourceResolver | None, call_input: Any) -> str | None:
    """Derive and canonicalise the RBAC resource for a single call.

    Args:
        resolver: A static resource string, a sync/async callable receiving
            ``call_input``, or ``None`` when the adapter has no resolver
            configured for this call.
        call_input: The adapter-specific call input handed to the callable.

    Returns:
        The canonical resource string, or ``None`` when the resource cannot be
        derived — because there is no resolver, because the callable raised,
        because it returned a non-``str``, or because canonicalisation rejected
        the value. Callers must treat ``None`` as a fail-closed denial.
    """
    if resolver is None:
        return None
    if isinstance(resolver, str):
        return canonicalize_resource(resolver)

    try:
        derived: Any = resolver(call_input)
        if inspect.isawaitable(derived):
            derived = await derived
    except Exception as exc:
        logger.warning("resource_resolver_failed", error=str(exc), error_type=type(exc).__name__)
        return None

    if not isinstance(derived, str):
        logger.warning("resource_resolver_returned_non_str", result_type=type(derived).__name__)
        return None

    canonical = canonicalize_resource(derived)
    if canonical is None:
        logger.warning("resource_resolver_returned_uncanonical_value")
    return canonical


async def run_governed(
    *,
    agent_id: str,
    action: str,
    resource: str | None,
    registry: AgentRegistry,
    rbac_engine: RBACEngine,
    audit_log: AppendOnlyAuditLog,
    executor: Callable[[], Awaitable[Any]],
    circuit_breaker: CircuitBreaker | None = None,
    tracer: AgentTracer | None = None,
) -> Any:
    """Execute ``executor`` through the AgentGuard governance pipeline.

    Pipeline:
        1. Canonicalise the supplied resource.
        2. Resolve agent identity.
        3. If the resource is unresolvable -> write a ``denied`` audit event
           against :data:`UNRESOLVED_RESOURCE` and raise
           :class:`PermissionDeniedError` without consulting RBAC.
        4. Check RBAC permission for (action, canonical resource).
        5. If denied -> write ``denied`` audit event, raise
           :class:`PermissionDeniedError`.
        6. Write pre-execution audit event with ``result="allowed"``.
        7. Execute through circuit breaker if provided.
        8. On executor exception -> write ``error`` audit event with
           measured ``duration_ms`` and re-raise.
        9. Return the execution result.

    Args:
        agent_id: The calling agent's registered ID.
        action: The action being performed (e.g., ``"tool:credit_check"``).
        resource: The target resource, already derived by the caller from the
            tool identity and call arguments. It must NEVER be a value the
            governed agent supplied for the purpose of naming its own RBAC
            subject — direct callers of this function are inside the trust
            boundary and own that derivation. Pass ``None`` when derivation
            failed; the call is then denied and audited. The value is passed
            through :func:`canonicalize_resource`, and a rejected value is
            treated exactly like ``None``.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for event recording.
        executor: Async zero-arg callable that performs the actual work.
        circuit_breaker: Optional circuit breaker wrapping the executor.
        tracer: Optional :class:`AgentTracer` — pipeline is wrapped in a span
            named ``agentguard.tool_call`` when provided.

    Returns:
        The value returned by ``executor()``.

    Raises:
        PermissionDeniedError: If the resource is unresolvable, or RBAC denies
            the action.
        Exception: Any exception raised by ``executor()`` is re-raised
            after logging an ``error`` audit event.
    """
    canonical_resource = canonicalize_resource(resource) if resource is not None else None
    audit_resource = canonical_resource if canonical_resource is not None else UNRESOLVED_RESOURCE

    trace_id = str(uuid.uuid4())
    span_cm = (
        tracer.span(
            "agentguard.tool_call",
            attributes={
                "agent_id": agent_id,
                "action": action,
                "resource": audit_resource,
                "trace_id": trace_id,
            },
        )
        if tracer is not None
        else nullcontext()
    )

    with span_cm:
        # 1. Resolve identity
        identity = await registry.resolve(agent_id)

        # 2. Fail closed when the resource could not be derived. RBAC is never
        #    consulted: there is no subject to decide about.
        if canonical_resource is None:
            reason = "resource_unresolvable: resource could not be derived from the call"
            unresolved_ctx = PermissionContext(
                agent=identity,
                requested_action=action,
                resource=UNRESOLVED_RESOURCE,
                granted=False,
                reason=reason,
            )
            unresolved_event = AuditEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(UTC),
                agent_id=agent_id,
                action=action,
                resource=UNRESOLVED_RESOURCE,
                permission_context=unresolved_ctx,
                result="denied",
                duration_ms=0.0,
                trace_id=trace_id,
            )
            await audit_log.write(unresolved_event)
            logger.warning(
                "resource_unresolvable",
                agent_id=agent_id,
                action=action,
                trace_id=trace_id,
            )
            raise PermissionDeniedError(agent_id, action, UNRESOLVED_RESOURCE, reason=reason)

        # 3. Check RBAC
        permission_ctx = await rbac_engine.check_permission(identity, action, canonical_resource)

        if not permission_ctx.granted:
            denied_event = AuditEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(UTC),
                agent_id=agent_id,
                action=action,
                resource=canonical_resource,
                permission_context=permission_ctx,
                result="denied",
                duration_ms=0.0,
                trace_id=trace_id,
            )
            await audit_log.write(denied_event)
            raise PermissionDeniedError(
                agent_id, action, canonical_resource, reason=permission_ctx.reason
            )

        # 4. Pre-event (log-first)
        pre_event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            agent_id=agent_id,
            action=action,
            resource=canonical_resource,
            permission_context=permission_ctx,
            result="allowed",
            duration_ms=0.0,
            trace_id=trace_id,
        )
        await audit_log.write(pre_event)

        # 5. Execute (act-second). On error, write error event before re-raising.
        start = time.monotonic()
        try:
            if circuit_breaker is not None:
                result = await circuit_breaker.call(executor)
            else:
                result = await executor()
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000.0
            error_event = AuditEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(UTC),
                agent_id=agent_id,
                action=action,
                resource=canonical_resource,
                permission_context=permission_ctx,
                result="error",
                duration_ms=duration_ms,
                trace_id=trace_id,
            )
            try:
                await audit_log.write(error_event)
            except Exception:
                # Failing to record an error event must not mask the original.
                logger.exception("audit_error_event_write_failed", trace_id=trace_id)
            logger.warning(
                "governed_execution_failed",
                agent_id=agent_id,
                action=action,
                resource=canonical_resource,
                trace_id=trace_id,
                error=str(exc),
            )
            raise

        logger.info(
            "governed_execution_completed",
            agent_id=agent_id,
            action=action,
            trace_id=trace_id,
        )
        return result
