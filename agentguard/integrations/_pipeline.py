"""Shared governance pipeline for integration adapters.

All framework adapters (MCP, LangGraph, CrewAI, ADK, A2A) route tool calls
through this pipeline to ensure consistent behavior:

    resolve identity -> RBAC check -> audit (pre) -> breaker -> execute
                      -> audit (on error, if execution raises)

The log-first, act-second contract holds in both directions: an ``allowed``
pre-event is written before execution; an ``error`` post-event is written
if execution raises (per ADR-004).
"""

from __future__ import annotations

import time
import uuid
from contextlib import nullcontext
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog

from agentguard.exceptions import PermissionDeniedError
from agentguard.models import AuditEvent

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from agentguard.core.audit import AppendOnlyAuditLog
    from agentguard.core.circuit_breaker import CircuitBreaker
    from agentguard.core.identity import AgentRegistry
    from agentguard.core.rbac import RBACEngine
    from agentguard.observability.tracer import AgentTracer

logger = structlog.get_logger()


async def run_governed(
    *,
    agent_id: str,
    action: str,
    resource: str,
    registry: AgentRegistry,
    rbac_engine: RBACEngine,
    audit_log: AppendOnlyAuditLog,
    executor: Callable[[], Awaitable[Any]],
    circuit_breaker: CircuitBreaker | None = None,
    tracer: AgentTracer | None = None,
) -> Any:
    """Execute ``executor`` through the AgentGuard governance pipeline.

    Pipeline:
        1. Resolve agent identity.
        2. Check RBAC permission for (action, resource).
        3. If denied -> write ``denied`` audit event, raise
           :class:`PermissionDeniedError`.
        4. Write pre-execution audit event with ``result="allowed"``.
        5. Execute through circuit breaker if provided.
        6. On executor exception -> write ``error`` audit event with
           measured ``duration_ms`` and re-raise.
        7. Return the execution result.

    Args:
        agent_id: The calling agent's registered ID.
        action: The action being performed (e.g., ``"tool:credit_check"``).
        resource: The target resource pattern.
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
        PermissionDeniedError: If RBAC denies the action.
        Exception: Any exception raised by ``executor()`` is re-raised
            after logging an ``error`` audit event.
    """
    trace_id = str(uuid.uuid4())
    span_cm = (
        tracer.span(
            "agentguard.tool_call",
            attributes={
                "agent_id": agent_id,
                "action": action,
                "resource": resource,
                "trace_id": trace_id,
            },
        )
        if tracer is not None
        else nullcontext()
    )

    with span_cm:
        # 1. Resolve identity
        identity = await registry.resolve(agent_id)

        # 2. Check RBAC
        permission_ctx = await rbac_engine.check_permission(identity, action, resource)

        if not permission_ctx.granted:
            denied_event = AuditEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(UTC),
                agent_id=agent_id,
                action=action,
                resource=resource,
                permission_context=permission_ctx,
                result="denied",
                duration_ms=0.0,
                trace_id=trace_id,
            )
            await audit_log.write(denied_event)
            raise PermissionDeniedError(
                agent_id, action, resource, reason=permission_ctx.reason
            )

        # 3. Pre-event (log-first)
        pre_event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            agent_id=agent_id,
            action=action,
            resource=resource,
            permission_context=permission_ctx,
            result="allowed",
            duration_ms=0.0,
            trace_id=trace_id,
        )
        await audit_log.write(pre_event)

        # 4. Execute (act-second). On error, write error event before re-raising.
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
                resource=resource,
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
                resource=resource,
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
