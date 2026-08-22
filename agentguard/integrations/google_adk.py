"""Google ADK integration — governed tool execution for ADK agents.

Wraps Google Agent Development Kit (ADK) tool calls so every invocation
passes through AgentGuard's governance pipeline (with error event logging
on failure).

The RBAC resource is derived from a resolver configured when the wrapper is
constructed — never from the agent's tool call. See
:mod:`agentguard.integrations._pipeline` for why.

Usage:
    from agentguard.integrations.google_adk import GovernedAdkTool

    governed = GovernedAdkTool(
        tool=my_adk_tool,
        agent_id=agent.agent_id,
        registry=registry,
        rbac_engine=engine,
        audit_log=audit,
        resource=lambda args: f"customers/{args['id']}",
    )
    result = await governed.run_async(args={"id": "A-001"})
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import structlog

from agentguard.integrations._pipeline import ResourceResolver, resolve_resource, run_governed

if TYPE_CHECKING:
    from agentguard.core.audit import AppendOnlyAuditLog
    from agentguard.core.circuit_breaker import CircuitBreaker
    from agentguard.core.identity import AgentRegistry
    from agentguard.core.rbac import RBACEngine
    from agentguard.observability.tracer import AgentTracer

logger = structlog.get_logger()


@runtime_checkable
class AdkToolProtocol(Protocol):
    """Minimal interface for a Google ADK tool."""

    name: str

    async def run_async(self, *, args: dict[str, Any], tool_context: Any) -> Any: ...


class GovernedAdkTool:
    """Governance-wrapped Google ADK tool.

    Intercepts ADK tool calls with identity, RBAC, circuit breaker, and
    audit logging (with error events on failure).

    Args:
        tool: A Google ADK-compatible tool with ``name`` and ``run_async``.
        agent_id: The calling agent's registered ID.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        resource: Required RBAC resource resolver — a static resource string,
            or a sync/async callable receiving the ``args`` dict and returning
            the resource. There is no default: a tool whose resource cannot be
            stated is a tool that cannot be governed.
        circuit_breaker: Optional circuit breaker.
        tracer: Optional :class:`AgentTracer` for OTel span emission.
    """

    def __init__(
        self,
        tool: Any,
        agent_id: str,
        registry: AgentRegistry,
        rbac_engine: RBACEngine,
        audit_log: AppendOnlyAuditLog,
        *,
        resource: ResourceResolver,
        circuit_breaker: CircuitBreaker | None = None,
        tracer: AgentTracer | None = None,
    ) -> None:
        self._tool = tool
        self._agent_id = agent_id
        self._registry = registry
        self._rbac = rbac_engine
        self._audit = audit_log
        self._resource = resource
        self._breaker = circuit_breaker
        self._tracer = tracer
        self.name: str = tool.name

    async def run_async(
        self,
        *,
        args: dict[str, Any],
        tool_context: Any = None,
    ) -> Any:
        """Execute the governed ADK tool call.

        The RBAC resource comes from this wrapper's configured resolver; there
        is deliberately no per-call override.

        Args:
            args: Tool arguments dict. Also handed to the resolver.
            tool_context: ADK tool context (passed through to underlying tool).

        Returns:
            The tool result.

        Raises:
            PermissionDeniedError: If the resource is unresolvable or RBAC
                denies the action.
            Exception: Re-raised from the tool on execution failure (after
                logging an ``error`` audit event).
        """
        resource = await resolve_resource(self._resource, args)

        async def _execute() -> Any:
            return await self._tool.run_async(args=args, tool_context=tool_context)

        return await run_governed(
            agent_id=self._agent_id,
            action=f"tool:{self.name}",
            resource=resource,
            registry=self._registry,
            rbac_engine=self._rbac,
            audit_log=self._audit,
            executor=_execute,
            circuit_breaker=self._breaker,
            tracer=self._tracer,
        )
