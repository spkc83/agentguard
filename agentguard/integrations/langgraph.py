"""LangGraph integration — governed tool execution for LangGraph agents.

Wraps LangGraph tool nodes so every tool call passes through AgentGuard's
governance pipeline: identity -> RBAC -> circuit breaker -> audit -> execute
(with error event logging on failure).

The RBAC resource is derived from a per-tool resolver configured when the node
is constructed — never from the agent's tool call. See
:mod:`agentguard.integrations._pipeline` for why.

Usage:
    from agentguard.integrations.langgraph import GovernedLangGraphToolNode

    governed = GovernedLangGraphToolNode(
        tools=[my_tool],
        agent_id=agent.agent_id,
        registry=registry,
        rbac_engine=engine,
        audit_log=audit,
        resources={"credit_check": lambda args: f"bureau/{args['bureau']}"},
    )
    result = await governed.ainvoke("credit_check", {"bureau": "experian"})
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import structlog

from agentguard.integrations._pipeline import ResourceResolver, resolve_resource, run_governed

if TYPE_CHECKING:
    from collections.abc import Mapping

    from agentguard.core.audit import AppendOnlyAuditLog
    from agentguard.core.circuit_breaker import CircuitBreaker
    from agentguard.core.identity import AgentRegistry
    from agentguard.core.rbac import RBACEngine
    from agentguard.observability.tracer import AgentTracer

logger = structlog.get_logger()


@runtime_checkable
class LangChainTool(Protocol):
    """Minimal interface for a LangChain/LangGraph tool."""

    name: str

    async def ainvoke(self, input: Any) -> Any: ...  # noqa: A002


class GovernedLangGraphToolNode:
    """Governance-wrapped LangGraph tool node.

    Drop-in replacement for LangGraph's ToolNode. Routes tool calls
    through the AgentGuard governance pipeline before execution.

    Args:
        tools: List of LangChain-compatible tools (each with ``name`` and
            async ``ainvoke``).
        agent_id: The calling agent's registered ID.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        resources: Per-tool RBAC resource resolvers, keyed by tool name. Each
            value is a static resource string or a sync/async callable that
            receives the tool input and returns the resource. A tool with no
            entry here can never be called: its resource is unresolvable, so
            the call is denied and audited.
        circuit_breaker: Optional circuit breaker for downstream protection.
        tracer: Optional :class:`AgentTracer` for OTel span emission.
    """

    def __init__(
        self,
        tools: list[Any],
        agent_id: str,
        registry: AgentRegistry,
        rbac_engine: RBACEngine,
        audit_log: AppendOnlyAuditLog,
        *,
        resources: Mapping[str, ResourceResolver],
        circuit_breaker: CircuitBreaker | None = None,
        tracer: AgentTracer | None = None,
    ) -> None:
        self._tools: dict[str, Any] = {t.name: t for t in tools}
        self._agent_id = agent_id
        self._registry = registry
        self._rbac = rbac_engine
        self._audit = audit_log
        self._resources: dict[str, ResourceResolver] = dict(resources)
        self._breaker = circuit_breaker
        self._tracer = tracer

    async def ainvoke(self, tool_name: str, tool_input: Any) -> Any:
        """Execute a governed tool call.

        The RBAC resource comes from this node's configured resolver for
        ``tool_name``; there is deliberately no way to pass one at call time.
        An unregistered tool, or a tool with no resolver, is a fail-closed,
        audited denial rather than a :class:`KeyError` — an unknown tool name
        is exactly the kind of event an audit trail must record.

        Args:
            tool_name: Name of the tool to call.
            tool_input: Input to pass to the tool, and to the resolver.

        Returns:
            The tool result.

        Raises:
            PermissionDeniedError: If the resource is unresolvable or RBAC
                denies the action.
            Exception: Re-raised from the tool on execution failure (after
                logging an ``error`` audit event).
        """
        tool = self._tools.get(tool_name)
        resource: str | None = None
        if tool is None:
            logger.warning(
                "langgraph_tool_not_registered",
                agent_id=self._agent_id,
                tool_name=tool_name,
            )
        else:
            resource = await resolve_resource(self._resources.get(tool_name), tool_input)

        async def _execute() -> Any:
            if tool is None:  # pragma: no cover - denial always precedes execution
                raise KeyError(f"Tool not found: {tool_name}")
            return await tool.ainvoke(tool_input)

        return await run_governed(
            agent_id=self._agent_id,
            action=f"tool:{tool_name}",
            resource=resource,
            registry=self._registry,
            rbac_engine=self._rbac,
            audit_log=self._audit,
            executor=_execute,
            circuit_breaker=self._breaker,
            tracer=self._tracer,
        )
