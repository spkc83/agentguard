"""LangGraph integration — governed tool execution for LangGraph agents.

Wraps LangGraph tool nodes so every tool call passes through AgentGuard's
governance pipeline: identity -> RBAC -> circuit breaker -> audit -> execute
(with error event logging on failure).

Usage:
    from agentguard.integrations.langgraph import GovernedLangGraphToolNode

    governed = GovernedLangGraphToolNode(
        tools=[my_tool],
        agent_id=agent.agent_id,
        registry=registry,
        rbac_engine=engine,
        audit_log=audit,
    )
    result = await governed.ainvoke("tool_name", input_data)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import structlog

from agentguard.integrations._pipeline import run_governed

if TYPE_CHECKING:
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
        circuit_breaker: CircuitBreaker | None = None,
        tracer: AgentTracer | None = None,
    ) -> None:
        self._tools: dict[str, Any] = {t.name: t for t in tools}
        self._agent_id = agent_id
        self._registry = registry
        self._rbac = rbac_engine
        self._audit = audit_log
        self._breaker = circuit_breaker
        self._tracer = tracer

    async def ainvoke(self, tool_name: str, tool_input: Any, resource: str = "*") -> Any:
        """Execute a governed tool call.

        Args:
            tool_name: Name of the tool to call.
            tool_input: Input to pass to the tool.
            resource: Resource pattern for RBAC check.

        Returns:
            The tool result.

        Raises:
            KeyError: If the tool is not registered.
            PermissionDeniedError: If RBAC denies the action.
            Exception: Re-raised from the tool on execution failure (after
                logging an ``error`` audit event).
        """
        if tool_name not in self._tools:
            raise KeyError(f"Tool not found: {tool_name}")

        tool = self._tools[tool_name]

        async def _execute() -> Any:
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
