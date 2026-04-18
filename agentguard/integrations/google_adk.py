"""Google ADK integration — governed tool execution for ADK agents.

Wraps Google Agent Development Kit (ADK) tool calls so every invocation
passes through AgentGuard's governance pipeline (with error event logging
on failure).

Usage:
    from agentguard.integrations.google_adk import GovernedAdkTool

    governed = GovernedAdkTool(
        tool=my_adk_tool,
        agent_id=agent.agent_id,
        registry=registry,
        rbac_engine=engine,
        audit_log=audit,
    )
    result = await governed.run_async(args={"key": "value"})
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
        circuit_breaker: Optional circuit breaker.
        resource: Default resource pattern for RBAC checks.
        tracer: Optional :class:`AgentTracer` for OTel span emission.
    """

    def __init__(
        self,
        tool: Any,
        agent_id: str,
        registry: AgentRegistry,
        rbac_engine: RBACEngine,
        audit_log: AppendOnlyAuditLog,
        circuit_breaker: CircuitBreaker | None = None,
        resource: str = "*",
        tracer: AgentTracer | None = None,
    ) -> None:
        self._tool = tool
        self._agent_id = agent_id
        self._registry = registry
        self._rbac = rbac_engine
        self._audit = audit_log
        self._breaker = circuit_breaker
        self._resource = resource
        self._tracer = tracer
        self.name: str = tool.name

    async def run_async(
        self,
        *,
        args: dict[str, Any],
        tool_context: Any = None,
        resource: str | None = None,
    ) -> Any:
        """Execute the governed ADK tool call.

        Args:
            args: Tool arguments dict.
            tool_context: ADK tool context (passed through to underlying tool).
            resource: Override resource pattern for RBAC check.

        Returns:
            The tool result.

        Raises:
            PermissionDeniedError: If RBAC denies the action.
            Exception: Re-raised from the tool on execution failure (after
                logging an ``error`` audit event).
        """
        effective_resource = resource or self._resource

        async def _execute() -> Any:
            return await self._tool.run_async(args=args, tool_context=tool_context)

        return await run_governed(
            agent_id=self._agent_id,
            action=f"tool:{self.name}",
            resource=effective_resource,
            registry=self._registry,
            rbac_engine=self._rbac,
            audit_log=self._audit,
            executor=_execute,
            circuit_breaker=self._breaker,
            tracer=self._tracer,
        )
