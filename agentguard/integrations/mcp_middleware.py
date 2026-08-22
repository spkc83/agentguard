"""MCP middleware — governs MCP tool calls through the AgentGuard runtime.

Wraps an MCP ClientSession (or any object with an async ``call_tool`` method)
and intercepts every tool call with the full governance pipeline:

    derive resource -> identity -> RBAC -> audit (pre) -> circuit breaker
                    -> call -> audit (on error, if the call raises)

The RBAC resource is derived from a per-tool resolver configured when the
client is constructed — never from the agent's tool call. See
:mod:`agentguard.integrations._pipeline` for why.
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
class McpSession(Protocol):
    """Minimal MCP session interface — must have an async call_tool method."""

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any: ...


class GovernedMcpClient:
    """Governance-wrapped MCP client.

    Drop-in layer between your agent and an MCP session. Every tool call
    goes through identity resolution, RBAC, circuit breaker, and audit
    logging before reaching the actual MCP server.

    Args:
        session: MCP ClientSession (or any object with async ``call_tool``).
        agent_id: The calling agent's registered ID.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        resources: Per-tool RBAC resource resolvers, keyed by MCP tool name.
            Each value is a static resource string or a sync/async callable
            that receives the arguments dict and returns the resource. A tool
            with no entry here can never be called: its resource is
            unresolvable, so the call is denied and audited. This doubles as an
            allowlist of the MCP tools this client may reach.
        circuit_breaker: Optional circuit breaker for downstream protection.
        tracer: Optional :class:`AgentTracer` for OTel span emission.
    """

    def __init__(
        self,
        session: Any,
        agent_id: str,
        registry: AgentRegistry,
        rbac_engine: RBACEngine,
        audit_log: AppendOnlyAuditLog,
        *,
        resources: Mapping[str, ResourceResolver],
        circuit_breaker: CircuitBreaker | None = None,
        tracer: AgentTracer | None = None,
    ) -> None:
        self._session = session
        self._agent_id = agent_id
        self._registry = registry
        self._rbac = rbac_engine
        self._audit = audit_log
        self._resources: dict[str, ResourceResolver] = dict(resources)
        self._breaker = circuit_breaker
        self._tracer = tracer

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        """Run a governed MCP tool call.

        The RBAC resource comes from this client's configured resolver for
        ``tool_name``; there is deliberately no way to pass one at call time.

        Args:
            tool_name: Name of the MCP tool to call.
            arguments: Tool arguments. Also handed to the resolver (``None``
                is normalised to ``{}`` for both).

        Returns:
            The tool result from the MCP session.

        Raises:
            PermissionDeniedError: If the resource is unresolvable or RBAC
                denies the action.
            CircuitOpenError: If the circuit breaker is open.
            Exception: Re-raised from the MCP session on call failure (after
                logging an ``error`` audit event).
        """
        arguments = arguments or {}
        resource = await resolve_resource(self._resources.get(tool_name), arguments)

        async def _execute() -> Any:
            return await self._session.call_tool(tool_name, arguments)

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
