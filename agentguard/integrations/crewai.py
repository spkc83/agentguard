"""CrewAI integration — governed tool execution for CrewAI agents.

Wraps CrewAI tools so every invocation passes through AgentGuard's
governance pipeline: identity -> RBAC -> circuit breaker -> audit -> execute
(with error event logging on failure).

The RBAC resource is derived from a resolver configured when the wrapper is
constructed — never from the agent's tool call. See
:mod:`agentguard.integrations._pipeline` for why.

Usage:
    from agentguard.integrations.crewai import GovernedCrewAITool

    governed_tool = GovernedCrewAITool(
        tool=my_crewai_tool,
        agent_id=agent.agent_id,
        registry=registry,
        rbac_engine=engine,
        audit_log=audit,
        resource="index/public",
    )
    result = await governed_tool.run("query")
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
class CrewAIToolProtocol(Protocol):
    """Minimal interface for a CrewAI tool."""

    name: str

    def _run(self, *args: Any, **kwargs: Any) -> Any: ...


class GovernedCrewAITool:
    """Governance-wrapped CrewAI tool.

    Wraps a CrewAI tool (which exposes a sync ``_run`` method) so every
    invocation goes through AgentGuard's governance pipeline.

    Args:
        tool: A CrewAI-compatible tool object with ``name`` and ``_run``.
        agent_id: The calling agent's registered ID.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        resource: Required RBAC resource resolver — a static resource string,
            or a sync/async callable receiving ``{"args": args, "kwargs":
            kwargs}`` and returning the resource. There is no default: a tool
            whose resource cannot be stated is a tool that cannot be governed.
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

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the governed CrewAI tool call.

        Args:
            *args: Positional arguments forwarded to the tool's ``_run``.
            **kwargs: Keyword arguments forwarded to the tool's ``_run``.

        Returns:
            The tool result.

        Raises:
            TypeError: If the removed ``_resource`` override is passed. It used
                to let the caller name its own RBAC subject.
            PermissionDeniedError: If the resource is unresolvable or RBAC
                denies the action.
            Exception: Re-raised from the tool on execution failure (after
                logging an ``error`` audit event).
        """
        if "_resource" in kwargs:
            raise TypeError("_resource is no longer accepted; configure `resource=` on the adapter")

        resource = await resolve_resource(self._resource, {"args": args, "kwargs": kwargs})

        async def _execute() -> Any:
            return self._tool._run(*args, **kwargs)

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
