"""A2A (Agent-to-Agent) protocol middleware — governs inter-agent messages.

Wraps agent-to-agent communication so every message passes through
AgentGuard's governance pipeline (with error event logging on failure).

Usage:
    from agentguard.integrations.a2a_middleware import GovernedA2AClient

    client = GovernedA2AClient(
        transport=my_a2a_transport,
        agent_id=agent.agent_id,
        registry=registry,
        rbac_engine=engine,
        audit_log=audit,
    )
    response = await client.send_message(
        target_agent="agent-002",
        message={"task": "analyze_credit"},
    )
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
class A2ATransport(Protocol):
    """Minimal interface for an A2A message transport."""

    async def send(self, target_agent: str, message: dict[str, Any]) -> Any: ...


class GovernedA2AClient:
    """Governance-wrapped A2A client.

    Intercepts agent-to-agent messages with identity resolution, RBAC,
    circuit breaker, and audit logging.

    Args:
        transport: A2A transport (any object with async ``send`` method).
        agent_id: The sending agent's registered ID.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        circuit_breaker: Optional circuit breaker.
        tracer: Optional :class:`AgentTracer` for OTel span emission.
    """

    def __init__(
        self,
        transport: Any,
        agent_id: str,
        registry: AgentRegistry,
        rbac_engine: RBACEngine,
        audit_log: AppendOnlyAuditLog,
        circuit_breaker: CircuitBreaker | None = None,
        tracer: AgentTracer | None = None,
    ) -> None:
        self._transport = transport
        self._agent_id = agent_id
        self._registry = registry
        self._rbac = rbac_engine
        self._audit = audit_log
        self._breaker = circuit_breaker
        self._tracer = tracer

    async def send_message(
        self,
        target_agent: str,
        message: dict[str, Any],
    ) -> Any:
        """Send a governed agent-to-agent message.

        Args:
            target_agent: The target agent's ID or name.
            message: The message payload.

        Returns:
            The response from the target agent.

        Raises:
            PermissionDeniedError: If RBAC denies the communication.
            Exception: Re-raised from the transport on send failure (after
                logging an ``error`` audit event).
        """

        async def _execute() -> Any:
            return await self._transport.send(target_agent, message)

        return await run_governed(
            agent_id=self._agent_id,
            action=f"a2a:send:{target_agent}",
            resource=f"agent/{target_agent}",
            registry=self._registry,
            rbac_engine=self._rbac,
            audit_log=self._audit,
            executor=_execute,
            circuit_breaker=self._breaker,
            tracer=self._tracer,
        )
