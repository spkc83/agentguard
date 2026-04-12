"""MCP middleware — governs MCP tool calls through the AgentGuard runtime.

Wraps an MCP ClientSession (or any object with an async call_tool method)
and intercepts every tool call with the full governance pipeline:
  identity resolve -> RBAC -> circuit breaker -> audit (pre) -> tool call
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

import structlog

from agentguard.core.audit import AppendOnlyAuditLog
from agentguard.core.circuit_breaker import CircuitBreaker
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import RBACEngine
from agentguard.exceptions import PermissionDeniedError
from agentguard.models import AuditEvent

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
        session: MCP ClientSession (or any object with async call_tool).
        agent_id: The calling agent's registered ID.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        circuit_breaker: Optional circuit breaker for downstream protection.
    """

    def __init__(
        self,
        session: Any,
        agent_id: str,
        registry: AgentRegistry,
        rbac_engine: RBACEngine,
        audit_log: AppendOnlyAuditLog,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        self._session = session
        self._agent_id = agent_id
        self._registry = registry
        self._rbac = rbac_engine
        self._audit = audit_log
        self._breaker = circuit_breaker

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        resource: str = "*",
    ) -> Any:
        """Run a governed MCP tool call.

        Args:
            tool_name: Name of the MCP tool to call.
            arguments: Tool arguments.
            resource: Resource pattern for RBAC check (defaults to "*").

        Returns:
            The tool result from the MCP session.

        Raises:
            PermissionDeniedError: If RBAC denies the action.
            CircuitOpenError: If the circuit breaker is open.
        """
        arguments = arguments or {}
        action = f"tool:{tool_name}"
        trace_id = str(uuid.uuid4())

        # 1. Resolve identity
        identity = await self._registry.resolve(self._agent_id)

        # 2. Check RBAC
        permission_ctx = await self._rbac.check_permission(identity, action, resource)

        if not permission_ctx.granted:
            # Log denied event BEFORE raising
            event = AuditEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(UTC),
                agent_id=self._agent_id,
                action=action,
                resource=resource,
                permission_context=permission_ctx,
                result="denied",
                duration_ms=0.0,
                trace_id=trace_id,
            )
            await self._audit.write(event)
            raise PermissionDeniedError(
                self._agent_id, action, resource, reason=permission_ctx.reason
            )

        # 3. Log allowed event BEFORE run (log-first, act-second)
        pre_event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(UTC),
            agent_id=self._agent_id,
            action=action,
            resource=resource,
            permission_context=permission_ctx,
            result="allowed",
            duration_ms=0.0,
            trace_id=trace_id,
        )
        await self._audit.write(pre_event)

        # 4. Call through circuit breaker if present
        if self._breaker:
            result = await self._breaker.call(self._session.call_tool, tool_name, arguments)
        else:
            result = await self._session.call_tool(tool_name, arguments)

        logger.info(
            "mcp_tool_call_completed",
            agent_id=self._agent_id,
            tool=tool_name,
            trace_id=trace_id,
        )
        return result
