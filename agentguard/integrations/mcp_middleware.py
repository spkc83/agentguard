"""MCP middleware — governs MCP tool calls through the AgentGuard runtime.

Wraps an MCP ClientSession (or any object with an async ``call_tool`` method)
and intercepts every tool call with the governance kernel:

    transform -> derive -> RBAC/policy/guardrails -> rate limit/breaker
              -> admission -> execute -> execution_completed -> delivery terminal

The RBAC resource is derived from a per-tool resolver configured when the
client is constructed — never from the agent's tool call. See
:class:`agentguard.guardrails.GovernanceKernel`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from agentguard.exceptions import PermissionDeniedError
from agentguard.guardrails import GuardrailPayload, ToolCallPayload, thaw_payload
from agentguard.guardrails.kernel import AdapterToolCall
from agentguard.integrations._pipeline import (
    ResourceResolver,
    _adapter_kernel,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from agentguard.compliance.engine import PolicyEngine
    from agentguard.core.audit import AuditLog
    from agentguard.core.authentication import AgentCredentialProvider
    from agentguard.core.circuit_breaker import CircuitBreaker, TokenBucketRateLimiter
    from agentguard.core.identity import AgentRegistry
    from agentguard.core.rbac import RBACEngine
    from agentguard.guardrails import ChainMode, Guardrail
    from agentguard.guardrails.kernel import GovernanceKernel
    from agentguard.observability.tracer import AgentTracer


@runtime_checkable
class McpSession(Protocol):
    """Minimal MCP session interface — must have an async call_tool method."""

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any: ...


class GovernedMcpClient:
    """Governance-wrapped MCP client.

    Duck-typed layer between your agent and an MCP session. Every tool call
    goes through the shared :class:`agentguard.guardrails.GovernanceKernel`
    before reaching the actual MCP server.

    Args:
        session: MCP ClientSession (or any object with async ``call_tool``).
        agent_id: Legacy calling-agent ID. Omit for a secure kernel.
        credential_provider: Secure-mode provider invoked exactly once for
            each call attempt; returned credentials are never cached.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        kernel: Preconfigured governance kernel. Do not combine it with the
            legacy dependency arguments.
        resources: Per-tool RBAC resource resolvers, keyed by MCP tool name.
            Each value is a static resource string or a sync/async callable
            that receives the arguments dict and returns the resource. A tool
            with no entry here can never be called: its resource is
            unresolvable, so the call is denied and audited. This doubles as an
            allowlist of the MCP tools this client may reach.
        circuit_breaker: Optional circuit breaker for downstream protection.
        tracer: Optional :class:`AgentTracer` for OTel span emission.
        chain_mode: Content-guardrail mode. ``shadow`` records would-be effects
            without blocking or transforming; other governance remains active.
    """

    def __init__(
        self,
        session: Any,
        agent_id: str | None = None,
        registry: AgentRegistry | None = None,
        rbac_engine: RBACEngine | None = None,
        audit_log: AuditLog | None = None,
        *,
        resources: Mapping[str, ResourceResolver],
        kernel: GovernanceKernel | None = None,
        credential_provider: AgentCredentialProvider | None = None,
        policy_engine: PolicyEngine | None = None,
        guardrails: Sequence[Guardrail] | None = None,
        rate_limiter: TokenBucketRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        tracer: AgentTracer | None = None,
        resolver_timeout: float = 1.0,
        chain_mode: ChainMode | str | None = None,
    ) -> None:
        self._session = session
        self._resources: dict[str, ResourceResolver] = dict(resources)
        self._caller = _adapter_kernel(
            agent_id=agent_id,
            credential_provider=credential_provider,
            kernel=kernel,
            registry=registry,
            rbac_engine=rbac_engine,
            audit_log=audit_log,
            policy_engine=policy_engine,
            guardrails=guardrails,
            rate_limiter=rate_limiter,
            circuit_breaker=circuit_breaker,
            tracer=tracer,
            resolver_timeout=resolver_timeout,
            chain_mode=chain_mode,
        )

    async def call_tool(
        self,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        **session_kwargs: Any,
    ) -> Any:
        """Run a governed MCP tool call.

        The RBAC resource comes from this client's configured resolver for
        ``tool_name``; there is deliberately no way to pass one at call time.

        Args:
            tool_name: Name of the MCP tool to call.
            arguments: Tool arguments. Also handed to the resolver (``None``
                is normalised to ``{}`` for both).

        Returns:
            The tool result from the MCP session. When the wrapped session is
            a native ``mcp`` SDK session (its class is defined in an ``mcp.*``
            module), a governance denial is returned as a
            ``CallToolResult(isError=True)`` — the MCP protocol's error shape —
            instead of raising, so native orchestrators see a protocol-level
            error rather than an unexpected exception. The denial is still
            audited and the underlying tool is never called.

        Raises:
            PermissionDeniedError: If the resource is unresolvable or RBAC
                denies the action — for duck-typed (non-``mcp.*``) sessions
                and legacy callers only; see Returns for native sessions.
            CircuitOpenError: If the circuit breaker is open.
            Exception: Re-raised from the MCP session on call failure (after
                logging an ``error`` audit event).
        """

        native_name = session_kwargs.pop("name", None)
        if tool_name is None:
            tool_name = native_name
        elif native_name is not None:
            raise TypeError("call_tool received both tool_name and name")
        if not isinstance(tool_name, str):
            raise TypeError("call_tool requires a tool name")
        if "resource" in session_kwargs:
            raise TypeError("resource is not accepted; configure `resources=` on the adapter")

        def _request() -> AdapterToolCall:
            normalized_arguments = arguments or {}
            payload = ToolCallPayload(arguments=cast("Any", normalized_arguments))

            async def _execute(governed_payload: GuardrailPayload) -> Any:
                if not isinstance(governed_payload, ToolCallPayload):
                    raise TypeError("MCP tools require a tool-call payload")
                governed_arguments = thaw_payload(governed_payload.arguments)
                assert isinstance(governed_arguments, dict)
                return await self._session.call_tool(
                    tool_name,
                    governed_arguments,
                    **session_kwargs,
                )

            return AdapterToolCall(
                action=f"tool:{tool_name}",
                resource=self._resources.get(tool_name),
                executor=_execute,
                payload=payload,
            )

        try:
            return await self._caller.guarded_tool_call(_request)
        except PermissionDeniedError as exc:
            # Native MCP clients represent tool denials as an error result. Keep
            # the exception contract for duck-typed sessions and legacy callers.
            if type(self._session).__module__.startswith("mcp."):
                try:
                    from mcp.types import CallToolResult, TextContent
                except ImportError:
                    raise
                return CallToolResult(
                    content=[TextContent(type="text", text=str(exc))],
                    isError=True,
                )
            raise
