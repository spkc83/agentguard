"""Google ADK integration — governed tool execution for ADK agents.

Wraps Google Agent Development Kit (ADK) tool calls so every invocation
passes through AgentGuard's governance kernel.

The RBAC resource is derived from a resolver configured when the wrapper is
constructed — never from the agent's tool call. See
:class:`agentguard.guardrails.GovernanceKernel`.

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

from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from agentguard.guardrails import GuardrailPayload, ToolCallPayload, thaw_payload
from agentguard.guardrails.kernel import AdapterToolCall
from agentguard.integrations._pipeline import (
    ResourceResolver,
    _adapter_kernel,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

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
class AdkToolProtocol(Protocol):
    """Minimal interface for a Google ADK tool."""

    name: str

    async def run_async(self, *, args: dict[str, Any], tool_context: Any) -> Any: ...


class GovernedAdkTool:
    """Governance-wrapped Google ADK tool.

    Intercepts ADK tool calls through the shared
    :class:`agentguard.guardrails.GovernanceKernel`.

    Args:
        tool: A Google ADK-compatible tool with ``name`` and ``run_async``.
        agent_id: Legacy calling-agent ID. Omit for a secure kernel.
        credential_provider: Secure-mode provider invoked exactly once for
            each call attempt; returned credentials are never cached.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        kernel: Preconfigured governance kernel. Do not combine it with the
            legacy dependency arguments.
        resource: Required RBAC resource resolver — a static resource string,
            or a sync/async callable receiving the ``args`` dict and returning
            the resource. There is no default: a tool whose resource cannot be
            stated is a tool that cannot be governed.
        circuit_breaker: Optional circuit breaker.
        tracer: Optional :class:`AgentTracer` for OTel span emission.
        chain_mode: Content-guardrail mode. ``shadow`` records would-be effects
            without blocking or transforming; other governance remains active.
    """

    def __init__(
        self,
        tool: Any,
        agent_id: str | None = None,
        registry: AgentRegistry | None = None,
        rbac_engine: RBACEngine | None = None,
        audit_log: AuditLog | None = None,
        *,
        resource: ResourceResolver,
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
        self._tool = tool
        self._resource = resource
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

        def _request() -> AdapterToolCall:
            payload = ToolCallPayload(arguments=cast("Any", args))

            async def _execute(governed_payload: GuardrailPayload) -> Any:
                if not isinstance(governed_payload, ToolCallPayload):
                    raise TypeError("ADK tools require a tool-call payload")
                governed_args = thaw_payload(governed_payload.arguments)
                assert isinstance(governed_args, dict)
                return await self._tool.run_async(
                    args=governed_args,
                    tool_context=tool_context,
                )

            return AdapterToolCall(
                action=f"tool:{self.name}",
                resource=self._resource,
                executor=_execute,
                payload=payload,
            )

        return await self._caller.guarded_tool_call(_request)

    async def __call__(self, **kwargs: Any) -> Any:
        """Expose the governed operation as an ADK ``FunctionTool`` callable."""
        return await self.run_async(args=kwargs)

    def as_function_tool(self) -> Any:
        """Build a native ADK ``FunctionTool`` without making ADK mandatory."""
        try:
            from google.adk.tools import FunctionTool
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise ImportError("Google ADK support requires `pip install agentguard[adk]`") from exc
        return FunctionTool(self)
