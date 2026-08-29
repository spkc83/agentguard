"""A2A (Agent-to-Agent) protocol middleware — governs inter-agent messages.

Wraps agent-to-agent communication so every message passes through
AgentGuard's governance kernel.

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

from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from agentguard.guardrails import FrozenValue, GuardrailPayload, MessagePayload, thaw_payload
from agentguard.guardrails.kernel import AdapterToolCall, canonicalize_resource
from agentguard.integrations._pipeline import _adapter_kernel

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
class A2ATransport(Protocol):
    """Minimal interface for an A2A message transport."""

    async def send(self, target_agent: str, message: dict[str, Any]) -> Any: ...


class GovernedA2AClient:
    """Governance-wrapped A2A client.

    Intercepts agent-to-agent messages through the shared
    :class:`agentguard.guardrails.GovernanceKernel`.

    Args:
        transport: A2A transport (any object with async ``send`` method).
        agent_id: Legacy sending-agent ID. Omit for a secure kernel.
        credential_provider: Secure-mode provider invoked exactly once for
            each send attempt; returned credentials are never cached.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        kernel: Preconfigured governance kernel. Do not combine it with the
            legacy dependency arguments.
        circuit_breaker: Optional circuit breaker.
        tracer: Optional :class:`AgentTracer` for OTel span emission.
        chain_mode: Content-guardrail mode. ``shadow`` records would-be effects
            without blocking or transforming; other governance remains active.
    """

    def __init__(
        self,
        transport: Any,
        agent_id: str | None = None,
        registry: AgentRegistry | None = None,
        rbac_engine: RBACEngine | None = None,
        audit_log: AuditLog | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        tracer: AgentTracer | None = None,
        *,
        kernel: GovernanceKernel | None = None,
        credential_provider: AgentCredentialProvider | None = None,
        policy_engine: PolicyEngine | None = None,
        guardrails: Sequence[Guardrail] | None = None,
        rate_limiter: TokenBucketRateLimiter | None = None,
        resolver_timeout: float = 1.0,
        chain_mode: ChainMode | str | None = None,
    ) -> None:
        self._transport = transport
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

    async def send_message(
        self,
        target_agent: str,
        message: dict[str, Any],
    ) -> Any:
        """Send a governed agent-to-agent message.

        Args:
            target_agent: The target agent's ID or name.
            message: The message payload.

        The RBAC resource is derived here as ``agent/{target_agent}`` — it is
        never supplied by the caller as a free-form value — and is then
        canonicalised by the pipeline, so a cased or traversing target name
        cannot slip past a deny rule.

        Returns:
            The response from the target agent.

        Raises:
            PermissionDeniedError: If the target name does not canonicalise to
                a usable resource, or RBAC denies the communication.
            Exception: Re-raised from the transport on send failure (after
                logging an ``error`` audit event).
        """

        def _request() -> AdapterToolCall:
            payload = MessagePayload(target=target_agent, message=message)

            def _canonical_target(native: Any) -> str:
                # Canonicalise the target ONCE and build both axes from the
                # same value. Canonicalising each axis separately re-opens the
                # deny-evasion the pipeline closed at ADR-023: the action axis
                # is not path-normalised, so "./peer" or "peer/" would carry a
                # variant action string past an exact-action deny rule while
                # the resource axis collapses to the canonical form. Raising
                # here makes the call unresolvable — an audited, fail-closed
                # denial — which also catches empty and whitespace targets
                # before "agent/" can normalise to the bare "agent" resource.
                canonical = canonicalize_resource(str(native["target"]))
                if canonical is None or "/" in canonical:
                    raise ValueError("A2A target does not canonicalise to a single agent name")
                return canonical

            def _action(native: Any) -> str:
                return f"a2a:send:{_canonical_target(native)}"

            def _resource(native: Any) -> str:
                return f"agent/{_canonical_target(native)}"

            async def _execute(governed_payload: GuardrailPayload) -> Any:
                if not isinstance(governed_payload, MessagePayload):
                    raise TypeError("A2A sends require a message payload")
                governed_message = thaw_payload(cast("FrozenValue", governed_payload.message))
                assert isinstance(governed_message, dict)
                message_send = getattr(self._transport, "message_send", None)
                if message_send is not None:
                    return await message_send(governed_payload.target, governed_message)
                return await self._transport.send(governed_payload.target, governed_message)

            return AdapterToolCall(
                action=_action,
                resource=_resource,
                executor=_execute,
                payload=payload,
                fallback_action="a2a:send:<unresolved>",
            )

        return await self._caller.guarded_tool_call(_request)

    async def message_send(
        self,
        target_agent: str,
        message: dict[str, Any],
    ) -> Any:
        """A2A SDK-compatible alias for the governed message boundary."""
        return await self.send_message(target_agent, message)
