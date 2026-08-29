"""Deprecated compatibility surface for the framework-independent kernel."""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any

from agentguard.compliance.engine import PolicyEngine
from agentguard.guardrails import Guardrail, GuardrailPayload, MessagePayload, ToolCallPayload
from agentguard.guardrails.chain import ChainMode
from agentguard.guardrails.kernel import (
    UNRESOLVED_ACTION,
    UNRESOLVED_RESOURCE,
    ActionResolver,
    GovernanceKernel,
    GovernedAdapterCaller,
    ResourceResolver,
    canonicalize_action,
    canonicalize_resource,
    default_guardrails,
    default_policy_engine,
    resolve_action,
    resolve_resource,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from agentguard.core.audit import AuditLog
    from agentguard.core.authentication import AgentCredentialProvider
    from agentguard.core.circuit_breaker import CircuitBreaker, TokenBucketRateLimiter
    from agentguard.core.identity import AgentRegistry
    from agentguard.core.rbac import RBACEngine
    from agentguard.observability.tracer import AgentTracer


def _adapter_kernel(
    *,
    agent_id: str | None,
    credential_provider: AgentCredentialProvider | None,
    kernel: GovernanceKernel | None,
    registry: AgentRegistry | None,
    rbac_engine: RBACEngine | None,
    audit_log: AuditLog | None,
    policy_engine: PolicyEngine | None,
    guardrails: Sequence[Guardrail] | None,
    rate_limiter: TokenBucketRateLimiter | None,
    circuit_breaker: CircuitBreaker | None,
    tracer: AgentTracer | None,
    resolver_timeout: float,
    chain_mode: ChainMode | str | None,
) -> GovernedAdapterCaller:
    """Build or accept one kernel and bind its mode-neutral adapter caller."""

    if kernel is not None:
        mixed = (
            any(
                value is not None
                for value in (
                    registry,
                    rbac_engine,
                    audit_log,
                    policy_engine,
                    guardrails,
                    rate_limiter,
                    circuit_breaker,
                    tracer,
                )
            )
            or resolver_timeout != 1.0
            or chain_mode is not None
        )
        if mixed:
            raise ValueError(
                "kernel cannot be combined with legacy governance dependencies or configuration"
            )
        selected = kernel
    else:
        if registry is None or rbac_engine is None or audit_log is None:
            raise TypeError(
                "registry, rbac_engine, and audit_log are required when kernel is not supplied"
            )
        selected = GovernanceKernel(
            registry=registry,
            rbac_engine=rbac_engine,
            audit_log=audit_log,
            policy_engine=policy_engine or default_policy_engine(),
            guardrails=tuple(guardrails) if guardrails is not None else default_guardrails(),
            chain_mode=ChainMode.ENFORCE if chain_mode is None else chain_mode,
            rate_limiter=rate_limiter,
            circuit_breaker=circuit_breaker,
            tracer=tracer,
            resolver_timeout=resolver_timeout,
        )
    return selected.bind_adapter(
        agent_id=agent_id,
        credential_provider=credential_provider,
    )


async def run_governed(
    *,
    agent_id: str,
    action: ActionResolver,
    resource: ResourceResolver | None,
    registry: AgentRegistry,
    rbac_engine: RBACEngine,
    audit_log: AuditLog,
    executor: Callable[[GuardrailPayload], Awaitable[Any]],
    payload: ToolCallPayload | MessagePayload | None = None,
    policy_engine: PolicyEngine | None = None,
    guardrails: Sequence[Guardrail] = (),
    rate_limiter: TokenBucketRateLimiter | None = None,
    circuit_breaker: CircuitBreaker | None = None,
    tracer: AgentTracer | None = None,
    resolver_timeout: float = 1.0,
    guardrail_timeout: float = 1.0,
    fallback_action: str | None = None,
    chain_mode: ChainMode | str = ChainMode.ENFORCE,
) -> Any:
    """Run the deprecated legacy ID-only compatibility path.

    This shim intentionally accepts no secure-mode credential configuration.
    Authenticated adapters bind a per-call credential provider directly to a
    :class:`GovernanceKernel` instead.

    Two contract changes from the pre-kernel ``run_governed``:

    - ``executor`` now receives the governed :class:`GuardrailPayload` as its
      single positional argument (it was previously zero-argument); a legacy
      zero-argument executor fails loudly with a ``TypeError``.
    - Unlike the adapter constructors, this shim applies NO default policy
      engine or content guardrails when ``policy_engine``/``guardrails`` are
      not supplied — direct callers are inside the trust boundary and own that
      configuration.
    """

    warnings.warn(
        "run_governed() is deprecated and legacy-only; construct "
        "GovernanceKernel and bind an adapter credential provider instead. "
        "Note: executor now takes the governed payload as one positional "
        "argument (previously zero-argument).",
        DeprecationWarning,
        stacklevel=2,
    )
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=rbac_engine,
        audit_log=audit_log,
        policy_engine=policy_engine,
        guardrails=guardrails,
        chain_mode=chain_mode,
        rate_limiter=rate_limiter,
        circuit_breaker=circuit_breaker,
        tracer=tracer,
        resolver_timeout=resolver_timeout,
        guardrail_timeout=guardrail_timeout,
    )
    return await kernel.guarded_tool_call(
        agent_id=agent_id,
        action=action,
        resource=resource,
        executor=executor,
        payload=payload,
        fallback_action=fallback_action,
    )


__all__ = [
    "UNRESOLVED_ACTION",
    "UNRESOLVED_RESOURCE",
    "ActionResolver",
    "ResourceResolver",
    "canonicalize_action",
    "canonicalize_resource",
    "default_guardrails",
    "default_policy_engine",
    "resolve_action",
    "resolve_resource",
    "run_governed",
]
