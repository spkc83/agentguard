"""CrewAI integration — governed tool execution for CrewAI agents.

Wraps CrewAI tools so every invocation passes through AgentGuard's
governance kernel: transform -> derive -> RBAC/policy/guardrails -> admission
-> execute -> execution_completed -> delivery terminal.

The RBAC resource is derived from a resolver configured when the wrapper is
constructed — never from the agent's tool call. See
:class:`agentguard.guardrails.GovernanceKernel`.

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
    result = await governed_tool.arun("query")
"""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import threading
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from agentguard.guardrails import GuardrailPayload, ToolCallPayload, thaw_payload
from agentguard.guardrails.kernel import AdapterToolCall
from agentguard.integrations._pipeline import (
    ResourceResolver,
    _adapter_kernel,
)

if TYPE_CHECKING:

    class _CrewAIBaseTool:
        def __init__(self, *, name: str, description: str, **_: Any) -> None:
            self.name = name
            self.description = description

        def to_structured_tool(self) -> Any: ...

else:
    try:
        from crewai.tools import BaseTool as _CrewAIBaseTool
    except ImportError:

        class _CrewAIBaseTool:
            """Dependency-free stand-in used when the CrewAI extra is absent."""

            def __init__(self, *, name: str, description: str, **_: Any) -> None:
                self.name = name
                self.description = description


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
class CrewAIToolProtocol(Protocol):
    """Minimal interface for a CrewAI tool."""

    name: str

    def _run(self, *args: Any, **kwargs: Any) -> Any: ...


class GovernedCrewAITool(_CrewAIBaseTool):
    """Governance-wrapped CrewAI tool.

    Wraps a CrewAI tool (which exposes a sync ``_run`` method) so every
    invocation goes through the shared
    :class:`agentguard.guardrails.GovernanceKernel`.

    Args:
        tool: A CrewAI-compatible tool object with ``name`` and ``_run``.
        agent_id: Legacy calling-agent ID. Omit for a secure kernel.
        credential_provider: Secure-mode provider invoked exactly once for
            each call attempt; returned credentials are never cached.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        kernel: Preconfigured governance kernel. Do not combine it with the
            legacy dependency arguments.
        resource: Required RBAC resource resolver — a static resource string,
            or a sync/async callable receiving ``{"args": args, "kwargs":
            kwargs}`` and returning the resource. There is no default: a tool
            whose resource cannot be stated is a tool that cannot be governed.
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
        name = cast("str", tool.name)
        description = cast("str", getattr(tool, "description", name))
        base_kwargs: dict[str, Any] = {"name": name, "description": description}
        args_schema = getattr(tool, "args_schema", None)
        if args_schema is not None:
            base_kwargs["args_schema"] = args_schema
        super().__init__(**base_kwargs)
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

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
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

        def _request() -> AdapterToolCall:
            if "_resource" in kwargs:
                raise TypeError(
                    "_resource is no longer accepted; configure `resource=` on the adapter"
                )

            payload = ToolCallPayload(arguments=cast("Any", {"args": args, "kwargs": kwargs}))

            async def _resource(native: Any) -> str:
                adjusted = {"args": tuple(native["args"]), "kwargs": native["kwargs"]}
                if isinstance(self._resource, str):
                    return self._resource
                derived = self._resource(adjusted)
                return await derived if inspect.isawaitable(derived) else derived

            async def _execute(governed_payload: GuardrailPayload) -> Any:
                if not isinstance(governed_payload, ToolCallPayload):
                    raise TypeError("CrewAI tools require a tool-call payload")
                native = thaw_payload(governed_payload.arguments)
                assert isinstance(native, dict)
                native_args = native["args"]
                native_kwargs = native["kwargs"]
                assert isinstance(native_args, list)
                assert isinstance(native_kwargs, dict)
                return self._tool._run(*native_args, **native_kwargs)

            return AdapterToolCall(
                action=f"tool:{self.name}",
                resource=_resource,
                executor=_execute,
                payload=payload,
            )

        return await self._caller.guarded_tool_call(_request)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """CrewAI ``BaseTool``-compatible synchronous entry point."""
        coroutine = self.arun(*args, **kwargs)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coroutine)

        result: list[Any] = []
        failure: list[BaseException] = []
        context = contextvars.copy_context()

        def _invoke() -> None:
            try:
                result.append(context.run(asyncio.run, coroutine))
            except BaseException as exc:  # pragma: no cover - asserted by caller
                failure.append(exc)

        thread = threading.Thread(target=_invoke, daemon=True)
        thread.start()
        thread.join()
        if failure:
            raise failure[0]
        return result[0]
