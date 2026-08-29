"""LangGraph integration — governed tool execution for LangGraph agents.

Wraps LangGraph tool nodes so every tool call passes through AgentGuard's
governance kernel: transform -> derive -> RBAC/policy/guardrails -> admission
-> execute -> execution_completed -> delivery terminal.

The RBAC resource is derived from a per-tool resolver configured when the node
is constructed — never from the agent's tool call. See
:class:`agentguard.guardrails.GovernanceKernel`.

Usage:
    from agentguard.integrations.langgraph import GovernedLangGraphToolNode

    governed = GovernedLangGraphToolNode(
        tools=[my_tool],
        agent_id=agent.agent_id,
        registry=registry,
        rbac_engine=engine,
        audit_log=audit,
        resources={"credit_check": lambda args: f"bureau/{args['bureau']}"},
    )
    result = await governed.ainvoke("credit_check", {"bureau": "experian"})
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

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
class LangChainTool(Protocol):
    """Minimal interface for a LangChain/LangGraph tool."""

    name: str

    async def ainvoke(self, input: Any) -> Any: ...  # noqa: A002


class GovernedLangGraphToolNode:
    """Governance-wrapped LangGraph tool node.

    Duck-typed wrapper (does not subclass LangGraph's ToolNode yet). Routes tool calls
    through the shared :class:`agentguard.guardrails.GovernanceKernel` before
    execution.

    Args:
        tools: List of LangChain-compatible tools (each with ``name`` and
            async ``ainvoke``).
        agent_id: Legacy calling-agent ID. Omit for a secure kernel.
        credential_provider: Secure-mode provider invoked exactly once for
            each call attempt; returned credentials are never cached.
        registry: Agent identity registry.
        rbac_engine: RBAC permission checker.
        audit_log: Audit log for recording events.
        kernel: Preconfigured governance kernel. Do not combine it with the
            legacy dependency arguments.
        resources: Per-tool RBAC resource resolvers, keyed by tool name. Each
            value is a static resource string or a sync/async callable that
            receives the tool input and returns the resource. A tool with no
            entry here can never be called: its resource is unresolvable, so
            the call is denied and audited.
        circuit_breaker: Optional circuit breaker for downstream protection.
        tracer: Optional :class:`AgentTracer` for OTel span emission.
        chain_mode: Content-guardrail mode. ``shadow`` records would-be effects
            without blocking or transforming; other governance remains active.
    """

    def __init__(
        self,
        tools: list[Any],
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
        self._tools: dict[str, Any] = {t.name: t for t in tools}
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

    async def _ainvoke_tool(self, tool_name: str, tool_input: Any) -> Any:
        """Execute a governed tool call.

        The RBAC resource comes from this node's configured resolver for
        ``tool_name``; there is deliberately no way to pass one at call time.
        An unregistered tool, or a tool with no resolver, is a fail-closed,
        audited denial rather than a :class:`KeyError` — an unknown tool name
        is exactly the kind of event an audit trail must record.

        Args:
            tool_name: Name of the tool to call.
            tool_input: Input to pass to the tool, and to the resolver.

        Returns:
            The tool result.

        Raises:
            PermissionDeniedError: If the resource is unresolvable or RBAC
                denies the action.
            Exception: Re-raised from the tool on execution failure (after
                logging an ``error`` audit event).
        """

        def _request() -> AdapterToolCall:
            tool = self._tools.get(tool_name)
            payload = ToolCallPayload(arguments=tool_input)

            async def _execute(governed_payload: GuardrailPayload) -> Any:
                if tool is None:  # pragma: no cover - denial always precedes execution
                    raise KeyError(f"Tool not found: {tool_name}")
                if not isinstance(governed_payload, ToolCallPayload):
                    raise TypeError("LangGraph tools require a tool-call payload")
                return await tool.ainvoke(thaw_payload(governed_payload.arguments))

            return AdapterToolCall(
                action=f"tool:{tool_name}",
                # A resolver entry without a registered tool must be an
                # unresolvable (audited) denial, not an allowed admission for
                # a tool that cannot exist followed by a KeyError.
                resource=self._resources.get(tool_name) if tool is not None else None,
                executor=_execute,
                payload=payload,
            )

        return await self._caller.guarded_tool_call(_request)

    async def ainvoke(
        self,
        input: Any,  # noqa: A002
        tool_input: Any = None,
        config: Any = None,
    ) -> Any:
        """Invoke one legacy tool call or consume a LangGraph messages state.

        ``ainvoke(name, input)`` remains supported for pre-1.0 callers.  A
        mapping input follows LangGraph's ToolNode contract: tool calls are
        read from the last message and native ``ToolMessage`` objects are
        returned when ``langchain-core`` is installed.
        """
        del config
        if isinstance(input, str):
            return await self._ainvoke_tool(input, tool_input)
        # Runnable.ainvoke permits a positional config as its second argument.
        # It is execution metadata, not governed tool input.
        return await self._ainvoke_state(input)

    async def __call__(self, input: Any, config: Any = None) -> Any:  # noqa: A002
        """Expose the node as a native LangGraph async runnable node."""

        return await self.ainvoke(input, config=config)

    async def _ainvoke_state(self, state: Any) -> dict[str, list[Any]]:
        if not isinstance(state, dict):
            raise TypeError("LangGraph ToolNode input must be a messages state mapping")
        messages = state.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("LangGraph ToolNode input requires a non-empty messages list")

        last_message = messages[-1]
        tool_calls = (
            last_message.get("tool_calls")
            if isinstance(last_message, dict)
            else getattr(last_message, "tool_calls", None)
        )
        if not isinstance(tool_calls, list):
            raise ValueError("The last LangGraph message does not contain tool calls")

        results: list[Any] = []
        for call in tool_calls:
            name = call.get("name") if isinstance(call, dict) else getattr(call, "name", None)
            args = call.get("args") if isinstance(call, dict) else getattr(call, "args", None)
            call_id = call.get("id") if isinstance(call, dict) else getattr(call, "id", None)
            if not isinstance(name, str) or not isinstance(call_id, str):
                raise ValueError("LangGraph tool calls require string name and id fields")
            try:
                result = await self._ainvoke_tool(name, args if args is not None else {})
            except PermissionDeniedError as exc:
                results.append(_tool_message(str(exc), name, call_id, status="error"))
            else:
                results.append(_tool_message(_message_content(result), name, call_id))
        return {"messages": results}


def _message_content(result: Any) -> str:
    if isinstance(result, str):
        return result
    return json.dumps(result, sort_keys=True, default=str, separators=(",", ":"))


def _tool_message(content: str, name: str, call_id: str, *, status: str = "success") -> Any:
    try:
        from langchain_core.messages import ToolMessage
    except ImportError:
        return {
            "content": content,
            "name": name,
            "status": status,
            "tool_call_id": call_id,
            "type": "tool",
        }
    return ToolMessage(content=content, name=name, tool_call_id=call_id, status=status)
