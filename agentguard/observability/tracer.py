"""OpenTelemetry-native agent decision tracer.

Provides structured tracing for AgentGuard governance decisions:
RBAC checks, policy evaluations, tool calls, and audit writes.

Falls back to a no-op tracer when opentelemetry-sdk is not installed,
so the observability extra is truly optional.

Usage:
    from agentguard.observability.tracer import AgentTracer

    tracer = AgentTracer(service_name="my-agent-service")
    with tracer.span("rbac_check", attributes={"agent_id": "abc"}) as span:
        result = await engine.check_permission(...)
        span.set_attribute("agentguard.rbac.granted", result.granted)
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import structlog

logger = structlog.get_logger()

# Namespace for all AgentGuard OTel attributes
ATTR_PREFIX = "agentguard"


class _NoOpSpan:
    """No-op span used when OTel is not available."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any) -> None:
        pass

    def record_exception(self, exception: BaseException) -> None:
        pass

    def end(self) -> None:
        pass


class AgentTracer:
    """OpenTelemetry tracer for AgentGuard governance decisions.

    Lazily imports opentelemetry-sdk. If not installed, all operations
    produce no-op spans with zero overhead.

    Args:
        service_name: OTel service name for the tracer.
        enabled: Set False to force no-op mode even when OTel is available.
    """

    def __init__(self, service_name: str = "agentguard", enabled: bool = True) -> None:
        self._service_name = service_name
        self._tracer: Any = None
        self._otel_available = False

        if enabled:
            try:
                from opentelemetry import trace

                # Library policy: never mutate the global TracerProvider. The
                # host application is responsible for configuring providers
                # and exporters. We just request a named tracer and trust
                # whatever provider is currently installed (including the
                # default ProxyTracerProvider when the app hasn't configured
                # one — spans will be no-ops until it does).
                self._tracer = trace.get_tracer(service_name)
                self._otel_available = True
                logger.debug("otel_tracer_initialized", service_name=service_name)
            except ImportError:
                logger.debug("otel_not_available", service_name=service_name)

    @property
    def is_active(self) -> bool:
        """True if OTel is available and tracer is initialized."""
        return self._otel_available

    @contextmanager
    def span(self, name: str, attributes: dict[str, Any] | None = None) -> Any:
        """Create a traced span.

        Args:
            name: Span name (e.g. "rbac_check", "tool_call").
            attributes: Initial span attributes.

        Yields:
            The span object (OTel Span or _NoOpSpan).
        """
        if not self._otel_available or self._tracer is None:
            yield _NoOpSpan()
            return

        prefixed_attrs = {}
        if attributes:
            for k, v in attributes.items():
                key = f"{ATTR_PREFIX}.{k}" if not k.startswith(ATTR_PREFIX) else k
                prefixed_attrs[key] = v

        with self._tracer.start_as_current_span(name, attributes=prefixed_attrs) as otel_span:
            yield otel_span

    def trace_rbac_check(
        self,
        agent_id: str,
        action: str,
        resource: str,
        granted: bool,
        reason: str = "",
    ) -> None:
        """Record an RBAC check as a span event.

        Args:
            agent_id: The agent requesting the action.
            action: The action being checked.
            resource: The target resource.
            granted: Whether permission was granted.
            reason: Reason for the decision.
        """
        with self.span(
            "rbac_check",
            attributes={
                "agent_id": agent_id,
                "rbac.action": action,
                "rbac.resource": resource,
                "rbac.granted": granted,
                "rbac.reason": reason,
            },
        ):
            pass

    def trace_policy_evaluation(
        self,
        agent_id: str,
        rule_id: str,
        passed: bool,
        severity: str,
    ) -> None:
        """Record a policy evaluation as a span event.

        Args:
            agent_id: The agent being evaluated.
            rule_id: The policy rule ID.
            passed: Whether the rule passed.
            severity: Rule severity.
        """
        with self.span(
            "policy_evaluation",
            attributes={
                "agent_id": agent_id,
                "policy.rule_id": rule_id,
                "policy.passed": passed,
                "policy.severity": severity,
            },
        ):
            pass

    def trace_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        result: str,
        duration_ms: float = 0.0,
    ) -> None:
        """Record a tool call as a span.

        Args:
            agent_id: The calling agent.
            tool_name: Name of the tool.
            result: Outcome (allowed, denied, error).
            duration_ms: Execution time.
        """
        with self.span(
            "tool_call",
            attributes={
                "agent_id": agent_id,
                "tool.name": tool_name,
                "tool.result": result,
                "tool.duration_ms": duration_ms,
            },
        ):
            pass
