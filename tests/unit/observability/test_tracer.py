"""Tests for agentguard.observability.tracer — OTel agent tracer."""

from __future__ import annotations

from agentguard.observability.tracer import AgentTracer, _NoOpSpan


class TestNoOpSpan:
    def test_set_attribute(self) -> None:
        span = _NoOpSpan()
        span.set_attribute("key", "value")  # should not raise

    def test_set_status(self) -> None:
        span = _NoOpSpan()
        span.set_status("ok")

    def test_record_exception(self) -> None:
        span = _NoOpSpan()
        span.record_exception(ValueError("test"))

    def test_end(self) -> None:
        span = _NoOpSpan()
        span.end()


class TestAgentTracer:
    def test_disabled_tracer(self) -> None:
        tracer = AgentTracer(enabled=False)
        assert not tracer.is_active

    def test_noop_span_when_disabled(self) -> None:
        tracer = AgentTracer(enabled=False)
        with tracer.span("test_span", attributes={"key": "val"}) as span:
            assert isinstance(span, _NoOpSpan)

    def test_noop_span_when_otel_unavailable(self) -> None:
        # Even with enabled=True, if OTel is not installed we get NoOp
        tracer = AgentTracer(service_name="test", enabled=True)
        # We can't guarantee OTel is installed in test env, but span should work
        with tracer.span("test_span") as span:
            span.set_attribute("test", "value")

    def test_trace_rbac_check(self) -> None:
        tracer = AgentTracer(enabled=False)
        # Should not raise even in disabled mode
        tracer.trace_rbac_check(
            agent_id="agent-001",
            action="tool:test",
            resource="*",
            granted=True,
            reason="allowed",
        )

    def test_trace_policy_evaluation(self) -> None:
        tracer = AgentTracer(enabled=False)
        tracer.trace_policy_evaluation(
            agent_id="agent-001",
            rule_id="OWASP-001",
            passed=True,
            severity="high",
        )

    def test_trace_tool_call(self) -> None:
        tracer = AgentTracer(enabled=False)
        tracer.trace_tool_call(
            agent_id="agent-001",
            tool_name="credit_check",
            result="allowed",
            duration_ms=5.0,
        )

    def test_span_with_no_attributes(self) -> None:
        tracer = AgentTracer(enabled=False)
        with tracer.span("bare_span") as span:
            assert isinstance(span, _NoOpSpan)
