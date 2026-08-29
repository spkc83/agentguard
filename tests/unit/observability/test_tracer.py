"""Tests for agentguard.observability.tracer — OTel agent tracer."""

from __future__ import annotations

from typing import Any

import pytest

from agentguard.observability.tracer import AgentTracer, _NoOpSpan


class TestNoOpSpan:
    def test_operations_do_not_raise(self) -> None:
        span = _NoOpSpan()
        span.set_attribute("key", "value")
        span.set_status("ok")
        span.record_exception(ValueError("test"))
        span.end()


class TestAgentTracer:
    def test_disabled_tracer(self) -> None:
        tracer = AgentTracer(enabled=False)
        assert not tracer.is_active

    def test_noop_span_when_disabled(self) -> None:
        tracer = AgentTracer(enabled=False)
        with tracer.span("test_span", attributes={"key": "val"}) as span:
            assert isinstance(span, _NoOpSpan)

    def test_default_proxy_provider_is_not_active(self, monkeypatch: pytest.MonkeyPatch) -> None:
        trace = pytest.importorskip("opentelemetry.trace")
        proxy_provider = trace.ProxyTracerProvider()
        monkeypatch.setattr(trace, "get_tracer_provider", lambda: proxy_provider)

        tracer = AgentTracer(service_name="test", enabled=True)

        assert not tracer.is_active
        with tracer.span("test_span") as span:
            assert isinstance(span, _NoOpSpan)

    def test_record_outcome_is_noop_without_configured_provider(self) -> None:
        AgentTracer(enabled=False).record_outcome("allowed", 5.0)

    def test_span_attributes_use_dotted_agentguard_namespace(self) -> None:
        tracer = AgentTracer(enabled=False)
        recorded: dict[str, object] = {}

        class _StubSpan:
            def __enter__(self) -> _StubSpan:
                return self

            def __exit__(self, *args: object) -> None:
                return None

        class _StubTracer:
            def start_as_current_span(
                self, name: str, attributes: dict[str, object] | None = None
            ) -> _StubSpan:
                recorded["name"] = name
                recorded["attributes"] = attributes or {}
                return _StubSpan()

        tracer._tracer = _StubTracer()
        tracer._trace_active = True
        with tracer.span(
            "agentguard.rbac_check",
            attributes={"agent.id": "abc", "agentguard.permission.granted": True},
        ):
            pass

        assert recorded == {
            "name": "agentguard.rbac_check",
            "attributes": {
                "agentguard.agent.id": "abc",
                "agentguard.permission.granted": True,
            },
        }

    def test_telemetry_failure_does_not_mask_span_error(self) -> None:
        tracer = AgentTracer(enabled=False)

        class _BrokenSpan:
            def __enter__(self) -> _BrokenSpan:
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def record_exception(self, exception: BaseException) -> None:
                raise RuntimeError("telemetry failed")

        class _StubTracer:
            def start_as_current_span(
                self, name: str, attributes: dict[str, object] | None = None
            ) -> _BrokenSpan:
                return _BrokenSpan()

        tracer._tracer = _StubTracer()
        tracer._trace_active = True

        with pytest.raises(ValueError, match="original"), tracer.span("test"):
            raise ValueError("original")

    def test_configured_sdk_provider_is_active_and_records_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        trace = pytest.importorskip("opentelemetry.trace")
        sdk_trace = pytest.importorskip("opentelemetry.sdk.trace")
        export = pytest.importorskip("opentelemetry.sdk.trace.export")
        memory_export = pytest.importorskip(
            "opentelemetry.sdk.trace.export.in_memory_span_exporter"
        )
        exporter = memory_export.InMemorySpanExporter()
        provider = sdk_trace.TracerProvider()
        provider.add_span_processor(export.SimpleSpanProcessor(exporter))
        monkeypatch.setattr(trace, "get_tracer_provider", lambda: provider)
        tracer = AgentTracer(service_name="test", enabled=True)

        assert tracer.is_active
        with (
            pytest.raises(ValueError, match="original"),
            tracer.span("agentguard.tool_call", attributes={"agent.id": "agent-001"}),
        ):
            raise ValueError("original")

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        span = spans[0]
        assert span.attributes["agentguard.agent.id"] == "agent-001"
        assert span.status.status_code is trace.StatusCode.ERROR
        assert any(event.name == "exception" for event in span.events)
        provider.shutdown()

    def test_configured_sdk_meter_records_outcome_and_duration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        metrics = pytest.importorskip("opentelemetry.metrics")
        sdk_metrics = pytest.importorskip("opentelemetry.sdk.metrics")
        export = pytest.importorskip("opentelemetry.sdk.metrics.export")
        reader = export.InMemoryMetricReader()
        provider = sdk_metrics.MeterProvider(metric_readers=[reader])
        monkeypatch.setattr(metrics, "get_meter_provider", lambda: provider)
        tracer = AgentTracer(service_name="test", enabled=True)

        tracer.record_outcome("denied", 12.5)

        metric_data: dict[str, Any] = {}
        collected = reader.get_metrics_data()
        for resource_metrics in collected.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_data[metric.name] = metric.data

        counter = metric_data["agentguard.governance.outcomes"]
        assert counter.data_points[0].value == 1
        assert dict(counter.data_points[0].attributes) == {"agentguard.result": "denied"}
        histogram = metric_data["agentguard.governance.duration"]
        assert histogram.data_points[0].count == 1
        assert histogram.data_points[0].sum == 12.5
        assert dict(histogram.data_points[0].attributes) == {"agentguard.result": "denied"}
        provider.shutdown()
