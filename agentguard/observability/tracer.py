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

    Lazily imports OpenTelemetry. If the host has not configured SDK providers,
    all operations produce no-op spans and metrics.

    Args:
        service_name: OTel service name for the tracer.
        enabled: Set False to force no-op mode even when OTel is available.
    """

    def __init__(self, service_name: str = "agentguard", enabled: bool = True) -> None:
        self._service_name = service_name
        self._tracer: Any = None
        self._outcome_counter: Any = None
        self._duration_histogram: Any = None
        self._trace_active = False

        if enabled:
            self._initialize_trace_provider()
            self._initialize_meter_provider()

    def _initialize_trace_provider(self) -> None:
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
        except ImportError:
            logger.debug("otel_tracer_not_configured", service_name=self._service_name)
            return

        provider = trace.get_tracer_provider()
        if not isinstance(provider, TracerProvider):
            logger.debug("otel_tracer_not_configured", service_name=self._service_name)
            return

        self._tracer = provider.get_tracer(self._service_name)
        self._trace_active = True
        logger.debug("otel_tracer_initialized", service_name=self._service_name)

    def _initialize_meter_provider(self) -> None:
        try:
            from opentelemetry import metrics
            from opentelemetry.sdk.metrics import MeterProvider
        except ImportError:
            logger.debug("otel_meter_not_configured", service_name=self._service_name)
            return

        provider = metrics.get_meter_provider()
        if not isinstance(provider, MeterProvider):
            logger.debug("otel_meter_not_configured", service_name=self._service_name)
            return

        meter = provider.get_meter(self._service_name)
        self._outcome_counter = meter.create_counter(
            "agentguard.governance.outcomes",
            unit="{call}",
            description="Governed calls by terminal outcome.",
        )
        self._duration_histogram = meter.create_histogram(
            "agentguard.governance.duration",
            unit="ms",
            description="Governed call duration in milliseconds.",
        )

    @property
    def is_active(self) -> bool:
        """True only when the host configured an OTel SDK tracer provider."""
        return self._trace_active

    @contextmanager
    def span(self, name: str, attributes: dict[str, Any] | None = None) -> Any:
        """Create a traced span.

        Args:
            name: Span name (e.g. "rbac_check", "tool_call").
            attributes: Initial span attributes.

        Yields:
            The span object (OTel Span or _NoOpSpan).
        """
        if not self._trace_active or self._tracer is None:
            yield _NoOpSpan()
            return

        prefixed_attrs = {}
        if attributes:
            for k, v in attributes.items():
                key = f"{ATTR_PREFIX}.{k}" if not k.startswith(f"{ATTR_PREFIX}.") else k
                prefixed_attrs[key] = v

        try:
            manager = self._tracer.start_as_current_span(name, attributes=prefixed_attrs)
            otel_span = manager.__enter__()
        except BaseException:
            logger.debug("otel_span_start_failed", span_name=name, exc_info=True)
            yield _NoOpSpan()
            return

        try:
            yield otel_span
        except BaseException as exc:
            self._record_span_error(otel_span, exc)
            raise
        finally:
            try:
                manager.__exit__(None, None, None)
            except BaseException:
                logger.debug("otel_span_end_failed", span_name=name, exc_info=True)

    @staticmethod
    def _record_span_error(span: Any, exception: BaseException) -> None:
        """Best-effort error instrumentation that cannot mask the original error."""
        try:
            from opentelemetry.trace import Status, StatusCode

            span.record_exception(exception)
            span.set_status(Status(StatusCode.ERROR, str(exception)))
        except BaseException:
            logger.debug("otel_span_error_recording_failed", exc_info=True)

    def record_outcome(self, result: str, duration_ms: float) -> None:
        """Record a governed call's terminal outcome and duration when configured."""
        if self._outcome_counter is None or self._duration_histogram is None:
            return
        attributes = {"agentguard.result": result}
        try:
            self._outcome_counter.add(1, attributes)
            self._duration_histogram.record(duration_ms, attributes)
        except BaseException:
            logger.debug("otel_metric_recording_failed", exc_info=True)
