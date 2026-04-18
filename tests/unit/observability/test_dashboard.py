"""Tests for agentguard.observability.dashboard — metrics dashboard."""

from __future__ import annotations

from datetime import UTC, datetime

from agentguard.models import AgentIdentity, AuditEvent, PermissionContext, PolicyResult
from agentguard.observability.dashboard import MetricsDashboard


def _make_identity(agent_id: str = "agent-001") -> AgentIdentity:
    return AgentIdentity(agent_id=agent_id, name="Test", roles=["analyst"])


def _make_event(
    agent_id: str = "agent-001",
    action: str = "tool:credit_check",
    result: str = "allowed",
    duration_ms: float = 5.0,
    timestamp: datetime | None = None,
    policy_results: list[PolicyResult] | None = None,
) -> AuditEvent:
    identity = _make_identity(agent_id)
    return AuditEvent(
        event_id=f"evt-{agent_id}",
        timestamp=timestamp or datetime(2026, 4, 10, 12, 0, 0, tzinfo=UTC),
        agent_id=agent_id,
        action=action,
        resource="*",
        permission_context=PermissionContext(
            agent=identity,
            requested_action=action,
            resource="*",
            granted=(result == "allowed"),
            reason="test",
        ),
        result=result,
        policy_results=policy_results or [],
        duration_ms=duration_ms,
        trace_id="trace-001",
    )


class TestMetricsDashboard:
    def test_empty_events(self) -> None:
        dashboard = MetricsDashboard()
        metrics = dashboard.compute([])
        assert metrics.total_events == 0
        assert metrics.denial_rate == 0.0
        assert metrics.agent_metrics == []

    def test_basic_counts(self) -> None:
        dashboard = MetricsDashboard()
        events = [
            _make_event(result="allowed"),
            _make_event(result="allowed"),
            _make_event(result="denied"),
            _make_event(result="error"),
        ]
        metrics = dashboard.compute(events)
        assert metrics.total_events == 4
        assert metrics.allowed_count == 2
        assert metrics.denied_count == 1
        assert metrics.error_count == 1
        assert metrics.escalated_count == 0

    def test_denial_rate(self) -> None:
        dashboard = MetricsDashboard()
        events = [
            _make_event(result="allowed"),
            _make_event(result="denied"),
            _make_event(result="denied"),
            _make_event(result="denied"),
        ]
        metrics = dashboard.compute(events)
        assert metrics.denial_rate == 0.75

    def test_latency_percentiles(self) -> None:
        dashboard = MetricsDashboard()
        events = [
            _make_event(duration_ms=1.0),
            _make_event(duration_ms=2.0),
            _make_event(duration_ms=3.0),
            _make_event(duration_ms=4.0),
            _make_event(duration_ms=100.0),
        ]
        metrics = dashboard.compute(events)
        assert metrics.latency_p50_ms == 3.0
        assert metrics.latency_p95_ms > 50.0
        assert metrics.latency_p99_ms > 80.0

    def test_latency_zero_duration_excluded(self) -> None:
        dashboard = MetricsDashboard()
        events = [
            _make_event(duration_ms=0.0),
            _make_event(duration_ms=0.0),
            _make_event(duration_ms=10.0),
        ]
        metrics = dashboard.compute(events)
        assert metrics.latency_p50_ms == 10.0

    def test_per_agent_metrics(self) -> None:
        dashboard = MetricsDashboard()
        events = [
            _make_event(agent_id="a1", result="allowed"),
            _make_event(agent_id="a1", result="denied"),
            _make_event(agent_id="a2", result="allowed"),
        ]
        metrics = dashboard.compute(events)
        assert len(metrics.agent_metrics) == 2

        a1 = next(m for m in metrics.agent_metrics if m.agent_id == "a1")
        assert a1.total_actions == 2
        assert a1.allowed == 1
        assert a1.denied == 1
        assert a1.denial_rate == 0.5

        a2 = next(m for m in metrics.agent_metrics if m.agent_id == "a2")
        assert a2.total_actions == 1
        assert a2.denial_rate == 0.0

    def test_top_actions(self) -> None:
        dashboard = MetricsDashboard()
        events = [
            _make_event(action="tool:a"),
            _make_event(action="tool:a"),
            _make_event(action="tool:a"),
            _make_event(action="tool:b"),
            _make_event(action="tool:b"),
            _make_event(action="tool:c"),
        ]
        metrics = dashboard.compute(events)
        assert metrics.top_actions[0] == ("tool:a", 3)
        assert metrics.top_actions[1] == ("tool:b", 2)

    def test_policy_violations(self) -> None:
        dashboard = MetricsDashboard()
        policy_results = [
            PolicyResult(
                rule_id="OWASP-001",
                rule_name="Prompt Injection",
                passed=False,
                severity="critical",
                evidence={},
                remediation="Fix",
            )
        ]
        events = [
            _make_event(policy_results=policy_results),
            _make_event(policy_results=policy_results),
            _make_event(),
        ]
        metrics = dashboard.compute(events)
        assert len(metrics.policy_violations) == 1
        assert metrics.policy_violations[0].rule_id == "OWASP-001"
        assert metrics.policy_violations[0].violation_count == 2

    def test_time_range(self) -> None:
        dashboard = MetricsDashboard()
        events = [
            _make_event(timestamp=datetime(2026, 4, 10, 10, 0, 0, tzinfo=UTC)),
            _make_event(timestamp=datetime(2026, 4, 10, 14, 0, 0, tzinfo=UTC)),
        ]
        metrics = dashboard.compute(events)
        assert metrics.time_range_start == datetime(2026, 4, 10, 10, 0, 0, tzinfo=UTC)
        assert metrics.time_range_end == datetime(2026, 4, 10, 14, 0, 0, tzinfo=UTC)

    def test_percentile_single_value(self) -> None:
        assert MetricsDashboard._percentile([5.0], 50) == 5.0
        assert MetricsDashboard._percentile([5.0], 99) == 5.0

    def test_percentile_empty(self) -> None:
        assert MetricsDashboard._percentile([], 50) == 0.0

    def test_per_agent_escalated_count(self) -> None:
        dashboard = MetricsDashboard()
        events = [
            _make_event(agent_id="a1", result="allowed"),
            _make_event(agent_id="a1", result="escalated"),
            _make_event(agent_id="a1", result="escalated"),
            _make_event(agent_id="a2", result="allowed"),
        ]
        metrics = dashboard.compute(events)
        a1 = next(m for m in metrics.agent_metrics if m.agent_id == "a1")
        a2 = next(m for m in metrics.agent_metrics if m.agent_id == "a2")
        assert a1.escalated == 2
        assert a2.escalated == 0

    def test_to_json_serialization(self) -> None:
        dashboard = MetricsDashboard()
        events = [_make_event(result="allowed"), _make_event(result="denied")]
        metrics = dashboard.compute(events)
        output = dashboard.to_json(metrics)
        assert '"total_events": 2' in output
        assert '"denied_count": 1' in output

    def test_to_markdown_rendering(self) -> None:
        dashboard = MetricsDashboard()
        events = [
            _make_event(agent_id="agent-x", result="allowed"),
            _make_event(agent_id="agent-x", result="denied"),
        ]
        metrics = dashboard.compute(events)
        output = dashboard.to_markdown(metrics)
        assert "# AgentGuard Dashboard" in output
        assert "Events analyzed:** 2" in output
        assert "## Latency (ms)" in output
        assert "## Per-agent activity" in output
        assert "agent-x" in output

    def test_to_markdown_empty(self) -> None:
        dashboard = MetricsDashboard()
        metrics = dashboard.compute([])
        output = dashboard.to_markdown(metrics)
        assert "# AgentGuard Dashboard" in output
        assert "Events analyzed:** 0" in output

    def test_all_zero_duration_events(self) -> None:
        """When no event has a positive duration, percentiles are 0.0 (line 148)."""
        dashboard = MetricsDashboard()
        events = [
            _make_event(duration_ms=0.0),
            _make_event(duration_ms=0.0),
            _make_event(duration_ms=0.0),
        ]
        metrics = dashboard.compute(events)
        assert metrics.total_events == 3
        assert metrics.latency_p50_ms == 0.0
        assert metrics.latency_p95_ms == 0.0
        assert metrics.latency_p99_ms == 0.0

    def test_to_markdown_with_policy_violations(self) -> None:
        """Markdown output renders the Policy violations section."""
        dashboard = MetricsDashboard()
        policy_results = [
            PolicyResult(
                rule_id="OWASP-AGENT-01",
                rule_name="Prompt Injection",
                passed=False,
                severity="critical",
                evidence={},
                remediation="Fix",
            )
        ]
        events = [_make_event(policy_results=policy_results)]
        metrics = dashboard.compute(events)
        output = dashboard.to_markdown(metrics)
        assert "## Policy violations" in output
        assert "OWASP-AGENT-01" in output
