"""Tests for agentguard.observability.replay — audit log replay debugger."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from agentguard.models import AgentIdentity, AuditEvent, PermissionContext, PolicyResult
from agentguard.observability.replay import ReplayDebugger


def _make_identity(agent_id: str = "agent-001") -> AgentIdentity:
    return AgentIdentity(agent_id=agent_id, name="Test", roles=["analyst"])


def _make_event(
    agent_id: str = "agent-001",
    action: str = "tool:credit_check",
    resource: str = "bureau/experian",
    result: str = "allowed",
    timestamp: datetime | None = None,
    policy_results: list[PolicyResult] | None = None,
) -> AuditEvent:
    identity = _make_identity(agent_id)
    return AuditEvent(
        event_id=f"evt-{agent_id}-{action}",
        timestamp=timestamp or datetime(2026, 4, 10, 12, 0, 0, tzinfo=UTC),
        agent_id=agent_id,
        action=action,
        resource=resource,
        permission_context=PermissionContext(
            agent=identity,
            requested_action=action,
            resource=resource,
            granted=(result == "allowed"),
            reason="test",
        ),
        result=result,
        policy_results=policy_results or [],
        duration_ms=5.0,
        trace_id="trace-001",
    )


class TestReplayDebugger:
    def test_filter_by_agent_id(self) -> None:
        debugger = ReplayDebugger()
        events = [
            _make_event(agent_id="agent-001"),
            _make_event(agent_id="agent-002"),
            _make_event(agent_id="agent-001"),
        ]
        filtered = debugger.filter(events, agent_id="agent-001")
        assert len(filtered) == 2
        assert all(e.agent_id == "agent-001" for e in filtered)

    def test_filter_by_action(self) -> None:
        debugger = ReplayDebugger()
        events = [
            _make_event(action="tool:credit_check"),
            _make_event(action="tool:web_search"),
            _make_event(action="tool:credit_check"),
        ]
        filtered = debugger.filter(events, action="credit_check")
        assert len(filtered) == 2

    def test_filter_by_result(self) -> None:
        debugger = ReplayDebugger()
        events = [
            _make_event(result="allowed"),
            _make_event(result="denied"),
            _make_event(result="allowed"),
        ]
        filtered = debugger.filter(events, result="denied")
        assert len(filtered) == 1

    def test_filter_by_time_range(self) -> None:
        debugger = ReplayDebugger()
        events = [
            _make_event(timestamp=datetime(2026, 4, 10, 10, 0, 0, tzinfo=UTC)),
            _make_event(timestamp=datetime(2026, 4, 10, 12, 0, 0, tzinfo=UTC)),
            _make_event(timestamp=datetime(2026, 4, 10, 14, 0, 0, tzinfo=UTC)),
        ]
        filtered = debugger.filter(
            events,
            start_time=datetime(2026, 4, 10, 11, 0, 0, tzinfo=UTC),
            end_time=datetime(2026, 4, 10, 13, 0, 0, tzinfo=UTC),
        )
        assert len(filtered) == 1

    def test_filter_combined(self) -> None:
        debugger = ReplayDebugger()
        events = [
            _make_event(agent_id="agent-001", result="allowed"),
            _make_event(agent_id="agent-001", result="denied"),
            _make_event(agent_id="agent-002", result="denied"),
        ]
        filtered = debugger.filter(events, agent_id="agent-001", result="denied")
        assert len(filtered) == 1

    def test_timeline_allowed(self) -> None:
        debugger = ReplayDebugger()
        events = [_make_event(result="allowed")]
        timeline = debugger.timeline(events)
        assert len(timeline) == 1
        assert timeline[0].index == 0
        assert "Allowed" in timeline[0].decision_summary
        assert timeline[0].flags == []

    def test_timeline_denied(self) -> None:
        debugger = ReplayDebugger()
        events = [_make_event(result="denied")]
        timeline = debugger.timeline(events)
        assert len(timeline) == 1
        assert "denied" in timeline[0].flags
        assert "DENIED" in timeline[0].decision_summary

    def test_timeline_error(self) -> None:
        debugger = ReplayDebugger()
        events = [_make_event(result="error")]
        timeline = debugger.timeline(events)
        assert "error" in timeline[0].flags

    def test_timeline_escalated(self) -> None:
        debugger = ReplayDebugger()
        events = [_make_event(result="escalated")]
        timeline = debugger.timeline(events)
        assert "escalated" in timeline[0].flags

    def test_timeline_policy_violation(self) -> None:
        debugger = ReplayDebugger()
        policy_results = [
            PolicyResult(
                rule_id="OWASP-001",
                rule_name="Prompt Injection",
                passed=False,
                severity="critical",
                evidence={"matched": "inject"},
                remediation="Review input",
            )
        ]
        events = [_make_event(policy_results=policy_results)]
        timeline = debugger.timeline(events)
        assert "policy_violation" in timeline[0].flags
        assert "OWASP-001" in timeline[0].decision_summary

    def test_summarize(self) -> None:
        debugger = ReplayDebugger()
        events = [
            _make_event(agent_id="a1", action="tool:a", result="allowed"),
            _make_event(agent_id="a1", action="tool:b", result="denied"),
            _make_event(agent_id="a2", action="tool:a", result="allowed"),
        ]
        summary = debugger.summarize(events)
        assert summary["total_events"] == 3
        assert summary["by_result"]["allowed"] == 2
        assert summary["by_result"]["denied"] == 1
        assert summary["by_agent"]["a1"] == 2
        assert summary["by_agent"]["a2"] == 1

    def test_summarize_empty(self) -> None:
        debugger = ReplayDebugger()
        summary = debugger.summarize([])
        assert summary["total_events"] == 0

    async def test_load(self, tmp_path: Path) -> None:
        """Test loading from an empty directory."""
        debugger = ReplayDebugger()
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        events = await debugger.load(audit_dir)
        assert events == []

    def test_timeline_filename_alignment(self) -> None:
        """Events in order produce index-aligned timeline entries."""
        debugger = ReplayDebugger()
        events = [
            _make_event(action="tool:a", timestamp=datetime(2026, 4, 10, 12, 0, 0, tzinfo=UTC)),
            _make_event(action="tool:b", timestamp=datetime(2026, 4, 10, 12, 0, 5, tzinfo=UTC)),
        ]
        timeline = debugger.timeline(events)
        assert [e.index for e in timeline] == [0, 1]
        assert "tool:a" in timeline[0].decision_summary
        assert "tool:b" in timeline[1].decision_summary
