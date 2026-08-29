"""Tests for agentguard.observability.replay — audit log replay debugger."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from agentguard.models import (
    AgentIdentity,
    AuditEvent,
    AuditEventType,
    AuditLink,
    EvidenceRef,
    GuardrailEvaluation,
    PermissionContext,
    PolicyResult,
    ReconciliationEvidence,
)
from agentguard.observability.replay import ReplayDebugger


def _make_identity(agent_id: str = "agent-001") -> AgentIdentity:
    return AgentIdentity(agent_id=agent_id, name="Test", roles=["analyst"])


def _make_event(
    agent_id: str = "agent-001",
    action: str = "tool:credit_check",
    resource: str = "bureau/experian",
    result: Literal["allowed", "denied", "escalated", "rejected", "error"] = "allowed",
    timestamp: datetime | None = None,
    policy_results: list[PolicyResult] | None = None,
    subject_ref: EvidenceRef | None = None,
    links: tuple[AuditLink, ...] = (),
    guardrail_evaluations: tuple[GuardrailEvaluation, ...] = (),
    event_id: str | None = None,
    invocation_id: str = "",
    event_type: AuditEventType = "legacy",
    reconciliation_evidence: ReconciliationEvidence | None = None,
) -> AuditEvent:
    identity = _make_identity(agent_id)
    return AuditEvent(
        event_id=event_id or f"evt-{agent_id}-{action}",
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
        subject_ref=subject_ref,
        links=links,
        guardrail_evaluations=guardrail_evaluations,
        chain_mode=(
            "shadow" if any(not item.enforced for item in guardrail_evaluations) else "enforce"
        ),
        invocation_id=invocation_id,
        event_type=event_type,
        reconciliation_evidence=reconciliation_evidence,
    )


def _reconciliation_evidence(
    *,
    state: Literal["in_doubt", "resumed", "reconciled"],
    classification: Literal[
        "claimed_without_terminal",
        "admission_without_completion",
        "completion_without_protected_result",
        "protected_result_available",
        "reconciled_denied",
    ],
) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        escalation_id="esc-1",
        claim_id="claim-1",
        reconciliation_id="recon-1",
        classification=classification,
        state=state,
        reconciler_id="reviewer-1",
        reason_digest="a" * 64,
        assessed_at=datetime(2026, 4, 10, 12, 0, tzinfo=UTC),
        audit_chain_id="chain-1",
        audit_head_sequence=3,
        audit_head_event_hash="b" * 64,
        journal_revision=2,
        journal_digest="c" * 64,
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

    def test_filter_by_subject_and_linked_reference(self) -> None:
        debugger = ReplayDebugger()
        application = EvidenceRef(namespace="application", value="APP-000038")
        notice = EvidenceRef(namespace="notice", value="NOTICE-12")
        events = [
            _make_event(
                subject_ref=application,
                links=(AuditLink(relation="notice", target=notice),),
            ),
            _make_event(subject_ref=EvidenceRef(namespace="application", value="APP-OTHER")),
        ]

        assert debugger.filter(events, subject_ref=application) == [events[0]]
        assert debugger.filter(events, linked_ref=notice) == [events[0]]

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

    def test_timeline_exposes_shadow_would_effects(self) -> None:
        evaluations = tuple(
            GuardrailEvaluation(
                guardrail_id=f"guard-{effect}",
                guardrail_version="2.1",
                stage="pre_tool",
                effect=effect,
                reason_codes=(f"reason.{effect}",),
                duration_ms=0.2,
                enforced=False,
            )
            for effect in ("deny", "escalate", "transform")
        )

        entry = ReplayDebugger().timeline([_make_event(guardrail_evaluations=evaluations)])[0]

        assert entry.flags == [
            "shadow_would_deny",
            "shadow_would_escalate",
            "shadow_would_transform",
        ]
        assert entry.shadow_evaluations[0].guardrail_id == "guard-deny"
        assert entry.shadow_evaluations[0].guardrail_version == "2.1"
        assert entry.shadow_evaluations[0].stage == "pre_tool"
        assert entry.shadow_evaluations[0].reason_codes == ("reason.deny",)
        assert "guard-deny@2.1 would deny at pre_tool" in entry.decision_summary

    def test_timeline_ignores_enforced_guardrail_effects(self) -> None:
        evaluation = GuardrailEvaluation(
            guardrail_id="enforced",
            guardrail_version="1",
            stage="pre_tool",
            effect="deny",
            reason_codes=("blocked",),
            duration_ms=0.1,
            enforced=True,
        )

        entry = ReplayDebugger().timeline([_make_event(guardrail_evaluations=(evaluation,))])[0]

        assert entry.shadow_evaluations == ()
        assert "shadow_would_deny" not in entry.flags

    def test_timeline_exposes_typed_redacted_reconciliation(self) -> None:
        event = _make_event(
            event_type="execution_in_doubt",
            result="error",
            reconciliation_evidence=_reconciliation_evidence(
                state="in_doubt",
                classification="claimed_without_terminal",
            ),
        )

        first, duplicate = ReplayDebugger().timeline([event, event])

        assert first.reconciliation is not None
        assert first.reconciliation.classification == "claimed_without_terminal"
        assert first.reconciliation.state == "in_doubt"
        assert first.reconciliation.reconciler_id == "reviewer-1"
        assert "in_doubt" in first.flags
        assert first.model_dump() == duplicate.model_copy(update={"index": 0}).model_dump()
        assert "reason" not in first.reconciliation.model_dump()
        assert "a" * 64 not in first.decision_summary

    def test_reconciled_and_resumed_timeline_semantics(self) -> None:
        resumed = _make_event(
            event_type="execution_reconciliation_resumed",
            reconciliation_evidence=_reconciliation_evidence(
                state="resumed",
                classification="protected_result_available",
            ),
        )
        reconciled = _make_event(
            event_type="execution_reconciled",
            result="denied",
            reconciliation_evidence=_reconciliation_evidence(
                state="reconciled",
                classification="reconciled_denied",
            ),
        )

        resumed_entry, reconciled_entry = ReplayDebugger().timeline([resumed, reconciled])

        assert resumed_entry.flags == ["reconciliation_resumed"]
        assert "Allowed" not in resumed_entry.decision_summary
        assert reconciled_entry.flags == ["reconciled", "denied"]
        assert "delivery denied" in reconciled_entry.decision_summary

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

    def test_summarize_subject_references(self) -> None:
        subject = EvidenceRef(namespace="application", value="APP-000038")
        summary = ReplayDebugger().summarize(
            [_make_event(subject_ref=subject), _make_event(subject_ref=subject)]
        )

        assert summary["by_subject"] == {"application:APP-000038": 2}

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
