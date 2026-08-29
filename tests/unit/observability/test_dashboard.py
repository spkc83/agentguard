"""Tests for agentguard.observability.dashboard — metrics dashboard."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from agentguard.models import (
    AgentIdentity,
    AuditEvent,
    AuditEventType,
    GuardrailEvaluation,
    HitlEvidence,
    PermissionContext,
    PolicyResult,
    ReconciliationEvidence,
)
from agentguard.observability.dashboard import MetricsDashboard


def _make_identity(agent_id: str = "agent-001") -> AgentIdentity:
    return AgentIdentity(agent_id=agent_id, name="Test", roles=["analyst"])


def _make_event(
    agent_id: str = "agent-001",
    action: str = "tool:credit_check",
    result: Literal["allowed", "denied", "escalated", "rejected", "error"] = "allowed",
    duration_ms: float = 5.0,
    timestamp: datetime | None = None,
    policy_results: list[PolicyResult] | None = None,
    invocation_id: str = "",
    event_type: AuditEventType = "legacy",
    guardrail_evaluations: tuple[GuardrailEvaluation, ...] = (),
    hitl_evidence: HitlEvidence | None = None,
    reconciliation_evidence: ReconciliationEvidence | None = None,
    event_id: str | None = None,
) -> AuditEvent:
    identity = _make_identity(agent_id)
    return AuditEvent(
        event_id=event_id or f"evt-{agent_id}",
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
        invocation_id=invocation_id,
        event_type=event_type,
        guardrail_evaluations=guardrail_evaluations,
        hitl_evidence=hitl_evidence,
        reconciliation_evidence=reconciliation_evidence,
        chain_mode=(
            "shadow" if any(not item.enforced for item in guardrail_evaluations) else "enforce"
        ),
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
    reconciliation_id: str = "recon-1",
) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        escalation_id="esc-1",
        claim_id="claim-1",
        reconciliation_id=reconciliation_id,
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

    def test_shadow_metrics_are_deduplicated_and_isolated(self) -> None:
        shadow_deny = GuardrailEvaluation(
            guardrail_id="pii",
            guardrail_version="3",
            stage="pre_tool",
            effect="deny",
            reason_codes=("pii.ssn",),
            duration_ms=0.2,
            enforced=False,
        )
        shadow_transform = GuardrailEvaluation(
            guardrail_id="mask",
            guardrail_version="1",
            stage="post_tool",
            effect="transform",
            reason_codes=("pii.masked",),
            duration_ms=0.3,
            enforced=False,
        )
        events = [
            _make_event(
                invocation_id="inv-1",
                event_type="admission",
                guardrail_evaluations=(shadow_deny,),
            ),
            _make_event(
                invocation_id="inv-1",
                event_type="delivery_completed",
                guardrail_evaluations=(shadow_deny, shadow_transform),
            ),
        ]

        metrics = MetricsDashboard().compute(events)

        assert metrics.total_events == 1
        assert metrics.allowed_count == 1
        assert metrics.denied_count == 0
        assert metrics.denial_rate == 0.0
        assert metrics.policy_violations == []
        assert metrics.shadow_evaluation_count == 2
        assert metrics.shadow_affected_invocation_count == 1
        assert metrics.shadow_would_deny_count == 1
        assert metrics.shadow_would_transform_count == 1
        pii = next(item for item in metrics.shadow_guardrails if item.guardrail_id == "pii")
        assert pii.stage == "pre_tool"
        assert pii.evaluation_count == 1
        assert pii.reason_code_counts == {"pii.ssn": 1}
        assert "Shadow guardrail observations (not enforced)" in MetricsDashboard().to_markdown(
            metrics
        )
        assert '"shadow_would_deny_count": 1' in MetricsDashboard().to_json(metrics)

    def test_shadow_conflict_is_surfaced_without_double_counting(self) -> None:
        first = GuardrailEvaluation(
            guardrail_id="risk",
            guardrail_version="7",
            stage="pre_tool",
            effect="deny",
            reason_codes=("risk.high",),
            duration_ms=0.1,
            enforced=False,
        )
        conflicting = first.model_copy(
            update={"effect": "escalate", "reason_codes": ("risk.review",)}
        )

        metrics = MetricsDashboard().compute(
            [
                _make_event(
                    invocation_id="inv-conflict",
                    event_type="admission",
                    guardrail_evaluations=(first,),
                ),
                _make_event(
                    invocation_id="inv-conflict",
                    event_type="delivery_completed",
                    guardrail_evaluations=(conflicting,),
                ),
            ]
        )

        assert metrics.shadow_evaluation_count == 1
        assert metrics.shadow_conflict_count == 1
        assert metrics.shadow_would_deny_count == 1
        assert metrics.shadow_would_escalate_count == 1
        assert metrics.shadow_guardrails[0].conflict_count == 1

        reversed_metrics = MetricsDashboard().compute(
            [
                _make_event(
                    invocation_id="inv-conflict",
                    event_type="admission",
                    guardrail_evaluations=(conflicting,),
                ),
                _make_event(
                    invocation_id="inv-conflict",
                    event_type="delivery_completed",
                    guardrail_evaluations=(first,),
                ),
            ]
        )
        assert reversed_metrics.shadow_would_deny_count == 1
        assert reversed_metrics.shadow_would_escalate_count == 1
        assert reversed_metrics.shadow_guardrails == metrics.shadow_guardrails

    def test_global_would_effect_counts_unique_invocations(self) -> None:
        first = GuardrailEvaluation(
            guardrail_id="risk-a",
            guardrail_version="1",
            stage="pre_tool",
            effect="deny",
            reason_codes=("risk.a",),
            duration_ms=0.1,
            enforced=False,
        )
        second = first.model_copy(update={"guardrail_id": "risk-b"})

        metrics = MetricsDashboard().compute(
            [
                _make_event(
                    invocation_id="inv-one",
                    event_type="admission",
                    guardrail_evaluations=(first, second),
                ),
                _make_event(
                    invocation_id="inv-one",
                    event_type="delivery_completed",
                ),
            ]
        )

        assert metrics.shadow_evaluation_count == 2
        assert metrics.shadow_would_deny_count == 1

    def test_shadow_summaries_separate_the_same_guardrail_by_stage(self) -> None:
        pre = GuardrailEvaluation(
            guardrail_id="classifier",
            guardrail_version="2",
            stage="pre_tool",
            effect="warn",
            reason_codes=("risk.observe",),
            duration_ms=0.1,
            enforced=False,
        )
        post = pre.model_copy(update={"stage": "post_tool", "effect": "allow"})

        metrics = MetricsDashboard().compute(
            [
                _make_event(
                    invocation_id="inv-stages",
                    event_type="admission",
                    guardrail_evaluations=(pre,),
                ),
                _make_event(
                    invocation_id="inv-stages",
                    event_type="delivery_completed",
                    guardrail_evaluations=(post,),
                ),
            ]
        )

        summary_counts = [
            (item.stage, item.warn_count, item.allow_count) for item in metrics.shadow_guardrails
        ]
        assert summary_counts == [
            ("post_tool", 0, 1),
            ("pre_tool", 1, 0),
        ]

    def test_hitl_lifecycle_counts_are_deduplicated_from_final_outcomes(self) -> None:
        decided_at = datetime(2026, 4, 10, 12, 1, tzinfo=UTC)
        requested = HitlEvidence(
            escalation_id="esc-1",
            state="requested",
            expires_at=datetime(2026, 4, 10, 12, 5, tzinfo=UTC),
        )
        approved = HitlEvidence(
            escalation_id="esc-1",
            decision_id="decision-1",
            state="approved",
            approver_id="reviewer-1",
            decided_at=decided_at,
        )
        events = [
            _make_event(
                event_id="request-1",
                invocation_id="inv-hitl",
                event_type="escalation_requested",
                result="escalated",
                hitl_evidence=requested,
            ),
            _make_event(
                event_id="request-duplicate",
                invocation_id="inv-retried-request",
                event_type="escalation_requested",
                result="escalated",
                hitl_evidence=requested,
            ),
            _make_event(
                event_id="approval-1",
                invocation_id="inv-hitl",
                event_type="approval_granted",
                hitl_evidence=approved,
            ),
            _make_event(
                event_id="approval-duplicate",
                invocation_id="inv-retried-approval",
                event_type="approval_granted",
                hitl_evidence=approved,
            ),
            _make_event(
                event_id="resume-1",
                invocation_id="inv-hitl",
                event_type="escalation_resumed",
                hitl_evidence=approved,
            ),
            _make_event(
                event_id="delivery-1",
                invocation_id="inv-hitl",
                event_type="delivery_completed",
            ),
        ]

        metrics = MetricsDashboard().compute(events)

        assert metrics.escalation_requested_count == 1
        assert metrics.approval_granted_count == 1
        assert metrics.escalation_resumed_count == 1
        assert metrics.escalated_count == 0
        assert metrics.allowed_count == 1

    def test_hitl_denials_expirations_and_rendering(self) -> None:
        decided_at = datetime(2026, 4, 10, 12, 5, tzinfo=UTC)
        denied = HitlEvidence(
            escalation_id="esc-denied",
            decision_id="decision-denied",
            state="denied",
            approver_id="reviewer-2",
            decided_at=decided_at,
        )
        expired = HitlEvidence(
            escalation_id="esc-expired",
            decision_id="decision-expired",
            state="expired",
            decided_at=decided_at,
            expires_at=decided_at,
        )
        metrics = MetricsDashboard().compute(
            [
                _make_event(
                    invocation_id="inv-denied",
                    event_type="approval_denied",
                    result="denied",
                    hitl_evidence=denied,
                ),
                _make_event(
                    invocation_id="inv-expired",
                    event_type="approval_expired",
                    result="denied",
                    hitl_evidence=expired,
                ),
                _make_event(
                    invocation_id="inv-final-escalated",
                    event_type="escalation",
                    result="escalated",
                ),
            ]
        )

        assert metrics.approval_denied_count == 1
        assert metrics.approval_expired_count == 1
        assert metrics.escalated_count == 1
        assert '"approval_denied_count": 1' in MetricsDashboard().to_json(metrics)
        markdown = MetricsDashboard().to_markdown(metrics)
        assert "## HITL lifecycle" in markdown
        assert "Approvals denied: 1" in markdown
        assert "Approvals expired: 1" in markdown

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

    def test_success_lifecycle_counts_one_invocation(self) -> None:
        events = [
            _make_event(invocation_id="inv-1", event_type="admission", duration_ms=0.0),
            _make_event(invocation_id="inv-1", event_type="execution_completed", duration_ms=4.0),
            _make_event(invocation_id="inv-1", event_type="delivery_completed", duration_ms=5.0),
        ]
        metrics = MetricsDashboard().compute(events)
        assert metrics.total_events == 1
        assert metrics.raw_event_count == 3
        assert metrics.allowed_count == 1
        assert metrics.execution_success_count == 1
        assert metrics.latency_p50_ms == 5.0

    def test_delivery_denial_preserves_execution_success(self) -> None:
        events = [
            _make_event(invocation_id="inv-1", event_type="admission", duration_ms=0.0),
            _make_event(invocation_id="inv-1", event_type="execution_completed", duration_ms=4.0),
            _make_event(
                invocation_id="inv-1",
                event_type="delivery_denied",
                result="denied",
                duration_ms=5.0,
            ),
        ]
        metrics = MetricsDashboard().compute(events)
        assert metrics.total_events == 1
        assert metrics.denied_count == 1
        assert metrics.delivery_denied_count == 1
        assert metrics.execution_success_count == 1

    def test_execution_error_is_terminal_without_delivery(self) -> None:
        events = [
            _make_event(invocation_id="inv-1", event_type="admission", duration_ms=0.0),
            _make_event(
                invocation_id="inv-1",
                event_type="execution_completed",
                result="error",
                duration_ms=3.0,
            ),
        ]
        metrics = MetricsDashboard().compute(events)
        assert metrics.total_events == 1
        assert metrics.error_count == 1
        assert metrics.incomplete_count == 0

    def test_pre_execution_terminal_branches_count_once(self) -> None:
        events = [
            _make_event(
                invocation_id="deny", event_type="denial", result="denied", duration_ms=0.0
            ),
            _make_event(
                invocation_id="reject",
                event_type="rejection",
                result="rejected",
                duration_ms=0.0,
            ),
            _make_event(
                invocation_id="escalate",
                event_type="escalation",
                result="escalated",
                duration_ms=0.0,
            ),
        ]
        metrics = MetricsDashboard().compute(events)
        assert metrics.total_events == 3
        assert metrics.denied_count == 1
        assert metrics.rejected_count == 1
        assert metrics.escalated_count == 1

    def test_post_execution_escalation_is_terminal(self) -> None:
        events = [
            _make_event(invocation_id="inv-1", event_type="execution_completed", duration_ms=2.0),
            _make_event(
                invocation_id="inv-1",
                event_type="delivery_escalated",
                result="escalated",
                duration_ms=3.0,
            ),
        ]
        metrics = MetricsDashboard().compute(events)
        assert metrics.total_events == 1
        assert metrics.escalated_count == 1
        assert metrics.execution_success_count == 1

    def test_duplicate_delivery_terminals_use_conservative_precedence(self) -> None:
        events = [
            _make_event(
                invocation_id="inv-1",
                event_type="delivery_denied",
                result="denied",
                duration_ms=2.0,
            ),
            _make_event(
                invocation_id="inv-1",
                event_type="delivery_completed",
                result="allowed",
                duration_ms=3.0,
            ),
            _make_event(
                invocation_id="inv-2",
                event_type="delivery_escalated",
                result="escalated",
                duration_ms=2.0,
            ),
            _make_event(
                invocation_id="inv-2",
                event_type="delivery_completed",
                result="allowed",
                duration_ms=3.0,
            ),
        ]

        metrics = MetricsDashboard().compute(events)

        assert metrics.denied_count == 1
        assert metrics.escalated_count == 1
        assert metrics.allowed_count == 0

    def test_admission_without_terminal_is_exposed_as_incomplete(self) -> None:
        metrics = MetricsDashboard().compute(
            [_make_event(invocation_id="inv-1", event_type="admission", duration_ms=0.0)]
        )
        assert metrics.total_events == 0
        assert metrics.raw_event_count == 1
        assert metrics.incomplete_count == 1

    def test_in_doubt_is_distinct_until_reconciled_denied(self) -> None:
        in_doubt = _make_event(
            event_id="invocation:inv-1:in-doubt",
            invocation_id="inv-1",
            event_type="execution_in_doubt",
            result="error",
            reconciliation_evidence=_reconciliation_evidence(
                state="in_doubt",
                classification="admission_without_completion",
            ),
        )

        pending = MetricsDashboard().compute([in_doubt, in_doubt])
        assert pending.in_doubt_count == 1
        assert pending.incomplete_count == 0
        assert pending.total_events == 0
        assert pending.allowed_count == 0
        assert pending.error_count == 0

        reconciled = _make_event(
            event_id="invocation:inv-1:reconcile:recon-1",
            invocation_id="inv-1",
            event_type="execution_reconciled",
            result="denied",
            reconciliation_evidence=_reconciliation_evidence(
                state="reconciled",
                classification="reconciled_denied",
            ),
        )
        closed = MetricsDashboard().compute([in_doubt, reconciled])
        assert closed.in_doubt_count == 0
        assert closed.incomplete_count == 0
        assert closed.total_events == 1
        assert closed.denied_count == 1

    def test_reconciliation_resumed_is_nonterminal_and_delivery_wins(self) -> None:
        resumed = _make_event(
            invocation_id="inv-1",
            event_type="execution_reconciliation_resumed",
            reconciliation_evidence=_reconciliation_evidence(
                state="resumed",
                classification="protected_result_available",
            ),
        )
        pending = MetricsDashboard().compute([resumed])
        assert pending.total_events == 0
        assert pending.incomplete_count == 1

        delivered = _make_event(
            invocation_id="inv-1",
            event_type="delivery_completed",
        )
        complete = MetricsDashboard().compute([resumed, delivered])
        assert complete.total_events == 1
        assert complete.allowed_count == 1
        assert complete.incomplete_count == 0

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
