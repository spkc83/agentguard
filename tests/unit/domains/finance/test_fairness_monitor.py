"""Fairness monitoring joins only attestable final decisions to private rows."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agentguard.core.audit import ChainVerificationResult, VerifiedAuditSnapshot
from agentguard.domains.finance.credit_risk.fairness import (
    FairnessAnalyzer,
    FairnessObservation,
)
from agentguard.domains.finance.credit_risk.fairness_monitor import (
    FairnessMonitor,
    FairnessMonitoringReport,
    PrivateFairnessAttributes,
)
from agentguard.domains.finance.credit_risk.model_governance import ModelFairnessStatus
from agentguard.domains.finance.credit_risk.model_validation import FairnessValidationEvidence
from agentguard.domains.finance.credit_risk.notice_governance import opaque_credit_ref
from agentguard.exceptions import AuditAttestationError, AuditTamperDetectedError
from agentguard.models import (
    AgentIdentity,
    AuditEvent,
    AuditLink,
    EvidenceRef,
    GuardrailEvaluation,
    PermissionContext,
)

_NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)
_MODEL_ID = "credit-pd"
_MODEL_VERSION = "2026.08"
_MODEL = opaque_credit_ref("credit-model", f"{_MODEL_ID}:{_MODEL_VERSION}")


def _ref(namespace: str, label: str) -> EvidenceRef:
    return EvidenceRef(namespace=namespace, value=hashlib.sha256(label.encode()).hexdigest())


class _Audit:
    def __init__(self, snapshot: VerifiedAuditSnapshot) -> None:
        self.snapshot = snapshot
        self.require_checkpoint: bool | None = None

    async def read_verified(self, *, require_checkpoint: bool = False) -> VerifiedAuditSnapshot:
        self.require_checkpoint = require_checkpoint
        return self.snapshot


class _Provider:
    provider_id = "private-fairness-store"
    version = "2026.08"

    def __init__(self, values: dict[str, object]) -> None:
        self.values = values
        self.calls: list[str] = []

    async def get(
        self,
        application_ref: EvidenceRef,
        decision_ref: EvidenceRef,
        model_ref: EvidenceRef,
    ) -> PrivateFairnessAttributes | None:
        assert application_ref.namespace == "credit-application"
        assert model_ref == _MODEL
        self.calls.append(decision_ref.value)
        value = self.values.get(decision_ref.value)
        if isinstance(value, Exception):
            raise value
        return value  # type: ignore[return-value]


def _attributes(
    group: str,
    *,
    pd: float = 0.2,
    default: bool | None = False,
    observed_at: datetime = _NOW,
) -> PrivateFairnessAttributes:
    return PrivateFairnessAttributes(
        group_name=group,
        predicted_pd=pd,
        observed_default=default,
        observed_at=observed_at,
    )


def _control() -> GuardrailEvaluation:
    return GuardrailEvaluation(
        guardrail_id="credit-decision-evidence",
        guardrail_version="1",
        stage="on_decision",
        effect="allow",
        reason_codes=(),
        duration_ms=0.1,
        enforced=True,
    )


def _event(
    label: str,
    *,
    action: str = "decision:approve",
    outcome: str = "approve",
    timestamp: datetime = _NOW,
    event_type: str = "delivery_completed",
    result: str = "allowed",
    decision_ref: EvidenceRef | None = None,
    application_ref: EvidenceRef | None = None,
    model_ref: EvidenceRef | None = _MODEL,
    controls: tuple[GuardrailEvaluation, ...] | None = None,
) -> AuditEvent:
    decision_ref = decision_ref or _ref("credit-decision", f"decision:{label}")
    application_ref = application_ref or _ref("credit-application", f"application:{label}")
    identity = AgentIdentity(agent_id="agent-1", name="Credit Agent", roles=["credit"])
    links: list[AuditLink] = []
    if decision_ref is not None:
        links.append(AuditLink(relation="decision", target=decision_ref))
    if model_ref is not None:
        links.append(AuditLink(relation="model", target=model_ref))
    payload = {
        "value": {
            "application_ref": application_ref.value,
            "decision_ref": decision_ref.value,
            "model_ref": (model_ref or _MODEL).value,
            "policy_ref": "c" * 64,
            "outcome": outcome,
        }
    }
    return AuditEvent.model_validate(
        {
            "event_id": f"event-{label}",
            "timestamp": timestamp,
            "agent_id": identity.agent_id,
            "action": action,
            "resource": "credit/decision",
            "permission_context": PermissionContext(
                agent=identity,
                requested_action=action,
                resource="credit/decision",
                granted=result == "allowed",
                reason="test",
            ),
            "result": result,
            "duration_ms": 1.0,
            "trace_id": "trace-1",
            "event_type": event_type,
            "payload_redacted": payload,
            "guardrail_evaluations": controls if controls is not None else (_control(),),
            "subject_ref": application_ref,
            "links": tuple(links),
        }
    )


def _snapshot(
    *events: AuditEvent,
    valid: bool = True,
    attestable: bool = True,
) -> VerifiedAuditSnapshot:
    return VerifiedAuditSnapshot(
        events=events,
        verification=ChainVerificationResult(
            valid=valid,
            event_count=len(events),
            error_index=None if valid else 1,
            error_event_id=None if valid else "event-corrupt",
            checkpoint_valid=attestable,
            checkpoint_status="verified" if attestable else "verified_unanchored",
            attestable=attestable,
            chain_id="audit-chain-1",
            head_sequence=len(events),
            head_event_hash="e" * 64,
        ),
    )


def _monitor(events: tuple[AuditEvent, ...], provider: _Provider) -> tuple[FairnessMonitor, _Audit]:
    audit = _Audit(_snapshot(*events))
    analyzer = FairnessAnalyzer("group-a", "group-b", min_group_size=1)
    return (
        FairnessMonitor(
            audit,
            provider,
            analyzer,
            model_id=_MODEL_ID,
            model_version=_MODEL_VERSION,
        ),
        audit,
    )


def _passing_monitor_report() -> FairnessMonitoringReport:
    analysis = FairnessAnalyzer("group-a", "group-b", min_group_size=1).analyze(
        (
            FairnessObservation(
                decision_ref="decision-a-approve",
                group_name="group-a",
                outcome="approve",
                predicted_pd=0.0,
                observed_default=False,
            ),
            FairnessObservation(
                decision_ref="decision-a-decline",
                group_name="group-a",
                outcome="decline",
                predicted_pd=1.0,
                observed_default=True,
            ),
            FairnessObservation(
                decision_ref="decision-b-approve",
                group_name="group-b",
                outcome="approve",
                predicted_pd=0.0,
                observed_default=False,
            ),
            FairnessObservation(
                decision_ref="decision-b-decline",
                group_name="group-b",
                outcome="decline",
                predicted_pd=1.0,
                observed_default=True,
            ),
        )
    )
    return FairnessMonitoringReport(
        window_started_at=_NOW - timedelta(days=1),
        window_ended_at=_NOW,
        provider_id="private-fairness-store",
        provider_version="2026.08",
        model_id=_MODEL_ID,
        model_version=_MODEL_VERSION,
        audit_chain_id="audit-chain-1",
        audit_head_sequence=4,
        audit_head_event_hash="e" * 64,
        selected_event_count=4,
        analyzed_observation_count=4,
        malformed_event_count=0,
        duplicate_decision_count=0,
        missing_observation_count=0,
        malformed_observation_count=0,
        provider_error_count=0,
        status=ModelFairnessStatus.PASSED,
        analysis=analysis,
    )


@pytest.mark.asyncio
async def test_requires_checkpoint_attested_untampered_audit() -> None:
    provider = _Provider({})
    analyzer = FairnessAnalyzer("group-a", "group-b", min_group_size=1)
    tampered = FairnessMonitor(
        _Audit(_snapshot(valid=False)),
        provider,
        analyzer,
        model_id=_MODEL_ID,
        model_version=_MODEL_VERSION,
    )
    unattested = FairnessMonitor(
        _Audit(_snapshot(attestable=False)),
        provider,
        analyzer,
        model_id=_MODEL_ID,
        model_version=_MODEL_VERSION,
    )

    with pytest.raises(AuditTamperDetectedError):
        await tampered.analyze(as_of=_NOW, window=timedelta(days=1))
    with pytest.raises(AuditAttestationError):
        await unattested.analyze(as_of=_NOW, window=timedelta(days=1))


@pytest.mark.asyncio
async def test_selects_only_final_deliveries_in_open_closed_window() -> None:
    included = _event("included")
    excluded = (
        _event("review", action="decision:review", outcome="review"),
        _event("denied", event_type="delivery_denied", result="denied"),
        _event("window-start", timestamp=_NOW - timedelta(days=1)),
        _event("future", timestamp=_NOW + timedelta(microseconds=1)),
    )
    provider = _Provider(
        {_ref("credit-decision", "decision:included").value: _attributes("group-a")}
    )
    monitor, audit = _monitor((included, *excluded), provider)

    report = await monitor.analyze(as_of=_NOW, window=timedelta(days=1))

    assert audit.require_checkpoint is True
    assert report.selected_event_count == 1
    assert report.analyzed_observation_count == 1
    assert provider.calls == [_ref("credit-decision", "decision:included").value]


@pytest.mark.asyncio
async def test_scopes_analysis_to_one_exact_model_version() -> None:
    target = _event("target")
    unrelated = _event(
        "unrelated",
        model_ref=opaque_credit_ref("credit-model", "credit-pd:2026.09"),
        controls=(),
    )
    target_decision = _ref("credit-decision", "decision:target")
    provider = _Provider({target_decision.value: _attributes("group-a")})
    monitor, _ = _monitor((target, unrelated), provider)

    report = await monitor.analyze(as_of=_NOW, window=timedelta(days=1))

    assert report.model_id == _MODEL_ID
    assert report.model_version == _MODEL_VERSION
    assert report.selected_event_count == 1
    assert report.analyzed_observation_count == 1
    assert provider.calls == [target_decision.value]


@pytest.mark.asyncio
async def test_naive_terminal_timestamp_is_an_integrity_failure() -> None:
    naive = _event("naive", timestamp=_NOW.replace(tzinfo=None))
    provider = _Provider({})
    monitor, _ = _monitor((naive,), provider)

    report = await monitor.analyze(as_of=_NOW, window=timedelta(days=1))

    assert report.selected_event_count == 1
    assert report.malformed_event_count == 1
    assert report.status is ModelFairnessStatus.INSUFFICIENT_DATA
    assert provider.calls == []


@pytest.mark.asyncio
async def test_override_uses_typed_final_payload_outcome() -> None:
    event = _event("override", action="decision:override", outcome="decline")
    decision = _ref("credit-decision", "decision:override")
    provider = _Provider({decision.value: _attributes("group-a", default=True)})
    monitor, _ = _monitor((event,), provider)

    report = await monitor.analyze(as_of=_NOW, window=timedelta(days=1))

    metric = next(item for item in report.analysis.group_metrics if item.group_name == "group-a")
    assert metric.declined == 1
    assert metric.approved == 0


@pytest.mark.asyncio
async def test_missing_malformed_and_failed_private_joins_prevent_pass() -> None:
    missing = _event("missing")
    failed = _event("failed")
    malformed = _event("malformed-private")
    failed_ref = _ref("credit-decision", "decision:failed")
    malformed_ref = _ref("credit-decision", "decision:malformed-private")
    provider = _Provider(
        {
            failed_ref.value: RuntimeError("private store unavailable"),
            malformed_ref.value: {
                "group_name": "group-a",
                "predicted_pd": 0.2,
                "observed_default": False,
                "observed_at": _NOW,
                "private_row_id": "must-not-escape",
            },
        }
    )
    monitor, _ = _monitor((missing, failed, malformed), provider)

    report = await monitor.analyze(as_of=_NOW, window=timedelta(days=1))

    assert report.missing_observation_count == 1
    assert report.malformed_observation_count == 1
    assert report.provider_error_count == 1
    assert report.status is ModelFairnessStatus.INSUFFICIENT_DATA


@pytest.mark.asyncio
async def test_unexpected_private_group_is_counted_instead_of_raising() -> None:
    event = _event("unexpected-group")
    decision = _ref("credit-decision", "decision:unexpected-group")
    provider = _Provider({decision.value: _attributes("group-c")})
    monitor, _ = _monitor((event,), provider)

    report = await monitor.analyze(as_of=_NOW, window=timedelta(days=1))

    assert report.malformed_observation_count == 1
    assert report.analyzed_observation_count == 0
    assert report.status is ModelFairnessStatus.INSUFFICIENT_DATA


@pytest.mark.asyncio
async def test_one_missing_join_overrides_an_otherwise_clean_pass() -> None:
    events: list[AuditEvent] = []
    values: dict[str, object] = {}
    for index, (group, outcome, default, pd) in enumerate(
        (
            ("group-a", "approve", False, 0.0),
            ("group-a", "decline", True, 1.0),
            ("group-b", "approve", False, 0.0),
            ("group-b", "decline", True, 1.0),
        )
    ):
        label = f"complete-{index}"
        events.append(_event(label, action=f"decision:{outcome}", outcome=outcome))
        values[_ref("credit-decision", f"decision:{label}").value] = _attributes(
            group, pd=pd, default=default
        )
    events.append(_event("missing-from-clean-sample"))
    monitor, _ = _monitor(tuple(events), _Provider(values))

    report = await monitor.analyze(as_of=_NOW, window=timedelta(days=1))

    assert report.analysis.overall_verdict.value == "PASS"
    assert report.missing_observation_count == 1
    assert report.status is ModelFairnessStatus.INSUFFICIENT_DATA


@pytest.mark.asyncio
async def test_duplicate_decision_references_are_excluded_and_counted_once() -> None:
    decision = _ref("credit-decision", "duplicate")
    first = _event("duplicate-1", decision_ref=decision)
    second = _event("duplicate-2", decision_ref=decision)
    provider = _Provider({decision.value: _attributes("group-a")})
    monitor, _ = _monitor((first, second), provider)

    report = await monitor.analyze(as_of=_NOW, window=timedelta(days=1))

    assert report.duplicate_decision_count == 1
    assert report.analyzed_observation_count == 0
    assert provider.calls == []
    assert report.status is ModelFairnessStatus.INSUFFICIENT_DATA


@pytest.mark.asyncio
async def test_malformed_links_evidence_and_control_are_integrity_failures() -> None:
    wrong_model = _event(
        "wrong-model",
        model_ref=EvidenceRef(namespace="wrong", value="b" * 64),
    )
    wrong_action = _event("wrong-action", action="decision:approve", outcome="decline")
    missing_control = _event("missing-control", controls=())
    duplicate_control = _event("duplicate-control", controls=(_control(), _control()))
    provider = _Provider({})
    monitor, _ = _monitor(
        (wrong_model, wrong_action, missing_control, duplicate_control),
        provider,
    )

    report = await monitor.analyze(as_of=_NOW, window=timedelta(days=1))

    assert report.selected_event_count == 4
    assert report.malformed_event_count == 4
    assert report.status is ModelFairnessStatus.INSUFFICIENT_DATA
    assert provider.calls == []


@pytest.mark.asyncio
async def test_serialized_report_contains_aggregates_but_no_private_or_row_references() -> None:
    events: list[AuditEvent] = []
    values: dict[str, object] = {}
    for index, (group, outcome, default, pd) in enumerate(
        (
            ("group-a", "approve", False, 0.0),
            ("group-a", "decline", True, 1.0),
            ("group-b", "approve", False, 0.0),
            ("group-b", "decline", True, 1.0),
        )
    ):
        label = f"private-{index}"
        event = _event(label, action=f"decision:{outcome}", outcome=outcome)
        decision = _ref("credit-decision", f"decision:{label}")
        events.append(event)
        values[decision.value] = _attributes(group, pd=pd, default=default)
    monitor, _ = _monitor(tuple(events), _Provider(values))

    report = await monitor.analyze(as_of=_NOW, window=timedelta(days=1))
    serialized = json.dumps(report.model_dump(mode="json"), sort_keys=True)

    assert report.status is ModelFairnessStatus.PASSED
    for event in events:
        assert event.event_id not in serialized
        assert event.subject_ref is not None
        assert event.subject_ref.value not in serialized
        decision = next(link.target for link in event.links if link.relation == "decision")
        assert decision.value not in serialized
    assert _MODEL.value not in serialized
    assert '"predicted_pd"' not in serialized
    assert '"observed_default"' not in serialized


def test_report_rejects_status_inconsistent_with_analysis_verdict() -> None:
    payload = _passing_monitor_report().model_dump(mode="python")
    payload["status"] = ModelFairnessStatus.FAILED

    with pytest.raises(ValidationError, match="status"):
        FairnessMonitoringReport.model_validate(payload)


def test_report_rejects_authorizing_status_with_integrity_errors() -> None:
    payload = _passing_monitor_report().model_dump(mode="python")
    payload["missing_observation_count"] = 1

    with pytest.raises(ValidationError, match="integrity"):
        FairnessMonitoringReport.model_validate(payload)


def test_validation_evidence_cannot_promote_inconsistent_monitor_status() -> None:
    report = _passing_monitor_report().model_copy(update={"status": ModelFairnessStatus.FAILED})

    with pytest.raises(ValueError, match="status"):
        FairnessValidationEvidence.from_monitor(report)


def test_validation_evidence_cannot_promote_monitor_with_integrity_errors() -> None:
    report = _passing_monitor_report().model_copy(update={"missing_observation_count": 1})

    with pytest.raises(ValueError, match="integrity"):
        FairnessValidationEvidence.from_monitor(report)
