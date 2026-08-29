"""Unresolved declines are classified only from attestable linked audit evidence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agentguard.core.audit import ChainVerificationResult, VerifiedAuditSnapshot
from agentguard.domains.finance.credit_risk.audit_correlation import (
    UNRESOLVED_DECLINE_CODE,
    find_unresolved_declines,
)
from agentguard.domains.finance.credit_risk.notice_governance import NoticeIssueEvidence
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
_APPLICATION = EvidenceRef(namespace="credit-application", value="a" * 64)
_OTHER_APPLICATION = EvidenceRef(namespace="credit-application", value="f" * 64)
_DECISION = EvidenceRef(namespace="credit-decision", value="d" * 64)
_OTHER_DECISION = EvidenceRef(namespace="credit-decision", value="e" * 64)


class _Audit:
    def __init__(self, snapshot: VerifiedAuditSnapshot) -> None:
        self.snapshot = snapshot
        self.require_checkpoint: bool | None = None

    async def read_verified(self, *, require_checkpoint: bool = False) -> VerifiedAuditSnapshot:
        self.require_checkpoint = require_checkpoint
        return self.snapshot


class _BrokenAudit:
    async def read_verified(self, *, require_checkpoint: bool = False) -> VerifiedAuditSnapshot:
        del require_checkpoint
        raise AuditTamperDetectedError(2, "event-broken")


def _event(
    event_id: str,
    *,
    action: str,
    event_type: str = "delivery_completed",
    result: str = "allowed",
    decision_ref: EvidenceRef | None = _DECISION,
    subject_ref: EvidenceRef | None = _APPLICATION,
    payload_redacted: dict[str, object] | None = None,
    guardrail_evaluations: tuple[GuardrailEvaluation, ...] | None = None,
    chain_mode: str = "enforce",
) -> AuditEvent:
    identity = AgentIdentity(agent_id="agent-1", name="Credit Agent", roles=["credit"])
    if guardrail_evaluations is None:
        guardrail_id = {
            "notice:issue": "credit-notice-completeness",
            "decision:override": "credit-decision-evidence",
        }.get(action)
        guardrail_evaluations = (
            (
                GuardrailEvaluation(
                    guardrail_id=guardrail_id,
                    guardrail_version="1",
                    stage="on_decision",
                    effect="allow",
                    reason_codes=(),
                    duration_ms=1.0,
                    enforced=True,
                ),
            )
            if guardrail_id is not None
            else ()
        )
    return AuditEvent.model_validate(
        {
            "event_id": event_id,
            "timestamp": _NOW,
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
            "payload_redacted": payload_redacted or {},
            "guardrail_evaluations": guardrail_evaluations,
            "chain_mode": chain_mode,
            "subject_ref": subject_ref,
            "links": (
                ()
                if decision_ref is None
                else (AuditLink(relation="decision", target=decision_ref),)
            ),
        }
    )


def _notice_payload(
    decision_ref: EvidenceRef = _DECISION,
    *,
    application_ref: EvidenceRef = _APPLICATION,
    late: bool = False,
) -> dict[str, object]:
    deadline = _NOW + timedelta(days=30)
    notification = deadline + timedelta(seconds=1) if late else _NOW + timedelta(days=1)
    evidence = {
        "application_ref": application_ref.value,
        "decision_ref": decision_ref.value,
        "notice_ref": "c" * 64,
        "model_ref": "f" * 64,
        "artifact_type": "DeniedApplicationNotice",
        "profile": "reg_b_c1_denial",
        "template_version": "2026.08",
        "body_sha256": "b" * 64,
        "notification_at": notification.isoformat(),
        "deadline_at": deadline.isoformat(),
    }
    if not late:
        NoticeIssueEvidence.model_validate(evidence)
    return {"value": evidence}


def _decision_payload(
    outcome: str,
    *,
    decision_ref: EvidenceRef = _DECISION,
    application_ref: EvidenceRef = _APPLICATION,
) -> dict[str, object]:
    return {
        "value": {
            "application_ref": application_ref.value,
            "decision_ref": decision_ref.value,
            "model_ref": "b" * 64,
            "policy_ref": "c" * 64,
            "outcome": outcome,
        }
    }


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
            error_event_id=None if valid else "event-broken",
            checkpoint_valid=attestable,
            checkpoint_status="verified" if attestable else "verified_unanchored",
            attestable=attestable,
        ),
    )


@pytest.mark.asyncio
async def test_exact_later_notice_clears_delivered_decline() -> None:
    audit = _Audit(
        _snapshot(
            _event("decline-1", action="decision:decline"),
            _event(
                "notice-1",
                action="notice:issue",
                payload_redacted=_notice_payload(),
            ),
        )
    )

    assert await find_unresolved_declines(audit) == ()
    assert audit.require_checkpoint is True


@pytest.mark.asyncio
async def test_missing_notice_returns_immutable_typed_finding() -> None:
    finding = (
        await find_unresolved_declines(
            _Audit(_snapshot(_event("decline-1", action="decision:decline")))
        )
    )[0]

    assert finding.code == UNRESOLVED_DECLINE_CODE
    assert finding.decision_ref == _DECISION
    assert finding.application_ref == _APPLICATION
    assert finding.decline_event_id == "decline-1"
    with pytest.raises(ValidationError, match="frozen"):
        finding.decline_event_id = "changed"


@pytest.mark.asyncio
async def test_mismatched_denied_late_and_malformed_notices_do_not_resolve() -> None:
    events = (
        _event("decline-1", action="decision:decline"),
        _event(
            "notice-mismatch",
            action="notice:issue",
            decision_ref=_OTHER_DECISION,
            payload_redacted=_notice_payload(_OTHER_DECISION),
        ),
        _event(
            "notice-denied",
            action="notice:issue",
            event_type="delivery_denied",
            result="denied",
            payload_redacted=_notice_payload(),
        ),
        _event(
            "notice-late",
            action="notice:issue",
            payload_redacted=_notice_payload(late=True),
        ),
        _event(
            "notice-malformed",
            action="notice:issue",
            payload_redacted={"value": {"applicant_name": "Private Person"}},
        ),
    )

    findings = await find_unresolved_declines(_Audit(_snapshot(*events)))

    assert tuple(finding.decline_event_id for finding in findings) == ("decline-1",)


@pytest.mark.asyncio
async def test_notice_application_link_must_be_present_and_match_evidence_and_decline() -> None:
    events = (
        _event("decline-1", action="decision:decline"),
        _event(
            "notice-evidence-mismatch",
            action="notice:issue",
            subject_ref=_OTHER_APPLICATION,
            payload_redacted=_notice_payload(),
        ),
        _event(
            "notice-subject-missing",
            action="notice:issue",
            subject_ref=None,
            payload_redacted=_notice_payload(),
        ),
        _event(
            "notice-decline-mismatch",
            action="notice:issue",
            subject_ref=_OTHER_APPLICATION,
            payload_redacted=_notice_payload(application_ref=_OTHER_APPLICATION),
        ),
    )

    findings = await find_unresolved_declines(_Audit(_snapshot(*events)))

    assert tuple(finding.decline_event_id for finding in findings) == ("decline-1",)


@pytest.mark.asyncio
async def test_override_decline_is_resolved_only_by_exact_later_notice() -> None:
    resolved = await find_unresolved_declines(
        _Audit(
            _snapshot(
                _event(
                    "override-decline",
                    action="decision:override",
                    payload_redacted=_decision_payload("decline"),
                ),
                _event("notice", action="notice:issue", payload_redacted=_notice_payload()),
            )
        )
    )
    unresolved = await find_unresolved_declines(
        _Audit(
            _snapshot(
                _event(
                    "override-decline-unresolved",
                    action="decision:override",
                    payload_redacted=_decision_payload("decline"),
                )
            )
        )
    )

    assert resolved == ()
    assert tuple(finding.decline_event_id for finding in unresolved) == (
        "override-decline-unresolved",
    )


@pytest.mark.asyncio
async def test_malformed_override_evidence_is_not_falsely_clean() -> None:
    events = (
        _event(
            "override-malformed",
            action="decision:override",
            payload_redacted={"value": {"outcome": "decline"}},
        ),
        _event("notice", action="notice:issue", payload_redacted=_notice_payload()),
    )

    findings = await find_unresolved_declines(_Audit(_snapshot(*events)))

    assert tuple(finding.decline_event_id for finding in findings) == ("override-malformed",)
    assert findings[0].integrity_errors == ("decision_evidence",)


@pytest.mark.asyncio
async def test_override_outcome_requires_exact_enforced_decision_evidence_control() -> None:
    exact = GuardrailEvaluation(
        guardrail_id="credit-decision-evidence",
        guardrail_version="1",
        stage="on_decision",
        effect="allow",
        reason_codes=(),
        duration_ms=1.0,
        enforced=True,
    )
    invalid_controls = (
        (),
        (exact, exact),
        (exact.model_copy(update={"guardrail_id": "other-control"}),),
        (exact.model_copy(update={"guardrail_version": "2"}),),
        (exact.model_copy(update={"stage": "post_tool"}),),
        (exact.model_copy(update={"effect": "warn"}),),
        (exact.model_copy(update={"enforced": False}),),
    )

    for offset, evaluations in enumerate(invalid_controls):
        findings = await find_unresolved_declines(
            _Audit(
                _snapshot(
                    _event(
                        f"override-{offset}",
                        action="decision:override",
                        payload_redacted=_decision_payload("approve"),
                        guardrail_evaluations=evaluations,
                        chain_mode="shadow" if offset == 6 else "enforce",
                    )
                )
            )
        )
        assert tuple(finding.decline_event_id for finding in findings) == (f"override-{offset}",)
        assert findings[0].integrity_errors == ("decision_evidence",)


@pytest.mark.asyncio
async def test_notice_requires_exact_enforced_completeness_evaluation() -> None:
    exact = GuardrailEvaluation(
        guardrail_id="credit-notice-completeness",
        guardrail_version="1",
        stage="on_decision",
        effect="allow",
        reason_codes=(),
        duration_ms=1.0,
        enforced=True,
    )
    invalid_controls = (
        (),
        (exact, exact),
        (exact.model_copy(update={"guardrail_version": "2"}),),
        (exact.model_copy(update={"stage": "post_tool"}),),
        (exact.model_copy(update={"effect": "warn"}),),
        (exact.model_copy(update={"enforced": False}),),
    )

    for offset, evaluations in enumerate(invalid_controls):
        findings = await find_unresolved_declines(
            _Audit(
                _snapshot(
                    _event(f"decline-{offset}", action="decision:decline"),
                    _event(
                        f"notice-{offset}",
                        action="notice:issue",
                        payload_redacted=_notice_payload(),
                        guardrail_evaluations=evaluations,
                        chain_mode="shadow" if offset == 5 else "enforce",
                    ),
                )
            )
        )
        assert tuple(finding.decline_event_id for finding in findings) == (f"decline-{offset}",)


@pytest.mark.asyncio
async def test_missing_or_malformed_decline_links_are_unresolved_integrity_findings() -> None:
    events = (
        _event("missing-link", action="decision:decline", decision_ref=None),
        _event(
            "wrong-namespace",
            action="decision:decline",
            decision_ref=EvidenceRef(namespace="notice", value="d" * 64),
        ),
        _event(
            "raw-reference",
            action="decision:decline",
            decision_ref=EvidenceRef(namespace="credit-decision", value="DECISION-RAW"),
        ),
        _event("missing-application", action="decision:decline", subject_ref=None),
        _event(
            "malformed-application",
            action="decision:decline",
            subject_ref=EvidenceRef(namespace="credit-application", value="APPLICATION-RAW"),
        ),
        _event(
            "notice-for-missing-application",
            action="notice:issue",
            payload_redacted=_notice_payload(),
        ),
    )

    findings = await find_unresolved_declines(_Audit(_snapshot(*events)))

    assert tuple(finding.decline_event_id for finding in findings) == (
        "missing-link",
        "wrong-namespace",
        "raw-reference",
        "missing-application",
        "malformed-application",
    )
    assert tuple(finding.integrity_errors for finding in findings) == (
        ("decision_link",),
        ("decision_link",),
        ("decision_link",),
        ("application_link",),
        ("application_link",),
    )
    assert tuple(finding.decision_ref for finding in findings[:3]) == (None, None, None)
    assert findings[3].decision_ref == _DECISION
    assert findings[3].application_ref is None


@pytest.mark.asyncio
async def test_broken_or_unattestable_evidence_refuses_classification() -> None:
    with pytest.raises(AuditTamperDetectedError):
        await find_unresolved_declines(_BrokenAudit())
    with pytest.raises(AuditTamperDetectedError):
        await find_unresolved_declines(
            _Audit(_snapshot(_event("decline", action="decision:decline"), valid=False))
        )
    with pytest.raises(AuditAttestationError):
        await find_unresolved_declines(
            _Audit(
                _snapshot(
                    _event("decline", action="decision:decline"),
                    attestable=False,
                )
            )
        )
