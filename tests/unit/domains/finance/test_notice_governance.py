"""Governed notice evidence remains linked, complete, and PII-free."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from agentguard.domains.finance.credit_risk.adverse_action import (
    DecisionComponentOrigin,
    PrincipalReasonSelection,
)
from agentguard.domains.finance.credit_risk.agent_templates import (
    CreditDecisionCandidate,
    CreditDecisionOutcome,
    CreditDecisionPolicy,
)
from agentguard.domains.finance.credit_risk.attribution import (
    AdverseContribution,
    AttributionMethod,
    AttributionResult,
)
from agentguard.domains.finance.credit_risk.notice_governance import (
    InMemoryPreparedNoticeProvider,
    NoticeCompletenessGuardrail,
    NoticeIssueEvidence,
    PreparedNoticeRecord,
    notice_audit_references,
    opaque_credit_ref,
    prepare_notice_record,
)
from agentguard.domains.finance.credit_risk.reason_codes import (
    MappedReason,
    ReasonCode,
    ReasonCodeSelection,
)
from agentguard.exceptions import AdverseActionError, AdverseActionFailure
from agentguard.guardrails import (
    GuardrailContext,
    GuardrailEffect,
    GuardrailStage,
    IdentitySnapshot,
)
from tests.unit.domains.finance.test_decision_reasons import policy_denial, review_judgment
from tests.unit.domains.finance.test_notice_renderer import _denial


def _reason_evidence() -> tuple[AttributionResult, ReasonCodeSelection]:
    code = ReasonCode(
        code="AG-RB-C1-09",
        code_set_version="2026.07",
        consumer_text="Excessive obligations in relation to income",
        reg_b_ref="12 CFR pt. 1002, app. C, Form C-1",
    )
    attribution = AttributionResult(
        model_id="credit-logit",
        model_version="2026.08",
        reference_id="portfolio-2026q2",
        method=AttributionMethod.COEFFICIENT_DELTA,
        feature_names=("dti_ratio",),
        contributions=(AdverseContribution(feature_name="dti_ratio", value=0.42),),
    )
    selection = ReasonCodeSelection(
        taxonomy_version="2026.07",
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        reference_id=attribution.reference_id,
        attribution_method=attribution.method,
        feature_names=attribution.feature_names,
        reasons=(
            MappedReason(
                code=code,
                source_features=("dti_ratio",),
                adverse_contribution=0.42,
                rank=1,
            ),
        ),
    )
    return attribution, selection


def _record() -> PreparedNoticeRecord:
    attribution, selection = _reason_evidence()
    candidate = CreditDecisionPolicy().evaluate(
        decision_id="DECISION-001",
        application_ref="APP-001",
        pd_score=0.30,
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
        reason_selection=selection,
    )
    return prepare_notice_record(
        candidate,
        _denial(),
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
    )


def _context(record: PreparedNoticeRecord | None = None) -> GuardrailContext:
    prepared = record or _record()
    return GuardrailContext.model_validate(
        {
            "trace_id": "trace-1",
            "invocation_id": "invocation-1",
            "stage": GuardrailStage.ON_DECISION,
            "identity": IdentitySnapshot(agent_id="agent-1", name="Credit Agent"),
            "action": "notice:issue",
            "resource": f"notice/{prepared.evidence.notice_ref}",
            "payload": prepared.evidence.to_payload(),
            "attributes": {"redacted_evidence": prepared.evidence},
        }
    )


def test_prepared_evidence_and_links_contain_no_notice_body_or_applicant_pii() -> None:
    record = _record()
    subject_ref, links = notice_audit_references(record.evidence)
    serialized = json.dumps(
        {
            "evidence": record.evidence.model_dump(mode="json"),
            "subject_ref": subject_ref.model_dump(mode="json"),
            "links": [link.model_dump(mode="json") for link in links],
        },
        sort_keys=True,
    )

    assert "Alex Example" not in serialized
    assert "100 Main Street" not in serialized
    assert "APP-001" not in serialized
    assert "DECISION-001" not in serialized
    assert record.rendered.body not in serialized
    assert record.rendered.body_sha256 in serialized
    assert {link.relation for link in links} == {"decision", "notice", "model"}


def test_notice_evidence_json_timestamps_round_trip_without_dob_masking() -> None:
    evidence = _record().evidence.model_copy(
        update={
            "notification_at": datetime(2026, 8, 27, 12, 0, 0, 123456, tzinfo=UTC),
            "deadline_at": datetime(2026, 9, 1, 12, 0, 0, 654321, tzinfo=UTC),
        }
    )

    serialized = evidence.model_dump(mode="json")

    assert isinstance(serialized["notification_at"], float)
    assert isinstance(serialized["deadline_at"], float)
    assert NoticeIssueEvidence.model_validate(serialized) == evidence


@pytest.mark.asyncio
async def test_notice_control_skips_decision_boundary() -> None:
    provider = InMemoryPreparedNoticeProvider()
    outcome = await NoticeCompletenessGuardrail(
        provider,
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
    ).evaluate(_context().model_copy(update={"action": "decision:decline"}))

    assert outcome.effect is GuardrailEffect.ALLOW


@pytest.mark.asyncio
async def test_notice_control_rejects_unsafe_audit_projection() -> None:
    record = _record()
    provider = InMemoryPreparedNoticeProvider()
    await provider.put(record)
    context = _context(record).model_copy(
        update={"attributes": {"redacted_evidence": {"notice_body": record.rendered.body}}}
    )

    outcome = await NoticeCompletenessGuardrail(
        provider,
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
    ).evaluate(context)

    assert outcome.reason_codes == ("PII.UNSAFE_DECISION_EVIDENCE",)


@pytest.mark.asyncio
async def test_trusted_prepared_notice_allows() -> None:
    record = _record()
    provider = InMemoryPreparedNoticeProvider()
    await provider.put(record)

    outcome = await NoticeCompletenessGuardrail(
        provider,
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
    ).evaluate(_context(record))

    assert outcome.effect is GuardrailEffect.ALLOW


@pytest.mark.asyncio
async def test_missing_or_tampered_notice_evidence_denies() -> None:
    record = _record()
    provider = InMemoryPreparedNoticeProvider()
    guardrail = NoticeCompletenessGuardrail(
        provider,
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
    )
    missing = await guardrail.evaluate(_context(record))
    await provider.put(record)
    payload = record.evidence.to_payload()
    tampered_body = dict(payload.body)
    tampered_body["body_sha256"] = "0" * 64
    tampered = payload.model_copy(update={"body": tampered_body})
    tampered_context = _context(record).model_copy(update={"payload": tampered})
    changed = await guardrail.evaluate(tampered_context)

    assert missing.reason_codes == (AdverseActionFailure.NOTICE_INCOMPLETE.value,)
    assert changed.reason_codes == (AdverseActionFailure.NOTICE_INCOMPLETE.value,)


def test_application_or_reason_mismatch_cannot_prepare_notice() -> None:
    record = _record()
    changed = record.candidate.model_copy(update={"application_ref": "APP-OTHER"})
    with pytest.raises(AdverseActionError) as exc_info:
        prepare_notice_record(changed, record.notice)
    assert exc_info.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE


def test_future_notification_cannot_be_recorded_as_completed() -> None:
    record = _record()

    with pytest.raises(AdverseActionError) as exc_info:
        prepare_notice_record(
            record.candidate,
            record.notice,
            clock=lambda: datetime(2026, 8, 27, 14, 59, tzinfo=UTC),
        )

    assert exc_info.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE


def test_late_safe_evidence_uses_stable_window_failure() -> None:
    evidence = _record().evidence
    with pytest.raises(AdverseActionError) as exc_info:
        NoticeIssueEvidence.model_validate(
            evidence.model_copy(
                update={"deadline_at": evidence.notification_at},
            ).model_dump()
            | {"notification_at": evidence.notification_at.replace(microsecond=1)}
        )
    assert exc_info.value.failure is AdverseActionFailure.NOTICE_WINDOW_EXCEEDED


def test_opaque_reference_is_domain_separated_and_namespace_allowlisted() -> None:
    decision = opaque_credit_ref("credit-decision", "SAME")
    notice = opaque_credit_ref("credit-notice", "SAME")
    assert decision.value != notice.value
    with pytest.raises(ValueError, match="namespace"):
        opaque_credit_ref("applicant", "SAME")


def _judgment_candidate() -> CreditDecisionCandidate:
    """A reviewed decline whose only principal reasons are the underwriter's."""

    attribution, _ = _reason_evidence()
    return CreditDecisionCandidate(
        decision_id="DECISION-001",
        application_ref="APP-001",
        outcome=CreditDecisionOutcome.DECLINE,
        pd_score=0.10,
        policy_id="pd-bands",
        policy_version="1",
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
        review_judgment=review_judgment(),
    )


def _policy_candidate() -> CreditDecisionCandidate:
    """An application the PD band would approve, declined by a hard overlay rule."""

    attribution, _ = _reason_evidence()
    return CreditDecisionPolicy().evaluate(
        decision_id="DECISION-001",
        application_ref="APP-001",
        pd_score=0.01,
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
        policy_denial=policy_denial(),
    )


def test_a_reviewed_decline_can_state_the_underwriters_own_reasons() -> None:
    candidate = _judgment_candidate()
    reasons = PrincipalReasonSelection.from_decision_basis(
        review_judgment=candidate.review_judgment,
    )

    record = prepare_notice_record(
        candidate,
        _denial(reasons=reasons),
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
    )

    origin = record.notice.principal_reasons.reasons[0].origin
    assert isinstance(origin, DecisionComponentOrigin)
    assert origin.component_kind == "human_review"
    assert origin.binding.escalation_id == "ESCALATION-001"
    assert record.evidence.artifact_type == "DeniedApplicationNotice"


def test_a_policy_overlay_decline_states_the_rule_that_denied_it() -> None:
    candidate = _policy_candidate()
    reasons = PrincipalReasonSelection.from_decision_basis(
        policy_denial=candidate.policy_denial,
    )

    record = prepare_notice_record(
        candidate,
        _denial(reasons=reasons),
        clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
    )

    origin = record.notice.principal_reasons.reasons[0].origin
    assert isinstance(origin, DecisionComponentOrigin)
    assert origin.component_kind == "policy_rule"
    assert origin.component_id == "POLICY-COLLATERAL-LTV"


def test_a_judgmental_decline_cannot_be_signed_with_the_models_reasons() -> None:
    with pytest.raises(AdverseActionError) as exc_info:
        prepare_notice_record(
            _judgment_candidate(),
            _denial(),
            clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
        )

    assert exc_info.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE


def test_a_model_decline_cannot_be_signed_with_borrowed_review_reasons() -> None:
    reasons = PrincipalReasonSelection.from_decision_basis(review_judgment=review_judgment())

    with pytest.raises(AdverseActionError) as exc_info:
        prepare_notice_record(
            _record().candidate,
            _denial(reasons=reasons),
            clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
        )

    assert exc_info.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE


def test_a_decline_with_no_basis_cannot_produce_a_notice() -> None:
    attribution, _ = _reason_evidence()
    candidate = CreditDecisionPolicy().evaluate(
        decision_id="DECISION-001",
        application_ref="APP-001",
        pd_score=0.30,
        model_id=attribution.model_id,
        model_version=attribution.model_version,
        attribution=attribution,
    )

    with pytest.raises(AdverseActionError) as exc_info:
        prepare_notice_record(
            candidate,
            _denial(),
            clock=lambda: datetime(2026, 8, 30, tzinfo=UTC),
        )

    assert exc_info.value.failure is AdverseActionFailure.NO_REASON_CODES
