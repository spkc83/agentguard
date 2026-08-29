"""Contract tests for complete, typed credit-notice artifacts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from agentguard.domains.finance import credit_risk
from agentguard.domains.finance.credit_risk.adverse_action import (
    AffiliateDisclosure,
    ApplicantDetails,
    CombinedCounterofferAdverseActionNotice,
    ConsumerReportSource,
    CounterofferAcceptanceInstructions,
    CounterofferFollowupTiming,
    CounterofferNotificationEvent,
    CraContact,
    CreditorDetails,
    CreditRequestDetails,
    CreditScoreDisclosure,
    CreditTerms,
    DecisionComponentOrigin,
    DecisionType,
    DeniedApplicationNotice,
    EnforcementAgency,
    EqualCreditOpportunityDisclosure,
    MailingAddress,
    ModelReasonOrigin,
    NoFCRA,
    NonCraThirdPartyDisclosure,
    PrincipalReason,
    PrincipalReasonSelection,
    StandaloneCounterofferNotice,
    StandaloneCounterofferTiming,
    ThirtyDayNoticeTiming,
    WithdrawalRecord,
    WrittenInformationRequest,
    WrittenNotificationEvent,
)
from agentguard.domains.finance.credit_risk.attribution import AttributionMethod
from agentguard.domains.finance.credit_risk.reason_codes import (
    BureauFactorCode,
    BureauFactorSelection,
    MappedBureauFactor,
    MappedReason,
    ReasonCode,
    ReasonCodeSelection,
)
from agentguard.exceptions import AdverseActionError, AdverseActionFailure

NOW = datetime(2026, 8, 27, 15, 0, tzinfo=UTC)


def _address() -> MailingAddress:
    return MailingAddress(
        line1="100 Main Street",
        city="Bismarck",
        region="ND",
        postal_code="58501",
    )


def _creditor() -> CreditorDetails:
    return CreditorDetails(
        name="Example Community Bank",
        address=_address(),
        telephone="800-555-0100",
    )


def _applicant() -> ApplicantDetails:
    return ApplicantDetails(
        applicant_id="APP-001",
        full_name="Alex Example",
        address=_address(),
    )


def _terms(amount: str = "25000") -> CreditTerms:
    return CreditTerms(
        product_name="Installment loan",
        principal_amount=Decimal(amount),
        annual_percentage_rate=Decimal("8.50"),
        term_months=48,
    )


def _request() -> CreditRequestDetails:
    return CreditRequestDetails(
        application_id="APP-001",
        received_at=NOW,
        requested_terms=_terms(),
    )


def _ecoa() -> EqualCreditOpportunityDisclosure:
    return EqualCreditOpportunityDisclosure(
        enforcement_agency=EnforcementAgency(
            name="Federal Trade Commission",
            address=MailingAddress(
                line1="600 Pennsylvania Avenue NW",
                city="Washington",
                region="DC",
                postal_code="20580",
            ),
        )
    )


def _selection() -> ReasonCodeSelection:
    code = ReasonCode(
        code="AG-RB-C1-09",
        code_set_version="2026.07",
        consumer_text="Excessive obligations in relation to income",
        reg_b_ref="12 CFR pt. 1002, app. C, Form C-1",
    )
    return ReasonCodeSelection(
        taxonomy_version="2026.07",
        model_id="credit-logit",
        model_version="2026.08",
        reference_id="portfolio-2026q2",
        attribution_method=AttributionMethod.COEFFICIENT_DELTA,
        feature_names=("dti_ratio",),
        reasons=(
            MappedReason(
                code=code,
                source_features=("dti_ratio",),
                adverse_contribution=0.42,
                rank=1,
            ),
        ),
    )


def _reasons() -> PrincipalReasonSelection:
    return PrincipalReasonSelection.from_attribution(_selection())


def _bureau_factors() -> BureauFactorSelection:
    code = BureauFactorCode(
        code="BANK-FCRA-001",
        code_set_version="2026.08",
        consumer_text="Balances on accounts are too high",
        fcra_ref="15 U.S.C. 1681g(f)(2)(B)",
    )
    return BureauFactorSelection(
        code_set_version="2026.08",
        model_id="bureau-score",
        model_version="3",
        reference_id="score-reference",
        attribution_method=AttributionMethod.SCORECARD_POINTS_LOST,
        feature_names=("revolving_balance",),
        factors=(
            MappedBureauFactor(
                code=code,
                source_features=("revolving_balance",),
                adverse_contribution=10.0,
                rank=1,
            ),
        ),
    )


def _written(at: datetime = NOW + timedelta(days=30)) -> WrittenNotificationEvent:
    return WrittenNotificationEvent(method="mailed", occurred_at=at)


def _denial() -> DeniedApplicationNotice:
    return DeniedApplicationNotice(
        notice_id="NOTICE-001",
        applicant=_applicant(),
        creditor=_creditor(),
        credit_request=_request(),
        timing=ThirtyDayNoticeTiming(
            basis="completed_application",
            trigger_at=NOW,
            notification=_written(),
        ),
        principal_reasons=_reasons(),
        ecoa_disclosure=_ecoa(),
        information_source=NoFCRA(),
    )


def test_attribution_selection_converts_losslessly_to_model_reason_provenance() -> None:
    selection = PrincipalReasonSelection.from_attribution(_selection())

    reason = selection.reasons[0]
    assert reason.code.code == "AG-RB-C1-09"
    assert reason.rank == 1
    assert isinstance(reason.origin, ModelReasonOrigin)
    assert reason.origin.model_id == "credit-logit"
    assert reason.origin.evaluated_feature_names == ("dti_ratio",)
    assert reason.origin.source_features == ("dti_ratio",)
    assert reason.origin.adverse_contribution == pytest.approx(0.42)


def test_non_model_reason_has_explicit_policy_or_human_origin() -> None:
    code = _selection().reasons[0].code
    selection = PrincipalReasonSelection(
        taxonomy_version="2026.07",
        reasons=(
            PrincipalReason(
                code=code,
                rank=1,
                origin=DecisionComponentOrigin(
                    component_kind="policy_rule",
                    component_id="CREDIT.MAX-DTI",
                    component_version="2026.08",
                ),
            ),
        ),
    )

    assert isinstance(selection.reasons[0].origin, DecisionComponentOrigin)
    assert selection.reasons[0].origin.component_id == "CREDIT.MAX-DTI"


def test_principal_reasons_reject_rank_or_taxonomy_drift() -> None:
    reason = _reasons().reasons[0]

    with pytest.raises(ValidationError, match="contiguous"):
        PrincipalReasonSelection(
            taxonomy_version="2026.07",
            reasons=(reason.model_copy(update={"rank": 2}),),
        )
    with pytest.raises(ValidationError, match="taxonomy"):
        PrincipalReasonSelection(
            taxonomy_version="different",
            reasons=(reason,),
        )


def test_written_notice_accepts_exact_thirty_day_boundary() -> None:
    timing = ThirtyDayNoticeTiming(
        basis="completed_application",
        trigger_at=NOW,
        notification=_written(NOW + timedelta(days=30)),
    )

    assert timing.deadline_at == NOW + timedelta(days=30)


def test_written_notice_rejects_oral_and_late_delivery() -> None:
    with pytest.raises(ValidationError):
        WrittenNotificationEvent(method="oral", occurred_at=NOW)  # type: ignore[arg-type]

    with pytest.raises(AdverseActionError) as exc_info:
        ThirtyDayNoticeTiming(
            basis="completed_application",
            trigger_at=NOW,
            notification=_written(NOW + timedelta(days=30, microseconds=1)),
        )

    assert exc_info.value.failure is AdverseActionFailure.NOTICE_WINDOW_EXCEEDED


def test_notice_trigger_cannot_precede_application_or_use_wrong_basis() -> None:
    with pytest.raises(AdverseActionError) as early:
        DeniedApplicationNotice(
            notice_id="NOTICE-001",
            applicant=_applicant(),
            creditor=_creditor(),
            credit_request=_request(),
            timing=ThirtyDayNoticeTiming(
                basis="completed_application",
                trigger_at=NOW - timedelta(microseconds=1),
                notification=_written(NOW),
            ),
            principal_reasons=_reasons(),
            ecoa_disclosure=_ecoa(),
            information_source=NoFCRA(),
        )
    assert early.value.failure is AdverseActionFailure.NOTICE_WINDOW_EXCEEDED

    with pytest.raises(AdverseActionError) as wrong_basis:
        DeniedApplicationNotice(
            notice_id="NOTICE-001",
            applicant=_applicant(),
            creditor=_creditor(),
            credit_request=_request(),
            timing=ThirtyDayNoticeTiming(
                basis="incomplete_application",
                trigger_at=NOW,
                notification=_written(NOW),
            ),
            principal_reasons=_reasons(),
            ecoa_disclosure=_ecoa(),
            information_source=NoFCRA(),
        )
    assert wrong_basis.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE


def test_denial_supports_action_taken_timing_for_existing_or_incomplete_credit() -> None:
    notice = DeniedApplicationNotice(
        notice_id="NOTICE-EXISTING-001",
        applicant=_applicant(),
        creditor=_creditor(),
        credit_request=_request(),
        timing=ThirtyDayNoticeTiming(
            basis="action_taken",
            trigger_at=NOW + timedelta(days=1),
            notification=_written(NOW + timedelta(days=31)),
        ),
        principal_reasons=_reasons(),
        ecoa_disclosure=_ecoa(),
        information_source=NoFCRA(),
    )

    assert notice.timing.basis == "action_taken"


def test_standalone_counteroffer_may_be_oral_but_acceptance_stays_inside_outer_window() -> None:
    notification = CounterofferNotificationEvent(
        method="oral",
        occurred_at=NOW + timedelta(days=2),
    )
    timing = StandaloneCounterofferTiming(
        trigger_at=NOW,
        notification=notification,
        accept_by=NOW + timedelta(days=60),
    )
    notice = StandaloneCounterofferNotice(
        notice_id="COUNTER-001",
        applicant=_applicant(),
        creditor=_creditor(),
        credit_request=_request(),
        timing=timing,
        offered_terms=_terms("20000"),
        principal_reasons=_reasons(),
        information_source=NoFCRA(),
    )

    assert notice.decision_type is DecisionType.COUNTEROFFER
    assert timing.outer_deadline_at == NOW + timedelta(days=90)

    with pytest.raises(AdverseActionError) as exc_info:
        StandaloneCounterofferTiming(
            trigger_at=NOW,
            notification=notification,
            accept_by=NOW + timedelta(days=91),
        )
    assert exc_info.value.failure is AdverseActionFailure.NOTICE_WINDOW_EXCEEDED


def test_standalone_counteroffer_rejects_adverse_action_source_blocks() -> None:
    source = ConsumerReportSource(
        agencies=(
            CraContact(
                name="Example CRA",
                address=_address(),
                toll_free_telephone="800-555-0199",
            ),
        ),
        score_used=False,
    )

    with pytest.raises(ValidationError):
        StandaloneCounterofferNotice(
            notice_id="COUNTER-001",
            applicant=_applicant(),
            creditor=_creditor(),
            credit_request=_request(),
            timing=StandaloneCounterofferTiming(
                trigger_at=NOW,
                notification=CounterofferNotificationEvent(method="oral", occurred_at=NOW),
                accept_by=NOW + timedelta(days=15),
            ),
            offered_terms=_terms("20000"),
            principal_reasons=_reasons(),
            information_source=source,  # type: ignore[arg-type]
        )


def test_combined_counteroffer_is_written_and_has_no_followup_state() -> None:
    notice = CombinedCounterofferAdverseActionNotice(
        notice_id="COMBINED-001",
        applicant=_applicant(),
        creditor=_creditor(),
        credit_request=_request(),
        timing=ThirtyDayNoticeTiming(
            basis="completed_application",
            trigger_at=NOW,
            notification=_written(NOW + timedelta(days=2)),
        ),
        offered_terms=_terms("20000"),
        acceptance=CounterofferAcceptanceInstructions(
            recipient="Credit Services",
            address=_address(),
            accept_by=NOW + timedelta(days=15),
        ),
        principal_reasons=_reasons(),
        ecoa_disclosure=_ecoa(),
        information_source=NoFCRA(),
    )

    assert notice.decision_type is DecisionType.COUNTEROFFER
    assert notice.acceptance.method == "written_notice"
    assert not hasattr(notice, "accept_by")
    assert not hasattr(notice, "followup_deadline")


def test_nonacceptance_window_runs_from_actual_counteroffer_communication() -> None:
    original = CounterofferNotificationEvent(method="delivered", occurred_at=NOW)
    timing = CounterofferFollowupTiming(
        original_counteroffer_notice_id="COUNTER-001",
        counteroffer_notification=original,
        notification=_written(NOW + timedelta(days=90)),
    )
    assert timing.deadline_at == NOW + timedelta(days=90)

    with pytest.raises(AdverseActionError) as exc_info:
        CounterofferFollowupTiming(
            original_counteroffer_notice_id="COUNTER-001",
            counteroffer_notification=original,
            notification=_written(NOW + timedelta(days=91)),
        )
    assert exc_info.value.failure is AdverseActionFailure.NOTICE_WINDOW_EXCEEDED


def test_consumer_report_source_requires_score_disclosure_iff_score_used() -> None:
    with pytest.raises(AdverseActionError) as missing:
        ConsumerReportSource(
            agencies=(),
            score_used=False,
        )
    assert missing.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE

    with pytest.raises(AdverseActionError) as score_missing:
        ConsumerReportSource(
            agencies=(
                CraContact(
                    name="Example CRA",
                    address=_address(),
                    toll_free_telephone="800-555-0199",
                ),
            ),
            score_used=True,
        )
    assert score_missing.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE

    disclosure = CreditScoreDisclosure(
        provider_name="Example Score Provider",
        score=680,
        score_min=300,
        score_max=850,
        created_at=NOW,
        factors=_bureau_factors(),
    )
    with pytest.raises(AdverseActionError) as unexpected:
        ConsumerReportSource(
            agencies=(
                CraContact(
                    name="Example CRA",
                    address=_address(),
                    toll_free_telephone="800-555-0199",
                ),
            ),
            score_used=False,
            score_disclosure=disclosure,
        )
    assert unexpected.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE


@pytest.mark.parametrize("score", [299, 851])
def test_credit_score_must_be_inside_a_valid_declared_range(score: int) -> None:
    with pytest.raises(AdverseActionError) as exc_info:
        CreditScoreDisclosure(
            provider_name="Example Score Provider",
            score=score,
            score_min=300,
            score_max=850,
            created_at=NOW,
            factors=_bureau_factors(),
        )

    assert exc_info.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE


def test_score_cannot_be_created_after_actual_notice_event() -> None:
    score = CreditScoreDisclosure(
        provider_name="Example Score Provider",
        score=680,
        score_min=300,
        score_max=850,
        created_at=NOW + timedelta(days=3),
        factors=_bureau_factors(),
    )
    source = ConsumerReportSource(
        agencies=(
            CraContact(
                name="Example CRA",
                address=_address(),
                toll_free_telephone="800-555-0199",
            ),
        ),
        score_used=True,
        score_disclosure=score,
    )

    with pytest.raises(AdverseActionError) as exc_info:
        DeniedApplicationNotice(
            notice_id="NOTICE-001",
            applicant=_applicant(),
            creditor=_creditor(),
            credit_request=_request(),
            timing=ThirtyDayNoticeTiming(
                basis="completed_application",
                trigger_at=NOW,
                notification=_written(NOW + timedelta(days=2)),
            ),
            principal_reasons=_reasons(),
            ecoa_disclosure=_ecoa(),
            information_source=source,
        )

    assert exc_info.value.failure is AdverseActionFailure.NOTICE_WINDOW_EXCEEDED


def test_non_cra_and_affiliate_sources_preserve_distinct_response_rules() -> None:
    non_cra = NonCraThirdPartyDisclosure(source_name="Data Source LLC", address=_address())
    affiliate = AffiliateDisclosure(affiliate_name="Bank Affiliate LLC", address=_address())

    assert non_cra.request_period_days == 60
    assert non_cra.response_rule == "reasonable_period"
    assert affiliate.request_period_days == 60
    assert affiliate.response_period_days == 30


def test_outside_source_request_and_affiliate_response_boundaries_are_enforced() -> None:
    notification_at = _denial().timing.notification.occurred_at
    valid_non_cra = NonCraThirdPartyDisclosure(
        source_name="Data Source LLC",
        address=_address(),
        information_request=WrittenInformationRequest(
            received_at=notification_at + timedelta(days=60)
        ),
    )
    valid_affiliate = AffiliateDisclosure(
        affiliate_name="Bank Affiliate LLC",
        address=_address(),
        information_request=WrittenInformationRequest(
            received_at=notification_at + timedelta(days=60)
        ),
        response_sent_at=notification_at + timedelta(days=90),
    )

    for source in (valid_non_cra, valid_affiliate):
        notice = _denial().model_copy(update={"information_source": source})
        DeniedApplicationNotice.model_validate(notice.model_dump())

    late_request = NonCraThirdPartyDisclosure(
        source_name="Data Source LLC",
        address=_address(),
        information_request=WrittenInformationRequest(
            received_at=notification_at + timedelta(days=60, microseconds=1)
        ),
    )
    with pytest.raises(AdverseActionError) as request_error:
        DeniedApplicationNotice.model_validate(
            _denial().model_copy(update={"information_source": late_request}).model_dump()
        )
    assert request_error.value.failure is AdverseActionFailure.NOTICE_WINDOW_EXCEEDED

    with pytest.raises(AdverseActionError) as response_error:
        AffiliateDisclosure(
            affiliate_name="Bank Affiliate LLC",
            address=_address(),
            information_request=WrittenInformationRequest(received_at=NOW + timedelta(days=3)),
            response_sent_at=NOW + timedelta(days=33, microseconds=1),
        )
    assert response_error.value.failure is AdverseActionFailure.NOTICE_WINDOW_EXCEEDED


def test_complete_notice_is_deeply_immutable_and_contains_no_pd_score() -> None:
    notice = _denial()

    assert notice.decision_type is DecisionType.DENIED
    assert "pd_score" not in type(notice).model_fields
    notice_id_field = "notice_id"
    with pytest.raises(ValidationError):
        setattr(notice, notice_id_field, "changed")
    append_method = "append"
    with pytest.raises(AttributeError):
        getattr(notice.principal_reasons.reasons, append_method)("injected")


def test_withdrawal_is_a_record_without_renderable_notice_identity() -> None:
    record = WithdrawalRecord(
        record_id="WITHDRAWAL-001",
        applicant=_applicant(),
        creditor=_creditor(),
        credit_request=_request(),
        withdrawn_at=NOW + timedelta(days=1),
    )

    assert record.decision_type is DecisionType.WITHDRAWN
    assert not hasattr(record, "notice_id")


def test_public_api_exports_typed_artifacts_and_removes_interim_generator() -> None:
    assert credit_risk.DeniedApplicationNotice is DeniedApplicationNotice
    assert credit_risk.NoticeRenderer.__name__ == "NoticeRenderer"
    assert credit_risk.BureauFactorRegistry.__name__ == "BureauFactorRegistry"
    assert not hasattr(credit_risk, "AdverseActionGenerator")
    assert not hasattr(credit_risk, "AdverseActionNotice")
