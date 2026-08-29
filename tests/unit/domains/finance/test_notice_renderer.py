"""Deterministic rendering tests for typed credit-notice artifacts."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import TypedDict

import pytest

from agentguard.domains.finance.credit_risk.adverse_action import (
    AffiliateDisclosure,
    ApplicantDetails,
    BothSources,
    CombinedCounterofferAdverseActionNotice,
    ConsumerReportSource,
    CounterofferAcceptanceInstructions,
    CounterofferFollowupTiming,
    CounterofferNonAcceptanceNotice,
    CounterofferNotificationEvent,
    CraContact,
    CreditorDetails,
    CreditRequestDetails,
    CreditScoreDisclosure,
    CreditTerms,
    DeniedApplicationNotice,
    EnforcementAgency,
    EqualCreditOpportunityDisclosure,
    IncompleteApplicationNotice,
    InformationSource,
    MailingAddress,
    NoFCRA,
    NonCraThirdPartyDisclosure,
    OutsideSources,
    PrincipalReasonSelection,
    StandaloneCounterofferNotice,
    StandaloneCounterofferTiming,
    ThirtyDayNoticeTiming,
    WithdrawalRecord,
    WrittenNotificationEvent,
)
from agentguard.domains.finance.credit_risk.attribution import AttributionMethod
from agentguard.domains.finance.credit_risk.notice_renderer import (
    NoticeProfile,
    NoticeRenderer,
    RenderedNotice,
)
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
FIXTURES = Path(__file__).parents[3] / "fixtures" / "notices"


def _address(line1: str = "100 Main Street") -> MailingAddress:
    return MailingAddress(
        line1=line1,
        city="Bismarck",
        region="ND",
        postal_code="58501",
    )


def _terms(amount: str = "25000") -> CreditTerms:
    return CreditTerms(
        product_name="Installment loan",
        principal_amount=Decimal(amount),
        annual_percentage_rate=Decimal("8.50"),
        term_months=48,
    )


def _reasons() -> PrincipalReasonSelection:
    code = ReasonCode(
        code="AG-RB-C1-09",
        code_set_version="2026.07",
        consumer_text="Excessive obligations in relation to income",
        reg_b_ref="12 CFR pt. 1002, app. C, Form C-1",
    )
    return PrincipalReasonSelection.from_attribution(
        ReasonCodeSelection(
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
    )


def _bureau_factors() -> BureauFactorSelection:
    factor = BureauFactorCode(
        code="BANK-FCRA-001",
        code_set_version="2026.08",
        consumer_text="Balances on accounts are too high",
        fcra_ref="15 U.S.C. 1681g(f)(2)(B)",
    )
    return BureauFactorSelection(
        code_set_version="2026.08",
        model_id="bureau-score",
        model_version="3",
        reference_id="bureau-reference",
        attribution_method=AttributionMethod.SCORECARD_POINTS_LOST,
        feature_names=("balance_points",),
        factors=(
            MappedBureauFactor(
                code=factor,
                source_features=("balance_points",),
                adverse_contribution=12.0,
                rank=1,
            ),
        ),
    )


class _CommonFields(TypedDict):
    notice_id: str
    applicant: ApplicantDetails
    creditor: CreditorDetails
    credit_request: CreditRequestDetails


def _common() -> _CommonFields:
    return {
        "notice_id": "NOTICE-001",
        "applicant": ApplicantDetails(
            applicant_id="APP-001",
            full_name="Alex Example",
            address=_address(),
        ),
        "creditor": CreditorDetails(
            name="Example Community Bank",
            address=_address("200 Bank Avenue"),
            telephone="800-555-0100",
        ),
        "credit_request": CreditRequestDetails(
            application_id="APP-001",
            received_at=NOW,
            requested_terms=_terms(),
        ),
    }


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


def _denial(
    *,
    scoring: bool = False,
    source: InformationSource | None = None,
) -> DeniedApplicationNotice:
    return DeniedApplicationNotice(
        **_common(),
        timing=ThirtyDayNoticeTiming(
            basis="completed_application",
            trigger_at=NOW,
            notification=WrittenNotificationEvent(
                method="mailed",
                occurred_at=NOW + timedelta(days=2),
            ),
        ),
        principal_reasons=_reasons(),
        ecoa_disclosure=_ecoa(),
        information_source=source or NoFCRA(),
        credit_scoring_applicable=scoring,
    )


def test_c1_render_matches_reference_fixture_and_exact_digest() -> None:
    rendered = NoticeRenderer().render(_denial(), profile=NoticeProfile.REG_B_C1)
    expected = (FIXTURES / "reg_b_c1_denial.txt").read_text(encoding="utf-8")

    assert rendered.body == expected
    assert rendered.body_sha256 == hashlib.sha256(expected.encode("utf-8")).hexdigest()
    assert rendered.profile is NoticeProfile.REG_B_C1
    assert rendered.template_version == "2026.08"


def test_render_is_canonical_and_deterministic_after_json_round_trip() -> None:
    notice = _denial()
    restored = DeniedApplicationNotice.model_validate_json(notice.model_dump_json())
    renderer = NoticeRenderer()

    first = renderer.render(notice)
    second = renderer.render(restored)

    assert first == second
    assert "\r" not in first.body
    assert first.body.endswith("\n")
    assert not first.body.endswith("\n\n")


def test_rendered_notice_rejects_noncanonical_body_or_false_digest() -> None:
    rendered = NoticeRenderer().render(_denial())

    with pytest.raises(AdverseActionError) as body_error:
        RenderedNotice.model_validate(
            rendered.model_copy(update={"body": rendered.body.replace("\n", "\r\n")}).model_dump()
        )
    assert body_error.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE

    with pytest.raises(AdverseActionError) as digest_error:
        RenderedNotice.model_validate(
            rendered.model_copy(update={"body_sha256": "0" * 64}).model_dump()
        )
    assert digest_error.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE

    with pytest.raises(AdverseActionError):
        RenderedNotice.model_validate(
            rendered.model_copy(update={"notice_id": "OTHER-NOTICE"}).model_dump()
        )
    with pytest.raises(AdverseActionError):
        RenderedNotice.model_validate(
            rendered.model_copy(update={"template_version": "untrusted"}).model_dump()
        )
    with pytest.raises(AdverseActionError):
        RenderedNotice.model_validate(
            rendered.model_copy(update={"profile": NoticeProfile.REG_B_C3}).model_dump()
        )


def test_c3_requires_explicit_credit_scoring_applicability() -> None:
    with pytest.raises(AdverseActionError) as exc_info:
        NoticeRenderer().render(_denial(), profile=NoticeProfile.REG_B_C3)

    assert exc_info.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE
    rendered = NoticeRenderer().render(_denial(scoring=True))
    assert rendered.profile is NoticeProfile.REG_B_C3
    assert "evaluated by a credit scoring system" in rendered.body
    assert "did not receive enough points" in rendered.body


def test_action_taken_denial_uses_general_c1_not_application_scoring_c3() -> None:
    base = _denial(scoring=True)
    notice = base.model_copy(
        update={
            "timing": ThirtyDayNoticeTiming(
                basis="action_taken",
                trigger_at=NOW,
                notification=WrittenNotificationEvent(method="mailed", occurred_at=NOW),
            )
        }
    )
    validated = DeniedApplicationNotice.model_validate(notice.model_dump())

    assert NoticeRenderer().render(validated).profile is NoticeProfile.REG_B_C1
    with pytest.raises(AdverseActionError):
        NoticeRenderer().render(validated, profile=NoticeProfile.REG_B_C3)


def test_consumer_report_block_names_cra_and_creditor_telephone() -> None:
    source = ConsumerReportSource(
        agencies=(
            CraContact(
                name="Example Credit Bureau",
                address=_address("300 Report Road"),
                toll_free_telephone="800-555-0199",
            ),
        ),
        score_used=False,
    )

    body = NoticeRenderer().render(_denial(source=source)).body

    assert "Example Credit Bureau" in body
    assert "800-555-0199" in body
    assert "did not make our decision" in body
    assert "800-555-0100" in body


def test_combined_fcra_sources_render_score_non_cra_and_affiliate_blocks() -> None:
    consumer_report = ConsumerReportSource(
        agencies=(
            CraContact(
                name="Example Credit Bureau",
                address=_address("300 Report Road"),
                toll_free_telephone="800-555-0199",
            ),
        ),
        score_used=True,
        score_disclosure=CreditScoreDisclosure(
            provider_name="Example Score Provider",
            score=680,
            score_min=300,
            score_max=850,
            created_at=NOW,
            factors=_bureau_factors(),
        ),
    )
    source = BothSources(
        consumer_report=consumer_report,
        outside_sources=OutsideSources(
            sources=(
                NonCraThirdPartyDisclosure(
                    source_name="Income Data LLC",
                    address=_address("400 Data Drive"),
                ),
                AffiliateDisclosure(
                    affiliate_name="Example Bank Affiliate",
                    address=_address("500 Affiliate Avenue"),
                ),
            )
        ),
    )

    rendered = NoticeRenderer().render(_denial(source=source))

    assert "Score: 680" in rendered.body
    assert "Balances on accounts are too high" in rendered.body
    assert "Income Data LLC" in rendered.body
    assert "reasonable period" in rendered.body
    assert "Example Bank Affiliate" in rendered.body
    assert "no later than 30 days" in rendered.body


def test_combined_counteroffer_uses_only_c4_profile() -> None:
    notice = CombinedCounterofferAdverseActionNotice(
        **_common(),
        timing=ThirtyDayNoticeTiming(
            basis="completed_application",
            trigger_at=NOW,
            notification=WrittenNotificationEvent(method="mailed", occurred_at=NOW),
        ),
        offered_terms=_terms("20000"),
        acceptance=CounterofferAcceptanceInstructions(
            recipient="Credit Services",
            address=_address("600 Acceptance Street"),
            accept_by=NOW + timedelta(days=15),
        ),
        principal_reasons=_reasons(),
        ecoa_disclosure=_ecoa(),
        information_source=NoFCRA(),
    )
    renderer = NoticeRenderer()

    assert renderer.render(notice).profile is NoticeProfile.REG_B_C4
    assert "send written notice to Credit Services" in renderer.render(notice).body
    assert "600 Acceptance Street" in renderer.render(notice).body
    with pytest.raises(AdverseActionError):
        renderer.render(notice, profile=NoticeProfile.REG_B_C1)


def test_incomplete_application_uses_c6_and_omits_ecoa_block() -> None:
    notice = IncompleteApplicationNotice(
        **_common(),
        timing=ThirtyDayNoticeTiming(
            basis="incomplete_application",
            trigger_at=NOW,
            notification=WrittenNotificationEvent(method="mailed", occurred_at=NOW),
        ),
        information_needed=("Most recent pay stub", "Signed tax return"),
        respond_by=NOW + timedelta(days=15),
    )

    rendered = NoticeRenderer().render(notice)

    assert rendered.profile is NoticeProfile.REG_B_C6
    assert "Most recent pay stub" in rendered.body
    assert "Equal Credit Opportunity Act" not in rendered.body


def test_standalone_counteroffer_uses_agentguard_profile() -> None:
    notice = StandaloneCounterofferNotice(
        **_common(),
        timing=StandaloneCounterofferTiming(
            trigger_at=NOW,
            notification=CounterofferNotificationEvent(method="oral", occurred_at=NOW),
            accept_by=NOW + timedelta(days=15),
        ),
        offered_terms=_terms("20000"),
        principal_reasons=_reasons(),
        information_source=NoFCRA(),
    )

    rendered = NoticeRenderer().render(notice)

    assert rendered.profile is NoticeProfile.AGENTGUARD_COUNTEROFFER
    assert "20,000.00" in rendered.body


def test_counteroffer_nonacceptance_links_original_and_renders_as_adverse_action() -> None:
    notice = CounterofferNonAcceptanceNotice(
        **_common(),
        timing=CounterofferFollowupTiming(
            original_counteroffer_notice_id="COUNTER-001",
            counteroffer_notification=CounterofferNotificationEvent(
                method="oral",
                occurred_at=NOW,
            ),
            notification=WrittenNotificationEvent(
                method="mailed",
                occurred_at=NOW + timedelta(days=90),
            ),
        ),
        offered_terms=_terms("20000"),
        principal_reasons=_reasons(),
        ecoa_disclosure=_ecoa(),
        information_source=NoFCRA(),
    )

    rendered = NoticeRenderer().render(notice)

    assert rendered.profile is NoticeProfile.REG_B_C1
    assert "Original counteroffer notice: COUNTER-001" in rendered.body
    assert "counteroffer was not accepted" in rendered.body


def test_scoring_counteroffer_nonacceptance_stays_c1_and_preserves_lifecycle() -> None:
    notice = CounterofferNonAcceptanceNotice(
        **_common(),
        timing=CounterofferFollowupTiming(
            original_counteroffer_notice_id="COUNTER-001",
            counteroffer_notification=CounterofferNotificationEvent(
                method="oral",
                occurred_at=NOW,
            ),
            notification=WrittenNotificationEvent(
                method="mailed",
                occurred_at=NOW + timedelta(days=90),
            ),
        ),
        offered_terms=_terms("20000"),
        principal_reasons=_reasons(),
        credit_scoring_applicable=True,
        ecoa_disclosure=_ecoa(),
        information_source=NoFCRA(),
    )

    rendered = NoticeRenderer().render(notice)

    assert rendered.profile is NoticeProfile.REG_B_C1
    assert "Original counteroffer notice: COUNTER-001" in rendered.body
    assert "Counteroffer: Installment loan" in rendered.body
    with pytest.raises(AdverseActionError):
        NoticeRenderer().render(notice, profile=NoticeProfile.REG_B_C3)


def test_withdrawal_is_not_renderable() -> None:
    common = _common()
    record = WithdrawalRecord(
        record_id="WITHDRAWAL-001",
        applicant=common["applicant"],
        creditor=common["creditor"],
        credit_request=common["credit_request"],
        withdrawn_at=NOW + timedelta(days=1),
    )

    with pytest.raises(AdverseActionError) as exc_info:
        NoticeRenderer().render(record)

    assert exc_info.value.failure is AdverseActionFailure.NOTICE_INCOMPLETE
