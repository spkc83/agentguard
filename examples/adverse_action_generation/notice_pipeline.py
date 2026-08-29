"""Truthful adverse-action attribution, artifact, and rendering demo.

Run:
    python examples/adverse_action_generation/notice_pipeline.py
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, cast

from agentguard.domains.finance.credit_risk import (
    ApplicantDetails,
    CreditorDetails,
    CreditRequestDetails,
    CreditTerms,
    DeniedApplicationNotice,
    EnforcementAgency,
    EqualCreditOpportunityDisclosure,
    MailingAddress,
    NoFCRA,
    NoticeRenderer,
    PrincipalReasonSelection,
    ReasonCode,
    ReasonCodeMapper,
    ReasonCodeRegistry,
    ScorecardAttributor,
    ScoreDirection,
    ThirtyDayNoticeTiming,
    WrittenNotificationEvent,
)
from agentguard.domains.finance.pii import PiiMasker

if TYPE_CHECKING:
    from collections.abc import Mapping
    from numbers import Real

TAXONOMY_VERSION = "demo-scorecard-reasons-v1"
REG_B_SPECIFIC_REASONS = "12 CFR 1002.9(b)(2)"


def _reason(code: str, text: str) -> ReasonCode:
    return ReasonCode(
        code=code,
        code_set_version=TAXONOMY_VERSION,
        consumer_text=text,
        reg_b_ref=REG_B_SPECIFIC_REASONS,
    )


def _build_mapper() -> ReasonCodeMapper:
    registry = ReasonCodeRegistry.with_appendix_c(
        taxonomy_version=TAXONOMY_VERSION,
        ecoa_feature_codes={
            "account_depth_points": "AG-RB-C1-02",
            "debt_capacity_points": "AG-RB-C1-09",
            "employment_stability_points": "AG-RB-C1-07",
            "fico_points": "AG-DEMO-SC-001",
            "payment_history_points": "AG-RB-C1-17",
            "utilization_points": "AG-DEMO-SC-002",
        },
        additional_ecoa_codes=(
            _reason("AG-DEMO-SC-001", "Credit score did not meet the required level"),
            _reason("AG-DEMO-SC-002", "Revolving account utilization was too high"),
        ),
    )
    return ReasonCodeMapper(registry)


def _address(line1: str) -> MailingAddress:
    return MailingAddress(
        line1=line1,
        city="Bismarck",
        region="ND",
        postal_code="58501",
    )


def main() -> None:
    mapper = _build_mapper()
    attributor = ScorecardAttributor(
        model_id="consumer-scorecard",
        model_version="1.0",
        reference_id="approved-reference-profile-v1",
        reference_points=cast(
            "Mapping[str, Real]",
            {
                "account_depth_points": 100,
                "debt_capacity_points": 100,
                "employment_stability_points": 100,
                "fico_points": 100,
                "payment_history_points": 100,
                "utilization_points": 100,
            },
        ),
        score_direction=ScoreDirection.HIGHER_IS_BETTER,
    )

    application_points = {
        "account_depth_points": 95,
        "debt_capacity_points": 40,
        "employment_stability_points": 85,
        "fico_points": 15,
        "payment_history_points": 55,
        "utilization_points": 70,
    }
    attribution = attributor.attribute(cast("Mapping[str, Real]", application_points))
    reasons = PrincipalReasonSelection.from_attribution(mapper.map(attribution))
    received_at = datetime.now(UTC)
    notice = DeniedApplicationNotice(
        notice_id=str(uuid.uuid4()),
        applicant=ApplicantDetails(
            applicant_id="APP-000123",
            full_name="Alex Example",
            address=_address("100 Main Street"),
        ),
        creditor=CreditorDetails(
            name="Example Lender",
            address=_address("200 Bank Avenue"),
            telephone="800-555-0100",
        ),
        credit_request=CreditRequestDetails(
            application_id="APP-000123",
            received_at=received_at,
            requested_terms=CreditTerms(
                product_name="Installment loan",
                principal_amount=Decimal("25000"),
                annual_percentage_rate=Decimal("8.50"),
                term_months=48,
            ),
        ),
        timing=ThirtyDayNoticeTiming(
            basis="completed_application",
            trigger_at=received_at,
            notification=WrittenNotificationEvent(
                method="mailed",
                occurred_at=received_at + timedelta(days=1),
            ),
        ),
        principal_reasons=reasons,
        ecoa_disclosure=EqualCreditOpportunityDisclosure(
            enforcement_agency=EnforcementAgency(
                name="Federal Trade Commission",
                address=MailingAddress(
                    line1="600 Pennsylvania Avenue NW",
                    city="Washington",
                    region="DC",
                    postal_code="20580",
                ),
            )
        ),
        information_source=NoFCRA(),
        credit_scoring_applicable=True,
    )
    rendered = NoticeRenderer().render(notice)
    print(rendered.body)  # noqa: T201
    print(f"SHA-256: {rendered.body_sha256}")  # noqa: T201

    repeated = PrincipalReasonSelection.from_attribution(
        mapper.map(attributor.attribute(cast("Mapping[str, Real]", application_points)))
    )
    assert reasons == repeated  # noqa: S101

    raw_note = (
        "Applicant John Doe (SSN 123-45-6789, phone 415-555-0100) declined "
        "on account 4111222233334444."
    )
    print(f"Masked for audit: {PiiMasker().mask_text(raw_note)}")  # noqa: T201


if __name__ == "__main__":
    main()
