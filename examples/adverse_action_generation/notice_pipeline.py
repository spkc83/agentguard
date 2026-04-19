"""Adverse action notice pipeline demo.

Focused walkthrough of generating ECOA / Regulation B adverse action notices
from a credit model's feature importances. Demonstrates:

    * Deterministic ordering — the same model output always produces the same
      notice (important for explainability and appeals).
    * The 4-reason cap (Regulation B).
    * Custom reason-code maps for institutions that use non-default mappings.
    * PII masking on any applicant-bearing text before it touches storage.

Run:
    python examples/adverse_action_generation/notice_pipeline.py
"""

from __future__ import annotations

import uuid

from agentguard.domains.finance.credit_risk.adverse_action import AdverseActionGenerator
from agentguard.domains.finance.pii import PiiMasker


def _print_notice(title: str, notice: object) -> None:
    print(f"\n--- {title} ---")  # noqa: T201
    print(notice.model_dump_json(indent=2))  # type: ignore[attr-defined]  # noqa: T201


def main() -> None:
    masker = PiiMasker()
    generator = AdverseActionGenerator()

    # 1. Typical adverse action notice from a declined application.
    #    Feature importances come from the PD model — higher absolute value
    #    means that feature contributed more to the denial.
    feature_importances = {
        "fico_score": 0.85,
        "dti_ratio": 0.60,
        "delinquency_24m": 0.45,
        "credit_utilization": 0.30,
        "months_employed": 0.15,
        "num_open_accounts": 0.05,
    }

    notice = generator.generate(
        notice_id=str(uuid.uuid4()),
        applicant_id="APP-000123",
        feature_importances=feature_importances,
        pd_score=0.28,
        creditor_name="Acme Bank",
        decision="denied",
    )
    _print_notice("Standard denial notice (top 4 reasons)", notice)

    # 2. Determinism check — identical inputs must produce identical reasons.
    notice_2 = generator.generate(
        notice_id="fixed-id",
        applicant_id="APP-000123",
        feature_importances=feature_importances,
        pd_score=0.28,
        creditor_name="Acme Bank",
    )
    notice_3 = generator.generate(
        notice_id="fixed-id",
        applicant_id="APP-000123",
        feature_importances=feature_importances,
        pd_score=0.28,
        creditor_name="Acme Bank",
    )
    assert notice_2.reasons == notice_3.reasons  # noqa: S101
    print(f"\nDeterministic ordering verified: {notice_2.reasons}")  # noqa: T201

    # 3. Custom reason-code map — an institution might want its own wording.
    custom_generator = AdverseActionGenerator(
        reason_map={
            "fico_score": "Insufficient credit history",
            "dti_ratio": "Monthly obligations exceed acceptable ratio",
            "delinquency_24m": "Recent payment history issues",
        },
        max_reasons=3,
    )
    custom_notice = custom_generator.generate(
        notice_id=str(uuid.uuid4()),
        applicant_id="APP-000456",
        feature_importances=feature_importances,
        creditor_name="Community Credit Union",
    )
    _print_notice("Custom reason map (3-reason cap)", custom_notice)

    # 4. PII masking before the notice ever gets persisted or logged.
    raw_note = (
        "Applicant John Doe (SSN 123-45-6789, phone 415-555-0100) declined "
        "on account 4111222233334444."
    )
    print(f"\nOriginal message: {raw_note}")  # noqa: T201
    print(f"Masked for audit: {masker.mask_text(raw_note)}")  # noqa: T201


if __name__ == "__main__":
    main()
