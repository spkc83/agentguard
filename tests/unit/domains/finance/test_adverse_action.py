"""Tests for truthful ECOA principal-reason selection."""

from __future__ import annotations

from typing import Any, cast

import pytest
from pydantic import ValidationError

from agentguard.domains.finance.credit_risk.attribution import (
    AdverseContribution,
    AttributionMethod,
    AttributionResult,
)
from agentguard.domains.finance.credit_risk.reason_codes import (
    MappedReason,
    ReasonCode,
    ReasonCodeMapper,
    ReasonCodeRegistry,
    ReasonCodeSelection,
)
from agentguard.exceptions import AdverseActionError, AdverseActionFailure


def _attribution(
    *, all_features: tuple[str, ...] | None = None, **values: float
) -> AttributionResult:
    feature_names = tuple(sorted(all_features or values))
    contributions = tuple(
        sorted(
            (
                AdverseContribution(feature_name=feature, value=value)
                for feature, value in values.items()
            ),
            key=lambda item: (-item.value, item.feature_name),
        )
    )
    return AttributionResult(
        model_id="credit-logit",
        model_version="2026.08",
        method=AttributionMethod.COEFFICIENT_DELTA,
        reference_id="portfolio-reference-2026q2",
        feature_names=feature_names,
        contributions=contributions,
    )


def _registry(
    feature_codes: dict[str, str] | None = None,
    *,
    additional_codes: tuple[ReasonCode, ...] = (),
) -> ReasonCodeRegistry:
    return ReasonCodeRegistry.with_appendix_c(
        taxonomy_version="2026.07",
        ecoa_feature_codes=feature_codes
        or {
            "fico_score": "AG-RB-C1-02",
            "dti_ratio": "AG-RB-C1-09",
            "annual_income": "AG-RB-C1-08",
        },
        additional_ecoa_codes=additional_codes,
    )


class TestReasonCodeRegistry:
    def test_appendix_c_codes_are_agentguard_local_and_versioned(self) -> None:
        registry = _registry()
        code = registry.ecoa_code_for_feature("fico_score")

        assert code.code == "AG-RB-C1-02"
        assert code.code_set_version == "2026.07"
        assert code.consumer_text == "Insufficient number of credit references provided"
        assert code.reg_b_ref == "12 CFR pt. 1002, app. C, Form C-1"

    def test_model_feature_binding_is_explicit(self) -> None:
        registry = _registry({"model_fico_bin_7": "AG-RB-C1-02"})

        with pytest.raises(AdverseActionError) as exc_info:
            registry.ecoa_code_for_feature("fico_score")

        assert exc_info.value.failure is AdverseActionFailure.UNMAPPED_FEATURES

    def test_custom_ecoa_code_requires_matching_taxonomy(self) -> None:
        custom = ReasonCode(
            code="BANK-RB-001",
            code_set_version="different",
            consumer_text="Specific deployed model reason",
            reg_b_ref="12 CFR 1002.9(b)(2)",
        )

        with pytest.raises(AdverseActionError) as exc_info:
            _registry({"custom": custom.code}, additional_codes=(custom,))

        assert exc_info.value.failure is AdverseActionFailure.TAXONOMY_MISMATCH

    def test_bureau_factor_model_cannot_be_substituted_directly(self) -> None:
        from agentguard.domains.finance.credit_risk.reason_codes import BureauFactorCode

        bureau = BureauFactorCode(
            code="BUREAU-42",
            code_set_version="2026.07",
            consumer_text="Length of time accounts have been established",
            fcra_ref="15 U.S.C. 1681g(f)(2)(B)",
        )

        with pytest.raises(AdverseActionError) as bureau_as_ecoa:
            ReasonCodeRegistry(
                taxonomy_version="2026.07",
                ecoa_reason_codes=(bureau,),  # type: ignore[arg-type]
                ecoa_feature_codes={"factor": bureau.code},
            )
        assert bureau_as_ecoa.value.failure is AdverseActionFailure.TAXONOMY_MISMATCH


class TestReasonCodeMapper:
    def test_maps_positive_contributions_deterministically(self) -> None:
        selection = ReasonCodeMapper(_registry()).map(
            _attribution(dti_ratio=0.25, fico_score=0.35, annual_income=0.10)
        )

        assert [reason.code.code for reason in selection.reasons] == [
            "AG-RB-C1-02",
            "AG-RB-C1-09",
            "AG-RB-C1-08",
        ]
        assert [reason.rank for reason in selection.reasons] == [1, 2, 3]

    def test_rejects_zero_true_factors(self) -> None:
        with pytest.raises(AdverseActionError) as exc_info:
            ReasonCodeMapper(_registry({"fico_score": "AG-RB-C1-02"})).map(
                _attribution(all_features=("fico_score",))
            )

        assert exc_info.value.failure is AdverseActionFailure.NO_TRUE_FACTORS
        assert exc_info.value.reason_code == "AA.NO_TRUE_FACTORS"

    def test_binding_must_cover_favorable_and_zero_model_features(self) -> None:
        mapper = ReasonCodeMapper(_registry({"fico_score": "AG-RB-C1-02"}))

        with pytest.raises(AdverseActionError) as exc_info:
            mapper.map(
                _attribution(
                    all_features=("fico_score", "unbound_favorable_feature"),
                    fico_score=0.5,
                )
            )

        assert exc_info.value.failure is AdverseActionFailure.UNMAPPED_FEATURES

    def test_rejects_unmapped_factor_even_below_presentation_limit(self) -> None:
        mapper = ReasonCodeMapper(_registry(), max_principal_reasons=1)

        with pytest.raises(AdverseActionError) as exc_info:
            mapper.map(_attribution(fico_score=0.9, unknown_feature=0.1))

        assert exc_info.value.failure is AdverseActionFailure.UNMAPPED_FEATURES

    def test_aggregates_features_bound_to_same_reason(self) -> None:
        mapper = ReasonCodeMapper(
            _registry(
                {
                    "revolving_dti": "AG-RB-C1-09",
                    "installment_dti": "AG-RB-C1-09",
                    "fico_score": "AG-RB-C1-02",
                }
            )
        )

        selection = mapper.map(_attribution(revolving_dti=0.2, installment_dti=0.3, fico_score=0.4))

        assert selection.reasons[0].code.code == "AG-RB-C1-09"
        assert selection.reasons[0].source_features == (
            "installment_dti",
            "revolving_dti",
        )
        assert selection.reasons[0].adverse_contribution == pytest.approx(0.5)

    def test_no_default_ecoa_reason_limit(self) -> None:
        custom_codes = tuple(
            ReasonCode(
                code=f"BANK-RB-{index:03d}",
                code_set_version="2026.07",
                consumer_text=f"Specific reason {index}",
                reg_b_ref="12 CFR 1002.9(b)(2)",
            )
            for index in range(1, 6)
        )
        registry = _registry(
            {f"feature_{index}": code.code for index, code in enumerate(custom_codes, 1)},
            additional_codes=custom_codes,
        )

        selection = ReasonCodeMapper(registry).map(
            _attribution(
                **cast(
                    "dict[str, Any]",
                    {f"feature_{index}": float(index) for index in range(1, 6)},
                )
            )
        )

        assert len(selection.reasons) == 5

    @pytest.mark.parametrize(
        "reasons",
        [
            (
                MappedReason(
                    code=ReasonCode(
                        code="BANK-RB-001",
                        code_set_version="2026.07",
                        consumer_text="One",
                        reg_b_ref="12 CFR 1002.9(b)(2)",
                    ),
                    source_features=("rogue",),
                    adverse_contribution=1.0,
                    rank=1,
                ),
            ),
            (
                MappedReason(
                    code=ReasonCode(
                        code="BANK-RB-001",
                        code_set_version="2026.07",
                        consumer_text="One",
                        reg_b_ref="12 CFR 1002.9(b)(2)",
                    ),
                    source_features=("bound",),
                    adverse_contribution=1.0,
                    rank=1,
                ),
                MappedReason(
                    code=ReasonCode(
                        code="BANK-RB-002",
                        code_set_version="2026.07",
                        consumer_text="Two",
                        reg_b_ref="12 CFR 1002.9(b)(2)",
                    ),
                    source_features=("bound",),
                    adverse_contribution=0.5,
                    rank=2,
                ),
            ),
        ],
    )
    def test_selection_rejects_rogue_or_reused_source_features(
        self, reasons: tuple[MappedReason, ...]
    ) -> None:
        with pytest.raises(ValidationError, match="source feature"):
            ReasonCodeSelection(
                taxonomy_version="2026.07",
                model_id="model",
                model_version="1",
                reference_id="ref",
                attribution_method=AttributionMethod.COEFFICIENT_DELTA,
                feature_names=("bound",),
                reasons=reasons,
            )

    def test_selection_rejects_nondeterministic_reason_order(self) -> None:
        low = MappedReason(
            code=ReasonCode(
                code="BANK-RB-001",
                code_set_version="2026.07",
                consumer_text="One",
                reg_b_ref="12 CFR 1002.9(b)(2)",
            ),
            source_features=("one",),
            adverse_contribution=0.5,
            rank=1,
        )
        high = MappedReason(
            code=ReasonCode(
                code="BANK-RB-002",
                code_set_version="2026.07",
                consumer_text="Two",
                reg_b_ref="12 CFR 1002.9(b)(2)",
            ),
            source_features=("two",),
            adverse_contribution=1.0,
            rank=2,
        )

        with pytest.raises(ValidationError, match="deterministic"):
            ReasonCodeSelection(
                taxonomy_version="2026.07",
                model_id="model",
                model_version="1",
                reference_id="ref",
                attribution_method=AttributionMethod.COEFFICIENT_DELTA,
                feature_names=("one", "two"),
                reasons=(low, high),
            )
