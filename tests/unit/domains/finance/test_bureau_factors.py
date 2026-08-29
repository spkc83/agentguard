"""Tests for independent FCRA credit-score factor selection."""

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
    BureauFactorCode,
    BureauFactorRegistry,
    BureauFactorSelection,
    MappedBureauFactor,
    ReasonCode,
    ReasonCodeRegistry,
)
from agentguard.exceptions import AdverseActionError, AdverseActionFailure


def _attribution(
    *, all_features: tuple[str, ...] | None = None, **values: float
) -> AttributionResult:
    return AttributionResult(
        model_id="bureau-score",
        model_version="2026.08",
        method=AttributionMethod.SCORECARD_POINTS_LOST,
        reference_id="score-reference-2026q2",
        feature_names=tuple(sorted(all_features or values)),
        contributions=tuple(
            sorted(
                (
                    AdverseContribution(feature_name=feature, value=value)
                    for feature, value in values.items()
                ),
                key=lambda item: (-item.value, item.feature_name),
            )
        ),
    )


def _code(index: int, *, inquiry_related: bool = False) -> BureauFactorCode:
    return BureauFactorCode(
        code=f"BUREAU-FACTOR-{index:02d}",
        code_set_version="bureau-2026.08",
        consumer_text=f"Credit score factor {index}",
        fcra_ref="15 U.S.C. 1681g(f)(2)(B)",
        inquiry_related=inquiry_related,
    )


def _registry(
    feature_codes: dict[str, str],
    *,
    codes: tuple[BureauFactorCode, ...] | None = None,
) -> BureauFactorRegistry:
    selected_codes = codes or tuple(_code(index) for index in range(1, 7))
    return BureauFactorRegistry(
        code_set_version="bureau-2026.08",
        factor_codes=selected_codes,
        feature_codes=feature_codes,
    )


def test_selection_preserves_provenance_and_complete_sorted_feature_schema() -> None:
    registry = _registry(
        {
            "zero_factor": "BUREAU-FACTOR-03",
            "utilization": "BUREAU-FACTOR-01",
            "account_age": "BUREAU-FACTOR-02",
        }
    )

    selection = registry.select(
        _attribution(
            all_features=("utilization", "account_age", "zero_factor"),
            utilization=0.6,
            account_age=0.4,
        )
    )

    assert selection.code_set_version == "bureau-2026.08"
    assert selection.model_id == "bureau-score"
    assert selection.model_version == "2026.08"
    assert selection.reference_id == "score-reference-2026q2"
    assert selection.attribution_method is AttributionMethod.SCORECARD_POINTS_LOST
    assert selection.feature_names == ("account_age", "utilization", "zero_factor")
    assert [factor.code.code for factor in selection.factors] == [
        "BUREAU-FACTOR-01",
        "BUREAU-FACTOR-02",
    ]
    assert [factor.rank for factor in selection.factors] == [1, 2]


def test_selection_aggregates_source_features_and_ranks_deterministically() -> None:
    registry = _registry(
        {
            "revolving_utilization": "BUREAU-FACTOR-01",
            "installment_utilization": "BUREAU-FACTOR-01",
            "account_age": "BUREAU-FACTOR-02",
        }
    )

    selection = registry.select(
        _attribution(
            revolving_utilization=0.2,
            installment_utilization=0.3,
            account_age=0.4,
        )
    )

    assert selection.factors[0].source_features == (
        "installment_utilization",
        "revolving_utilization",
    )
    assert selection.factors[0].adverse_contribution == pytest.approx(0.5)
    assert selection.factors[1].code.code == "BUREAU-FACTOR-02"


def test_binding_must_exactly_cover_zero_and_favorable_features() -> None:
    registry = _registry({"utilization": "BUREAU-FACTOR-01"})

    with pytest.raises(AdverseActionError) as exc_info:
        registry.select(
            _attribution(
                all_features=("utilization", "unbound_favorable"),
                utilization=0.5,
            )
        )

    assert exc_info.value.failure is AdverseActionFailure.UNMAPPED_FEATURES


def test_empty_factor_result_is_rejected() -> None:
    registry = _registry({"utilization": "BUREAU-FACTOR-01"})

    with pytest.raises(AdverseActionError) as exc_info:
        registry.select(_attribution(all_features=("utilization",)))

    assert exc_info.value.failure is AdverseActionFailure.NO_TRUE_FACTORS


@pytest.mark.parametrize(
    ("factor_count", "inquiry_indexes", "expected_count"),
    [
        (4, (), 4),
        (4, (1, 2), None),
        (5, (3,), 4),
        (5, (), 4),
        (5, (1, 4), None),
        (6, (2,), 4),
        (6, (6,), 5),
    ],
)
def test_factor_count_rule(
    factor_count: int,
    inquiry_indexes: tuple[int, ...],
    expected_count: int | None,
) -> None:
    codes = tuple(
        _code(index, inquiry_related=index in inquiry_indexes)
        for index in range(1, factor_count + 1)
    )
    registry = _registry(
        {f"feature_{index}": code.code for index, code in enumerate(codes, 1)},
        codes=codes,
    )
    attribution = _attribution(
        **cast(
            "dict[str, Any]",
            {
                f"feature_{index}": float(factor_count - index + 1)
                for index in range(1, factor_count + 1)
            },
        )
    )

    if expected_count is not None:
        selection = registry.select(attribution)
        assert len(selection.factors) == expected_count
        if expected_count == 5:
            assert selection.factors[-1].code.inquiry_related is True
    else:
        with pytest.raises(AdverseActionError) as exc_info:
            registry.select(attribution)
        assert exc_info.value.failure is AdverseActionFailure.INVALID_ATTRIBUTION


def test_registry_configuration_is_defensively_copied() -> None:
    factor = _code(1)
    codes = [factor]
    bindings = {"utilization": factor.code}
    registry = BureauFactorRegistry(
        code_set_version="bureau-2026.08",
        factor_codes=codes,
        feature_codes=bindings,
    )
    codes.clear()
    bindings["new_feature"] = factor.code

    assert registry.feature_names == ("utilization",)
    assert registry.factor_for_feature("utilization") == factor
    with pytest.raises(AdverseActionError):
        registry.factor_for_feature("new_feature")
    with pytest.raises(AttributeError):
        registry._code_set_version = "changed"  # type: ignore[misc]


def test_ecoa_reason_cannot_be_registered_as_bureau_factor() -> None:
    ecoa = ReasonCode(
        code="BANK-RB-001",
        code_set_version="bureau-2026.08",
        consumer_text="Specific principal reason",
        reg_b_ref="12 CFR 1002.9(b)(2)",
    )

    with pytest.raises(AdverseActionError) as exc_info:
        BureauFactorRegistry(
            code_set_version="bureau-2026.08",
            factor_codes=(ecoa,),  # type: ignore[arg-type]
            feature_codes={"factor": ecoa.code},
        )

    assert exc_info.value.failure is AdverseActionFailure.TAXONOMY_MISMATCH


def test_bureau_factor_cannot_be_registered_as_ecoa_reason() -> None:
    bureau = _code(1)

    with pytest.raises(AdverseActionError) as exc_info:
        ReasonCodeRegistry(
            taxonomy_version="bureau-2026.08",
            ecoa_reason_codes=(bureau,),  # type: ignore[arg-type]
            ecoa_feature_codes={"factor": bureau.code},
        )

    assert exc_info.value.failure is AdverseActionFailure.TAXONOMY_MISMATCH


def test_ecoa_and_bureau_code_namespaces_are_independent() -> None:
    shared_code = "SHARED-CODE-01"
    ecoa = ReasonCode(
        code=shared_code,
        code_set_version="ecoa-2026.08",
        consumer_text="Specific principal reason",
        reg_b_ref="12 CFR 1002.9(b)(2)",
    )
    bureau = BureauFactorCode(
        code=shared_code,
        code_set_version="bureau-2026.08",
        consumer_text="Specific credit score factor",
        fcra_ref="15 U.S.C. 1681g(f)(2)(B)",
    )

    ecoa_registry = ReasonCodeRegistry(
        taxonomy_version="ecoa-2026.08",
        ecoa_reason_codes=(ecoa,),
        ecoa_feature_codes={"factor": shared_code},
    )
    bureau_registry = BureauFactorRegistry(
        code_set_version="bureau-2026.08",
        factor_codes=(bureau,),
        feature_codes={"factor": shared_code},
    )

    assert ecoa_registry.ecoa_code_for_feature("factor") == ecoa
    assert bureau_registry.factor_for_feature("factor") == bureau


def test_inquiry_marker_is_explicit_boolean() -> None:
    with pytest.raises(TypeError):
        BureauFactorCode(
            code="BUREAU-FACTOR-01",
            code_set_version="bureau-2026.08",
            consumer_text="Number of recent inquiries",
            fcra_ref="15 U.S.C. 1681g(f)(2)(B)",
            inquiry_related=1,  # type: ignore[arg-type]
        )


def test_selection_runtime_namespace_and_integrity_are_enforced() -> None:
    code = _code(1)
    factor = MappedBureauFactor(
        code=code,
        source_features=("utilization",),
        adverse_contribution=0.5,
        rank=1,
    )
    payload = {
        "code_set_version": "bureau-2026.08",
        "model_id": "bureau-score",
        "model_version": "2026.08",
        "reference_id": "reference",
        "attribution_method": AttributionMethod.SCORECARD_POINTS_LOST,
        "feature_names": ("utilization",),
        "factors": (factor,),
    }

    assert BureauFactorSelection.model_validate(payload).factors == (factor,)
    with pytest.raises(ValidationError):
        BureauFactorSelection.model_validate({**payload, "factors": ()})
    with pytest.raises(ValidationError):
        MappedBureauFactor(
            code=ReasonCode(
                code="BANK-RB-001",
                code_set_version="bureau-2026.08",
                consumer_text="Specific principal reason",
                reg_b_ref="12 CFR 1002.9(b)(2)",
            ),  # type: ignore[arg-type]
            source_features=("utilization",),
            adverse_contribution=0.5,
            rank=1,
        )
