"""Tests for agentguard.domains.finance.synthetic.generators."""

from __future__ import annotations

import math
import random
import subprocess
import sys
from collections.abc import Sequence
from typing import Any

import pytest

from agentguard.domains.finance.synthetic.generators import (
    CreditApplicationSchema as LegacyCreditApplicationSchema,
)
from agentguard.domains.finance.synthetic.generators import (
    SyntheticCreditGenerator as LegacySyntheticCreditGenerator,
)
from agentguard.testing.synthetic import (
    CreditApplicationSchema,
    SyntheticCreditGenerator,
    is_synthetic_approval,
)


def _correlation(left: Sequence[float], right: Sequence[float]) -> float:
    left_mean = sum(left) / len(left)
    right_mean = sum(right) / len(right)
    numerator = sum((x - left_mean) * (y - right_mean) for x, y in zip(left, right, strict=True))
    left_ss = sum((x - left_mean) ** 2 for x in left)
    right_ss = sum((y - right_mean) ** 2 for y in right)
    return numerator / math.sqrt(left_ss * right_ss)


def _disparate_impact(records: Sequence[dict[str, Any]]) -> float:
    disadvantaged = [r for r in records if r["synthetic_demographic_proxy"] == "group_a"]
    reference = [r for r in records if r["synthetic_demographic_proxy"] != "group_a"]
    disadvantaged_rate = sum(is_synthetic_approval(r) for r in disadvantaged) / len(disadvantaged)
    reference_rate = sum(is_synthetic_approval(r) for r in reference) / len(reference)
    return disadvantaged_rate / reference_rate


class TestSyntheticCreditGenerator:
    def test_legacy_namespace_reexports_canonical_objects(self) -> None:
        assert LegacySyntheticCreditGenerator is SyntheticCreditGenerator
        assert LegacyCreditApplicationSchema is CreditApplicationSchema

    def test_generate_basic(self) -> None:
        gen = SyntheticCreditGenerator(seed=42)
        records = gen.generate(n_samples=100)
        assert len(records) == 100

    def test_generate_one(self) -> None:
        assert len(SyntheticCreditGenerator(seed=42).generate(n_samples=1)) == 1

    def test_record_schema(self) -> None:
        gen = SyntheticCreditGenerator(seed=42)
        records = gen.generate(n_samples=10)
        record = records[0]

        expected_fields = [
            "application_id",
            "fico_score",
            "dti_ratio",
            "ltv_ratio",
            "annual_income",
            "employment_status",
            "loan_purpose",
            "loan_amount",
            "term_months",
            "delinquency_24m",
            "credit_utilization",
            "num_open_accounts",
            "months_employed",
            "synthetic_demographic_proxy",
            "is_default",
        ]
        for field in expected_fields:
            assert field in record, f"Missing field: {field}"

    def test_fico_in_range(self) -> None:
        gen = SyntheticCreditGenerator(seed=42)
        records = gen.generate(n_samples=500)
        for r in records:
            assert 300 <= r["fico_score"] <= 850

    def test_dti_in_range(self) -> None:
        gen = SyntheticCreditGenerator(seed=42)
        records = gen.generate(n_samples=500)
        for r in records:
            assert 0.0 <= r["dti_ratio"] <= 1.0

    def test_reproducible(self) -> None:
        gen1 = SyntheticCreditGenerator(seed=123)
        gen2 = SyntheticCreditGenerator(seed=123)
        records1 = gen1.generate(n_samples=50)
        records2 = gen2.generate(n_samples=50)
        assert records1 == records2

    def test_reproducible_across_processes(self) -> None:
        script = (
            "import json; "
            "from agentguard.testing.synthetic import SyntheticCreditGenerator; "
            "print(json.dumps(SyntheticCreditGenerator(seed=713, default_rate=0.12, bias=0.4)"
            ".generate(20), separators=(',', ':')))"
        )
        first = subprocess.run(  # noqa: S603
            [sys.executable, "-c", script], check=True, capture_output=True, text=True
        ).stdout.splitlines()[-1]
        second = subprocess.run(  # noqa: S603
            [sys.executable, "-c", script], check=True, capture_output=True, text=True
        ).stdout.splitlines()[-1]
        assert first == second

    def test_generator_does_not_consume_global_random_state(self) -> None:
        random.seed(123)
        expected = random.random()  # noqa: S311
        random.seed(123)
        SyntheticCreditGenerator(seed=42).generate(10)
        assert random.random() == expected  # noqa: S311

    @pytest.mark.parametrize("default_rate", [0.0, 1.0, -0.1, 1.1, math.nan, math.inf])
    def test_rejects_invalid_default_rate(self, default_rate: float) -> None:
        with pytest.raises(ValueError, match="default_rate"):
            SyntheticCreditGenerator(default_rate=default_rate)

    @pytest.mark.parametrize("bias", [-0.1, 1.1, math.nan, math.inf])
    def test_rejects_invalid_bias(self, bias: float) -> None:
        with pytest.raises(ValueError, match="bias"):
            SyntheticCreditGenerator(bias=bias)

    @pytest.mark.parametrize("n_samples", [0, -1])
    def test_rejects_non_positive_sample_count(self, n_samples: int) -> None:
        with pytest.raises(ValueError, match="n_samples"):
            SyntheticCreditGenerator().generate(n_samples)

    def test_default_rate_roughly_matches(self) -> None:
        gen = SyntheticCreditGenerator(seed=42, default_rate=0.10)
        records = gen.generate(n_samples=5000)
        actual_rate = sum(1 for r in records if r["is_default"]) / len(records)
        # Should be in the ballpark (within 10 percentage points)
        assert 0.01 < actual_rate < 0.50

    def test_demographic_proxies_present(self) -> None:
        gen = SyntheticCreditGenerator(seed=42)
        records = gen.generate(n_samples=100)
        groups = {r["synthetic_demographic_proxy"] for r in records}
        assert len(groups) > 1  # Multiple groups represented

    def test_employment_distribution(self) -> None:
        gen = SyntheticCreditGenerator(seed=42)
        records = gen.generate(n_samples=1000)
        statuses = {r["employment_status"] for r in records}
        assert "employed" in statuses

    def test_fico_correlates_with_default(self) -> None:
        """High-FICO records default less frequently than low-FICO records (R6 C5)."""
        gen = SyntheticCreditGenerator(seed=42, default_rate=0.15)
        records = gen.generate(n_samples=3000)

        high_fico = [r for r in records if r["fico_score"] >= 720]
        low_fico = [r for r in records if r["fico_score"] < 640]
        assert high_fico, "need samples in the high FICO band"
        assert low_fico, "need samples in the low FICO band"

        high_rate = sum(r["is_default"] for r in high_fico) / len(high_fico)
        low_rate = sum(r["is_default"] for r in low_fico) / len(low_fico)
        assert low_rate > high_rate, (
            f"low-FICO default rate {low_rate:.3f} should exceed high-FICO {high_rate:.3f}"
        )

    def test_joint_income_property_loan_and_obligation_structure(self) -> None:
        records = SyntheticCreditGenerator(seed=907, default_rate=0.08).generate(5000)
        incomes = [float(r["annual_income"]) for r in records]
        loans = [float(r["loan_amount"]) for r in records]
        implied_properties = [float(r["loan_amount"]) / float(r["ltv_ratio"]) for r in records]

        assert _correlation(incomes, implied_properties) > 0.65
        assert _correlation(implied_properties, loans) > 0.70
        assert all(0.0 <= float(r["dti_ratio"]) <= 1.0 for r in records)

    def test_locked_unbiased_fixture_has_near_parity(self) -> None:
        records = SyntheticCreditGenerator(seed=4600, default_rate=0.08, bias=0.0).generate(40_000)
        assert _disparate_impact(records) >= 0.95

    def test_locked_biased_fixture_has_expected_disparate_impact(self) -> None:
        records = SyntheticCreditGenerator(seed=4600, default_rate=0.08, bias=0.75).generate(40_000)
        assert _disparate_impact(records) == pytest.approx(0.65, abs=0.03)


def test_fixed_synthetic_approval_predicate() -> None:
    passing = {
        "fico_score": 660,
        "dti_ratio": 0.43,
        "ltv_ratio": 0.90,
        "is_default": True,
    }
    assert is_synthetic_approval(passing)
    assert not is_synthetic_approval({**passing, "fico_score": 659, "is_default": False})
    assert not is_synthetic_approval({**passing, "dti_ratio": 0.431, "is_default": False})
    assert not is_synthetic_approval({**passing, "ltv_ratio": 0.901, "is_default": False})


def test_record_schema_rejects_impossible_or_nonfinite_values() -> None:
    valid = SyntheticCreditGenerator(seed=42).generate(1)[0]
    with pytest.raises(ValueError):
        CreditApplicationSchema.model_validate({**valid, "fico_score": 999})
    with pytest.raises(ValueError):
        CreditApplicationSchema.model_validate({**valid, "dti_ratio": math.nan})
    with pytest.raises(ValueError):
        CreditApplicationSchema.model_validate({**valid, "synthetic_demographic_proxy": "real"})


def test_subnormal_default_rate_does_not_overflow() -> None:
    rows = SyntheticCreditGenerator(seed=42, default_rate=5e-324).generate(1)
    assert len(rows) == 1
