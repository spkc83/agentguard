"""Tests for agentguard.domains.finance.synthetic.generators."""

from __future__ import annotations

from agentguard.domains.finance.synthetic.generators import SyntheticCreditGenerator


class TestSyntheticCreditGenerator:
    def test_generate_basic(self) -> None:
        gen = SyntheticCreditGenerator(seed=42)
        records = gen.generate(n_samples=100)
        assert len(records) == 100

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
