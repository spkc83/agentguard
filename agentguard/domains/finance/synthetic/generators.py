"""High-level synthetic data API for credit risk benchmarks.

Generates synthetic credit application datasets with realistic
statistical profiles. Uses simple statistical sampling for v0.4.0;
the WGAN-GP backend (wgan_gp.py) provides higher-fidelity generation
when PyTorch is available.

All generated data includes synthetic demographic proxies for
fairness testing — never real demographics.
"""

from __future__ import annotations

import random
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict

logger = structlog.get_logger()


class CreditApplicationSchema(BaseModel):
    """Schema for a single synthetic credit application.

    Args:
        application_id: Unique application identifier.
        fico_score: FICO credit score (300-850).
        dti_ratio: Debt-to-income ratio (0-1).
        ltv_ratio: Loan-to-value ratio (0-1.5).
        annual_income: Annual income in USD.
        employment_status: Employment category.
        loan_purpose: Purpose of the loan.
        loan_amount: Requested loan amount in USD.
        term_months: Loan term in months.
        delinquency_24m: Number of delinquencies in past 24 months.
        credit_utilization: Credit utilization ratio (0-1).
        num_open_accounts: Number of open credit accounts.
        months_employed: Months at current employer.
        synthetic_demographic_proxy: Synthetic group label for fairness testing.
        is_default: Whether the applicant defaults (label).
    """

    model_config = ConfigDict(frozen=True)

    application_id: str
    fico_score: int
    dti_ratio: float
    ltv_ratio: float
    annual_income: float
    employment_status: str
    loan_purpose: str
    loan_amount: float
    term_months: int
    delinquency_24m: int
    credit_utilization: float
    num_open_accounts: int
    months_employed: int
    synthetic_demographic_proxy: str
    is_default: bool


class SyntheticCreditGenerator:
    """Generates synthetic credit application datasets.

    Uses statistical sampling with realistic marginal distributions
    matching typical consumer credit portfolios. Default rate is
    controllable via the default_rate parameter.

    Args:
        seed: Random seed for reproducibility.
        default_rate: Target default rate (default 0.08 = 8%).
    """

    def __init__(self, seed: int = 42, default_rate: float = 0.08) -> None:
        self._rng = random.Random(seed)
        self._default_rate = default_rate

    def generate(self, n_samples: int = 1000) -> list[dict[str, Any]]:
        """Generate a synthetic credit application dataset.

        Args:
            n_samples: Number of applications to generate.

        Returns:
            List of dicts, each representing one application.
        """
        employment_options = ["employed", "self_employed", "retired", "unemployed"]
        employment_weights = [0.65, 0.15, 0.12, 0.08]
        purpose_options = [
            "home_purchase",
            "refinance",
            "home_improvement",
            "debt_consolidation",
            "other",
        ]
        demographic_groups = ["group_a", "group_b", "group_c", "group_d"]

        records: list[dict[str, Any]] = []

        for i in range(n_samples):
            fico = self._clamp(int(self._rng.gauss(700, 60)), 300, 850)
            dti = self._clamp(round(self._rng.gauss(0.35, 0.12), 3), 0.0, 1.0)
            ltv = self._clamp(round(self._rng.gauss(0.75, 0.15), 3), 0.1, 1.5)
            income = max(15000, round(self._rng.gauss(75000, 35000), 0))
            loan_amount = max(5000, round(self._rng.gauss(200000, 100000), 0))
            utilization = self._clamp(round(self._rng.gauss(0.30, 0.20), 3), 0.0, 1.0)
            delinq = max(0, int(self._rng.gauss(0.3, 0.8)))
            accounts = max(1, int(self._rng.gauss(5, 3)))
            months_emp = max(0, int(self._rng.gauss(48, 36)))

            employment = self._rng.choices(employment_options, weights=employment_weights, k=1)[0]
            purpose = self._rng.choice(purpose_options)
            term = self._rng.choice([180, 240, 360])
            demographic = self._rng.choice(demographic_groups)

            # Default probability correlated with risk factors
            base_pd = self._default_rate
            pd_adj = base_pd * (1 + (700 - fico) / 200 + (dti - 0.35) * 2 + delinq * 0.3)
            pd_adj = self._clamp(pd_adj, 0.001, 0.95)
            is_default = self._rng.random() < pd_adj

            records.append(
                {
                    "application_id": f"APP-{i:06d}",
                    "fico_score": fico,
                    "dti_ratio": dti,
                    "ltv_ratio": ltv,
                    "annual_income": income,
                    "employment_status": employment,
                    "loan_purpose": purpose,
                    "loan_amount": loan_amount,
                    "term_months": term,
                    "delinquency_24m": delinq,
                    "credit_utilization": utilization,
                    "num_open_accounts": accounts,
                    "months_employed": months_emp,
                    "synthetic_demographic_proxy": demographic,
                    "is_default": is_default,
                }
            )

        actual_default_rate = sum(1 for r in records if r["is_default"]) / len(records)
        logger.info(
            "synthetic_data_generated",
            n_samples=n_samples,
            target_default_rate=self._default_rate,
            actual_default_rate=round(actual_default_rate, 4),
        )
        return records

    @staticmethod
    def _clamp(value: float, min_val: float, max_val: float) -> float:
        return max(min_val, min(max_val, value))
