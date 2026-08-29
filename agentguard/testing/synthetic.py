"""Deterministic synthetic credit records for tests and benchmarks.

The generator is an artificial evaluation control. Its group labels are not
real demographics and must never be interpreted as demographic inference.
"""

# ruff: noqa: S311 -- deterministic pseudo-randomness is the benchmark contract.

from __future__ import annotations

import math
import random
from numbers import Real
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from collections.abc import Mapping

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = structlog.get_logger()

_EMPLOYMENT_OPTIONS = ("employed", "self_employed", "retired", "unemployed")
_EMPLOYMENT_WEIGHTS = (0.65, 0.15, 0.12, 0.08)
_PURPOSE_OPTIONS = (
    "home_purchase",
    "refinance",
    "home_improvement",
    "debt_consolidation",
    "other",
)
_SYNTHETIC_GROUPS = ("group_a", "group_b", "group_c", "group_d")


class CreditApplicationSchema(BaseModel):
    """Schema for one synthetic credit application benchmark record."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    application_id: str
    fico_score: int = Field(ge=300, le=850)
    dti_ratio: float = Field(ge=0.0, le=1.0)
    ltv_ratio: float = Field(ge=0.0, le=2.0)
    annual_income: float = Field(ge=15_000.0, le=350_000.0)
    employment_status: Literal["employed", "self_employed", "retired", "unemployed"]
    loan_purpose: Literal[
        "home_purchase",
        "refinance",
        "home_improvement",
        "debt_consolidation",
        "other",
    ]
    loan_amount: float = Field(ge=5_000.0)
    term_months: Literal[180, 240, 360]
    delinquency_24m: int = Field(ge=0)
    credit_utilization: float = Field(ge=0.0, le=1.0)
    num_open_accounts: int = Field(ge=1)
    months_employed: int = Field(ge=0)
    synthetic_demographic_proxy: Literal["group_a", "group_b", "group_c", "group_d"]
    is_default: bool

    @field_validator(
        "dti_ratio",
        "ltv_ratio",
        "annual_income",
        "loan_amount",
        "credit_utilization",
    )
    @classmethod
    def _finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("numeric record fields must be finite")
        return value


def is_synthetic_approval(record: Mapping[str, Any]) -> bool:
    """Apply the fixed benchmark underwriting predicate.

    Approval requires FICO >= 660, DTI <= 0.43, and LTV <= 0.90. The
    generated default label is deliberately not part of this predicate.
    """

    return (
        float(record["fico_score"]) >= 660
        and float(record["dti_ratio"]) <= 0.43
        and float(record["ltv_ratio"]) <= 0.90
    )


class SyntheticCreditGenerator:
    """Generate reproducible joint synthetic credit benchmark records.

    ``bias`` shifts latent credit quality only for artificial ``group_a``.
    At zero, group assignment and all underwriting factors are independent.
    The generator owns a private seeded RNG and never consumes ambient state.
    """

    def __init__(
        self,
        seed: int = 42,
        default_rate: float = 0.08,
        bias: float = 0.0,
    ) -> None:
        if (
            isinstance(default_rate, bool)
            or not isinstance(default_rate, Real)
            or not math.isfinite(float(default_rate))
            or not 0.0 < default_rate < 1.0
        ):
            raise ValueError("default_rate must be finite and strictly between 0 and 1")
        if (
            isinstance(bias, bool)
            or not isinstance(bias, Real)
            or not math.isfinite(float(bias))
            or not 0.0 <= bias <= 1.0
        ):
            raise ValueError("bias must be finite and between 0 and 1 inclusive")
        self._rng: random.Random = random.Random(seed)
        self._default_rate: float = float(default_rate)
        self._bias: float = float(bias)

    def generate(self, n_samples: int = 1000) -> list[dict[str, Any]]:
        """Generate ``n_samples`` records in one dependency-ordered pass."""

        if isinstance(n_samples, bool) or not isinstance(n_samples, int) or n_samples < 1:
            raise ValueError("n_samples must be a positive integer")

        records = [self._generate_record(index) for index in range(n_samples)]
        actual_default_rate = sum(bool(row["is_default"]) for row in records) / n_samples
        logger.info(
            "synthetic_data_generated",
            n_samples=n_samples,
            target_default_rate=self._default_rate,
            actual_default_rate=round(actual_default_rate, 4),
            bias=self._bias,
        )
        return records

    def _generate_record(self, index: int) -> dict[str, Any]:
        group = self._rng.choice(_SYNTHETIC_GROUPS)
        latent_quality = self._rng.gauss(0.0, 1.0)
        quality = latent_quality - (self._bias if group == "group_a" else 0.0)

        fico = int(self._clamp(round(700 + 52 * quality + self._rng.gauss(0, 18)), 300, 850))
        income = round(
            self._clamp(
                math.exp(math.log(75_000) + 0.25 * quality + self._rng.gauss(0, 0.20)),
                15_000,
                350_000,
            ),
            2,
        )
        property_multiplier = self._clamp(2.6 + 0.30 * quality + self._rng.gauss(0, 0.25), 1.2, 5.0)
        property_value = income * property_multiplier
        requested_ltv = self._clamp(0.76 - 0.075 * quality + self._rng.gauss(0, 0.09), 0.10, 1.20)
        loan_amount = round(max(5_000.0, property_value * requested_ltv), 2)
        ltv = loan_amount / property_value

        term = self._rng.choice((180, 240, 360))
        existing_obligation_rate = self._clamp(
            0.15 - 0.025 * quality + self._rng.gauss(0, 0.035), 0.01, 0.55
        )
        annual_existing_obligations = income * existing_obligation_rate
        annual_proposed_obligation = loan_amount * 12 / term
        dti = self._clamp(
            (annual_existing_obligations + annual_proposed_obligation) / income, 0.0, 1.0
        )

        utilization = self._clamp(0.30 - 0.09 * quality + self._rng.gauss(0, 0.12), 0.0, 1.0)
        delinquencies = max(0, int(round(0.4 - 0.32 * quality + self._rng.gauss(0, 0.65))))
        accounts = max(1, int(round(6 + 0.7 * quality + self._rng.gauss(0, 2.0))))
        months_employed = max(0, int(round(52 + 12 * quality + self._rng.gauss(0, 28))))

        risk_logit = (
            math.log(self._default_rate / (1.0 - self._default_rate))
            + (680 - fico) / 75
            + 2.0 * (dti - 0.35)
            + 1.2 * (ltv - 0.80)
            + 0.35 * delinquencies
            + 0.8 * (utilization - 0.30)
        )
        if risk_logit >= 0:
            probability_of_default = 1.0 / (1.0 + math.exp(-risk_logit))
        else:
            odds = math.exp(risk_logit)
            probability_of_default = odds / (1.0 + odds)

        return {
            "application_id": f"APP-{index:06d}",
            "fico_score": fico,
            "dti_ratio": dti,
            "ltv_ratio": ltv,
            "annual_income": income,
            "employment_status": self._rng.choices(
                _EMPLOYMENT_OPTIONS, weights=_EMPLOYMENT_WEIGHTS, k=1
            )[0],
            "loan_purpose": self._rng.choice(_PURPOSE_OPTIONS),
            "loan_amount": loan_amount,
            "term_months": term,
            "delinquency_24m": delinquencies,
            "credit_utilization": utilization,
            "num_open_accounts": accounts,
            "months_employed": months_employed,
            "synthetic_demographic_proxy": group,
            "is_default": self._rng.random() < probability_of_default,
        }

    @staticmethod
    def _clamp(value: float, minimum: float, maximum: float) -> float:
        return max(minimum, min(maximum, value))


__all__ = [
    "CreditApplicationSchema",
    "SyntheticCreditGenerator",
    "is_synthetic_approval",
]
