"""Pure credit-decision policy contracts for governed credit emission."""

from __future__ import annotations

import math
from enum import StrEnum
from numbers import Real

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from agentguard.exceptions import AdverseActionFailure  # noqa: TC001 - Pydantic runtime type
from agentguard.guardrails import DecisionPayload

from .attribution import AttributionResult  # noqa: TC001 - Pydantic runtime type
from .reason_codes import ReasonCodeSelection  # noqa: TC001 - Pydantic runtime type


def _canonical_text(value: str, *, field_name: str) -> str:
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError(f"{field_name} must be canonical printable text")
    return value


class CreditDecisionOutcome(StrEnum):
    """Closed decision bands produced by :class:`CreditDecisionPolicy`."""

    APPROVE = "approve"
    REVIEW = "review"
    DECLINE = "decline"


class CreditDecisionPolicyConfig(BaseModel):
    """Versioned PD thresholds for one deterministic credit-decision policy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    policy_id: str = "pd-bands"
    policy_version: str = "1"
    auto_approve_threshold: float = 0.05
    decline_threshold: float = 0.20

    @field_validator("policy_id", "policy_version")
    @classmethod
    def _validate_identifiers(cls, value: str, info: object) -> str:
        field_name = getattr(info, "field_name", "identifier")
        return _canonical_text(value, field_name=field_name)

    @field_validator("auto_approve_threshold", "decline_threshold", mode="before")
    @classmethod
    def _validate_threshold(cls, value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError("decision thresholds must be finite values in [0, 1]")
        result = float(value)
        if not math.isfinite(result) or not 0 <= result <= 1:
            raise ValueError("decision thresholds must be finite values in [0, 1]")
        return result

    @model_validator(mode="after")
    def _validate_order(self) -> CreditDecisionPolicyConfig:
        if self.auto_approve_threshold >= self.decline_threshold:
            raise ValueError("auto_approve_threshold must be below decline_threshold")
        return self


class CreditDecisionCandidate(BaseModel):
    """Local typed candidate presented to the governed emission boundary.

    A decline may intentionally lack reason evidence or carry a typed mapping
    failure. That lets the ``ON_DECISION`` guardrail sign the exact fail-closed
    outcome instead of losing the decision before governance.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str
    application_ref: str
    outcome: CreditDecisionOutcome
    pd_score: float
    policy_id: str
    policy_version: str
    model_id: str
    model_version: str
    attribution: AttributionResult | None = None
    reason_selection: ReasonCodeSelection | None = None
    reason_failure: AdverseActionFailure | None = None

    @field_validator(
        "decision_id",
        "application_ref",
        "policy_id",
        "policy_version",
        "model_id",
        "model_version",
    )
    @classmethod
    def _validate_identifiers(cls, value: str, info: object) -> str:
        field_name = getattr(info, "field_name", "identifier")
        return _canonical_text(value, field_name=field_name)

    @field_validator("pd_score", mode="before")
    @classmethod
    def _validate_pd(cls, value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError("pd_score must be a finite value in [0, 1]")
        result = float(value)
        if not math.isfinite(result) or not 0 <= result <= 1:
            raise ValueError("pd_score must be a finite value in [0, 1]")
        return result

    @model_validator(mode="after")
    def _validate_reason_state(self) -> CreditDecisionCandidate:
        if self.reason_selection is not None and self.reason_failure is not None:
            raise ValueError("reason selection and reason failure are mutually exclusive")
        return self

    @property
    def requires_review(self) -> bool:
        return self.outcome is CreditDecisionOutcome.REVIEW

    def to_payload(self) -> DecisionPayload:
        """Return the immutable full-fidelity payload consumed by decision guardrails."""

        return DecisionPayload.model_validate(
            {
                "domain": "credit_risk",
                "decision_id": self.decision_id,
                "outcome": self.outcome.value,
                "body": self.model_dump(mode="json"),
            }
        )


class CreditDecisionPolicy:
    """Pure deterministic threshold policy with no logging or governance side effects."""

    def __init__(self, config: CreditDecisionPolicyConfig | None = None) -> None:
        self._config = config or CreditDecisionPolicyConfig()

    @property
    def config(self) -> CreditDecisionPolicyConfig:
        return self._config

    def evaluate(
        self,
        *,
        decision_id: str,
        application_ref: str,
        pd_score: float,
        model_id: str,
        model_version: str,
        attribution: AttributionResult | None = None,
        reason_selection: ReasonCodeSelection | None = None,
        reason_failure: AdverseActionFailure | None = None,
    ) -> CreditDecisionCandidate:
        """Classify one PD without fabricating reasons or inspecting raw features."""

        config = self._config
        if pd_score < config.auto_approve_threshold:
            outcome = CreditDecisionOutcome.APPROVE
        elif pd_score >= config.decline_threshold:
            outcome = CreditDecisionOutcome.DECLINE
        else:
            outcome = CreditDecisionOutcome.REVIEW
        return CreditDecisionCandidate(
            decision_id=decision_id,
            application_ref=application_ref,
            outcome=outcome,
            pd_score=pd_score,
            policy_id=config.policy_id,
            policy_version=config.policy_version,
            model_id=model_id,
            model_version=model_version,
            attribution=attribution,
            reason_selection=reason_selection,
            reason_failure=reason_failure,
        )
