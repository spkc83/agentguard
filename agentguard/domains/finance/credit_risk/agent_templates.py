"""Pure credit-decision policy contracts for governed credit emission."""

from __future__ import annotations

import math
from enum import StrEnum
from numbers import Real

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from agentguard.exceptions import AdverseActionFailure  # noqa: TC001 - Pydantic runtime type
from agentguard.guardrails import DecisionPayload

from .attribution import AttributionResult  # noqa: TC001 - Pydantic runtime type
from .decision_reasons import (  # noqa: TC001 - Pydantic runtime type
    PolicyDenialSelection,
    ReviewJudgment,
)
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

    A decline may also rest on a credit-policy overlay denial or a completed
    reviewer's judgment instead of, or alongside, model reasons. Both non-model
    bases must name this exact application and decision, so neither can be
    lifted from another file.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str
    application_ref: str
    outcome: CreditDecisionOutcome
    # The model reference (pd_score + model_id + model_version) is optional as a
    # group: a decline taken BEFORE scoring — an incomplete application or a hard
    # knockout — has no model score. It is all-or-nothing (see the validator), so
    # a partial model reference can never be recorded.
    pd_score: float | None = None
    policy_id: str
    policy_version: str
    model_id: str | None = None
    model_version: str | None = None
    attribution: AttributionResult | None = None
    reason_selection: ReasonCodeSelection | None = None
    policy_denial: PolicyDenialSelection | None = None
    review_judgment: ReviewJudgment | None = None
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
    def _validate_identifiers(cls, value: str | None, info: object) -> str | None:
        if value is None:
            return None
        field_name = getattr(info, "field_name", "identifier")
        return _canonical_text(value, field_name=field_name)

    @field_validator("pd_score", mode="before")
    @classmethod
    def _validate_pd(cls, value: object) -> float | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, Real):
            raise ValueError("pd_score must be a finite value in [0, 1]")
        result = float(value)
        if not math.isfinite(result) or not 0 <= result <= 1:
            raise ValueError("pd_score must be a finite value in [0, 1]")
        return result

    @property
    def has_model_reference(self) -> bool:
        """Whether this decision rests on a model score (all model fields present)."""

        return (
            self.pd_score is not None
            and self.model_id is not None
            and self.model_version is not None
        )

    @model_validator(mode="after")
    def _validate_reason_state(self) -> CreditDecisionCandidate:
        # The model reference is all-or-nothing: a partial reference could let a
        # decision claim a model on one axis (e.g. a model_id link) while omitting
        # the score the provenance guardrail checks.
        model_fields = (self.pd_score, self.model_id, self.model_version)
        present = sum(field is not None for field in model_fields)
        if present not in (0, len(model_fields)):
            raise ValueError(
                "a model reference requires pd_score, model_id, and model_version together"
            )
        if not self.has_model_reference:
            # A pre-scoring decision must be a decline carried by a model-independent
            # basis, and it must not smuggle in model attribution or model reasons.
            if self.outcome is not CreditDecisionOutcome.DECLINE:
                raise ValueError("a decision without a model score must be a decline")
            if self.policy_denial is None and self.review_judgment is None:
                raise ValueError(
                    "a decline without a model score requires a policy or review basis"
                )
            if self.attribution is not None or self.reason_selection is not None:
                raise ValueError(
                    "a decline without a model score cannot carry model attribution or reasons"
                )
        bases = (self.reason_selection, self.policy_denial, self.review_judgment)
        if self.reason_failure is not None and any(basis is not None for basis in bases):
            raise ValueError("a reason failure excludes every principal-reason basis")
        for basis in (self.policy_denial, self.review_judgment):
            if basis is None:
                continue
            if self.outcome is not CreditDecisionOutcome.DECLINE:
                raise ValueError("policy and review reasons are legal only on a decline")
            if (
                basis.application_ref != self.application_ref
                or basis.decision_id != self.decision_id
            ):
                raise ValueError("policy and review reasons must name this application decision")
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
        pd_score: float | None = None,
        model_id: str | None = None,
        model_version: str | None = None,
        attribution: AttributionResult | None = None,
        reason_selection: ReasonCodeSelection | None = None,
        policy_denial: PolicyDenialSelection | None = None,
        review_judgment: ReviewJudgment | None = None,
        reason_failure: AdverseActionFailure | None = None,
    ) -> CreditDecisionCandidate:
        """Classify one PD without fabricating reasons or inspecting raw features.

        A recorded credit-policy overlay denial is a hard cutoff: it declines the
        application whatever band the PD falls in. When no model score is supplied
        (a pre-scoring knockout or incomplete application), a policy or review
        basis is required and the outcome is always a decline; the candidate
        carries no model reference. Passing part of a model reference — a score
        without its model identity, or vice versa — is rejected downstream.
        """

        config = self._config
        if pd_score is None or model_id is None or model_version is None:
            if policy_denial is None and review_judgment is None:
                raise ValueError(
                    "a decision without a model score requires a policy or review basis"
                )
            outcome = CreditDecisionOutcome.DECLINE
        elif policy_denial is not None:
            outcome = CreditDecisionOutcome.DECLINE
        elif pd_score < config.auto_approve_threshold:
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
            policy_denial=policy_denial,
            review_judgment=review_judgment,
            reason_failure=reason_failure,
        )
