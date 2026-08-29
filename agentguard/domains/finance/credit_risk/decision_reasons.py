"""Non-model principal-reason evidence for governed credit declines.

Regulation B requires an adverse action notice to state the actual principal
reasons for the decline. A decline is not always a model decline: a credit
policy overlay can deny on a hard rule, and an underwriter can decline on
judgment after a completed review. This module supplies the two typed,
bindable bases for those reasons so that neither can be asserted as free text.

A ``PolicyDenialSelection`` is only ever produced by evaluating a versioned
:class:`CreditPolicyBundle` over the declared fact schema for one application
and decision, so a guardrail holding the same bundle can recompute it exactly.
A :class:`ReviewJudgment` records reviewer-selected codes drawn from the
versioned ECOA registry and binds them to the escalation whose completed review
lineage ``review_governance`` verifies.
"""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime  # noqa: TC003 - Pydantic resolves this at runtime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.domains.finance.credit_risk.reason_codes import (
    ReasonCode,
    ReasonCodeRegistry,
)
from agentguard.exceptions import AdverseActionError, AdverseActionFailure
from agentguard.guardrails import canonical_json_bytes

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

POLICY_REASON_DIGEST_DOMAIN = "agentguard.credit-policy.reason.v1"
REVIEW_REASON_DIGEST_DOMAIN = "agentguard.credit-review.reason.v1"


def _canonical_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError(f"{field_name} must be canonical nonempty printable text")
    return value


def _finite(value: object, *, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(f"{field_name} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{field_name} must be a finite number")
    return number


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


class _ReasonModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PolicyComparison(StrEnum):
    """Closed comparison vocabulary for one declared credit-policy fact."""

    LESS_THAN = "lt"
    LESS_OR_EQUAL = "le"
    GREATER_THAN = "gt"
    GREATER_OR_EQUAL = "ge"
    EQUAL = "eq"
    NOT_EQUAL = "ne"

    def holds(self, observed: float, threshold: float) -> bool:
        """Return whether ``observed <comparison> threshold`` is satisfied."""

        match self:
            case PolicyComparison.LESS_THAN:
                return observed < threshold
            case PolicyComparison.LESS_OR_EQUAL:
                return observed <= threshold
            case PolicyComparison.GREATER_THAN:
                return observed > threshold
            case PolicyComparison.GREATER_OR_EQUAL:
                return observed >= threshold
            case PolicyComparison.EQUAL:
                return observed == threshold
            case PolicyComparison.NOT_EQUAL:
                return observed != threshold


class PolicyFact(_ReasonModel):
    """One declared, finite credit-policy input value for a single application."""

    name: str
    value: float

    @field_validator("name", mode="before")
    @classmethod
    def _validate_name(cls, value: object) -> str:
        return _canonical_text(value, field_name="name")

    @field_validator("value", mode="before")
    @classmethod
    def _validate_value(cls, value: object) -> float:
        return _finite(value, field_name="value")


class CreditPolicyRule(_ReasonModel):
    """One deterministic hard credit-policy rule bound to a registered code."""

    rule_id: str
    reason_code_id: str
    fact_name: str
    comparison: PolicyComparison
    threshold: float
    severity: int = Field(ge=1)

    @field_validator("rule_id", "reason_code_id", "fact_name", mode="before")
    @classmethod
    def _validate_identifier(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))

    @field_validator("threshold", mode="before")
    @classmethod
    def _validate_threshold(cls, value: object) -> float:
        return _finite(value, field_name="threshold")

    @field_validator("severity", mode="before")
    @classmethod
    def _validate_severity(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("severity must be an integer")
        return value


class PolicyRuleFinding(_ReasonModel):
    """One credit-policy rule that actually denied this application."""

    rule_id: str
    code: ReasonCode
    fact_name: str
    comparison: PolicyComparison
    threshold: float
    observed_value: float
    severity: int = Field(ge=1)
    rank: int = Field(ge=1)

    @field_validator("rule_id", "fact_name", mode="before")
    @classmethod
    def _validate_identifier(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))

    @field_validator("threshold", "observed_value", mode="before")
    @classmethod
    def _validate_number(cls, value: object, info: object) -> float:
        return _finite(value, field_name=getattr(info, "field_name", "value"))

    @field_validator("severity", "rank", mode="before")
    @classmethod
    def _validate_integer(cls, value: object, info: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{getattr(info, 'field_name', 'value')} must be an integer")
        return value

    @model_validator(mode="after")
    def _validate_trigger(self) -> PolicyRuleFinding:
        if not self.comparison.holds(self.observed_value, self.threshold):
            raise ValueError("a policy finding must record a rule that actually triggered")
        return self


class PolicyDenialSelection(_ReasonModel):
    """The complete policy-overlay denial recorded for one credit decision.

    The selection carries the declared facts it was computed from so that a
    guardrail holding the same :class:`CreditPolicyBundle` can recompute every
    finding rather than trusting the caller's rule identifiers.
    """

    taxonomy_version: str
    bundle_id: str
    bundle_version: str
    application_ref: str
    decision_id: str
    facts: tuple[PolicyFact, ...]
    findings: tuple[PolicyRuleFinding, ...]

    @field_validator(
        "taxonomy_version",
        "bundle_id",
        "bundle_version",
        "application_ref",
        "decision_id",
        mode="before",
    )
    @classmethod
    def _validate_identifier(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))

    @model_validator(mode="after")
    def _validate_selection(self) -> PolicyDenialSelection:
        fact_names = tuple(fact.name for fact in self.facts)
        if not fact_names or fact_names != tuple(sorted(set(fact_names))):
            raise ValueError("facts must be unique, nonempty, and sorted by name")
        if not self.findings:
            raise ValueError("a policy denial must contain at least one triggered rule")
        rule_ids = tuple(finding.rule_id for finding in self.findings)
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("policy findings must be unique by rule")
        if tuple(finding.rank for finding in self.findings) != tuple(
            range(1, len(self.findings) + 1)
        ):
            raise ValueError("policy finding ranks must be contiguous and ordered")
        if any(finding.code.code_set_version != self.taxonomy_version for finding in self.findings):
            raise ValueError("policy finding codes must match taxonomy_version")
        known = {fact.name: fact.value for fact in self.facts}
        for finding in self.findings:
            if known.get(finding.fact_name) != finding.observed_value:
                raise ValueError("every policy finding must cite a recorded declared fact")
        expected = tuple(
            sorted(self.findings, key=lambda finding: (-finding.severity, finding.rule_id))
        )
        if self.findings != expected:
            raise ValueError("policy findings must use deterministic severity and rule ordering")
        return self

    def reason_digest(self, finding: PolicyRuleFinding) -> str:
        """Return the binding digest tying one finding to this decision."""

        if finding not in self.findings:
            raise ValueError("finding does not belong to this policy denial")
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "domain": POLICY_REASON_DIGEST_DOMAIN,
                    "application_ref": self.application_ref,
                    "decision_id": self.decision_id,
                    "bundle_id": self.bundle_id,
                    "bundle_version": self.bundle_version,
                    "taxonomy_version": self.taxonomy_version,
                    "rule_id": finding.rule_id,
                    "code": finding.code.code,
                    "fact_name": finding.fact_name,
                    "comparison": finding.comparison.value,
                    "threshold": finding.threshold,
                    "observed_value": finding.observed_value,
                    "severity": finding.severity,
                }
            )
        ).hexdigest()


class JudgmentalReason(_ReasonModel):
    """One reviewer-selected principal reason drawn from the versioned registry."""

    code: ReasonCode
    rank: int = Field(ge=1)

    @field_validator("rank", mode="before")
    @classmethod
    def _validate_rank(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("rank must be an integer")
        return value


class ReviewJudgment(_ReasonModel):
    """A completed human review's own principal reasons for declining.

    ``escalation_id`` is the lineage identifier that
    :func:`~agentguard.domains.finance.credit_risk.review_governance.verify_review_escalation`
    attests before an override may be emitted, so a judgmental reason cannot be
    recorded without a completed, signed review of this application.
    """

    taxonomy_version: str
    application_ref: str
    decision_id: str
    escalation_id: str
    reviewer_id: str
    decided_at: datetime
    reasons: tuple[JudgmentalReason, ...]

    @field_validator(
        "taxonomy_version",
        "application_ref",
        "decision_id",
        "escalation_id",
        "reviewer_id",
        mode="before",
    )
    @classmethod
    def _validate_identifier(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))

    @field_validator("decided_at")
    @classmethod
    def _validate_decided_at(cls, value: datetime) -> datetime:
        return _utc(value, field_name="decided_at")

    @model_validator(mode="after")
    def _validate_reasons(self) -> ReviewJudgment:
        if not self.reasons:
            raise ValueError("a review judgment must state at least one principal reason")
        if tuple(reason.rank for reason in self.reasons) != tuple(range(1, len(self.reasons) + 1)):
            raise ValueError("judgmental reason ranks must be contiguous and ordered")
        if len({reason.code.code for reason in self.reasons}) != len(self.reasons):
            raise ValueError("judgmental reason codes must be unique")
        if any(reason.code.code_set_version != self.taxonomy_version for reason in self.reasons):
            raise ValueError("judgmental reason codes must match taxonomy_version")
        return self

    def reason_digest(self, reason: JudgmentalReason) -> str:
        """Return the binding digest tying one reviewer reason to this review."""

        if reason not in self.reasons:
            raise ValueError("reason does not belong to this review judgment")
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "domain": REVIEW_REASON_DIGEST_DOMAIN,
                    "application_ref": self.application_ref,
                    "decision_id": self.decision_id,
                    "escalation_id": self.escalation_id,
                    "reviewer_id": self.reviewer_id,
                    "decided_at": self.decided_at.isoformat(),
                    "taxonomy_version": self.taxonomy_version,
                    "code": reason.code.code,
                    "rank": reason.rank,
                }
            )
        ).hexdigest()


class CreditPolicyBundle:
    """Immutable versioned set of hard credit-policy rules over declared facts."""

    def __init__(
        self,
        *,
        bundle_id: str,
        bundle_version: str,
        rules: Iterable[CreditPolicyRule],
        registry: ReasonCodeRegistry,
    ) -> None:
        if not isinstance(registry, ReasonCodeRegistry):
            raise TypeError("registry must be a ReasonCodeRegistry")
        self._bundle_id = _canonical_text(bundle_id, field_name="bundle_id")
        self._bundle_version = _canonical_text(bundle_version, field_name="bundle_version")
        self._taxonomy_version = registry.taxonomy_version
        indexed: dict[str, CreditPolicyRule] = {}
        codes: dict[str, ReasonCode] = {}
        for rule in rules:
            if not isinstance(rule, CreditPolicyRule):
                raise TypeError("rules must be CreditPolicyRule instances")
            if rule.rule_id in indexed:
                raise AdverseActionError(AdverseActionFailure.TAXONOMY_MISMATCH)
            indexed[rule.rule_id] = rule
            codes[rule.rule_id] = registry.ecoa_code(rule.reason_code_id)
        if not indexed:
            raise ValueError("a credit policy bundle must declare at least one rule")
        self._rules = MappingProxyType(indexed)
        self._codes = MappingProxyType(codes)
        self._fact_names = tuple(sorted({rule.fact_name for rule in indexed.values()}))

    @property
    def bundle_id(self) -> str:
        return self._bundle_id

    @property
    def bundle_version(self) -> str:
        return self._bundle_version

    @property
    def taxonomy_version(self) -> str:
        return self._taxonomy_version

    @property
    def fact_names(self) -> tuple[str, ...]:
        """Return the complete declared fact schema the bundle evaluates."""

        return self._fact_names

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._rules))

    def evaluate(
        self,
        *,
        application_ref: str,
        decision_id: str,
        facts: Sequence[PolicyFact],
    ) -> PolicyDenialSelection | None:
        """Resolve the complete declared fact schema before selecting denials.

        Returns ``None`` when no rule denies, so a caller cannot attach a policy
        reason to a decision the overlay did not deny.
        """

        ordered = tuple(sorted(facts, key=lambda fact: fact.name))
        if any(not isinstance(fact, PolicyFact) for fact in ordered):
            raise AdverseActionError(AdverseActionFailure.INVALID_ATTRIBUTION)
        if tuple(fact.name for fact in ordered) != self._fact_names:
            raise AdverseActionError(AdverseActionFailure.UNMAPPED_FEATURES)
        observed = {fact.name: fact.value for fact in ordered}
        triggered = [
            (rule, observed[rule.fact_name])
            for rule in self._rules.values()
            if rule.comparison.holds(observed[rule.fact_name], rule.threshold)
        ]
        if not triggered:
            return None
        triggered.sort(key=lambda item: (-item[0].severity, item[0].rule_id))
        findings = tuple(
            PolicyRuleFinding(
                rule_id=rule.rule_id,
                code=self._codes[rule.rule_id],
                fact_name=rule.fact_name,
                comparison=rule.comparison,
                threshold=rule.threshold,
                observed_value=value,
                severity=rule.severity,
                rank=rank,
            )
            for rank, (rule, value) in enumerate(triggered, 1)
        )
        return PolicyDenialSelection(
            taxonomy_version=self._taxonomy_version,
            bundle_id=self._bundle_id,
            bundle_version=self._bundle_version,
            application_ref=application_ref,
            decision_id=decision_id,
            facts=ordered,
            findings=findings,
        )


__all__ = [
    "POLICY_REASON_DIGEST_DOMAIN",
    "REVIEW_REASON_DIGEST_DOMAIN",
    "CreditPolicyBundle",
    "CreditPolicyRule",
    "JudgmentalReason",
    "PolicyComparison",
    "PolicyDenialSelection",
    "PolicyFact",
    "PolicyRuleFinding",
    "ReviewJudgment",
]
