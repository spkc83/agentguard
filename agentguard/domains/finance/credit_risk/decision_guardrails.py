"""Runtime guardrails for truthful governed credit-decision emission."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

from agentguard.exceptions import AdverseActionError
from agentguard.guardrails import (
    DecisionPayload,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
    thaw_payload,
)
from agentguard.guardrails.reason_codes import (
    AA_ATTRIBUTION_MODEL_MISMATCH,
    AA_CODE_NOT_ATTRIBUTED,
    AA_NO_REASON_CODES,
    AA_POLICY_REASON_UNBOUND,
    AA_REVIEW_REASON_UNBOUND,
    AA_UNKNOWN_CODE,
    FAIR_PROTECTED_FEATURE_IN_INPUT,
    HITL_REVIEW_BAND,
    PII_UNSAFE_DECISION_EVIDENCE,
)

from .agent_templates import CreditDecisionCandidate, CreditDecisionOutcome
from .decision_reasons import CreditPolicyBundle
from .reason_codes import ReasonCodeMapper, ReasonCodeRegistry

_ON_DECISION = frozenset({GuardrailStage.ON_DECISION})
_OVERRIDE_ACTION = "decision:override"


def _governs_credit_decision(context: GuardrailContext) -> bool:
    return context.action.startswith("decision:")


def parse_credit_candidate(context: GuardrailContext) -> CreditDecisionCandidate | None:
    payload = context.payload
    if not isinstance(payload, DecisionPayload) or payload.domain != "credit_risk":
        return None
    try:
        candidate = CreditDecisionCandidate.model_validate(thaw_payload(payload.body))
    except (TypeError, ValueError):
        return None
    if candidate.decision_id != payload.decision_id or candidate.outcome.value != payload.outcome:
        return None
    return candidate


def _invalid_payload() -> GuardrailOutcome:
    return GuardrailOutcome(
        effect=GuardrailEffect.DENY,
        reason_codes=(PII_UNSAFE_DECISION_EVIDENCE,),
    )


class DecisionEvidenceGuardrail:
    """Reject anything other than the exact typed credit-decision envelope."""

    id = "credit-decision-evidence"
    version = "1"
    resume_fingerprint = (
        "agentguard.domains.finance.credit_risk.decision_guardrails:DecisionEvidenceGuardrail:1"
    )
    stages = _ON_DECISION
    config: dict[str, object] = {"domain": "credit_risk"}

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if not _governs_credit_decision(context):
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        candidate = parse_credit_candidate(context)
        if candidate is None:
            return _invalid_payload()
        expected_action = f"decision:{candidate.outcome.value}"
        if context.action == "decision:override":
            if candidate.outcome is CreditDecisionOutcome.REVIEW:
                return _invalid_payload()
        elif context.action != expected_action:
            return _invalid_payload()
        try:
            from .governed_agent import DecisionAuditEvidence, decision_audit_evidence

            retained = context.attributes.get("redacted_evidence")
            projected = DecisionAuditEvidence.model_validate(thaw_payload(retained))
        except (TypeError, ValueError):
            return _invalid_payload()
        if projected != decision_audit_evidence(candidate):
            return _invalid_payload()
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


class ProtectedAttributeGuardrail:
    """Deny decisions whose complete evaluated schema uses forbidden features."""

    id = "credit-protected-attributes"
    version = "1"
    resume_fingerprint = (
        "agentguard.domains.finance.credit_risk.decision_guardrails:ProtectedAttributeGuardrail:1"
    )
    stages = _ON_DECISION

    def __init__(self, protected_features: Iterable[str]) -> None:
        features = tuple(sorted(set(protected_features)))
        if not features or any(
            not feature or feature != feature.strip() or not feature.isprintable()
            for feature in features
        ):
            raise ValueError("protected_features must be nonempty canonical identifiers")
        self._protected_features = frozenset(features)
        self.config = {"protected_features": features}

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if not _governs_credit_decision(context):
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        candidate = parse_credit_candidate(context)
        if candidate is None:
            return _invalid_payload()
        attribution = candidate.attribution
        if attribution is not None and self._protected_features.intersection(
            attribution.feature_names
        ):
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(FAIR_PROTECTED_FEATURE_IN_INPUT,),
            )
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


class DecisionBandGuardrail:
    """Escalate review-band results without converting them to declines."""

    id = "credit-decision-band"
    version = "1"
    resume_fingerprint = (
        "agentguard.domains.finance.credit_risk.decision_guardrails:DecisionBandGuardrail:1"
    )
    stages = _ON_DECISION
    config: dict[str, object] = {}

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if not _governs_credit_decision(context):
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        candidate = parse_credit_candidate(context)
        if candidate is None:
            return _invalid_payload()
        if candidate.outcome is CreditDecisionOutcome.REVIEW:
            return GuardrailOutcome(
                effect=GuardrailEffect.ESCALATE,
                reason_codes=(HITL_REVIEW_BAND,),
            )
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


def _declared_codes(candidate: CreditDecisionCandidate) -> tuple[tuple[str, str], ...]:
    """Return every (code, taxonomy version) pair the decline actually cites."""

    declared: list[tuple[str, str]] = []
    if candidate.reason_selection is not None:
        selection = candidate.reason_selection
        declared.extend(
            (reason.code.code, selection.taxonomy_version) for reason in selection.reasons
        )
    if candidate.policy_denial is not None:
        denial = candidate.policy_denial
        declared.extend((finding.code.code, denial.taxonomy_version) for finding in denial.findings)
    if candidate.review_judgment is not None:
        judgment = candidate.review_judgment
        declared.extend(
            (reason.code.code, judgment.taxonomy_version) for reason in judgment.reasons
        )
    return tuple(declared)


class ReasonCodeGuardrail:
    """Require known versioned ECOA principal reasons for every decline.

    A decline may cite model reasons, credit-policy overlay reasons, a completed
    reviewer's own reasons, or a mix. Every cited code, whatever its basis, must
    come from the same registered taxonomy.
    """

    id = "credit-reason-codes"
    version = "1"
    resume_fingerprint = (
        "agentguard.domains.finance.credit_risk.decision_guardrails:ReasonCodeGuardrail:1"
    )
    stages = _ON_DECISION

    def __init__(self, registry: ReasonCodeRegistry) -> None:
        if not isinstance(registry, ReasonCodeRegistry):
            raise TypeError("registry must be a ReasonCodeRegistry")
        self._taxonomy_version = registry.taxonomy_version
        self._known_codes = frozenset(registry.ecoa_code_ids)
        self.config = {
            "taxonomy_version": self._taxonomy_version,
            "known_codes": tuple(sorted(self._known_codes)),
        }

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if not _governs_credit_decision(context):
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        candidate = parse_credit_candidate(context)
        if candidate is None:
            return _invalid_payload()
        if candidate.outcome is not CreditDecisionOutcome.DECLINE:
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        if candidate.reason_failure is not None:
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(candidate.reason_failure.value,),
            )
        declared = _declared_codes(candidate)
        if not declared:
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(AA_NO_REASON_CODES,),
            )
        if any(
            version != self._taxonomy_version or code not in self._known_codes
            for code, version in declared
        ):
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(AA_UNKNOWN_CODE,),
            )
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


class AttributionIntegrityGuardrail:
    """Recompute reason evidence and require an exact attribution match.

    A decline that states no model reason is checked only when it has no other
    basis: a decline resting on a policy-overlay denial or a completed review
    cites those reasons instead, and each is verified by its own control.
    """

    id = "credit-attribution-integrity"
    version = "1"
    resume_fingerprint = (
        "agentguard.domains.finance.credit_risk.decision_guardrails:AttributionIntegrityGuardrail:1"
    )
    stages = _ON_DECISION

    def __init__(self, mapper: ReasonCodeMapper, registry: ReasonCodeRegistry) -> None:
        if not isinstance(mapper, ReasonCodeMapper):
            raise TypeError("mapper must be a ReasonCodeMapper")
        if not isinstance(registry, ReasonCodeRegistry):
            raise TypeError("registry must be a ReasonCodeRegistry")
        self._mapper = mapper
        self.config = {
            "taxonomy_version": registry.taxonomy_version,
            "feature_names": registry.ecoa_feature_names,
            "known_codes": registry.ecoa_code_ids,
        }

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if not _governs_credit_decision(context):
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        candidate = parse_credit_candidate(context)
        if candidate is None:
            return _invalid_payload()
        if candidate.outcome is not CreditDecisionOutcome.DECLINE:
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        attribution = candidate.attribution
        selection = candidate.reason_selection
        if selection is None:
            non_model_basis = candidate.policy_denial is not None or (
                candidate.review_judgment is not None
            )
            if non_model_basis:
                return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(AA_CODE_NOT_ATTRIBUTED,),
            )
        if attribution is None:
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(AA_CODE_NOT_ATTRIBUTED,),
            )
        if (
            candidate.model_id != attribution.model_id
            or candidate.model_version != attribution.model_version
            or selection.model_id != attribution.model_id
            or selection.model_version != attribution.model_version
            or selection.reference_id != attribution.reference_id
            or selection.attribution_method is not attribution.method
            or selection.feature_names != attribution.feature_names
        ):
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(AA_ATTRIBUTION_MODEL_MISMATCH,),
            )
        try:
            expected = self._mapper.map(attribution)
        except AdverseActionError as exc:
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(exc.reason_code,),
            )
        if selection != expected:
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(AA_CODE_NOT_ATTRIBUTED,),
            )
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


class PolicyReasonIntegrityGuardrail:
    """Recompute a claimed credit-policy denial from its own recorded facts.

    The control holds the versioned bundle itself, so a policy principal reason
    survives only when re-evaluating that bundle over the facts recorded for
    this application and decision produces exactly the claimed denial.
    """

    id = "credit-policy-reason-integrity"
    version = "1"
    resume_fingerprint = (
        "agentguard.domains.finance.credit_risk.decision_guardrails:"
        "PolicyReasonIntegrityGuardrail:1"
    )
    stages = _ON_DECISION

    def __init__(self, bundle: CreditPolicyBundle) -> None:
        if not isinstance(bundle, CreditPolicyBundle):
            raise TypeError("bundle must be a CreditPolicyBundle")
        self._bundle = bundle
        self.config = {
            "bundle_id": bundle.bundle_id,
            "bundle_version": bundle.bundle_version,
            "taxonomy_version": bundle.taxonomy_version,
            "rule_ids": bundle.rule_ids,
            "fact_names": bundle.fact_names,
        }

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if not _governs_credit_decision(context):
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        candidate = parse_credit_candidate(context)
        if candidate is None:
            return _invalid_payload()
        denial = candidate.policy_denial
        if denial is None:
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        if (
            candidate.outcome is not CreditDecisionOutcome.DECLINE
            or denial.bundle_id != self._bundle.bundle_id
            or denial.bundle_version != self._bundle.bundle_version
        ):
            return _unbound_policy_reason()
        try:
            recomputed = self._bundle.evaluate(
                application_ref=candidate.application_ref,
                decision_id=candidate.decision_id,
                facts=denial.facts,
            )
        except (AdverseActionError, TypeError, ValueError):
            return _unbound_policy_reason()
        if recomputed != denial:
            return _unbound_policy_reason()
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


class ReviewReasonIntegrityGuardrail:
    """Admit a reviewer's own principal reasons only on a reviewed override.

    A judgmental reason cannot be recomputed, so it is bound instead: it is
    legal only on a ``decision:override`` decline that names this application,
    decision, and the escalation whose completed review lineage the override
    executor verifies before emission.
    """

    id = "credit-review-reason-integrity"
    version = "1"
    resume_fingerprint = (
        "agentguard.domains.finance.credit_risk.decision_guardrails:"
        "ReviewReasonIntegrityGuardrail:1"
    )
    stages = _ON_DECISION

    def __init__(self, registry: ReasonCodeRegistry) -> None:
        if not isinstance(registry, ReasonCodeRegistry):
            raise TypeError("registry must be a ReasonCodeRegistry")
        self._taxonomy_version = registry.taxonomy_version
        self._known_codes = frozenset(registry.ecoa_code_ids)
        self.config = {
            "taxonomy_version": self._taxonomy_version,
            "known_codes": tuple(sorted(self._known_codes)),
        }

    async def evaluate(self, context: GuardrailContext) -> GuardrailOutcome:
        if not _governs_credit_decision(context):
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        candidate = parse_credit_candidate(context)
        if candidate is None:
            return _invalid_payload()
        judgment = candidate.review_judgment
        if judgment is None:
            return GuardrailOutcome(effect=GuardrailEffect.ALLOW)
        if (
            context.action != _OVERRIDE_ACTION
            or candidate.outcome is not CreditDecisionOutcome.DECLINE
            or judgment.application_ref != candidate.application_ref
            or judgment.decision_id != candidate.decision_id
            or judgment.taxonomy_version != self._taxonomy_version
            or any(reason.code.code not in self._known_codes for reason in judgment.reasons)
        ):
            return GuardrailOutcome(
                effect=GuardrailEffect.DENY,
                reason_codes=(AA_REVIEW_REASON_UNBOUND,),
            )
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


def _unbound_policy_reason() -> GuardrailOutcome:
    return GuardrailOutcome(
        effect=GuardrailEffect.DENY,
        reason_codes=(AA_POLICY_REASON_UNBOUND,),
    )
