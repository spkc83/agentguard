"""Checkpoint-attested lineage verification for credit decision overrides."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Protocol

from pydantic import BaseModel, ConfigDict

from agentguard.exceptions import AuditAttestationError, AuditTamperDetectedError
from agentguard.guardrails.reason_codes import HITL_REVIEW_BAND
from agentguard.models import EvidenceRef  # noqa: TC001 - Pydantic runtime field type

from .agent_templates import CreditDecisionCandidate, CreditDecisionOutcome
from .notice_governance import opaque_credit_ref

if TYPE_CHECKING:
    from agentguard.core.audit import VerifiedAuditSnapshot
    from agentguard.models import AuditEvent, AuditLink


class AuditLogProtocol(Protocol):
    """Minimum verified-audit boundary required by the lineage verifier."""

    async def read_verified(self, *, require_checkpoint: bool = False) -> VerifiedAuditSnapshot: ...


class VerifiedReviewEscalation(BaseModel):
    """Immutable signed lineage that authorizes referencing a completed review."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    escalation_ref: EvidenceRef
    source_review_decision_ref: EvidenceRef
    application_ref: EvidenceRef
    model_ref: EvidenceRef
    requested_event_id: str
    approval_event_id: str
    resumed_event_id: str
    delivery_event_id: str


class ReviewLineageValidator(Protocol):
    """Trusted boundary used inside an admitted override executor."""

    async def verify(
        self,
        *,
        escalation_id: str,
        candidate: CreditDecisionCandidate,
    ) -> VerifiedReviewEscalation: ...


class ReviewEscalationVerifier:
    """Verify that an override parent is a completed review-band escalation."""

    def __init__(self, audit_log: AuditLogProtocol) -> None:
        self._audit_log = audit_log

    async def verify(
        self,
        *,
        escalation_id: str,
        candidate: CreditDecisionCandidate,
    ) -> VerifiedReviewEscalation:
        """Return trusted review lineage or reject the parent reference."""

        return await verify_review_escalation(
            self._audit_log,
            escalation_id=escalation_id,
            candidate=candidate,
        )


def _is_opaque_ref(reference: EvidenceRef, namespace: str) -> bool:
    return (
        reference.namespace == namespace
        and len(reference.value) == 64
        and all(character in "0123456789abcdef" for character in reference.value)
    )


def _require_trusted(snapshot: VerifiedAuditSnapshot) -> None:
    verification = snapshot.verification
    if not verification.valid:
        raise AuditTamperDetectedError(
            event_index=verification.error_index or 0,
            event_id=verification.error_event_id or "<unverified-review-lineage>",
        )
    if not verification.attestable:
        raise AuditAttestationError(verification.checkpoint_status)


def _canonical_escalation_id(value: str) -> str:
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError("escalation_id must be canonical printable text")
    return value


def _require_review_band_evaluation(event: AuditEvent) -> None:
    evaluations = tuple(
        evaluation
        for evaluation in event.guardrail_evaluations
        if evaluation.guardrail_id == "credit-decision-band"
    )
    if len(evaluations) != 1:
        raise ValueError("review request requires one signed decision-band evaluation")
    evaluation = evaluations[0]
    if (
        evaluation.guardrail_version != "1"
        or evaluation.stage != "on_decision"
        or evaluation.effect != "escalate"
        or evaluation.reason_codes != (HITL_REVIEW_BAND,)
        or not evaluation.enforced
    ):
        raise ValueError("review request has invalid signed decision-band evidence")


def _exact_links(event: AuditEvent) -> tuple[AuditLink, AuditLink]:
    if len(event.links) != 2:
        raise ValueError("review lineage requires exactly one decision and one model link")
    decisions = tuple(link for link in event.links if link.relation == "decision")
    models = tuple(link for link in event.links if link.relation == "model")
    if (
        len(decisions) != 1
        or len(models) != 1
        or not _is_opaque_ref(decisions[0].target, "credit-decision")
        or not _is_opaque_ref(models[0].target, "credit-model")
    ):
        raise ValueError("review lineage contains malformed decision or model links")
    return decisions[0], models[0]


def _require_event_contract(
    event: AuditEvent,
    *,
    application_ref: EvidenceRef,
    decision_ref: EvidenceRef,
    model_ref: EvidenceRef,
) -> None:
    if event.subject_ref != application_ref:
        raise ValueError("review lineage application does not match the override")
    decision_link, model_link = _exact_links(event)
    if decision_link.target != decision_ref:
        raise ValueError("review lineage decision links do not match")
    if model_link.target != model_ref:
        raise ValueError("review lineage model does not match the override")
    if (
        event.action != "decision:review"
        or event.permission_context.requested_action != "decision:review"
        or event.permission_context.resource != event.resource
        or not event.permission_context.granted
    ):
        raise ValueError("review lineage is not an authorized decision:review lifecycle")


def _require_review_projection(
    event: AuditEvent,
    *,
    application_ref: EvidenceRef,
    decision_ref: EvidenceRef,
    model_ref: EvidenceRef,
    policy_ref: EvidenceRef,
) -> None:
    if len(event.payload_digest) != 64 or any(
        character not in "0123456789abcdef" for character in event.payload_digest
    ):
        raise ValueError("review lineage is missing its signed payload digest")
    if set(event.payload_redacted) != {"value"}:
        raise ValueError("review lineage has malformed redacted evidence")
    value = event.payload_redacted.get("value")
    if not isinstance(value, Mapping) or set(value) != {
        "application_ref",
        "decision_ref",
        "model_ref",
        "policy_ref",
        "outcome",
    }:
        raise ValueError("review lineage has malformed decision evidence")
    if (
        value.get("application_ref") != application_ref.value
        or value.get("decision_ref") != decision_ref.value
        or value.get("model_ref") != model_ref.value
        or value.get("policy_ref") != policy_ref.value
        or value.get("outcome") != CreditDecisionOutcome.REVIEW.value
    ):
        raise ValueError("review decision evidence does not match its signed lineage")


async def verify_review_escalation(
    audit_log: AuditLogProtocol,
    *,
    escalation_id: str,
    candidate: CreditDecisionCandidate,
) -> VerifiedReviewEscalation:
    """Verify an approved and delivered review before it is linked by an override.

    Only signed, PII-free audit metadata and the allowlisted decision projection
    are inspected. The final candidate's private score and attribution remain
    outside the audit boundary.
    """

    escalation_id = _canonical_escalation_id(escalation_id)
    if candidate.outcome is CreditDecisionOutcome.REVIEW:
        raise ValueError("an override parent can be verified only for a final candidate")

    snapshot = await audit_log.read_verified(require_checkpoint=True)
    _require_trusted(snapshot)
    events = snapshot.events
    requests = tuple(
        (index, event)
        for index, event in enumerate(events)
        if event.event_type == "escalation_requested"
        and event.hitl_evidence is not None
        and event.hitl_evidence.escalation_id == escalation_id
    )
    approvals = tuple(
        (index, event)
        for index, event in enumerate(events)
        if event.event_type == "approval_granted"
        and event.hitl_evidence is not None
        and event.hitl_evidence.escalation_id == escalation_id
    )
    resumes = tuple(
        (index, event)
        for index, event in enumerate(events)
        if event.event_type == "escalation_resumed"
        and event.hitl_evidence is not None
        and event.hitl_evidence.escalation_id == escalation_id
    )
    delivery_id = f"hitl:{escalation_id}:delivery"
    deliveries = tuple(
        (index, event)
        for index, event in enumerate(events)
        if event.event_type == "delivery_completed" and event.event_id == delivery_id
    )
    if len(requests) != 1 or len(approvals) != 1 or len(resumes) != 1 or len(deliveries) != 1:
        raise ValueError("review escalation requires one request, approval, resume, and delivery")

    request_index, request = requests[0]
    approval_index, approval = approvals[0]
    resume_index, resume = resumes[0]
    delivery_index, delivery = deliveries[0]
    if not request_index < approval_index < resume_index < delivery_index:
        raise ValueError("review escalation lifecycle is out of order")
    if request.event_id != f"hitl:{escalation_id}:requested":
        raise ValueError("review escalation request has an invalid stable event ID")
    if request.result != "escalated" or request.reason_codes != (HITL_REVIEW_BAND,):
        raise ValueError("review escalation was not raised by the review-band guardrail")
    _require_review_band_evaluation(request)
    if request.hitl_evidence is None or request.hitl_evidence.state != "requested":
        raise ValueError("review escalation request evidence is malformed")
    if (
        approval.result != "allowed"
        or approval.hitl_evidence is None
        or approval.hitl_evidence.state != "approved"
        or approval.event_id
        != f"hitl:{escalation_id}:decision:{approval.hitl_evidence.decision_id}"
    ):
        raise ValueError("review escalation approval evidence is malformed")
    if (
        resume.result != "allowed"
        or resume.hitl_evidence is None
        or resume.hitl_evidence.state != "approved"
        or resume.event_id != f"hitl:{escalation_id}:resumed:{resume.hitl_evidence.decision_id}"
        or resume.hitl_evidence != approval.hitl_evidence
    ):
        raise ValueError("review escalation resume does not match its approval")
    if delivery.result != "allowed" or delivery.hitl_evidence is not None:
        raise ValueError("review escalation delivery evidence is malformed")

    decision_link, model_link = _exact_links(request)
    application_ref = opaque_credit_ref("credit-application", candidate.application_ref)
    expected_model_ref = opaque_credit_ref(
        "credit-model", f"{candidate.model_id}:{candidate.model_version}"
    )
    expected_policy_ref = opaque_credit_ref(
        "credit-policy", f"{candidate.policy_id}:{candidate.policy_version}"
    )
    if not _is_opaque_ref(
        request.subject_ref or EvidenceRef(namespace="", value=""), "credit-application"
    ):
        raise ValueError("review escalation application reference is malformed")
    if request.subject_ref != application_ref or model_link.target != expected_model_ref:
        raise ValueError("review escalation does not belong to the override candidate")
    final_decision_ref = opaque_credit_ref("credit-decision", candidate.decision_id)
    if decision_link.target != final_decision_ref:
        raise ValueError("an override must reuse the reviewed decision identity")

    for event in (request, approval, resume, delivery):
        _require_event_contract(
            event,
            application_ref=application_ref,
            decision_ref=decision_link.target,
            model_ref=expected_model_ref,
        )
    if any(
        event.invocation_id != request.invocation_id
        or event.trace_id != request.trace_id
        or event.agent_id != request.agent_id
        or event.resource != request.resource
        for event in (approval, resume, delivery)
    ):
        raise ValueError("review escalation lifecycle correlation does not match")
    _require_review_projection(
        request,
        application_ref=application_ref,
        decision_ref=decision_link.target,
        model_ref=expected_model_ref,
        policy_ref=expected_policy_ref,
    )
    _require_review_projection(
        delivery,
        application_ref=application_ref,
        decision_ref=decision_link.target,
        model_ref=expected_model_ref,
        policy_ref=expected_policy_ref,
    )

    return VerifiedReviewEscalation(
        escalation_ref=EvidenceRef(namespace="hitl-escalation", value=escalation_id),
        source_review_decision_ref=decision_link.target,
        application_ref=application_ref,
        model_ref=expected_model_ref,
        requested_event_id=request.event_id,
        approval_event_id=approval.event_id,
        resumed_event_id=resume.event_id,
        delivery_event_id=delivery.event_id,
    )
