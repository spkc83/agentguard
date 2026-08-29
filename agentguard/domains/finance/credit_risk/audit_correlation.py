"""Verified audit correlation for unresolved adverse-action notices."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias

from pydantic import BaseModel, ConfigDict, ValidationError

from agentguard.exceptions import (
    AdverseActionError,
    AuditAttestationError,
    AuditTamperDetectedError,
)
from agentguard.models import EvidenceRef  # noqa: TC001 - Pydantic runtime field type

from .governed_agent import DecisionAuditEvidence
from .notice_governance import NoticeIssueEvidence

if TYPE_CHECKING:
    from agentguard.core.audit import VerifiedAuditSnapshot
    from agentguard.models import AuditEvent, AuditLink

UNRESOLVED_DECLINE_CODE: Literal["AA.UNRESOLVED_DECLINE"] = "AA.UNRESOLVED_DECLINE"
LinkageIntegrityError: TypeAlias = Literal["decision_link", "application_link", "decision_evidence"]


class AuditLogProtocol(Protocol):
    """Minimum verified-audit boundary required by the correlator."""

    async def read_verified(self, *, require_checkpoint: bool = False) -> VerifiedAuditSnapshot: ...


class UnresolvedDeclineFinding(BaseModel):
    """Immutable, PII-free evidence that a delivered decline lacks a valid notice."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: Literal["AA.UNRESOLVED_DECLINE"] = UNRESOLVED_DECLINE_CODE
    decision_ref: EvidenceRef | None = None
    application_ref: EvidenceRef | None = None
    decline_event_id: str
    integrity_errors: tuple[LinkageIntegrityError, ...] = ()


def _is_opaque_ref(reference: EvidenceRef, namespace: str) -> bool:
    value = reference.value
    return (
        reference.namespace == namespace
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _decision_link(event: AuditEvent) -> AuditLink | None:
    links = tuple(link for link in event.links if link.relation == "decision")
    if len(links) != 1 or not _is_opaque_ref(links[0].target, "credit-decision"):
        return None
    return links[0]


def _application_ref(event: AuditEvent) -> EvidenceRef | None:
    subject = event.subject_ref
    if subject is None or not _is_opaque_ref(subject, "credit-application"):
        return None
    return subject


def _notice_evidence(event: AuditEvent) -> NoticeIssueEvidence | None:
    value = event.payload_redacted.get("value")
    if not isinstance(value, Mapping):
        return None
    candidate: object = value
    if value.get("kind") == "decision":
        if value.get("domain") != "credit_risk_notice" or value.get("outcome") != "issued":
            return None
        candidate = value.get("body")
    try:
        return NoticeIssueEvidence.model_validate(candidate)
    except (AdverseActionError, TypeError, ValidationError, ValueError):
        return None


def _decision_evidence(event: AuditEvent) -> DecisionAuditEvidence | None:
    value = event.payload_redacted.get("value")
    if not isinstance(value, Mapping):
        return None
    try:
        return DecisionAuditEvidence.model_validate(value)
    except (TypeError, ValidationError, ValueError):
        return None


def _has_exact_allow_control(event: AuditEvent, guardrail_id: str) -> bool:
    evaluations = tuple(
        evaluation
        for evaluation in event.guardrail_evaluations
        if evaluation.guardrail_id == guardrail_id
    )
    return len(evaluations) == 1 and (
        evaluations[0].guardrail_version == "1"
        and evaluations[0].stage == "on_decision"
        and evaluations[0].effect == "allow"
        and evaluations[0].enforced
    )


def _is_delivered(event: AuditEvent, action: str) -> bool:
    return (
        event.event_type == "delivery_completed"
        and event.action == action
        and event.result == "allowed"
    )


def _require_trusted(snapshot: VerifiedAuditSnapshot) -> None:
    verification = snapshot.verification
    if not verification.valid:
        raise AuditTamperDetectedError(
            event_index=verification.error_index or 0,
            event_id=verification.error_event_id or "<unverified-evidence>",
        )
    if not verification.attestable:
        raise AuditAttestationError(verification.checkpoint_status)


async def find_unresolved_declines(
    audit_log: AuditLogProtocol,
) -> tuple[UnresolvedDeclineFinding, ...]:
    """Find delivered declines lacking a later, timely, exactly linked notice.

    Classification uses only signed event metadata, typed opaque references, and
    allowlisted notice evidence. Raw decision payloads and applicant data are not
    inspected.
    """

    snapshot = await audit_log.read_verified(require_checkpoint=True)
    _require_trusted(snapshot)

    valid_notices: list[tuple[int, EvidenceRef, EvidenceRef]] = []
    for index, event in enumerate(snapshot.events):
        if not _is_delivered(event, "notice:issue"):
            continue
        if not _has_exact_allow_control(event, "credit-notice-completeness"):
            continue
        decision_link = _decision_link(event)
        application_ref = _application_ref(event)
        evidence = _notice_evidence(event)
        if (
            decision_link is None
            or application_ref is None
            or evidence is None
            or evidence.decision_ref != decision_link.target.value
            or evidence.application_ref != application_ref.value
        ):
            continue
        valid_notices.append((index, decision_link.target, application_ref))

    findings: list[UnresolvedDeclineFinding] = []
    for index, event in enumerate(snapshot.events):
        direct_decline = _is_delivered(event, "decision:decline")
        delivered_override = _is_delivered(event, "decision:override")
        if not direct_decline and not delivered_override:
            continue
        decision_link = _decision_link(event)
        decline_application = _application_ref(event)
        invalid_links: list[LinkageIntegrityError] = []
        if decision_link is None:
            invalid_links.append("decision_link")
        if decline_application is None:
            invalid_links.append("application_link")
        if delivered_override:
            override_evidence = _decision_evidence(event)
            evidence_matches_links = (
                _has_exact_allow_control(event, "credit-decision-evidence")
                and override_evidence is not None
                and override_evidence.outcome.value in {"approve", "decline"}
                and decision_link is not None
                and override_evidence.decision_ref == decision_link.target.value
                and decline_application is not None
                and override_evidence.application_ref == decline_application.value
            )
            if not evidence_matches_links:
                invalid_links.append("decision_evidence")
            elif override_evidence is not None and override_evidence.outcome.value == "approve":
                continue
        integrity_errors = tuple(invalid_links)
        resolved = (
            not integrity_errors
            and decision_link is not None
            and decline_application is not None
            and any(
                notice_index > index
                and notice_ref == decision_link.target
                and notice_application == decline_application
                for notice_index, notice_ref, notice_application in valid_notices
            )
        )
        if resolved:
            continue
        findings.append(
            UnresolvedDeclineFinding(
                decision_ref=None if decision_link is None else decision_link.target,
                application_ref=decline_application,
                decline_event_id=event.event_id,
                integrity_errors=integrity_errors,
            )
        )
    return tuple(findings)
