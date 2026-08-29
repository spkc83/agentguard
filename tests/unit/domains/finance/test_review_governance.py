"""Review overrides require checkpoint-attested, exact audit lineage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agentguard.core.audit import ChainVerificationResult, VerifiedAuditSnapshot
from agentguard.domains.finance.credit_risk.agent_templates import (
    CreditDecisionCandidate,
    CreditDecisionOutcome,
)
from agentguard.domains.finance.credit_risk.notice_governance import opaque_credit_ref
from agentguard.domains.finance.credit_risk.review_governance import (
    ReviewEscalationVerifier,
    verify_review_escalation,
)
from agentguard.exceptions import AuditAttestationError, AuditTamperDetectedError
from agentguard.guardrails.reason_codes import HITL_REVIEW_BAND
from agentguard.models import (
    AgentIdentity,
    AuditEvent,
    AuditLink,
    EvidenceRef,
    GuardrailEvaluation,
    HitlEvidence,
    PermissionContext,
)

_NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)
_ESCALATION_ID = "escalation-review-1"
_APPLICATION_ID = "application-local-1"
_SOURCE_DECISION_ID = "review-decision-1"
_MODEL_ID = "credit-model"
_MODEL_VERSION = "2026.08"
_INVOCATION_ID = "invocation-review-1"
_TRACE_ID = "trace-review-1"
_APPLICATION = opaque_credit_ref("credit-application", _APPLICATION_ID)
_SOURCE_DECISION = opaque_credit_ref("credit-decision", _SOURCE_DECISION_ID)
_MODEL = opaque_credit_ref("credit-model", f"{_MODEL_ID}:{_MODEL_VERSION}")
_POLICY = opaque_credit_ref("credit-policy", "credit-policy:2026.08")
_REVIEW_BAND_EVALUATION = GuardrailEvaluation(
    guardrail_id="credit-decision-band",
    guardrail_version="1",
    stage="on_decision",
    effect="escalate",
    reason_codes=(HITL_REVIEW_BAND,),
    duration_ms=0.1,
    enforced=True,
)


class _Audit:
    def __init__(self, snapshot: VerifiedAuditSnapshot) -> None:
        self.snapshot = snapshot
        self.require_checkpoint: bool | None = None

    async def read_verified(self, *, require_checkpoint: bool = False) -> VerifiedAuditSnapshot:
        self.require_checkpoint = require_checkpoint
        return self.snapshot


def _candidate(
    *,
    application_ref: str = _APPLICATION_ID,
    decision_id: str = _SOURCE_DECISION_ID,
    model_version: str = _MODEL_VERSION,
    policy_version: str = "2026.08",
    outcome: CreditDecisionOutcome = CreditDecisionOutcome.APPROVE,
) -> CreditDecisionCandidate:
    return CreditDecisionCandidate(
        decision_id=decision_id,
        application_ref=application_ref,
        outcome=outcome,
        pd_score=0.02,
        policy_id="credit-policy",
        policy_version=policy_version,
        model_id=_MODEL_ID,
        model_version=model_version,
    )


def _links(
    *,
    decision: EvidenceRef = _SOURCE_DECISION,
    model: EvidenceRef = _MODEL,
) -> tuple[AuditLink, ...]:
    return (
        AuditLink(relation="decision", target=decision),
        AuditLink(relation="model", target=model),
    )


def _projection(
    *,
    decision: EvidenceRef = _SOURCE_DECISION,
    model: EvidenceRef = _MODEL,
    policy: EvidenceRef = _POLICY,
    outcome: str = "review",
) -> dict[str, object]:
    return {
        "value": {
            "application_ref": _APPLICATION.value,
            "decision_ref": decision.value,
            "model_ref": model.value,
            "policy_ref": policy.value,
            "outcome": outcome,
        }
    }


def _event(
    event_type: str,
    *,
    event_id: str,
    result: str,
    hitl: HitlEvidence | None = None,
    reason_codes: tuple[str, ...] = (),
    guardrail_evaluations: tuple[GuardrailEvaluation, ...] = (),
    subject_ref: EvidenceRef = _APPLICATION,
    links: tuple[AuditLink, ...] | None = None,
    payload_redacted: dict[str, object] | None = None,
    payload_digest: str = "",
    invocation_id: str = _INVOCATION_ID,
    trace_id: str = _TRACE_ID,
) -> AuditEvent:
    identity = AgentIdentity(agent_id="agent-credit", name="Credit Agent", roles=["credit"])
    return AuditEvent.model_validate(
        {
            "event_id": event_id,
            "timestamp": _NOW,
            "agent_id": identity.agent_id,
            "action": "decision:review",
            "resource": "credit/decision",
            "permission_context": PermissionContext(
                agent=identity,
                requested_action="decision:review",
                resource="credit/decision",
                granted=True,
                reason="authorized",
            ),
            "result": result,
            "duration_ms": 1.0,
            "trace_id": trace_id,
            "invocation_id": invocation_id,
            "event_type": event_type,
            "reason_codes": reason_codes,
            "guardrail_evaluations": guardrail_evaluations,
            "payload_digest": payload_digest,
            "payload_redacted": payload_redacted or {},
            "subject_ref": subject_ref,
            "links": _links() if links is None else links,
            "hitl_evidence": hitl,
        }
    )


def _events() -> tuple[AuditEvent, AuditEvent, AuditEvent, AuditEvent]:
    request = _event(
        "escalation_requested",
        event_id=f"hitl:{_ESCALATION_ID}:requested",
        result="escalated",
        hitl=HitlEvidence(
            escalation_id=_ESCALATION_ID,
            state="requested",
            expires_at=_NOW + timedelta(hours=1),
        ),
        reason_codes=(HITL_REVIEW_BAND,),
        guardrail_evaluations=(_REVIEW_BAND_EVALUATION,),
        payload_redacted=_projection(),
        payload_digest="a" * 64,
    )
    approval = _event(
        "approval_granted",
        event_id=f"hitl:{_ESCALATION_ID}:decision:approval-1",
        result="allowed",
        hitl=HitlEvidence(
            escalation_id=_ESCALATION_ID,
            decision_id="approval-1",
            state="approved",
            approver_id="underwriter-1",
            decided_at=_NOW + timedelta(minutes=1),
        ),
    )
    resumed = _event(
        "escalation_resumed",
        event_id=f"hitl:{_ESCALATION_ID}:resumed:approval-1",
        result="allowed",
        hitl=approval.hitl_evidence,
        reason_codes=(HITL_REVIEW_BAND,),
        payload_redacted=_projection(),
        payload_digest="a" * 64,
    )
    delivery = _event(
        "delivery_completed",
        event_id=f"hitl:{_ESCALATION_ID}:delivery",
        result="allowed",
        payload_redacted=_projection(),
        payload_digest="a" * 64,
    )
    return request, approval, resumed, delivery


def _snapshot(
    *events: AuditEvent,
    valid: bool = True,
    attestable: bool = True,
) -> VerifiedAuditSnapshot:
    return VerifiedAuditSnapshot(
        events=events,
        verification=ChainVerificationResult(
            valid=valid,
            event_count=len(events),
            error_index=None if valid else 1,
            error_event_id=None if valid else "event-broken",
            checkpoint_valid=attestable,
            checkpoint_status="verified" if attestable else "verified_unanchored",
            attestable=attestable,
        ),
    )


@pytest.mark.asyncio
async def test_verified_review_returns_frozen_exact_lineage() -> None:
    audit = _Audit(_snapshot(*_events()))

    verified = await ReviewEscalationVerifier(audit).verify(
        escalation_id=_ESCALATION_ID,
        candidate=_candidate(),
    )

    assert audit.require_checkpoint is True
    assert verified.escalation_ref == EvidenceRef(namespace="hitl-escalation", value=_ESCALATION_ID)
    assert verified.source_review_decision_ref == _SOURCE_DECISION
    assert verified.application_ref == _APPLICATION
    assert verified.model_ref == _MODEL
    assert verified.resumed_event_id == f"hitl:{_ESCALATION_ID}:resumed:approval-1"
    with pytest.raises(ValidationError, match="frozen"):
        verified.delivery_event_id = "changed"


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_index", range(4))
async def test_missing_lifecycle_transition_is_rejected(missing_index: int) -> None:
    events = _events()

    with pytest.raises(ValueError, match="one request, approval, resume, and delivery"):
        await verify_review_escalation(
            _Audit(
                _snapshot(*(event for index, event in enumerate(events) if index != missing_index))
            ),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )


@pytest.mark.asyncio
async def test_duplicate_and_out_of_order_lifecycle_are_rejected() -> None:
    request, approval, resumed, delivery = _events()
    for events, message in (
        ((request, request, approval, resumed, delivery), "one request"),
        ((request, approval, resumed, resumed, delivery), "one request"),
        ((approval, request, resumed, delivery), "out of order"),
        ((request, resumed, approval, delivery), "out of order"),
    ):
        with pytest.raises(ValueError, match=message):
            await verify_review_escalation(
                _Audit(_snapshot(*events)),
                escalation_id=_ESCALATION_ID,
                candidate=_candidate(),
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("event_index", range(4))
@pytest.mark.parametrize("mismatch", ["application", "model", "decision"])
async def test_any_lifecycle_linkage_mismatch_is_rejected(
    event_index: int,
    mismatch: str,
) -> None:
    events = list(_events())
    other = EvidenceRef(
        namespace={
            "application": "credit-application",
            "model": "credit-model",
            "decision": "credit-decision",
        }[mismatch],
        value="f" * 64,
    )
    update: dict[str, object]
    if mismatch == "application":
        update = {"subject_ref": other}
    elif mismatch == "model":
        update = {"links": _links(model=other)}
    else:
        update = {"links": _links(decision=other)}
    events[event_index] = events[event_index].model_copy(update=update)

    with pytest.raises(ValueError, match="application|model|decision|does not belong"):
        await verify_review_escalation(
            _Audit(_snapshot(*events)),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("candidate", "message"),
    [
        (_candidate(application_ref="different-application"), "does not belong"),
        (_candidate(model_version="different-version"), "does not belong"),
        (_candidate(decision_id="different-decision"), "reuse the reviewed decision"),
        (_candidate(policy_version="different-version"), "decision evidence"),
        (_candidate(outcome=CreditDecisionOutcome.REVIEW), "final candidate"),
    ],
)
async def test_override_candidate_must_match_reviewed_entity_and_governance(
    candidate: CreditDecisionCandidate,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        await verify_review_escalation(
            _Audit(_snapshot(*_events())),
            escalation_id=_ESCALATION_ID,
            candidate=candidate,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "update",
    [
        {"reason_codes": ()},
        {"reason_codes": (HITL_REVIEW_BAND, "OTHER")},
        {"payload_digest": ""},
        {"payload_redacted": _projection(outcome="approve")},
        {"payload_redacted": {"value": {"outcome": "review"}}},
        {"links": (*_links(), AuditLink(relation="parent", target=_SOURCE_DECISION))},
    ],
)
async def test_malformed_request_evidence_is_rejected(update: dict[str, object]) -> None:
    request, approval, resumed, delivery = _events()

    with pytest.raises(ValueError):
        await verify_review_escalation(
            _Audit(_snapshot(request.model_copy(update=update), approval, resumed, delivery)),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "evaluation",
    [
        None,
        _REVIEW_BAND_EVALUATION.model_copy(update={"guardrail_id": "other-guardrail"}),
        _REVIEW_BAND_EVALUATION.model_copy(update={"guardrail_version": "2"}),
        _REVIEW_BAND_EVALUATION.model_copy(update={"stage": "post_tool"}),
        _REVIEW_BAND_EVALUATION.model_copy(update={"effect": "deny"}),
        _REVIEW_BAND_EVALUATION.model_copy(update={"reason_codes": ("OTHER",)}),
    ],
)
async def test_review_request_rejects_missing_or_wrong_signed_band_evaluation(
    evaluation: GuardrailEvaluation | None,
) -> None:
    request, approval, resumed, delivery = _events()
    request = request.model_copy(
        update={"guardrail_evaluations": () if evaluation is None else (evaluation,)}
    )

    with pytest.raises(ValueError, match="decision-band"):
        await verify_review_escalation(
            _Audit(_snapshot(request, approval, resumed, delivery)),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )


@pytest.mark.asyncio
async def test_review_request_rejects_duplicate_signed_band_evaluations() -> None:
    request, approval, resumed, delivery = _events()
    request = request.model_copy(
        update={
            "guardrail_evaluations": (
                _REVIEW_BAND_EVALUATION,
                _REVIEW_BAND_EVALUATION,
            )
        }
    )

    with pytest.raises(ValueError, match="one signed decision-band"):
        await verify_review_escalation(
            _Audit(_snapshot(request, approval, resumed, delivery)),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )


@pytest.mark.asyncio
async def test_review_request_rejects_non_enforced_band_evaluation() -> None:
    request, approval, resumed, delivery = _events()
    request = request.model_copy(
        update={
            "chain_mode": "shadow",
            "guardrail_evaluations": (
                _REVIEW_BAND_EVALUATION.model_copy(update={"enforced": False}),
            ),
        }
    )

    with pytest.raises(ValueError, match="invalid signed decision-band"):
        await verify_review_escalation(
            _Audit(_snapshot(request, approval, resumed, delivery)),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )


@pytest.mark.asyncio
async def test_mismatched_lifecycle_correlation_is_rejected() -> None:
    request, approval, resumed, delivery = _events()
    approval = approval.model_copy(update={"invocation_id": "different-invocation"})

    with pytest.raises(ValueError, match="correlation"):
        await verify_review_escalation(
            _Audit(_snapshot(request, approval, resumed, delivery)),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["decision_id", "approver_id", "state"])
async def test_resume_must_match_approved_hitl_identity_and_state(field: str) -> None:
    request, approval, resumed, delivery = _events()
    assert resumed.hitl_evidence is not None
    values: dict[str, object] = {
        "decision_id": "different-approval",
        "approver_id": "different-underwriter",
        "state": "denied",
    }
    changed = resumed.hitl_evidence.model_copy(update={field: values[field]})
    resumed = resumed.model_copy(update={"hitl_evidence": changed})

    with pytest.raises(ValueError, match="resume does not match|requires approved"):
        await verify_review_escalation(
            _Audit(_snapshot(request, approval, resumed, delivery)),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("event_index", [0, 3])
async def test_request_and_delivery_require_exact_candidate_policy(event_index: int) -> None:
    events = list(_events())
    different_policy = EvidenceRef(namespace="credit-policy", value="f" * 64)
    events[event_index] = events[event_index].model_copy(
        update={"payload_redacted": _projection(policy=different_policy)}
    )

    with pytest.raises(ValueError, match="decision evidence"):
        await verify_review_escalation(
            _Audit(_snapshot(*events)),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )


@pytest.mark.asyncio
async def test_tampered_or_unattestable_snapshot_is_rejected() -> None:
    events = _events()
    with pytest.raises(AuditTamperDetectedError):
        await verify_review_escalation(
            _Audit(_snapshot(*events, valid=False)),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )
    with pytest.raises(AuditAttestationError):
        await verify_review_escalation(
            _Audit(_snapshot(*events, attestable=False)),
            escalation_id=_ESCALATION_ID,
            candidate=_candidate(),
        )
