"""Tests for agentguard.models — shared Pydantic contracts."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agentguard.exceptions import AuthenticationFailure, RegistryFailure
from agentguard.models import (
    UNAUTHENTICATED_AGENT_ID,
    UNAUTHENTICATED_AGENT_NAME,
    AgentIdentity,
    AuditEvent,
    AuthenticationEvidence,
    GuardrailEvaluation,
    HitlEvidence,
    PermissionContext,
    PolicyResult,
    ReconciliationEvidence,
    RegistryMutationEvidence,
    SandboxResult,
)

_DECIDED_AT = datetime(2026, 8, 26, 15, 0, tzinfo=UTC)
_EXPIRES_AT = datetime(2026, 8, 26, 16, 0, tzinfo=UTC)


def _authentication_evidence(state: str = "verified") -> AuthenticationEvidence:
    if state == "rejected":
        return AuthenticationEvidence(
            state="rejected",
            method="unknown",
            credential_digest="d" * 64,
            authenticated_at=_DECIDED_AT,
            failure_reason=AuthenticationFailure.CREDENTIAL_INVALID,
        )
    return AuthenticationEvidence(
        state="verified",
        method="workload_identity",
        authority="trust-domain.example",
        agent_id="agent-1",
        credential_digest="d" * 64,
        authenticated_at=_DECIDED_AT,
        issued_at=datetime(2026, 8, 26, 14, 0, tzinfo=UTC),
        not_before=datetime(2026, 8, 26, 14, 30, tzinfo=UTC),
        expires_at=_EXPIRES_AT,
        registry_revision=7,
    )


def _reconciliation_evidence(state: str = "in_doubt") -> ReconciliationEvidence:
    return ReconciliationEvidence(
        escalation_id="esc-1",
        claim_id="claim-1",
        reconciliation_id="reconcile-1",
        classification=(
            "reconciled_denied" if state == "reconciled" else "claimed_without_terminal"
        ),
        state=state,  # type: ignore[arg-type]
        reconciler_id="operator-1",
        reason_digest="a" * 64,
        assessed_at=_DECIDED_AT,
        audit_chain_id="chain-1",
        audit_head_sequence=7,
        audit_head_event_hash="b" * 64,
        journal_revision=3,
        journal_digest="c" * 64,
    )


def _registry_evidence(state: str = "authorized") -> RegistryMutationEvidence:
    values: dict[str, object] = {
        "state": state,
        "operation_id": "operation-1",
        "registry_id": "registry-1",
        "mutation": "revoke",
        "principal_id": "administrator-1",
        "authentication_method": "hardware_token",
        "authentication_authority": "admin.example",
        "credential_digest": "1" * 64,
        "capabilities_digest": "2" * 64,
        "target_agent_id": "agent-1",
        "request_digest": "3" * 64,
        "prepared_at": _DECIDED_AT,
    }
    if state == "authorized":
        values.update(
            base_registry_revision=4,
            target_registry_revision=5,
            before_record_digest="4" * 64,
            after_record_digest="5" * 64,
            base_credential_epoch=2,
            target_credential_epoch=3,
        )
    else:
        values["failure_reason"] = RegistryFailure.CAPABILITY_DENIED
    return RegistryMutationEvidence.model_validate(values)


class TestRegistryMutationEvidence:
    def test_authorized_prepare_evidence_is_frozen_and_advances_revoke_epoch(self) -> None:
        evidence = _registry_evidence()

        assert evidence.base_registry_revision is not None
        assert evidence.target_registry_revision == evidence.base_registry_revision + 1
        assert evidence.base_credential_epoch is not None
        assert evidence.target_credential_epoch == evidence.base_credential_epoch + 1
        with pytest.raises(ValidationError):
            evidence.state = "rejected"

    def test_rejected_evidence_cannot_claim_authorized_target_state(self) -> None:
        payload = _registry_evidence("rejected").model_dump()
        payload["target_registry_revision"] = 5

        with pytest.raises(ValidationError):
            RegistryMutationEvidence.model_validate(payload)

    def test_revision_conflict_separates_requested_and_observed_facts(self) -> None:
        payload = _registry_evidence("rejected").model_dump()
        payload.update(
            failure_reason=RegistryFailure.REVISION_CONFLICT,
            requested_registry_revision=3,
            observed_registry_revision=4,
        )

        evidence = RegistryMutationEvidence.model_validate(payload)
        assert evidence.requested_registry_revision == 3
        assert evidence.observed_registry_revision == 4

        payload["observed_registry_revision"] = 3
        with pytest.raises(ValidationError):
            RegistryMutationEvidence.model_validate(payload)

    def test_non_revision_rejection_cannot_claim_observed_registry_state(self) -> None:
        payload = _registry_evidence("rejected").model_dump()
        payload["observed_registry_revision"] = 4

        with pytest.raises(ValidationError):
            RegistryMutationEvidence.model_validate(payload)

    @pytest.mark.parametrize(
        "updates",
        [
            {"target_registry_revision": 7},
            {"target_credential_epoch": 2},
            {"after_record_digest": None},
            {"failure_reason": RegistryFailure.UNKNOWN_ROLE},
        ],
    )
    def test_authorized_evidence_rejects_inconsistent_prepare_state(
        self, updates: dict[str, object]
    ) -> None:
        payload = _registry_evidence().model_dump()
        payload.update(updates)

        with pytest.raises(ValidationError):
            RegistryMutationEvidence.model_validate(payload)


class TestHitlEvidence:
    def test_requested_evidence_is_frozen_and_redacted(self) -> None:
        evidence = HitlEvidence(
            escalation_id="esc-1",
            state="requested",
            reason_redacted="Policy requires human review",
            expires_at=_EXPIRES_AT,
        )

        assert evidence.decision_id == ""
        assert evidence.approver_id == ""
        with pytest.raises(ValidationError):
            evidence.state = "approved"

    @pytest.mark.parametrize("forbidden", ["token", "approval_token", "ciphertext"])
    def test_secret_bearing_fields_are_forbidden(self, forbidden: str) -> None:
        payload = {
            "escalation_id": "esc-1",
            "state": "requested",
            "expires_at": _EXPIRES_AT,
            forbidden: "secret",
        }

        with pytest.raises(ValidationError):
            HitlEvidence.model_validate(payload)

    @pytest.mark.parametrize("state", ["approved", "denied"])
    def test_human_decisions_require_authenticated_fields(self, state: str) -> None:
        evidence = HitlEvidence(
            escalation_id="esc-1",
            decision_id="decision-1",
            state=state,  # type: ignore[arg-type]
            approver_id="human-1",
            reason_redacted="Reviewed",
            decided_at=_DECIDED_AT,
        )

        assert evidence.state == state

    def test_expiry_requires_timeout_decision_without_approver(self) -> None:
        evidence = HitlEvidence(
            escalation_id="esc-1",
            decision_id="timeout-1",
            state="expired",
            reason_redacted="Approval window expired",
            decided_at=_EXPIRES_AT,
            expires_at=_EXPIRES_AT,
        )

        assert evidence.approver_id == ""

    @pytest.mark.parametrize(
        "payload",
        [
            {"escalation_id": "esc", "state": "requested"},
            {
                "escalation_id": "esc",
                "state": "requested",
                "decision_id": "decision",
                "expires_at": _EXPIRES_AT,
            },
            {
                "escalation_id": "esc",
                "state": "approved",
                "decision_id": "decision",
                "decided_at": _DECIDED_AT,
            },
            {
                "escalation_id": "esc",
                "state": "expired",
                "decision_id": "timeout",
                "decided_at": _DECIDED_AT,
                "expires_at": _EXPIRES_AT,
            },
            {
                "escalation_id": "esc",
                "state": "denied",
                "decision_id": "decision",
                "approver_id": "human",
                "decided_at": datetime(2026, 8, 26, 15, 0),
            },
        ],
    )
    def test_invalid_state_contracts_are_rejected(self, payload: dict[str, object]) -> None:
        with pytest.raises(ValidationError):
            HitlEvidence.model_validate(payload)


class TestReconciliationEvidence:
    def test_evidence_is_frozen_redacted_and_digest_only(self) -> None:
        evidence = _reconciliation_evidence()

        assert evidence.state == "in_doubt"
        assert "reason" not in evidence.model_dump()
        with pytest.raises(ValidationError):
            evidence.state = "reconciled"

    @pytest.mark.parametrize("forbidden", ["reason", "result", "payload", "executor"])
    def test_secret_or_replay_bearing_fields_are_forbidden(self, forbidden: str) -> None:
        payload = _reconciliation_evidence().model_dump()
        payload[forbidden] = "must-not-persist"

        with pytest.raises(ValidationError):
            ReconciliationEvidence.model_validate(payload)


class TestAuthenticationEvidence:
    def test_verified_evidence_is_frozen_and_contains_no_roles(self) -> None:
        evidence = _authentication_evidence()

        assert evidence.agent_id == "agent-1"
        assert "roles" not in evidence.model_dump()
        with pytest.raises(ValidationError):
            evidence.agent_id = "forged"

    def test_rejected_evidence_contains_only_failure_classification(self) -> None:
        evidence = _authentication_evidence("rejected")

        assert evidence.agent_id == ""
        assert evidence.authority == ""
        assert evidence.issued_at is None
        assert evidence.registry_revision is None

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("method", " "),
            ("method", "workload_identity "),
            ("authority", " trust-domain.example"),
            ("agent_id", "agent-1\n"),
        ],
    )
    def test_verified_evidence_rejects_noncanonical_identifiers(
        self, field: str, value: str
    ) -> None:
        payload = _authentication_evidence().model_dump()
        payload[field] = value

        with pytest.raises(ValidationError):
            AuthenticationEvidence.model_validate(payload)

    @pytest.mark.parametrize(
        "forbidden",
        ["credential", "raw_credential", "raw_error", "claimed_agent_id", "roles", "subject"],
    )
    def test_untrusted_or_secret_fields_are_forbidden(self, forbidden: str) -> None:
        payload = _authentication_evidence("rejected").model_dump()
        payload[forbidden] = "must-not-persist"

        with pytest.raises(ValidationError):
            AuthenticationEvidence.model_validate(payload)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("authority", "unverified-issuer"),
            ("agent_id", "claimed-agent"),
            ("issued_at", _DECIDED_AT),
            ("not_before", _DECIDED_AT),
            ("expires_at", _EXPIRES_AT),
            ("registry_revision", 1),
            ("failure_reason", None),
        ],
    )
    def test_rejected_state_cannot_carry_trusted_fields(self, field: str, value: object) -> None:
        payload = _authentication_evidence("rejected").model_dump()
        payload[field] = value

        with pytest.raises(ValidationError):
            AuthenticationEvidence.model_validate(payload)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("agent_id", ""),
            ("authority", ""),
            ("issued_at", None),
            ("not_before", None),
            ("expires_at", None),
            ("failure_reason", AuthenticationFailure.CREDENTIAL_INVALID),
            ("credential_digest", "not-a-digest"),
            ("authenticated_at", datetime(2026, 8, 26, 15, 0)),
            ("issued_at", datetime(2026, 8, 26, 15, 1, tzinfo=UTC)),
            ("issued_at", datetime(2026, 8, 26, 14, 45, tzinfo=UTC)),
            ("not_before", datetime(2026, 8, 26, 15, 1, tzinfo=UTC)),
            ("expires_at", _DECIDED_AT),
        ],
    )
    def test_verified_state_requires_trusted_valid_metadata(
        self, field: str, value: object
    ) -> None:
        payload = _authentication_evidence().model_dump()
        payload[field] = value

        with pytest.raises(ValidationError):
            AuthenticationEvidence.model_validate(payload)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("assessed_at", datetime(2026, 8, 26, 15, 0)),
            ("reason_digest", "raw operator reason"),
            ("audit_head_event_hash", "not-a-hash"),
            ("journal_digest", "not-a-hash"),
            ("audit_head_sequence", -1),
            ("journal_revision", -1),
        ],
    )
    def test_invalid_attestation_fields_are_rejected(self, field: str, value: object) -> None:
        payload = _reconciliation_evidence().model_dump()
        payload[field] = value

        with pytest.raises(ValidationError):
            ReconciliationEvidence.model_validate(payload)


class TestGuardrailEvaluation:
    def test_create_frozen_evaluation(self) -> None:
        evaluation = GuardrailEvaluation(
            guardrail_id="pii-redaction",
            guardrail_version="1.2.0",
            stage="input",
            effect="transform",
            reason_codes=("PII_REDACTED",),
            duration_ms=0.25,
            enforced=True,
        )

        assert evaluation.reason_codes == ("PII_REDACTED",)
        with pytest.raises(ValidationError):
            evaluation.enforced = False

    @pytest.mark.parametrize("duration_ms", [-0.1, float("inf"), float("nan")])
    def test_duration_must_be_finite_and_nonnegative(self, duration_ms: float) -> None:
        with pytest.raises(ValidationError):
            GuardrailEvaluation(
                guardrail_id="test",
                guardrail_version="1",
                stage="pre_tool",
                effect="allow",
                reason_codes=(),
                duration_ms=duration_ms,
                enforced=True,
            )

    def test_extra_fields_are_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            GuardrailEvaluation.model_validate(
                {
                    "guardrail_id": "test",
                    "guardrail_version": "1",
                    "stage": "pre_tool",
                    "effect": "allow",
                    "reason_codes": [],
                    "duration_ms": 0,
                    "enforced": True,
                    "unsigned": "forged",
                }
            )

    @pytest.mark.parametrize("effect", ["deny", "escalate"])
    def test_terminal_evaluation_requires_reason_codes(self, effect: str) -> None:
        with pytest.raises(ValidationError, match="require reason codes"):
            GuardrailEvaluation(
                guardrail_id="test",
                guardrail_version="1",
                stage="pre_tool",
                effect=effect,  # type: ignore[arg-type]
                reason_codes=(),
                duration_ms=0,
                enforced=False,
            )


class TestAgentIdentity:
    def test_create_minimal(self) -> None:
        identity = AgentIdentity(agent_id="agent-1", name="Test Agent", roles=["readonly"])
        assert identity.agent_id == "agent-1"
        assert identity.name == "Test Agent"
        assert identity.roles == ["readonly"]
        assert identity.metadata == {}

    def test_extra_fields_are_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            AgentIdentity.model_validate(
                {
                    "agent_id": "agent-1",
                    "name": "Test Agent",
                    "roles": [],
                    "unsigned": "forged",
                }
            )

    def test_create_with_metadata(self) -> None:
        identity = AgentIdentity(
            agent_id="agent-2",
            name="Credit Agent",
            roles=["credit-analyst", "readonly"],
            metadata={"framework": "langgraph", "version": "0.2"},
        )
        assert identity.metadata["framework"] == "langgraph"

    def test_frozen(self) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=[])
        with pytest.raises(ValidationError):
            identity.agent_id = "b"


class TestPermissionContext:
    def test_defaults(self) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=["readonly"])
        ctx = PermissionContext(
            agent=identity,
            requested_action="tool:web_search",
            resource="https://example.com",
        )
        assert ctx.granted is False
        assert ctx.reason == ""
        assert ctx.context == {}

    def test_granted(self) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=["system-agent"])
        ctx = PermissionContext(
            agent=identity,
            requested_action="tool:web_search",
            resource="*",
            granted=True,
            reason="system-agent has wildcard access",
        )
        assert ctx.granted is True


class TestPolicyResult:
    def test_create(self) -> None:
        result = PolicyResult(
            rule_id="OWASP-AGENT-01",
            rule_name="Prompt Injection Detection",
            passed=False,
            severity="critical",
            evidence={"matched_pattern": "ignore previous instructions"},
            remediation="Sanitize user inputs before prompt interpolation.",
        )
        assert result.passed is False
        assert result.severity == "critical"

    def test_severity_validation(self) -> None:
        """Severity must be one of: critical, high, medium, low."""
        with pytest.raises(ValidationError):
            PolicyResult(
                rule_id="X",
                rule_name="X",
                passed=True,
                severity="banana",  # type: ignore[arg-type]
                evidence={},
                remediation="",
            )


class TestAuditEvent:
    def test_create_minimal(self) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=["readonly"])
        ctx = PermissionContext(
            agent=identity, requested_action="tool:read", resource="file.txt", granted=True
        )
        event = AuditEvent(
            event_id="evt-001",
            timestamp=datetime.now(UTC),
            agent_id="a",
            action="tool:read",
            resource="file.txt",
            permission_context=ctx,
            result="allowed",
            duration_ms=1.5,
            trace_id="trace-abc",
        )
        assert event.result == "allowed"
        assert event.policy_results == []
        assert event.guardrail_evaluations == ()
        assert event.hitl_evidence is None
        assert event.hash_schema_version == 8
        assert event.event_hash == ""
        assert event.prev_hash == ""

    @pytest.mark.parametrize(
        ("event_type", "state"),
        [
            ("authentication_succeeded", "verified"),
            ("authentication_rejected", "rejected"),
        ],
    )
    def test_authentication_event_requires_matching_typed_evidence(
        self, event_type: str, state: str
    ) -> None:
        evidence = _authentication_evidence(state)
        rejected = state == "rejected"
        identity = AgentIdentity(
            agent_id=UNAUTHENTICATED_AGENT_ID if rejected else evidence.agent_id,
            name=UNAUTHENTICATED_AGENT_NAME if rejected else "A",
            roles=[],
        )
        context = PermissionContext(
            agent=identity,
            requested_action="authenticate",
            resource="agent",
            granted=not rejected,
            reason=evidence.failure_reason.value if evidence.failure_reason else "",
        )

        event = AuditEvent(
            event_id="evt-auth",
            timestamp=datetime.now(UTC),
            agent_id=identity.agent_id,
            action="authenticate",
            resource="agent",
            permission_context=context,
            result="rejected" if rejected else "allowed",
            duration_ms=0,
            trace_id="trace-auth",
            event_type=event_type,  # type: ignore[arg-type]
            reason_codes=(evidence.failure_reason.value,) if evidence.failure_reason else (),
            authentication_evidence=evidence,
        )

        assert event.authentication_evidence is not None
        assert event.authentication_evidence.state == state

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("agent_id", "claimed-agent"),
            ("action", "tool:claimed"),
            ("resource", "claimed-resource"),
            ("payload_digest", "d" * 64),
            ("payload_redacted", {"claimed_agent_id": "claimed-agent"}),
            ("reason_codes", (AuthenticationFailure.CREDENTIAL_EXPIRED.value,)),
        ],
    )
    def test_rejected_authentication_event_cannot_persist_untrusted_request_data(
        self, field: str, value: object
    ) -> None:
        evidence = _authentication_evidence("rejected")
        identity = AgentIdentity(
            agent_id=UNAUTHENTICATED_AGENT_ID,
            name=UNAUTHENTICATED_AGENT_NAME,
            roles=[],
        )
        context = PermissionContext(
            agent=identity,
            requested_action="authenticate",
            resource="agent",
            reason=evidence.failure_reason.value if evidence.failure_reason else "",
        )
        payload: dict[str, object] = {
            "event_id": "evt-auth-rejected",
            "timestamp": datetime.now(UTC),
            "agent_id": UNAUTHENTICATED_AGENT_ID,
            "action": "authenticate",
            "resource": "agent",
            "permission_context": context,
            "result": "rejected",
            "duration_ms": 0,
            "trace_id": "trace-auth",
            "event_type": "authentication_rejected",
            "reason_codes": (evidence.failure_reason.value,) if evidence.failure_reason else (),
            "authentication_evidence": evidence,
        }
        payload[field] = value

        with pytest.raises(ValidationError):
            AuditEvent.model_validate(payload)

    def test_authentication_evidence_is_forbidden_on_unrelated_event(self) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=[])
        context = PermissionContext(agent=identity, requested_action="x", resource="y")

        with pytest.raises(ValidationError, match="authentication event type"):
            AuditEvent(
                event_id="evt-auth",
                timestamp=datetime.now(UTC),
                agent_id="a",
                action="authenticate",
                resource="agent",
                permission_context=context,
                result="allowed",
                duration_ms=0,
                trace_id="trace-auth",
                authentication_evidence=_authentication_evidence(),
            )

    def test_result_validation(self) -> None:
        """Result must be one of: allowed, denied, escalated, error."""
        identity = AgentIdentity(agent_id="a", name="A", roles=[])
        ctx = PermissionContext(agent=identity, requested_action="x", resource="y")
        with pytest.raises(ValidationError):
            AuditEvent(
                event_id="evt-002",
                timestamp=datetime.now(UTC),
                agent_id="a",
                action="x",
                resource="y",
                permission_context=ctx,
                result="banana",  # type: ignore[arg-type]
                duration_ms=0,
                trace_id="t",
            )

    @pytest.mark.parametrize(
        ("event_type", "state"),
        [
            ("escalation_requested", "requested"),
            ("approval_granted", "approved"),
            ("approval_denied", "denied"),
            ("approval_expired", "expired"),
            ("escalation_resumed", "approved"),
        ],
    )
    def test_hitl_event_type_matches_evidence_state(self, event_type: str, state: str) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=[])
        ctx = PermissionContext(agent=identity, requested_action="x", resource="y")
        decision = state != "requested"
        event = AuditEvent(
            event_id="evt-hitl",
            timestamp=_DECIDED_AT,
            agent_id="a",
            action="x",
            resource="y",
            permission_context=ctx,
            result="escalated",
            duration_ms=0,
            trace_id="t",
            event_type=event_type,  # type: ignore[arg-type]
            hitl_evidence=HitlEvidence(
                escalation_id="esc",
                decision_id="decision" if decision else "",
                state=state,  # type: ignore[arg-type]
                approver_id="human" if state in {"approved", "denied"} else "",
                decided_at=(
                    _EXPIRES_AT if state == "expired" else _DECIDED_AT if decision else None
                ),
                expires_at=_EXPIRES_AT if state in {"requested", "expired"} else None,
            ),
        )

        assert event.hitl_evidence is not None
        assert event.hitl_evidence.state == state

    @pytest.mark.parametrize(
        ("event_type", "state"),
        [
            ("execution_in_doubt", "in_doubt"),
            ("execution_reconciliation_resumed", "resumed"),
            ("execution_reconciled", "reconciled"),
        ],
    )
    def test_reconciliation_event_type_matches_evidence_state(
        self, event_type: str, state: str
    ) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=[])
        ctx = PermissionContext(agent=identity, requested_action="x", resource="y")

        event = AuditEvent(
            event_id="evt-reconciliation",
            timestamp=_DECIDED_AT,
            agent_id="a",
            action="x",
            resource="y",
            permission_context=ctx,
            result="denied" if state == "reconciled" else "escalated",
            duration_ms=0,
            trace_id="t",
            event_type=event_type,  # type: ignore[arg-type]
            reconciliation_evidence=_reconciliation_evidence(state),
        )

        assert event.reconciliation_evidence is not None
        assert event.reconciliation_evidence.state == state

    def test_reconciliation_event_requires_evidence(self) -> None:
        payload = AuditEvent(
            event_id="evt",
            timestamp=_DECIDED_AT,
            agent_id="a",
            action="x",
            resource="y",
            permission_context=PermissionContext(
                agent=AgentIdentity(agent_id="a", name="A", roles=[]),
                requested_action="x",
                resource="y",
            ),
            result="escalated",
            duration_ms=0,
            trace_id="t",
        ).model_dump()
        payload["event_type"] = "execution_in_doubt"

        with pytest.raises(ValidationError, match="requires in_doubt"):
            AuditEvent.model_validate(payload)

    def test_unrelated_event_rejects_reconciliation_evidence(self) -> None:
        payload = AuditEvent(
            event_id="evt",
            timestamp=_DECIDED_AT,
            agent_id="a",
            action="x",
            resource="y",
            permission_context=PermissionContext(
                agent=AgentIdentity(agent_id="a", name="A", roles=[]),
                requested_action="x",
                resource="y",
            ),
            result="allowed",
            duration_ms=0,
            trace_id="t",
        ).model_dump()
        payload["reconciliation_evidence"] = _reconciliation_evidence().model_dump()

        with pytest.raises(ValidationError, match="reconciliation event type"):
            AuditEvent.model_validate(payload)


class TestSandboxResult:
    def test_create(self) -> None:
        result = SandboxResult(
            stdout="hello",
            stderr="",
            exit_code=0,
            duration_ms=42.0,
            backend="docker",
        )
        assert result.exit_code == 0
        assert result.success is True

    def test_failure(self) -> None:
        result = SandboxResult(
            stdout="",
            stderr="error: timeout",
            exit_code=1,
            duration_ms=30000.0,
            backend="docker",
        )
        assert result.success is False
