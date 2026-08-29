"""Tests for agentguard.core.audit — immutable HMAC-chained audit log."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 — used in fixture type hints resolved at runtime

import pytest

from agentguard.core.audit import (
    AppendOnlyAuditLog,
    AuditCheckpoint,
    AuditKeyEpoch,
    AuditKeyring,
    AuditLog,
    FileAuditBackend,
)
from agentguard.exceptions import (
    AuditEventConflictError,
    AuditKeyMissingError,
    AuditKeyUnavailableError,
    AuditKeyWeakError,
    AuditTamperDetectedError,
    AuthenticationFailure,
    RegistryFailure,
)
from agentguard.models import (
    UNAUTHENTICATED_AGENT_ID,
    UNAUTHENTICATED_AGENT_NAME,
    AgentIdentity,
    AuditEvent,
    AuditLink,
    AuthenticationEvidence,
    EvidenceRef,
    GuardrailEvaluation,
    HitlEvidence,
    PermissionContext,
    PolicyResult,
    ReconciliationEvidence,
    RegistryMutationEvidence,
)

_LEGACY_FIXTURE = Path(__file__).parents[2] / "fixtures" / "audit" / "v1-single-event.jsonl"
_V2_FIXTURE = Path(__file__).parents[2] / "fixtures" / "audit" / "v2-single-event.jsonl"
_V3_FIXTURE = Path(__file__).parents[2] / "fixtures" / "audit" / "v3-single-event.jsonl"
_V3_CHECKPOINT_FIXTURE = (
    Path(__file__).parents[2] / "fixtures" / "audit" / "v3-single-event-checkpoint.json"
)


def _evaluation() -> GuardrailEvaluation:
    return GuardrailEvaluation(
        guardrail_id="pii-redaction",
        guardrail_version="1.2.0",
        stage="input",
        effect="transform",
        reason_codes=("PII_REDACTED",),
        duration_ms=0.25,
        enforced=True,
    )


def _hitl_evidence(state: str = "approved") -> HitlEvidence:
    decided_at = datetime(2026, 8, 26, 15, 0, tzinfo=UTC)
    expires_at = datetime(2026, 8, 26, 14, 0, tzinfo=UTC)
    return HitlEvidence(
        escalation_id="esc-001",
        decision_id="decision-001",
        state=state,  # type: ignore[arg-type]
        approver_id="human-001" if state != "expired" else "",
        reason_redacted="Reviewed against policy",
        decided_at=decided_at,
        expires_at=expires_at,
    )


def _reconciliation_evidence(
    state: str = "in_doubt",
    classification: str = "claimed_without_terminal",
) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        escalation_id="esc-001",
        claim_id="claim-001",
        reconciliation_id="reconcile-001",
        classification=classification,  # type: ignore[arg-type]
        state=state,  # type: ignore[arg-type]
        reconciler_id="operator-001",
        reason_digest="a" * 64,
        assessed_at=datetime(2026, 8, 26, 15, 0, tzinfo=UTC),
        audit_chain_id="chain-evidence-001",
        audit_head_sequence=4,
        audit_head_event_hash="b" * 64,
        journal_revision=2,
        journal_digest="c" * 64,
    )


def _authentication_evidence(state: str = "verified") -> AuthenticationEvidence:
    if state == "rejected":
        return AuthenticationEvidence(
            state="rejected",
            method="unknown",
            credential_digest="d" * 64,
            authenticated_at=datetime(2026, 8, 26, 15, 0, tzinfo=UTC),
            failure_reason=AuthenticationFailure.CREDENTIAL_INVALID,
        )
    return AuthenticationEvidence(
        state="verified",
        method="workload_identity",
        authority="trust-domain.example",
        agent_id="agent-001",
        credential_digest="d" * 64,
        authenticated_at=datetime(2026, 8, 26, 15, 0, tzinfo=UTC),
        issued_at=datetime(2026, 8, 26, 14, 0, tzinfo=UTC),
        not_before=datetime(2026, 8, 26, 14, 30, tzinfo=UTC),
        expires_at=datetime(2026, 8, 26, 16, 0, tzinfo=UTC),
        registry_revision=7,
    )


def _authentication_event(state: str = "verified") -> AuditEvent:
    evidence = _authentication_evidence(state)
    rejected = state == "rejected"
    identity = AgentIdentity(
        agent_id=UNAUTHENTICATED_AGENT_ID if rejected else evidence.agent_id,
        name=UNAUTHENTICATED_AGENT_NAME if rejected else "Authenticated agent",
        roles=[],
    )
    context = PermissionContext(
        agent=identity,
        requested_action="authenticate",
        resource="agent",
        granted=not rejected,
        reason=evidence.failure_reason.value if evidence.failure_reason else "",
    )
    return AuditEvent(
        event_id=f"evt-authentication-{state}",
        timestamp=datetime(2026, 8, 26, 15, 0, tzinfo=UTC),
        agent_id=identity.agent_id,
        action="authenticate",
        resource="agent",
        permission_context=context,
        result="rejected" if rejected else "allowed",
        duration_ms=1.0,
        trace_id="trace-authentication",
        event_type="authentication_rejected" if rejected else "authentication_succeeded",
        reason_codes=(evidence.failure_reason.value,) if evidence.failure_reason else (),
        authentication_evidence=evidence,
    )


def _registry_mutation_evidence(state: str = "authorized") -> RegistryMutationEvidence:
    common: dict[str, object] = {
        "state": state,
        "operation_id": f"registry-operation-{state}",
        "registry_id": "primary-registry",
        "mutation": "replace_roles",
        "principal_id": "administrator-001",
        "authentication_method": "hardware_token",
        "authentication_authority": "admin-trust.example",
        "credential_digest": "1" * 64,
        "capabilities_digest": "2" * 64,
        "target_agent_id": "agent-001",
        "request_digest": "3" * 64,
        "prepared_at": datetime(2026, 8, 26, 15, 0, tzinfo=UTC),
    }
    if state == "authorized":
        common.update(
            base_registry_revision=7,
            target_registry_revision=8,
            before_record_digest="4" * 64,
            after_record_digest="5" * 64,
            base_credential_epoch=2,
            target_credential_epoch=2,
        )
    else:
        common["failure_reason"] = RegistryFailure.UNKNOWN_ROLE
    return RegistryMutationEvidence.model_validate(common)


def _registry_mutation_event(state: str = "authorized") -> AuditEvent:
    evidence = _registry_mutation_evidence(state)
    action = f"registry.{evidence.mutation}"
    resource = f"agent_registry:{evidence.registry_id}"
    rejected = state == "rejected"
    identity = AgentIdentity(
        agent_id=evidence.principal_id,
        name=evidence.principal_id,
        roles=[],
    )
    context = PermissionContext(
        agent=identity,
        requested_action=action,
        resource=resource,
        granted=not rejected,
        reason=evidence.failure_reason.value if evidence.failure_reason else "",
    )
    return AuditEvent(
        event_id=f"evt-registry-{state}",
        timestamp=datetime(2026, 8, 26, 15, 0, tzinfo=UTC),
        agent_id=evidence.principal_id,
        action=action,
        resource=resource,
        permission_context=context,
        result="rejected" if rejected else "allowed",
        duration_ms=0.5,
        trace_id=f"trace-registry-{state}",
        event_type=("registry_mutation_rejected" if rejected else "registry_mutation_authorized"),
        reason_codes=(evidence.failure_reason.value,) if evidence.failure_reason else (),
        registry_mutation_evidence=evidence,
    )


def _make_event(event_id: str = "evt-001", agent_id: str = "a") -> AuditEvent:
    """Helper to create a minimal AuditEvent for testing."""
    identity = AgentIdentity(agent_id=agent_id, name="Test", roles=["readonly"])
    ctx = PermissionContext(
        agent=identity, requested_action="tool:test", resource="res", granted=True
    )
    return AuditEvent(
        event_id=event_id,
        timestamp=datetime(2026, 4, 10, 12, 0, 0, tzinfo=UTC),
        agent_id=agent_id,
        action="tool:test",
        resource="res",
        permission_context=ctx,
        result="allowed",
        duration_ms=1.0,
        trace_id="trace-001",
    )


def _keyring(*entries: tuple[str, bytes, int], legacy_key_id: str | None = None) -> AuditKeyring:
    return AuditKeyring(
        keys={key_id: key for key_id, key, _ in entries},
        epochs=tuple(
            AuditKeyEpoch(
                key_id=key_id,
                activation_sequence=sequence,
                key_fingerprint=hashlib.sha256(key).hexdigest(),
            )
            for key_id, key, sequence in entries
        ),
        legacy_key_id=legacy_key_id or entries[0][0],
    )


class TestFileAuditBackend:
    """Tests for the JSONL file-based audit storage."""

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_append_creates_file(self, tmp_audit_dir: Path) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        event = _make_event()
        await backend.append(event)

        files = list(tmp_audit_dir.glob("*.jsonl"))
        assert len(files) == 1

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_append_and_read_back(self, tmp_audit_dir: Path) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        event = _make_event()
        await backend.append(event)

        events = await backend.read_all()
        assert len(events) == 1
        assert events[0].event_id == "evt-001"

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_append_multiple(self, tmp_audit_dir: Path) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        for i in range(5):
            await backend.append(_make_event(event_id=f"evt-{i:03d}"))

        events = await backend.read_all()
        assert len(events) == 5


class TestAppendOnlyAuditLog:
    """Tests for the HMAC-chained audit log."""

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_write_sets_hashes(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        event = _make_event()
        written = await log.write(event)

        assert written.event_hash != ""
        assert written.prev_hash == ""  # First event has no predecessor
        assert written.hash_schema_version == 8
        assert written.sequence == 1
        assert written.key_id
        assert (tmp_audit_dir / "audit-head.json").is_file()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_chain_links(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        e1 = await log.write(_make_event(event_id="evt-001"))
        e2 = await log.write(_make_event(event_id="evt-002"))

        assert e2.prev_hash == e1.event_hash
        assert e2.event_hash != e1.event_hash

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_write_once_deduplicates_same_event_across_instances(
        self, tmp_audit_dir: Path
    ) -> None:
        event = _make_event(event_id="stable-hitl-event")
        first_log = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        second_log = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))

        first, retry = await asyncio.gather(
            first_log.write_once(event),
            second_log.write_once(event),
        )

        assert retry == first
        events = await FileAuditBackend(tmp_audit_dir).read_all()
        assert events == [first]

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_write_once_rejects_conflicting_stable_event_id(
        self, tmp_audit_dir: Path
    ) -> None:
        log = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        await log.write_once(_make_event(event_id="stable-hitl-event"))

        with pytest.raises(AuditEventConflictError):
            await log.write_once(
                _make_event(event_id="stable-hitl-event").model_copy(
                    update={"action": "tool:conflict"}
                )
            )

        assert len(await FileAuditBackend(tmp_audit_dir).read_all()) == 1

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_write_once_normalizes_v4_input_before_retry_fingerprint(
        self, tmp_audit_dir: Path
    ) -> None:
        event = _make_event(event_id="stable-v4-input").model_copy(
            update={"hash_schema_version": 4}
        )
        log = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))

        first = await log.write_once(event)
        retry = await log.write_once(event)

        assert first.hash_schema_version == 8
        assert retry == first
        assert len(await FileAuditBackend(tmp_audit_dir).read_all()) == 1

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_verify_chain_passes(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        for i in range(10):
            await log.write(_make_event(event_id=f"evt-{i:03d}"))

        result = await log.verify_chain()
        assert result.valid is True
        assert result.event_count == 10
        assert result.checkpoint_valid is True

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_concurrent_writers_allocate_one_contiguous_chain(
        self, tmp_audit_dir: Path
    ) -> None:
        logs = [
            AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir)) for _ in range(20)
        ]

        await asyncio.gather(
            *(log.write(_make_event(event_id=f"evt-{index:03d}")) for index, log in enumerate(logs))
        )

        verifier = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        result = await verifier.verify_chain()
        events = await FileAuditBackend(directory=tmp_audit_dir).read_all()
        assert result.valid is True
        assert result.checkpoint_valid is True
        assert [event.sequence for event in events] == list(range(1, 21))
        assert len({event.event_hash for event in events}) == 20

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_steady_state_append_reads_only_checkpoint_and_tail(
        self, tmp_audit_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        log = AppendOnlyAuditLog(backend=backend)
        await log.write(_make_event(event_id="evt-001"))

        def _unexpected_full_read() -> list[AuditEvent]:
            raise AssertionError("steady-state append parsed full audit history")

        monkeypatch.setattr(backend, "_read_all_sync", _unexpected_full_read)
        written = await log.write(_make_event(event_id="evt-002"))

        assert written.sequence == 2

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_signed_checkpoint_detects_tail_truncation(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        for index in range(3):
            await log.write(_make_event(event_id=f"evt-{index}"))

        log_file = next(tmp_audit_dir.glob("audit-*.jsonl"))
        lines = log_file.read_text().splitlines()
        log_file.write_text("\n".join(lines[:-1]) + "\n")

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_tampered_checkpoint_is_rejected(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        await log.write(_make_event())
        checkpoint_file = tmp_audit_dir / "audit-head.json"
        checkpoint = json.loads(checkpoint_file.read_text())
        checkpoint["head_event_hash"] = "0" * 64
        checkpoint_file.write_text(json.dumps(checkpoint))

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_local_checkpoint_without_trusted_anchor_is_not_attestable(
        self, tmp_audit_dir: Path
    ) -> None:
        writer = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        await writer.write(_make_event())

        reader = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        result = await reader.verify_chain()

        assert result.valid is True
        assert result.checkpoint_valid is True
        assert result.checkpoint_status == "verified_unanchored"
        assert result.attestable is False

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_external_checkpoint_anchors_a_new_reader(self, tmp_audit_dir: Path) -> None:
        writer = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        await writer.write(_make_event())
        trusted = await writer.export_checkpoint()
        assert trusted is not None

        reader = AppendOnlyAuditLog(
            backend=FileAuditBackend(directory=tmp_audit_dir),
            trusted_checkpoint=trusted,
        )
        result = await reader.verify_chain()

        assert result.checkpoint_status == "verified"
        assert result.attestable is True

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_paired_log_and_local_checkpoint_rollback_is_detected(
        self, tmp_audit_dir: Path
    ) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        await log.write(_make_event(event_id="evt-1"))
        await log.write(_make_event(event_id="evt-2"))
        log_file = next(tmp_audit_dir.glob("audit-*.jsonl"))
        old_log = log_file.read_bytes()
        old_checkpoint = (tmp_audit_dir / "audit-head.json").read_bytes()
        await log.write(_make_event(event_id="evt-3"))

        log_file.write_bytes(old_log)
        (tmp_audit_dir / "audit-head.json").write_bytes(old_checkpoint)

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_phase2_evidence_references_are_signed(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        event = _make_event().model_copy(
            update={
                "subject_ref": EvidenceRef(namespace="application", value="APP-000038"),
                "policy_bundle_version": "sha256:bundle",
                "links": (
                    AuditLink(
                        relation="notice",
                        target=EvidenceRef(namespace="notice", value="NOTICE-12"),
                    ),
                ),
            }
        )
        await log.write(event)
        log_file = next(tmp_audit_dir.glob("audit-*.jsonl"))
        stored = json.loads(log_file.read_text())
        stored["subject_ref"]["value"] = "APP-TAMPERED"
        log_file.write_text(json.dumps(stored) + "\n")

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.parametrize(
        ("field", "tampered_value"),
        [
            ("guardrail_id", "different-guardrail"),
            ("guardrail_version", "9.9.9"),
            ("stage", "pre_tool"),
            ("effect", "allow"),
            ("reason_codes", ["DIFFERENT.REASON"]),
            ("duration_ms", 99.0),
            ("enforced", False),
        ],
    )
    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v4_guardrail_evaluations_are_signed(
        self,
        tmp_audit_dir: Path,
        field: str,
        tampered_value: object,
    ) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        written = await log.write(
            _make_event().model_copy(update={"guardrail_evaluations": (_evaluation(),)})
        )

        assert written.hash_schema_version == 8
        stored_path = next(tmp_audit_dir.glob("audit-*.jsonl"))
        stored = json.loads(stored_path.read_text())
        stored["guardrail_evaluations"][0][field] = tampered_value
        stored_path.write_text(json.dumps(stored) + "\n")

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            (("unsigned_future_field",), "forged"),
            (("permission_context", "unsigned_future_field"), "forged"),
            (("permission_context", "agent", "unsigned_future_field"), "forged"),
            (("policy_results", 0, "unsigned_future_field"), "forged"),
            (("guardrail_evaluations", 0, "unsigned_future_field"), "forged"),
        ],
    )
    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v4_rejects_unsigned_unknown_fields(
        self,
        tmp_audit_dir: Path,
        path: tuple[str | int, ...],
        value: object,
    ) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        await log.write(
            _make_event().model_copy(
                update={
                    "policy_results": [
                        PolicyResult(
                            rule_id="TEST-001",
                            rule_name="test",
                            passed=True,
                            severity="low",
                            evidence={},
                            remediation="none",
                        )
                    ],
                    "guardrail_evaluations": (_evaluation(),),
                }
            )
        )
        stored_path = next(tmp_audit_dir.glob("audit-*.jsonl"))
        stored = json.loads(stored_path.read_text())
        target = stored
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = value
        stored_path.write_text(json.dumps(stored) + "\n")

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.parametrize(
        ("field", "tampered_value"),
        [
            ("escalation_id", "esc-forged"),
            ("decision_id", "decision-forged"),
            ("state", "denied"),
            ("approver_id", "human-forged"),
            ("reason_redacted", "forged reason"),
            ("decided_at", "2026-08-26T15:30:00Z"),
            ("expires_at", "2026-08-26T13:30:00Z"),
        ],
    )
    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v6_hitl_evidence_fields_are_signed(
        self,
        tmp_audit_dir: Path,
        field: str,
        tampered_value: object,
    ) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        written = await log.write(
            _make_event().model_copy(
                update={
                    "event_type": "approval_granted",
                    "hitl_evidence": _hitl_evidence(),
                }
            )
        )

        assert written.hash_schema_version == 8
        stored_path = next(tmp_audit_dir.glob("audit-*.jsonl"))
        stored = json.loads(stored_path.read_text())
        stored["hitl_evidence"][field] = tampered_value
        stored_path.write_text(json.dumps(stored) + "\n")

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.parametrize(
        ("field", "tampered_value"),
        [
            ("escalation_id", "esc-forged"),
            ("claim_id", "claim-forged"),
            ("reconciliation_id", "reconcile-forged"),
            ("classification", "admission_without_completion"),
            ("state", "resumed"),
            ("reconciler_id", "operator-forged"),
            ("reason_digest", "d" * 64),
            ("assessed_at", "2026-08-26T15:30:00Z"),
            ("audit_chain_id", "chain-forged"),
            ("audit_head_sequence", 99),
            ("audit_head_event_hash", "e" * 64),
            ("journal_revision", 99),
            ("journal_digest", "f" * 64),
        ],
    )
    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v6_reconciliation_evidence_fields_are_signed(
        self,
        tmp_audit_dir: Path,
        field: str,
        tampered_value: object,
    ) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        written = await log.write(
            _make_event().model_copy(
                update={
                    "event_type": "execution_in_doubt",
                    "reconciliation_evidence": _reconciliation_evidence(),
                }
            )
        )

        assert written.hash_schema_version == 8
        stored_path = next(tmp_audit_dir.glob("audit-*.jsonl"))
        stored = json.loads(stored_path.read_text())
        stored["reconciliation_evidence"][field] = tampered_value
        stored_path.write_text(json.dumps(stored) + "\n")

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v6_reconciliation_write_once_is_idempotent_and_conflict_safe(
        self, tmp_audit_dir: Path
    ) -> None:
        log = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        event = _make_event(event_id="invocation:1:in-doubt").model_copy(
            update={
                "event_type": "execution_in_doubt",
                "reconciliation_evidence": _reconciliation_evidence(),
            }
        )

        first = await log.write_once(event)
        retry = await log.write_once(event)
        assert retry == first

        conflicting = event.model_copy(
            update={
                "reconciliation_evidence": _reconciliation_evidence().model_copy(
                    update={"journal_revision": 3}
                )
            }
        )
        with pytest.raises(AuditEventConflictError):
            await log.write_once(conflicting)

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v6_serialization_contains_no_raw_reconciliation_material(
        self, tmp_audit_dir: Path
    ) -> None:
        log = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        await log.write(
            _make_event(event_id="invocation:1:in-doubt").model_copy(
                update={
                    "event_type": "execution_in_doubt",
                    "reconciliation_evidence": _reconciliation_evidence(),
                }
            )
        )

        serialized = next(tmp_audit_dir.glob("audit-*.jsonl")).read_text()
        for forbidden in (
            "raw operator reason",
            "protected result plaintext",
            "executor-reference",
        ):
            assert forbidden not in serialized

    @pytest.mark.parametrize(
        ("field", "tampered_value"),
        [
            ("state", "rejected"),
            ("method", "forged"),
            ("authority", "forged.example"),
            ("agent_id", "agent-forged"),
            ("credential_digest", "e" * 64),
            ("authenticated_at", "2026-08-26T15:30:00Z"),
            ("issued_at", "2026-08-26T13:30:00Z"),
            ("not_before", "2026-08-26T13:30:00Z"),
            ("expires_at", "2026-08-26T17:00:00Z"),
            ("registry_revision", 99),
        ],
    )
    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v7_authentication_evidence_fields_are_signed(
        self,
        tmp_audit_dir: Path,
        field: str,
        tampered_value: object,
    ) -> None:
        log = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        written = await log.write(_authentication_event())

        assert written.hash_schema_version == 8
        stored_path = next(tmp_audit_dir.glob("audit-*.jsonl"))
        stored = json.loads(stored_path.read_text())
        stored["authentication_evidence"][field] = tampered_value
        stored_path.write_text(json.dumps(stored) + "\n")

        with pytest.raises((AuditTamperDetectedError, ValueError)):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v7_rejected_authentication_serializes_no_untrusted_claims(
        self, tmp_audit_dir: Path
    ) -> None:
        log = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        await log.write(_authentication_event("rejected"))

        serialized = next(tmp_audit_dir.glob("audit-*.jsonl")).read_text()
        stored_evidence = json.loads(serialized)["authentication_evidence"]
        assert "roles" not in stored_evidence
        for forbidden in ("claimed-agent", "raw credential", "raw verifier error"):
            assert forbidden not in serialized

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v7_rejected_failure_classification_is_signed(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        await log.write(_authentication_event("rejected"))

        stored_path = next(tmp_audit_dir.glob("audit-*.jsonl"))
        stored = json.loads(stored_path.read_text())
        replacement = AuthenticationFailure.CREDENTIAL_EXPIRED.value
        stored["authentication_evidence"]["failure_reason"] = replacement
        stored["permission_context"]["reason"] = replacement
        stored["reason_codes"] = [replacement]
        stored_path.write_text(json.dumps(stored) + "\n")

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.parametrize(
        "path",
        [
            ("unsigned_future_field",),
            ("hitl_evidence", "token"),
            ("hitl_evidence", "ciphertext"),
        ],
    )
    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v6_rejects_unsigned_unknown_fields(
        self,
        tmp_audit_dir: Path,
        path: tuple[str, ...],
    ) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        await log.write(
            _make_event().model_copy(
                update={
                    "event_type": "approval_granted",
                    "hitl_evidence": _hitl_evidence(),
                }
            )
        )
        stored_path = next(tmp_audit_dir.glob("audit-*.jsonl"))
        stored = json.loads(stored_path.read_text())
        target = stored
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = "forged"
        stored_path.write_text(json.dumps(stored) + "\n")

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_caller_cannot_supply_chain_integrity_fields(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        with pytest.raises(ValueError, match="assigned by the audit sink"):
            await log.write(_make_event().model_copy(update={"sequence": 99}))

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_verify_detects_tampering(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        for i in range(5):
            await log.write(_make_event(event_id=f"evt-{i:03d}"))

        # Tamper with the log file: modify event at index 2
        log_files = list(tmp_audit_dir.glob("*.jsonl"))
        assert len(log_files) == 1
        lines = log_files[0].read_text().strip().split("\n")
        tampered = json.loads(lines[2])
        tampered["action"] = "tool:HACKED"
        lines[2] = json.dumps(tampered)
        log_files[0].write_text("\n".join(lines) + "\n")

        with pytest.raises(AuditTamperDetectedError) as exc_info:
            await log.verify_chain()
        assert exc_info.value.event_index == 2

    async def test_missing_key_raises(
        self, tmp_audit_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without AGENTGUARD_AUDIT_KEY, constructing the log should fail."""
        monkeypatch.delenv("AGENTGUARD_AUDIT_KEY", raising=False)
        with pytest.raises(AuditKeyMissingError):
            AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

    @pytest.mark.parametrize("weak", ["dev-key", "short", "x" * 31])
    async def test_weak_key_raises(
        self, tmp_audit_dir: Path, monkeypatch: pytest.MonkeyPatch, weak: str
    ) -> None:
        """A key under 32 bytes must be rejected — a weak key is recoverable."""
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", weak)
        with pytest.raises(AuditKeyWeakError):
            AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

    async def test_minimum_length_key_accepted(
        self, tmp_audit_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A key at exactly the 32-byte floor is accepted."""
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "x" * 32)
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        assert (await log.verify_chain()).valid is True

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_empty_log_verifies(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        result = await log.verify_chain()
        assert result.valid is True
        assert result.event_count == 0

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_custom_backend_protocol_swap(self, tmp_audit_dir: Path) -> None:
        """Any AuditBackend-conforming object can replace FileAuditBackend unchanged."""

        class InMemoryBackend:
            def __init__(self) -> None:
                self.events: list[AuditEvent] = []

            async def append(self, event: AuditEvent) -> None:
                self.events.append(event)

            async def read_all(self) -> list[AuditEvent]:
                return list(self.events)

        backend = InMemoryBackend()
        log = AppendOnlyAuditLog(backend=backend)
        for i in range(3):
            await log.write(_make_event(event_id=f"evt-{i:03d}"))

        result = await log.verify_chain()
        assert result.valid is True
        assert result.event_count == 3
        assert len(backend.events) == 3

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_chain_survives_restart(self, tmp_audit_dir: Path) -> None:
        """Simulates process restart: new AppendOnlyAuditLog against existing log."""
        backend = FileAuditBackend(directory=tmp_audit_dir)

        # Session 1: write 3 events
        log1 = AppendOnlyAuditLog(backend=backend)
        for i in range(3):
            await log1.write(_make_event(event_id=f"s1-{i:03d}"))

        # Session 2: new instance (simulates restart), write 2 more
        log2 = AppendOnlyAuditLog(backend=backend)
        for i in range(2):
            await log2.write(_make_event(event_id=f"s2-{i:03d}"))

        # Verify the full chain is intact across both sessions
        log3 = AppendOnlyAuditLog(backend=backend)
        result = await log3.verify_chain()
        assert result.valid is True
        assert result.event_count == 5

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v1_file_chain_verifies_and_accepts_v6_append(self, tmp_audit_dir: Path) -> None:
        """A package upgrade must not invalidate already signed evidence."""
        fixture_path = tmp_audit_dir / "audit-2026-04-10.jsonl"
        shutil.copyfile(_LEGACY_FIXTURE, fixture_path)

        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        before = await log.verify_chain()
        assert before.valid is True
        assert before.event_count == 2

        written = await log.write(_make_event(event_id="v6-001"))
        assert written.hash_schema_version == 8
        assert written.sequence == 3
        assert written.prev_hash == (
            "57eac3d4e0be3ab7189a61c4bf3721f705ba609bb6d7e33aefd51b640c2afc93"
        )
        after = await log.verify_chain()
        assert after.valid is True
        assert after.event_count == 3
        assert after.checkpoint_valid is True

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v2_file_verifies_unchanged_and_accepts_v6_append(
        self, tmp_audit_dir: Path
    ) -> None:
        fixture_path = tmp_audit_dir / "audit-2026-04-10.jsonl"
        shutil.copyfile(_V2_FIXTURE, fixture_path)
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        before = await log.verify_chain()
        assert before.valid is True
        assert before.checkpoint_valid is None

        written = await log.write(_make_event(event_id="v6-after-v2"))
        assert written.hash_schema_version == 8
        assert written.sequence == 2
        assert written.prev_hash == (
            "60983c2311ec0e8fa4cdcd0124fc7fdeb4b13a8ebf24726c9cb58b727c243e08"
        )
        assert (await log.verify_chain()).checkpoint_valid is True

    @pytest.mark.usefixtures("_set_audit_key")
    @pytest.mark.parametrize(
        ("fixture", "unsigned_update"),
        [
            (_LEGACY_FIXTURE, {"invocation_id": "forged"}),
            (_LEGACY_FIXTURE, {"subject_ref": {"namespace": "app", "value": "42"}}),
            (
                _LEGACY_FIXTURE,
                {"guardrail_evaluations": [_evaluation().model_dump(mode="json")]},
            ),
            (
                _LEGACY_FIXTURE,
                {
                    "event_type": "approval_granted",
                    "hitl_evidence": _hitl_evidence().model_dump(mode="json"),
                },
            ),
            (_V2_FIXTURE, {"policy_bundle_version": "sha256:forged"}),
            (_V2_FIXTURE, {"chain_mode": "shadow"}),
            (
                _V2_FIXTURE,
                {"guardrail_evaluations": [_evaluation().model_dump(mode="json")]},
            ),
            (
                _V2_FIXTURE,
                {
                    "event_type": "approval_granted",
                    "hitl_evidence": _hitl_evidence().model_dump(mode="json"),
                },
            ),
            (_V3_FIXTURE, {"guardrail_evaluations": [_evaluation().model_dump(mode="json")]}),
            (
                _V3_FIXTURE,
                {
                    "event_type": "approval_granted",
                    "hitl_evidence": _hitl_evidence().model_dump(mode="json"),
                },
            ),
        ],
    )
    async def test_legacy_unsigned_schema_extensions_are_rejected(
        self,
        tmp_audit_dir: Path,
        fixture: Path,
        unsigned_update: dict[str, object],
    ) -> None:
        records = [json.loads(line) for line in fixture.read_text().splitlines() if line]
        records[0].update(unsigned_update)
        target = tmp_audit_dir / "audit-2026-04-10.jsonl"
        target.write_text("\n".join(json.dumps(record) for record in records) + "\n")

        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v1_unsigned_policy_effect_is_rejected(self, tmp_audit_dir: Path) -> None:
        records = [json.loads(line) for line in _LEGACY_FIXTURE.read_text().splitlines() if line]
        records[1]["policy_results"][0]["effect"] = "deny"
        target = tmp_audit_dir / "audit-2026-04-10.jsonl"
        target.write_text("\n".join(json.dumps(record) for record in records) + "\n")

        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v1_classification_is_backend_independent(self) -> None:
        """Custom backends get v1 recognition from AuditEvent itself."""

        class InMemoryBackend:
            def __init__(self) -> None:
                self.events = [
                    AuditEvent.model_validate_json(line)
                    for line in _LEGACY_FIXTURE.read_text().splitlines()
                    if line
                ]

            async def append(self, event: AuditEvent) -> None:
                self.events.append(event)

            async def read_all(self) -> list[AuditEvent]:
                return list(self.events)

        backend = InMemoryBackend()
        assert backend.events[0].hash_schema_version == 1
        log = AppendOnlyAuditLog(backend=backend)
        assert (await log.verify_chain()).valid is True

        appended = await log.write(_make_event(event_id="v6-memory"))
        assert appended.hash_schema_version == 8
        assert appended.sequence == 3
        assert (await log.verify_chain()).event_count == 3

        backend.events[0] = backend.events[0].model_copy(update={"action": "tool:tampered"})
        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v3_checkpointed_history_accepts_v6_append(self, tmp_audit_dir: Path) -> None:
        shutil.copyfile(_V3_FIXTURE, tmp_audit_dir / "audit-2026-04-10.jsonl")
        shutil.copyfile(_V3_CHECKPOINT_FIXTURE, tmp_audit_dir / "audit-head.json")
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        before = await log.verify_chain()
        written = await log.write(
            _make_event(event_id="v6-after-v3").model_copy(
                update={"guardrail_evaluations": (_evaluation(),)}
            )
        )
        after = await log.verify_chain()

        assert before.valid is True
        assert before.checkpoint_valid is True
        assert written.hash_schema_version == 8
        assert written.sequence == 2
        assert written.prev_hash == (
            "f325ab9517cd1c2592550e2f126349d7742fc05256254f49793396575b0c1a5d"
        )
        assert after.valid is True
        assert after.checkpoint_valid is True

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v4_checkpointed_history_accepts_v6_hitl_append(
        self, tmp_audit_dir: Path
    ) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        signer = AppendOnlyAuditLog(backend=backend)
        epoch = signer.keyring.epoch_for_sequence(1)
        unsigned_v4 = _make_event(event_id="v4-existing").model_copy(
            update={
                "guardrail_evaluations": (_evaluation(),),
                "hash_schema_version": 4,
                "sequence": 1,
                "key_id": epoch.key_id,
                "chain_id": "chain-v4-v5",
            }
        )
        signed_v4 = unsigned_v4.model_copy(update={"event_hash": signer._compute_hash(unsigned_v4)})
        assert epoch.key_id == "61b77ff187e9bff7"
        assert signed_v4.event_hash == (
            "36e77e0c5c27930a9729fa644bc21d6673207b3401ea11865ee1908553af69c2"
        )
        await backend.append(signed_v4)
        backend._write_checkpoint_sync(signer._checkpoint_for(signed_v4))

        reader = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        assert (await reader.verify_chain()).valid is True
        written_v6 = await reader.write(
            _make_event(event_id="v6-hitl").model_copy(
                update={
                    "event_type": "approval_granted",
                    "hitl_evidence": _hitl_evidence(),
                }
            )
        )

        assert written_v6.hash_schema_version == 8
        assert written_v6.sequence == 2
        assert written_v6.prev_hash == signed_v4.event_hash
        assert (await reader.verify_chain()).checkpoint_valid is True

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v5_checkpointed_history_accepts_v6_reconciliation_append(
        self, tmp_audit_dir: Path
    ) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        signer = AppendOnlyAuditLog(backend=backend)
        epoch = signer.keyring.epoch_for_sequence(1)
        unsigned_v5 = _make_event(event_id="v5-existing").model_copy(
            update={
                "event_type": "approval_granted",
                "hitl_evidence": _hitl_evidence(),
                "hash_schema_version": 5,
                "sequence": 1,
                "key_id": epoch.key_id,
                "chain_id": "chain-v5-v6",
            }
        )
        signed_v5 = unsigned_v5.model_copy(update={"event_hash": signer._compute_hash(unsigned_v5)})
        await backend.append(signed_v5)
        backend._write_checkpoint_sync(signer._checkpoint_for(signed_v5))

        reader = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        assert (await reader.verify_chain()).valid is True
        written_v6 = await reader.write(
            _make_event(event_id="v6-reconciliation").model_copy(
                update={
                    "event_type": "execution_in_doubt",
                    "reconciliation_evidence": _reconciliation_evidence(),
                }
            )
        )

        assert written_v6.hash_schema_version == 8
        assert written_v6.sequence == 2
        assert written_v6.prev_hash == signed_v5.event_hash
        assert (await reader.verify_chain()).checkpoint_valid is True

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_frozen_v6_hash_bytes_remain_exact(self, tmp_audit_dir: Path) -> None:
        signer = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        epoch = signer.keyring.epoch_for_sequence(1)
        event = _make_event(event_id="v6-frozen").model_copy(
            update={
                "event_type": "execution_in_doubt",
                "reconciliation_evidence": _reconciliation_evidence(),
                "hash_schema_version": 6,
                "sequence": 1,
                "key_id": epoch.key_id,
                "chain_id": "frozen-v6-chain",
            }
        )

        assert signer._compute_hash(event) == (
            "678fa4a6bd2c2aae50b416131020de039fa4b54c19e31fd7f94590fb82990e95"
        )

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_frozen_v5_hash_bytes_remain_exact(self, tmp_audit_dir: Path) -> None:
        signer = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        epoch = signer.keyring.epoch_for_sequence(1)
        event = _make_event(event_id="v5-frozen").model_copy(
            update={
                "event_type": "approval_granted",
                "hitl_evidence": _hitl_evidence(),
                "hash_schema_version": 5,
                "sequence": 1,
                "key_id": epoch.key_id,
                "chain_id": "frozen-v5-chain",
            }
        )

        assert signer._compute_hash(event) == (
            "00986665e8288cf480cc3506374588b88be1dc5b5d2b971729a09ee543766d12"
        )

    @pytest.mark.parametrize(
        ("state", "expected_hash"),
        [
            ("verified", "27c9bffd22a27a54add93c2a8e1bbc74625b023fa6a7849d30556ecd56daaafc"),
            ("rejected", "fea66d02bfb8e3bb05496c70349919e57c67e4aa423d61be6c8f5d3d51a5e1d2"),
        ],
    )
    @pytest.mark.usefixtures("_set_audit_key")
    async def test_frozen_v7_authentication_hash_bytes_remain_exact(
        self, tmp_audit_dir: Path, state: str, expected_hash: str
    ) -> None:
        signer = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        epoch = signer.keyring.epoch_for_sequence(1)
        event = _authentication_event(state).model_copy(
            update={
                "event_id": f"v7-{state}-frozen",
                "hash_schema_version": 7,
                "sequence": 1,
                "key_id": epoch.key_id,
                "chain_id": f"frozen-v7-{state}-chain",
            }
        )

        assert signer._compute_hash(event) == expected_hash

    @pytest.mark.parametrize(
        ("state", "expected_hash"),
        [
            ("authorized", "b82ded46a5dd574abc9dac87b1a4636e4a02ea8f88cea720ae21f6327ccb1989"),
            ("rejected", "a6bf120a3f650caa21092229be372571c6abdc7c075e41ee7e602f014f815d56"),
        ],
    )
    @pytest.mark.usefixtures("_set_audit_key")
    async def test_frozen_v8_registry_hash_bytes_remain_exact(
        self, tmp_audit_dir: Path, state: str, expected_hash: str
    ) -> None:
        signer = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        epoch = signer.keyring.epoch_for_sequence(1)
        event = _registry_mutation_event(state).model_copy(
            update={
                "event_id": f"v8-registry-{state}-frozen",
                "hash_schema_version": 8,
                "sequence": 1,
                "key_id": epoch.key_id,
                "chain_id": f"frozen-v8-registry-{state}-chain",
            }
        )

        assert signer._compute_hash(event) == expected_hash

    @pytest.mark.parametrize(
        ("field", "tampered_value"),
        [
            ("state", "rejected"),
            ("operation_id", "registry-operation-forged"),
            ("registry_id", "registry-forged"),
            ("mutation", "rotate_credentials"),
            ("principal_id", "administrator-forged"),
            ("authentication_method", "forged_method"),
            ("authentication_authority", "forged.example"),
            ("credential_digest", "a" * 64),
            ("capabilities_digest", "b" * 64),
            ("target_agent_id", "agent-forged"),
            ("request_digest", "c" * 64),
            ("base_registry_revision", 6),
            ("target_registry_revision", 9),
            ("requested_registry_revision", 6),
            ("observed_registry_revision", 7),
            ("before_record_digest", "d" * 64),
            ("after_record_digest", "e" * 64),
            ("base_credential_epoch", 3),
            ("target_credential_epoch", 3),
            ("prepared_at", "2026-08-26T15:30:00Z"),
            ("failure_reason", RegistryFailure.UNKNOWN_ROLE.value),
        ],
    )
    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v8_registry_evidence_fields_are_signed(
        self,
        tmp_audit_dir: Path,
        field: str,
        tampered_value: object,
    ) -> None:
        log = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir))
        written = await log.write(_registry_mutation_event())

        assert written.hash_schema_version == 8
        stored_path = next(tmp_audit_dir.glob("audit-*.jsonl"))
        stored = json.loads(stored_path.read_text())
        stored["registry_mutation_evidence"][field] = tampered_value
        stored_path.write_text(json.dumps(stored) + "\n")

        with pytest.raises((AuditTamperDetectedError, ValueError)):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v7_unsigned_registry_evidence_is_rejected(self) -> None:
        class InMemoryBackend:
            def __init__(self, event: AuditEvent) -> None:
                self.events = [event]

            async def append(self, event: AuditEvent) -> None:
                self.events.append(event)

            async def read_all(self) -> list[AuditEvent]:
                return list(self.events)

        signer = AppendOnlyAuditLog(backend=InMemoryBackend(_make_event()))
        epoch = signer.keyring.epoch_for_sequence(1)
        unsigned_v7 = _make_event(event_id="v7-registry-forged").model_copy(
            update={
                "hash_schema_version": 7,
                "sequence": 1,
                "key_id": epoch.key_id,
                "chain_id": "chain-v7-registry-forged",
            }
        )
        signed_v7 = unsigned_v7.model_copy(update={"event_hash": signer._compute_hash(unsigned_v7)})
        forged = signed_v7.model_copy(
            update={"registry_mutation_evidence": _registry_mutation_evidence()}
        )
        signer = AppendOnlyAuditLog(backend=InMemoryBackend(forged))

        with pytest.raises(AuditTamperDetectedError):
            await signer.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v5_unsigned_reconciliation_evidence_is_rejected(self) -> None:
        class InMemoryBackend:
            def __init__(self, event: AuditEvent) -> None:
                self.events = [event]

            async def append(self, event: AuditEvent) -> None:
                self.events.append(event)

            async def read_all(self) -> list[AuditEvent]:
                return list(self.events)

        signer = AppendOnlyAuditLog(backend=InMemoryBackend(_make_event()))
        epoch = signer.keyring.epoch_for_sequence(1)
        unsigned_v5 = _make_event(event_id="v5-forged").model_copy(
            update={
                "hash_schema_version": 5,
                "sequence": 1,
                "key_id": epoch.key_id,
                "chain_id": "chain-v5-forged",
            }
        )
        signed_v5 = unsigned_v5.model_copy(update={"event_hash": signer._compute_hash(unsigned_v5)})
        forged = signed_v5.model_copy(
            update={
                "event_type": "execution_in_doubt",
                "reconciliation_evidence": _reconciliation_evidence(),
            }
        )
        log = AppendOnlyAuditLog(backend=InMemoryBackend(forged))

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_v4_unsigned_hitl_evidence_is_rejected(self) -> None:
        class InMemoryBackend:
            def __init__(self, event: AuditEvent) -> None:
                self.events = [event]

            async def append(self, event: AuditEvent) -> None:
                self.events.append(event)

            async def read_all(self) -> list[AuditEvent]:
                return list(self.events)

        signer = AppendOnlyAuditLog(backend=InMemoryBackend(_make_event()))
        epoch = signer.keyring.epoch_for_sequence(1)
        unsigned_v4 = _make_event(event_id="v4-forged").model_copy(
            update={
                "hash_schema_version": 4,
                "sequence": 1,
                "key_id": epoch.key_id,
                "chain_id": "chain-v4-forged",
            }
        )
        signed_v4 = unsigned_v4.model_copy(update={"event_hash": signer._compute_hash(unsigned_v4)})
        forged = signed_v4.model_copy(
            update={
                "event_type": "approval_granted",
                "hitl_evidence": _hitl_evidence(),
            }
        )
        log = AppendOnlyAuditLog(backend=InMemoryBackend(forged))

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_sequence_gap_is_rejected_for_custom_backend(self) -> None:
        class InMemoryBackend:
            def __init__(self) -> None:
                self.events: list[AuditEvent] = []

            async def append(self, event: AuditEvent) -> None:
                self.events.append(event)

            async def read_all(self) -> list[AuditEvent]:
                return list(self.events)

        backend = InMemoryBackend()
        log = AppendOnlyAuditLog(backend=backend)
        written = await log.write(_make_event())
        gap = written.model_copy(update={"sequence": 2, "event_hash": ""})
        backend.events[0] = gap.model_copy(update={"event_hash": log._compute_hash(gap)})

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()


class TestAuditKeyRotation:
    """Tests for immutable, sequence-bound audit signing-key epochs."""

    async def test_append_only_log_conforms_to_public_protocol(self, tmp_audit_dir: Path) -> None:
        ring = _keyring(("key-1", b"first-audit-key", 1))
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir), keyring=ring)

        assert isinstance(log, AuditLog)

    async def test_events_verify_across_key_rotation(self, tmp_audit_dir: Path) -> None:
        initial = _keyring(("key-1", b"first-audit-key", 1))
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir), keyring=initial)
        first = await log.write(_make_event(event_id="before-rotation"))

        rotated = initial.with_rotation(
            key_id="key-2", key=b"second-audit-key", activation_sequence=2
        )
        log.install_keyring(rotated)
        second = await log.write(_make_event(event_id="after-rotation"))

        assert (first.key_id, second.key_id) == ("key-1", "key-2")
        assert (await log.verify_chain()).valid is True

    async def test_known_retired_key_reuse_at_future_sequence_is_rejected(self) -> None:
        class InMemoryBackend:
            def __init__(self) -> None:
                self.events: list[AuditEvent] = []

            async def append(self, event: AuditEvent) -> None:
                self.events.append(event)

            async def read_all(self) -> list[AuditEvent]:
                return list(self.events)

        old_key = b"first-audit-key"
        ring = _keyring(("key-1", old_key, 1)).with_rotation(
            key_id="key-2", key=b"second-audit-key", activation_sequence=2
        )
        backend = InMemoryBackend()
        log = AppendOnlyAuditLog(backend=backend, keyring=ring)
        await log.write(_make_event(event_id="first"))
        current = await log.write(_make_event(event_id="second"))

        retired_signer = AppendOnlyAuditLog(
            backend=InMemoryBackend(), keyring=_keyring(("key-1", old_key, 1))
        )
        forged = current.model_copy(update={"key_id": "key-1", "event_hash": ""})
        backend.events[1] = forged.model_copy(
            update={"event_hash": retired_signer._compute_hash(forged)}
        )

        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    async def test_rotation_is_active_before_next_event(self, tmp_audit_dir: Path) -> None:
        ring = _keyring(("key-1", b"first-audit-key", 1))
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir), keyring=ring)
        log.install_keyring(
            ring.with_rotation(key_id="key-2", key=b"second-audit-key", activation_sequence=1)
        )

        written = await log.write(_make_event(event_id="first"))

        assert written.sequence == 1
        assert written.key_id == "key-2"

    def test_changed_pending_key_bytes_fail_epoch_fingerprint_validation(self) -> None:
        ring = _keyring(("key-1", b"first-audit-key", 1)).with_rotation(
            key_id="key-2", key=b"second-audit-key", activation_sequence=2
        )

        with pytest.raises(ValueError, match="fingerprint"):
            AuditKeyring(
                keys={"key-1": b"first-audit-key", "key-2": b"changed-key"},
                epochs=ring.epochs,
                legacy_key_id="key-1",
            )

    def test_duplicate_epoch_activation_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="activation"):
            _keyring(
                ("key-1", b"first-audit-key", 1),
                ("key-2", b"second-audit-key", 1),
            )

        pending = _keyring(("key-1", b"first-audit-key", 1)).with_rotation(
            key_id="key-2", key=b"second-audit-key", activation_sequence=1
        )
        with pytest.raises(ValueError, match="strictly increase"):
            pending.with_rotation(key_id="key-3", key=b"third-audit-key", activation_sequence=1)

    async def test_checkpoint_signer_must_equal_tail_key(self, tmp_audit_dir: Path) -> None:
        first_key = b"first-audit-key"
        ring = _keyring(("key-1", first_key, 1)).with_rotation(
            key_id="key-2", key=b"second-audit-key", activation_sequence=2
        )
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir), keyring=ring)
        await log.write(_make_event(event_id="first"))
        tail = await log.write(_make_event(event_id="second"))
        checkpoint_path = tmp_audit_dir / "audit-head.json"
        checkpoint = json.loads(checkpoint_path.read_text())
        checkpoint["signing_key_id"] = "key-1"
        old_signer = AppendOnlyAuditLog(
            backend=FileAuditBackend(directory=tmp_audit_dir),
            keyring=_keyring(("key-1", first_key, 1)),
        )
        parsed = AuditCheckpoint.model_validate(checkpoint)
        checkpoint["signature"] = old_signer._compute_checkpoint_hash(parsed)
        checkpoint_path.write_text(json.dumps(checkpoint))

        assert tail.key_id == "key-2"
        with pytest.raises(AuditTamperDetectedError):
            await log.verify_chain()

    async def test_missing_historical_key_fails_verification(self) -> None:
        class InMemoryBackend:
            def __init__(self) -> None:
                self.events: list[AuditEvent] = []

            async def append(self, event: AuditEvent) -> None:
                self.events.append(event)

            async def read_all(self) -> list[AuditEvent]:
                return list(self.events)

        backend = InMemoryBackend()
        writer = AppendOnlyAuditLog(
            backend=backend, keyring=_keyring(("historical", b"old-audit-key", 1))
        )
        await writer.write(_make_event())
        verifier = AppendOnlyAuditLog(
            backend=backend, keyring=_keyring(("replacement", b"new-audit-key", 1))
        )

        with pytest.raises(AuditKeyUnavailableError):
            await verifier.verify_chain()

    def test_install_keyring_rejects_rebinding_and_removal(self) -> None:
        initial = _keyring(("key-1", b"first-audit-key", 1))
        log = AppendOnlyAuditLog(backend=object(), keyring=initial)  # type: ignore[arg-type]

        rebound = _keyring(("key-1", b"changed-key", 1))
        with pytest.raises(ValueError, match="rebind|remove"):
            log.install_keyring(rebound)


class TestPreparedCheckpointRecovery:
    """Crash recovery either discards an uncommitted prepare or promotes its event."""

    async def test_recovery_discards_prepare_when_event_was_not_appended(
        self, tmp_audit_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = FileAuditBackend(tmp_audit_dir)
        ring = _keyring(("key-1", b"first-audit-key", 1))
        log = AppendOnlyAuditLog(backend, keyring=ring)
        original_append = backend._append_line_sync
        monkeypatch.setattr(
            backend,
            "_append_line_sync",
            lambda _event: (_ for _ in ()).throw(OSError("injected before append")),
        )

        with pytest.raises(OSError, match="injected"):
            await log.write(_make_event())

        monkeypatch.setattr(backend, "_append_line_sync", original_append)
        assert await log.recover_interrupted_append() == "discarded"
        written = await log.write(_make_event())
        assert written.sequence == 1

    async def test_recovery_promotes_prepare_when_event_was_fsynced(
        self, tmp_audit_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = FileAuditBackend(tmp_audit_dir)
        ring = _keyring(("key-1", b"first-audit-key", 1))
        log = AppendOnlyAuditLog(backend, keyring=ring)
        monkeypatch.setattr(
            backend,
            "_promote_pending_checkpoint_sync",
            lambda: (_ for _ in ()).throw(OSError("injected after append")),
        )

        with pytest.raises(OSError, match="injected"):
            await log.write(_make_event())

        recovered = AppendOnlyAuditLog(FileAuditBackend(tmp_audit_dir), keyring=ring)
        assert await recovered.recover_interrupted_append() == "promoted"
        assert (await recovered.verify_chain()).valid is True

    async def test_corrupt_pending_checkpoint_fails_closed(
        self, tmp_audit_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        backend = FileAuditBackend(tmp_audit_dir)
        ring = _keyring(("key-1", b"first-audit-key", 1))
        log = AppendOnlyAuditLog(backend, keyring=ring)
        monkeypatch.setattr(
            backend,
            "_append_line_sync",
            lambda _event: (_ for _ in ()).throw(OSError("injected before append")),
        )
        with pytest.raises(OSError):
            await log.write(_make_event())
        pending_path = tmp_audit_dir / ".audit-head.pending.json"
        pending = json.loads(pending_path.read_text())
        pending["signature"] = "0" * 64
        pending_path.write_text(json.dumps(pending))

        with pytest.raises(AuditTamperDetectedError):
            await log.recover_interrupted_append()
