"""Tests for durable, tamper-evident HITL escalation state."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentguard.compliance.continuation import SealedContinuation
from agentguard.compliance.escalation_store import (
    ApprovedEscalation,
    ContinuationKind,
    DecisionDisposition,
    EscalationConflictError,
    EscalationExpiredError,
    EscalationRecord,
    EscalationStateError,
    EscalationStatus,
    EscalationStore,
    EscalationStoreError,
    EscalationTamperError,
)

KEY = b"k" * 32
NOW = datetime(2026, 8, 26, 12, tzinfo=UTC)


def _record_path(directory: Path) -> Path:
    return next(directory.glob("*.json"))


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "escalations"


@pytest.fixture
def store(state_dir: Path) -> EscalationStore:
    return EscalationStore(state_dir, signing_key=KEY, clock=lambda: NOW)


async def test_create_persists_only_verifier_with_private_permissions(
    store: EscalationStore, state_dir: Path
) -> None:
    created = await store.create("esc-1", ttl=timedelta(minutes=5))

    assert created.record.status is EscalationStatus.PENDING
    assert created.record.revision == 0
    assert len(created.token) == 43
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(_record_path(state_dir).stat().st_mode) == 0o600

    raw = _record_path(state_dir).read_text()
    stored = json.loads(raw)
    assert created.token not in raw
    assert stored["token_verifier"] == hashlib.sha256(created.token.encode()).hexdigest()
    assert "context" not in stored
    assert "payload" not in stored
    assert "continuation" not in stored
    assert "decision" not in stored
    assert "approver" not in raw
    assert "reason" not in raw
    assert not hasattr(store, "decide")
    assert not hasattr(store, "claim")
    assert not hasattr(store, "complete")


async def test_reopen_reads_authentic_pending_state(
    store: EscalationStore, state_dir: Path
) -> None:
    created = await store.create("esc-1", ttl=timedelta(minutes=5))
    reopened = EscalationStore(state_dir, signing_key=KEY, clock=lambda: NOW)

    loaded = await reopened.get("esc-1")
    assert loaded == created.record


def test_public_models_are_frozen_and_reject_unknown_fields() -> None:
    record = EscalationRecord(
        escalation_id="esc-1",
        status=EscalationStatus.PENDING,
        revision=0,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )

    with pytest.raises(ValidationError):
        record.revision = 1
    with pytest.raises(ValidationError):
        EscalationRecord.model_validate({**record.model_dump(), "unexpected": True})


@pytest.mark.parametrize("mutation", ["signed_field", "unknown_field"])
async def test_tampered_or_unknown_persisted_fields_fail_closed(
    store: EscalationStore, state_dir: Path, mutation: str
) -> None:
    await store.create("esc-1", ttl=timedelta(minutes=5))
    path = _record_path(state_dir)
    stored = json.loads(path.read_text())
    if mutation == "signed_field":
        stored["status"] = "approved"
    else:
        stored["unknown"] = "not signed by the schema"
    path.write_text(json.dumps(stored))
    os.chmod(path, 0o600)

    with pytest.raises(EscalationTamperError):
        await store.get("esc-1")


async def test_wrong_signing_key_and_symlinked_record_fail_closed(
    store: EscalationStore, state_dir: Path, tmp_path: Path
) -> None:
    await store.create("esc-1", ttl=timedelta(minutes=5))
    reopened = EscalationStore(state_dir, signing_key=b"x" * 32, clock=lambda: NOW)
    with pytest.raises(EscalationTamperError):
        await reopened.get("esc-1")

    path = _record_path(state_dir)
    target = tmp_path / "outside.json"
    path.replace(target)
    path.symlink_to(target)
    with pytest.raises(EscalationTamperError):
        await store.get("esc-1")


async def test_ttl_expires_at_exact_boundary(
    store: EscalationStore,
) -> None:
    clock = [NOW]
    store._clock = lambda: clock[0]
    await store.create("esc-1", ttl=timedelta(seconds=10))
    clock[0] = NOW + timedelta(seconds=9)
    assert (await store.get("esc-1")).status is EscalationStatus.PENDING

    clock[0] = NOW + timedelta(seconds=10)
    expired = await store.get("esc-1")
    assert expired.status is EscalationStatus.EXPIRED
    assert expired.revision == 1


async def test_list_records_materializes_expiry_and_sorts(store: EscalationStore) -> None:
    clock = [NOW]
    store._clock = lambda: clock[0]
    await store.create("z-last", ttl=timedelta(seconds=1))
    await store.create("a-first", ttl=timedelta(minutes=1))

    clock[0] = NOW + timedelta(seconds=1)
    records = await store.list_records()

    assert [record.escalation_id for record in records] == ["a-first", "z-last"]
    assert records[1].status is EscalationStatus.EXPIRED


async def test_blocking_file_work_runs_off_event_loop(
    store: EscalationStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    await store.create("esc-1", ttl=timedelta(minutes=5))
    entered = threading.Event()
    release = threading.Event()
    original = store._get_sync

    def blocking_get(escalation_id: str) -> EscalationRecord:
        entered.set()
        release.wait(timeout=2)
        return original(escalation_id)

    monkeypatch.setattr(store, "_get_sync", blocking_get)
    task = asyncio.create_task(store.get("esc-1"))
    await asyncio.to_thread(entered.wait, 2)
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    assert (await task).escalation_id == "esc-1"


def test_short_key_and_symlinked_directory_are_rejected(tmp_path: Path, state_dir: Path) -> None:
    with pytest.raises(ValueError, match="256 bits"):
        EscalationStore(state_dir, signing_key=b"short")

    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(EscalationStoreError):
        EscalationStore(link, signing_key=KEY)


def _sealed() -> SealedContinuation:
    return SealedContinuation(
        algorithm="test-aead:v1",
        key_id="test-key",
        nonce=b"test-nonce",
        ciphertext=b"opaque-envelope",
    )


async def test_resumable_create_uses_v2_and_persists_only_opaque_envelope(
    store: EscalationStore, state_dir: Path
) -> None:
    created = await store.create(
        "esc-resume", ttl=timedelta(minutes=5), sealed_continuation=_sealed()
    )

    stored = json.loads(_record_path(state_dir).read_text())
    assert created.record.status is EscalationStatus.PENDING
    assert stored["schema_version"] == 2
    assert stored["sealed_continuation"]["algorithm"] == _sealed().algorithm
    assert stored["sealed_continuation"]["key_id"] == _sealed().key_id
    assert created.token not in json.dumps(stored)
    assert "payload" not in stored
    assert "credential" not in stored
    assert "result" not in stored


async def test_prepare_and_commit_approval_are_explicit_idempotent_steps(
    store: EscalationStore,
) -> None:
    clock = [NOW]
    store._clock = lambda: clock[0]
    created = await store.create(
        "esc-resume", ttl=timedelta(minutes=5), sealed_continuation=_sealed()
    )

    prepared = await store.prepare_decision(
        "esc-resume",
        token=created.token,
        decision_id="decision-1",
        disposition=DecisionDisposition.APPROVE,
        approver_id="workload:approver-1",
        reason_digest="a" * 64,
    )
    assert prepared.record.status is EscalationStatus.DECISION_PREPARED
    assert prepared.decided_at == NOW

    clock[0] = NOW + timedelta(seconds=10)
    retried = await store.prepare_decision(
        "esc-resume",
        token=created.token,
        decision_id="decision-1",
        disposition=DecisionDisposition.APPROVE,
        approver_id="workload:approver-1",
        reason_digest="a" * 64,
    )
    assert retried == prepared

    committed = await store.commit_decision("esc-resume", decision_id=prepared.decision_id)
    assert committed.status is EscalationStatus.APPROVED
    assert await store.commit_decision("esc-resume", decision_id=prepared.decision_id) == committed


async def test_conflicting_or_concurrent_decision_is_rejected(
    store: EscalationStore,
) -> None:
    created = await store.create(
        "esc-resume", ttl=timedelta(minutes=5), sealed_continuation=_sealed()
    )

    results = await asyncio.gather(
        store.prepare_decision(
            "esc-resume",
            token=created.token,
            decision_id="decision-approve",
            disposition=DecisionDisposition.APPROVE,
            approver_id="workload:approver-1",
            reason_digest="a" * 64,
        ),
        store.prepare_decision(
            "esc-resume",
            token=created.token,
            decision_id="decision-deny",
            disposition=DecisionDisposition.DENY,
            approver_id="workload:approver-2",
            reason_digest="b" * 64,
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, BaseException) for result in results) == 1
    assert sum(isinstance(result, EscalationConflictError) for result in results) == 1


async def test_decision_rejects_wrong_or_expired_token_without_auto_finalizing(
    store: EscalationStore,
) -> None:
    clock = [NOW]
    store._clock = lambda: clock[0]
    created = await store.create(
        "esc-resume", ttl=timedelta(seconds=10), sealed_continuation=_sealed()
    )

    with pytest.raises(EscalationStateError):
        await store.prepare_decision(
            "esc-resume",
            token="x" * 43,
            decision_id="decision-1",
            disposition=DecisionDisposition.APPROVE,
            approver_id="workload:approver-1",
            reason_digest="a" * 64,
        )

    clock[0] = NOW + timedelta(seconds=10)
    with pytest.raises(EscalationExpiredError):
        await store.prepare_decision(
            "esc-resume",
            token=created.token,
            decision_id="decision-1",
            disposition=DecisionDisposition.APPROVE,
            approver_id="workload:approver-1",
            reason_digest="a" * 64,
        )
    assert (await store.get("esc-resume")).status is EscalationStatus.PENDING


async def test_resumable_expiry_requires_prepare_audit_commit_sequence(
    store: EscalationStore,
) -> None:
    clock = [NOW]
    store._clock = lambda: clock[0]
    await store.create("esc-resume", ttl=timedelta(seconds=10), sealed_continuation=_sealed())
    clock[0] = NOW + timedelta(seconds=10)

    prepared = await store.prepare_expiry("esc-resume")
    assert prepared.status is EscalationStatus.EXPIRY_PREPARED
    assert await store.prepare_expiry("esc-resume") == prepared
    expired = await store.commit_expiry("esc-resume")
    assert expired.status is EscalationStatus.EXPIRED
    assert await store.commit_expiry("esc-resume") == expired
    assert await store.prepare_expiry("esc-resume") == expired


async def test_approved_continuation_can_be_inspected_then_claimed_exactly_once(
    store: EscalationStore,
) -> None:
    created = await store.create(
        "esc-resume", ttl=timedelta(minutes=5), sealed_continuation=_sealed()
    )
    prepared = await store.prepare_decision(
        "esc-resume",
        token=created.token,
        decision_id="decision-1",
        disposition=DecisionDisposition.APPROVE,
        approver_id="workload:approver-1",
        reason_digest="a" * 64,
    )
    await store.commit_decision("esc-resume", decision_id=prepared.decision_id)

    inspected = await store.inspect_approved("esc-resume", token=created.token)
    assert inspected == ApprovedEscalation(
        record=inspected.record,
        sealed_continuation=_sealed(),
        decision_id="decision-1",
        approver_id="workload:approver-1",
        reason_digest="a" * 64,
        decided_at=prepared.decided_at,
    )
    claimed = await store.claim_approved("esc-resume", token=created.token)
    assert claimed.record.status is EscalationStatus.CLAIMED
    assert claimed.sealed_continuation == _sealed()
    expected_claim = hashlib.sha256(b"esc-resume\0decision-1").hexdigest()
    assert claimed.claim_id == f"claim:{expected_claim}"
    assert claimed.claimed_at == NOW
    assert await store.inspect_claimed("esc-resume") == claimed
    with pytest.raises(EscalationStateError):
        await store.claim_approved("esc-resume", token=created.token)


async def test_approved_continuation_can_expire_through_audited_prepare_commit(
    store: EscalationStore,
) -> None:
    clock = [NOW]
    store._clock = lambda: clock[0]
    created = await store.create(
        "esc-resume", ttl=timedelta(seconds=10), sealed_continuation=_sealed()
    )
    prepared = await store.prepare_decision(
        "esc-resume",
        token=created.token,
        decision_id="decision-1",
        disposition=DecisionDisposition.APPROVE,
        approver_id="workload:approver-1",
        reason_digest="a" * 64,
    )
    await store.commit_decision("esc-resume", decision_id=prepared.decision_id)
    clock[0] = NOW + timedelta(seconds=10)

    expiring = await store.prepare_expiry("esc-resume")
    assert expiring.status is EscalationStatus.EXPIRY_PREPARED
    assert await store.prepare_expiry("esc-resume") == expiring
    expired = await store.commit_expiry("esc-resume")
    assert expired.status is EscalationStatus.EXPIRED


async def test_denial_cannot_expose_or_claim_continuation(store: EscalationStore) -> None:
    created = await store.create(
        "esc-resume", ttl=timedelta(minutes=5), sealed_continuation=_sealed()
    )
    prepared = await store.prepare_decision(
        "esc-resume",
        token=created.token,
        decision_id="decision-1",
        disposition=DecisionDisposition.DENY,
        approver_id="workload:approver-1",
        reason_digest="a" * 64,
    )
    record = await store.commit_decision("esc-resume", decision_id=prepared.decision_id)
    assert record.status is EscalationStatus.DENIED
    with pytest.raises(EscalationStateError):
        await store.inspect_approved("esc-resume", token=created.token)


async def test_v1_records_keep_legacy_automatic_expiry_semantics(
    store: EscalationStore,
) -> None:
    clock = [NOW]
    store._clock = lambda: clock[0]
    await store.create("legacy", ttl=timedelta(seconds=1))
    clock[0] = NOW + timedelta(seconds=1)

    expired = await store.get("legacy")
    assert expired.status is EscalationStatus.EXPIRED


async def test_v2_transition_metadata_is_redacted_and_timestamp_is_stable(
    store: EscalationStore, state_dir: Path
) -> None:
    created = await store.create(
        "esc-resume", ttl=timedelta(minutes=5), sealed_continuation=_sealed()
    )
    prepared = await store.prepare_decision(
        "esc-resume",
        token=created.token,
        decision_id="decision-1",
        disposition=DecisionDisposition.APPROVE,
        approver_id="workload:approver-1",
        reason_digest="c" * 64,
    )

    raw = _record_path(state_dir).read_text()
    assert "human supplied reason" not in raw
    assert '"reason_digest":"' + "c" * 64 + '"' in raw
    assert datetime.fromisoformat(json.loads(raw)["decision"]["decided_at"]) == prepared.decided_at


async def _approve_post_delivery(
    store: EscalationStore,
    *,
    escalation_id: str = "esc-post",
) -> tuple[str, str]:
    created = await store.create(
        escalation_id,
        ttl=timedelta(minutes=5),
        sealed_continuation=_sealed(),
        continuation_kind=ContinuationKind.POST_DELIVERY,
    )
    prepared = await store.prepare_decision(
        escalation_id,
        token=created.token,
        decision_id="decision-post",
        disposition=DecisionDisposition.APPROVE,
        approver_id="workload:approver-1",
        reason_digest="d" * 64,
    )
    await store.commit_decision(escalation_id, decision_id=prepared.decision_id)
    return created.token, prepared.decision_id


async def test_continuation_kind_is_signed_and_post_payload_stays_opaque(
    store: EscalationStore, state_dir: Path
) -> None:
    token, _ = await _approve_post_delivery(store)

    stored = json.loads(_record_path(state_dir).read_text())
    assert stored["continuation_kind"] == "post_delivery"
    assert stored["sealed_continuation"]["ciphertext"]
    assert "result" not in stored
    assert token not in json.dumps(stored)

    stored["continuation_kind"] = "pre_execution"
    _record_path(state_dir).write_text(json.dumps(stored))
    os.chmod(_record_path(state_dir), 0o600)
    with pytest.raises(EscalationTamperError):
        await store.get("esc-post")


async def test_pre_and_post_claim_paths_are_disjoint(store: EscalationStore) -> None:
    post_token, _ = await _approve_post_delivery(store)
    with pytest.raises(EscalationStateError, match="claim_post_delivery"):
        await store.claim_approved("esc-post", token=post_token)

    pre = await store.create("esc-pre", ttl=timedelta(minutes=5), sealed_continuation=_sealed())
    prepared = await store.prepare_decision(
        "esc-pre",
        token=pre.token,
        decision_id="decision-pre",
        disposition=DecisionDisposition.APPROVE,
        approver_id="workload:approver-1",
        reason_digest="e" * 64,
    )
    await store.commit_decision("esc-pre", decision_id=prepared.decision_id)
    with pytest.raises(EscalationStateError, match="claim_approved"):
        await store.claim_post_delivery("esc-pre", token=pre.token)


async def test_concurrent_post_delivery_claim_has_one_winner(
    store: EscalationStore,
) -> None:
    token, _ = await _approve_post_delivery(store)

    results = await asyncio.gather(
        *(store.claim_post_delivery("esc-post", token=token) for _ in range(8)),
        return_exceptions=True,
    )

    winners = [result for result in results if not isinstance(result, BaseException)]
    assert len(winners) == 1
    assert winners[0].record.status is EscalationStatus.DELIVERY_CLAIMED
    assert sum(isinstance(result, EscalationStateError) for result in results) == 7


@pytest.mark.parametrize(
    ("method_name", "expected"),
    [
        ("commit_delivered", EscalationStatus.DELIVERED),
        ("commit_delivery_denied", EscalationStatus.DELIVERY_DENIED),
        ("commit_handoff", EscalationStatus.HANDED_OFF),
    ],
)
async def test_post_delivery_terminal_commits_are_idempotent_and_conflict_safe(
    store: EscalationStore,
    method_name: str,
    expected: EscalationStatus,
) -> None:
    token, _ = await _approve_post_delivery(store)
    claimed = await store.claim_post_delivery("esc-post", token=token)
    assert claimed.claim_id is not None
    commit = getattr(store, method_name)

    terminal = await commit("esc-post", claim_id=claimed.claim_id)
    assert terminal.status is expected
    assert await commit("esc-post", claim_id=claimed.claim_id) == terminal
    assert (await store.inspect_claimed("esc-post")).record == terminal

    with pytest.raises(EscalationConflictError):
        await store.commit_delivered("esc-post", claim_id="wrong-claim")
    conflicting = (
        store.commit_delivery_denied
        if expected is not EscalationStatus.DELIVERY_DENIED
        else store.commit_handoff
    )
    with pytest.raises(EscalationConflictError):
        await conflicting("esc-post", claim_id=claimed.claim_id)


async def test_approved_post_delivery_continuation_keeps_expiry_semantics(
    store: EscalationStore,
) -> None:
    clock = [NOW]
    store._clock = lambda: clock[0]
    token, _ = await _approve_post_delivery(store)
    clock[0] = NOW + timedelta(minutes=5)

    with pytest.raises(EscalationExpiredError):
        await store.claim_post_delivery("esc-post", token=token)
    prepared = await store.prepare_expiry("esc-post")
    assert prepared.status is EscalationStatus.EXPIRY_PREPARED
    assert (await store.commit_expiry("esc-post")).status is EscalationStatus.EXPIRED
