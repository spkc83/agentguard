"""Operator-invoked retention bounds for durable evidence stores.

Pruning must never trade a verification or in-doubt guarantee for space: only
terminal records older than an explicit cutoff may be removed.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path  # noqa: TC003 -- pytest resolves fixture annotations at runtime

import pytest

from agentguard.compliance.continuation import ApprovalDisposition, SealedContinuation
from agentguard.compliance.escalation_store import EscalationStatus, EscalationStore
from agentguard.compliance.execution_journal import (
    ExecutionJournal,
    ExecutionJournalStatus,
    InDoubtClassification,
)

ESCALATION_KEY = b"e" * 32
JOURNAL_KEY = b"j" * 32
NOW = datetime(2026, 8, 28, 12, tzinfo=UTC)
PAYLOAD_DIGEST = "a" * 64
POLICY_VERSION = f"sha256:{'b' * 64}"
CHAIN_FINGERPRINT = "c" * 64


class _Clock:
    """A movable trusted clock for retention-window tests."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now


class _NoopProtector:
    """The journal only needs a protector for outcome sealing, unused here."""

    async def seal(self, plaintext: bytes, *, aad: bytes) -> SealedContinuation:
        raise NotImplementedError

    async def open(self, sealed: SealedContinuation, *, aad: bytes) -> bytes:
        raise NotImplementedError


def _sealed(marker: str) -> SealedContinuation:
    return SealedContinuation(
        algorithm="test-aead:v1",
        key_id="retention-test-key",
        nonce=b"n" * 12,
        ciphertext=base64.b64encode(marker.encode()),
    )


@pytest.fixture
def clock() -> _Clock:
    return _Clock(NOW)


@pytest.fixture
def store(tmp_path: Path, clock: _Clock) -> EscalationStore:
    return EscalationStore(tmp_path / "escalations", signing_key=ESCALATION_KEY, clock=clock)


@pytest.fixture
def journal(tmp_path: Path, clock: _Clock) -> ExecutionJournal:
    return ExecutionJournal(
        tmp_path / "journal",
        signing_key=JOURNAL_KEY,
        protector=_NoopProtector(),
        clock=clock,
    )


async def _denied(store: EscalationStore, escalation_id: str) -> None:
    created = await store.create(
        escalation_id,
        ttl=timedelta(minutes=5),
        sealed_continuation=_sealed(escalation_id),
    )
    await store.prepare_decision(
        escalation_id,
        token=created.token,
        decision_id=f"decision-{escalation_id}",
        disposition=ApprovalDisposition.DENY,
        approver_id="approver-1",
        reason_digest="d" * 64,
    )
    await store.commit_decision(escalation_id, decision_id=f"decision-{escalation_id}")


async def _approved(store: EscalationStore, escalation_id: str) -> None:
    created = await store.create(
        escalation_id,
        ttl=timedelta(minutes=5),
        sealed_continuation=_sealed(escalation_id),
    )
    await store.prepare_decision(
        escalation_id,
        token=created.token,
        decision_id=f"decision-{escalation_id}",
        disposition=ApprovalDisposition.APPROVE,
        approver_id="approver-1",
        reason_digest="d" * 64,
    )
    await store.commit_decision(escalation_id, decision_id=f"decision-{escalation_id}")


async def _claim(journal: ExecutionJournal, escalation_id: str) -> None:
    await journal.create_claim(
        escalation_id,
        claim_id=f"claim-{escalation_id}",
        invocation_id=f"inv-{escalation_id}",
        payload_digest=PAYLOAD_DIGEST,
        policy_bundle_version=POLICY_VERSION,
        chain_fingerprint=CHAIN_FINGERPRINT,
    )


async def test_prune_removes_only_old_terminal_escalations(
    store: EscalationStore, clock: _Clock
) -> None:
    await _denied(store, "esc-old-denied")
    await store.create(
        "esc-old-pending",
        ttl=timedelta(minutes=5),
        sealed_continuation=_sealed("esc-old-pending"),
    )
    await _approved(store, "esc-old-approved")
    clock.now = NOW + timedelta(days=1)
    await _denied(store, "esc-recent-denied")

    removed = await store.prune_terminal(NOW + timedelta(hours=1))

    assert removed == 1
    remaining = {record.escalation_id: record.status for record in await store.list_records()}
    assert remaining == {
        "esc-old-pending": EscalationStatus.PENDING,
        "esc-old-approved": EscalationStatus.APPROVED,
        "esc-recent-denied": EscalationStatus.DENIED,
    }


async def test_prune_keeps_a_terminal_escalation_inside_the_window(
    store: EscalationStore,
) -> None:
    await _denied(store, "esc-inside-window")

    removed = await store.prune_terminal(NOW)

    assert removed == 0
    assert len(await store.list_records()) == 1


async def test_prune_removes_expired_escalations(store: EscalationStore, clock: _Clock) -> None:
    created = await store.create(
        "esc-expiring",
        ttl=timedelta(minutes=5),
        sealed_continuation=_sealed("esc-expiring"),
    )
    assert created.record.status is EscalationStatus.PENDING
    clock.now = NOW + timedelta(minutes=6)
    await store.prepare_expiry("esc-expiring")
    await store.commit_expiry("esc-expiring")

    removed = await store.prune_terminal(NOW + timedelta(hours=1))

    assert removed == 1
    assert await store.list_records() == ()


async def test_prune_keeps_a_legacy_record_whose_expiry_is_not_yet_materialized(
    store: EscalationStore, clock: _Clock
) -> None:
    """A v1 record past its TTL is still durably PENDING until expiry is committed."""

    await store.create("esc-legacy", ttl=timedelta(minutes=5))
    clock.now = NOW + timedelta(days=1)

    removed = await store.prune_terminal(NOW + timedelta(hours=1))

    assert removed == 0
    assert len(await store.list_records()) == 1


async def test_prune_requires_an_aware_cutoff(store: EscalationStore) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        await store.prune_terminal(datetime(2026, 8, 28, 12))  # noqa: DTZ001


async def test_prune_removes_only_old_terminal_journal_entries(
    journal: ExecutionJournal, clock: _Clock
) -> None:
    await _claim(journal, "old-denied")
    await journal.mark_admitted(
        "old-denied", claim_id="claim-old-denied", invocation_id="inv-old-denied"
    )
    await journal.commit_execution_denied(
        "old-denied", claim_id="claim-old-denied", invocation_id="inv-old-denied"
    )
    await _claim(journal, "old-claimed")
    await _claim(journal, "old-in-doubt")
    await journal.mark_in_doubt(
        "old-in-doubt",
        claim_id="claim-old-in-doubt",
        invocation_id="inv-old-in-doubt",
        classification=InDoubtClassification.CLAIMED_WITHOUT_TERMINAL,
    )
    clock.now = NOW + timedelta(days=1)
    await _claim(journal, "recent-denied")
    await journal.mark_admitted(
        "recent-denied", claim_id="claim-recent-denied", invocation_id="inv-recent-denied"
    )
    await journal.commit_execution_denied(
        "recent-denied", claim_id="claim-recent-denied", invocation_id="inv-recent-denied"
    )

    removed = await journal.prune_terminal(NOW + timedelta(hours=1))

    assert removed == 1
    assert (await journal.find("old-claimed")).status is ExecutionJournalStatus.CLAIMED
    assert (await journal.find("old-in-doubt")).status is ExecutionJournalStatus.IN_DOUBT
    assert (await journal.find("recent-denied")).status is ExecutionJournalStatus.DELIVERY_DENIED


async def test_prune_never_removes_an_in_doubt_journal_entry(
    journal: ExecutionJournal, clock: _Clock
) -> None:
    await _claim(journal, "stuck")
    await journal.mark_in_doubt(
        "stuck",
        claim_id="claim-stuck",
        invocation_id="inv-stuck",
        classification=InDoubtClassification.CLAIMED_WITHOUT_TERMINAL,
    )
    clock.now = NOW + timedelta(days=365)

    removed = await journal.prune_terminal(NOW + timedelta(days=364))

    assert removed == 0
    assert (await journal.find("stuck")).status is ExecutionJournalStatus.IN_DOUBT


async def test_journal_prune_requires_an_aware_cutoff(journal: ExecutionJournal) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        await journal.prune_terminal(datetime(2026, 8, 28, 12))  # noqa: DTZ001


async def test_pruned_stores_still_verify_the_records_they_keep(
    store: EscalationStore, journal: ExecutionJournal, clock: _Clock
) -> None:
    await _denied(store, "esc-gone")
    await _claim(journal, "kept")
    clock.now = NOW + timedelta(days=1)

    assert await store.prune_terminal(NOW + timedelta(hours=1)) == 1
    assert await journal.prune_terminal(NOW + timedelta(hours=1)) == 0

    reopened_store = EscalationStore(store._directory, signing_key=ESCALATION_KEY, clock=clock)
    reopened_journal = ExecutionJournal(
        journal._directory,
        signing_key=JOURNAL_KEY,
        protector=_NoopProtector(),
        clock=clock,
    )
    assert await reopened_store.list_records() == ()
    assert (await reopened_journal.find("kept")).status is ExecutionJournalStatus.CLAIMED
