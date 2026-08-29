"""Tests for the durable protected execution journal."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentguard.compliance.continuation import PostExecutionContinuation, SealedContinuation
from agentguard.compliance.engine import PolicyBundleSnapshot
from agentguard.compliance.execution_journal import (
    ExecutionJournal,
    ExecutionJournalAlreadyExistsError,
    ExecutionJournalConflictError,
    ExecutionJournalStateError,
    ExecutionJournalStatus,
    ExecutionJournalTamperError,
    InDoubtClassification,
    ProtectedExecutionOutcome,
)
from agentguard.guardrails import GuardrailEffect, GuardrailOutcome, GuardrailStage
from agentguard.guardrails.contracts import ToolResultPayload
from agentguard.guardrails.normalization import canonical_json_bytes
from agentguard.models import AgentIdentity, PermissionContext

KEY = b"j" * 32
NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)
PAYLOAD_DIGEST = "a" * 64
POLICY_VERSION = f"sha256:{'b' * 64}"
CHAIN_FINGERPRINT = "c" * 64


class _TestProtector:
    """Small authenticated-encryption stand-in for contract tests."""

    key = b"protector-key-material-for-tests"

    async def seal(self, plaintext: bytes, *, aad: bytes) -> SealedContinuation:
        nonce = hashlib.sha256(aad).digest()[:12]
        stream = hashlib.sha256(self.key + nonce + aad).digest()
        ciphertext = bytes(
            value ^ stream[index % len(stream)] for index, value in enumerate(plaintext)
        )
        tag = hmac.new(self.key, aad + nonce + ciphertext, hashlib.sha256).digest()
        return SealedContinuation(
            algorithm="test-aead:v1",
            key_id="journal-test-key",
            nonce=nonce,
            ciphertext=tag + ciphertext,
        )

    async def open(self, sealed: SealedContinuation, *, aad: bytes) -> bytes:
        tag, ciphertext = sealed.ciphertext[:32], sealed.ciphertext[32:]
        expected = hmac.new(self.key, aad + sealed.nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("authentication failed")
        stream = hashlib.sha256(self.key + sealed.nonce + aad).digest()
        return bytes(value ^ stream[index % len(stream)] for index, value in enumerate(ciphertext))


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "execution-journal"


@pytest.fixture
def journal(state_dir: Path) -> ExecutionJournal:
    return ExecutionJournal(
        state_dir,
        signing_key=KEY,
        protector=_TestProtector(),
        clock=lambda: NOW,
    )


def _record_path(directory: Path) -> Path:
    return next(directory.glob("*.json"))


async def _claim(journal: ExecutionJournal) -> None:
    await journal.create_claim(
        "esc-1",
        claim_id="claim-1",
        invocation_id="inv-1",
        payload_digest=PAYLOAD_DIGEST,
        policy_bundle_version=POLICY_VERSION,
        chain_fingerprint=CHAIN_FINGERPRINT,
    )


def _outcome(*, answer: str = "sensitive-result") -> ProtectedExecutionOutcome:
    payload = ToolResultPayload(result={"answer": answer})
    completed_at = NOW + timedelta(seconds=1)
    continuation = PostExecutionContinuation(
        escalation_id="esc-1",
        invocation_id="inv-1",
        trace_id="trace-1",
        agent_id="agent-1",
        action="tool:search",
        resource="search",
        permission_context=PermissionContext(
            agent=AgentIdentity(agent_id="agent-1", name="Agent", roles=["operator"]),
            requested_action="tool:search",
            resource="search",
            granted=True,
            reason="approved",
        ),
        stage=GuardrailStage.POST_TOOL,
        payload=payload,
        payload_digest=hashlib.sha256(
            canonical_json_bytes(payload.model_dump(mode="json"))
        ).hexdigest(),
        policy_bundle_version=POLICY_VERSION,
        policy_bundle_snapshot=PolicyBundleSnapshot(version=POLICY_VERSION, policy_sets=()),
        policy_results=(),
        prior_outcomes=(GuardrailOutcome(effect=GuardrailEffect.ALLOW),),
        prior_guardrail_decisions=(),
        guardrail_cursor=None,
        chain_fingerprint=CHAIN_FINGERPRINT,
        execution_duration_ms=12.5,
        execution_completed_at=completed_at,
        created_at=completed_at,
        expires_at=completed_at + timedelta(minutes=5),
    )
    return ProtectedExecutionOutcome(
        escalation_id="esc-1",
        claim_id="claim-1",
        invocation_id="inv-1",
        admission_payload_digest=PAYLOAD_DIGEST,
        policy_bundle_version=POLICY_VERSION,
        chain_fingerprint=CHAIN_FINGERPRINT,
        continuation=continuation,
    )


async def _protect(journal: ExecutionJournal) -> ProtectedExecutionOutcome:
    await _claim(journal)
    await journal.mark_admitted("esc-1", claim_id="claim-1", invocation_id="inv-1")
    outcome = _outcome()
    await journal.protect_outcome(
        "esc-1", claim_id="claim-1", invocation_id="inv-1", outcome=outcome
    )
    return outcome


async def test_create_is_private_authenticated_and_idempotent(
    journal: ExecutionJournal, state_dir: Path
) -> None:
    await _claim(journal)
    first = await journal.get("esc-1", claim_id="claim-1", invocation_id="inv-1")
    await _claim(journal)
    second = await journal.get("esc-1", claim_id="claim-1", invocation_id="inv-1")

    assert first == second
    assert first.status is ExecutionJournalStatus.CLAIMED
    assert first.revision == 0
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(_record_path(state_dir).stat().st_mode) == 0o600

    with pytest.raises(ExecutionJournalAlreadyExistsError):
        await journal.create_claim(
            "esc-1",
            claim_id="claim-1",
            invocation_id="inv-1",
            payload_digest="d" * 64,
            policy_bundle_version=POLICY_VERSION,
            chain_fingerprint=CHAIN_FINGERPRINT,
        )


async def test_find_returns_only_the_sole_authenticated_escalation_entry(
    journal: ExecutionJournal,
) -> None:
    await _claim(journal)
    assert (await journal.find("esc-1")).claim_id == "claim-1"

    await journal.create_claim(
        "esc-1",
        claim_id="claim-2",
        invocation_id="inv-2",
        payload_digest=PAYLOAD_DIGEST,
        policy_bundle_version=POLICY_VERSION,
        chain_fingerprint=CHAIN_FINGERPRINT,
    )
    with pytest.raises(ExecutionJournalConflictError, match="multiple journal entries"):
        await journal.find("esc-1")


async def test_protected_outcome_round_trips_without_plaintext_or_executor_reference(
    journal: ExecutionJournal, state_dir: Path
) -> None:
    expected = await _protect(journal)
    raw = _record_path(state_dir).read_text()

    assert "sensitive-result" not in raw
    assert "result_payload" not in raw
    assert "permission_context" not in raw
    assert "executor_ref" not in raw
    assert (
        await journal.open_outcome("esc-1", claim_id="claim-1", invocation_id="inv-1")
    ) == expected


async def test_outcome_is_bound_to_payload_policy_chain_and_exact_content(
    journal: ExecutionJournal,
) -> None:
    await _protect(journal)
    same = await journal.protect_outcome(
        "esc-1", claim_id="claim-1", invocation_id="inv-1", outcome=_outcome()
    )
    assert same.status is ExecutionJournalStatus.OUTCOME_PROTECTED

    with pytest.raises(ExecutionJournalConflictError):
        await journal.protect_outcome(
            "esc-1",
            claim_id="claim-1",
            invocation_id="inv-1",
            outcome=_outcome(answer="different"),
        )

    changed = _outcome().model_copy(
        update={
            "continuation": _outcome().continuation.model_copy(
                update={"chain_fingerprint": "d" * 64}
            )
        }
    )
    with pytest.raises(ExecutionJournalConflictError):
        await journal.protect_outcome(
            "esc-1", claim_id="claim-1", invocation_id="inv-1", outcome=changed
        )


async def test_known_result_lifecycle_has_explicit_post_claim_and_terminals(
    journal: ExecutionJournal,
) -> None:
    await _protect(journal)
    completed = await journal.mark_completion_audited(
        "esc-1", claim_id="claim-1", invocation_id="inv-1"
    )
    claimed = await journal.claim_post_processing(
        "esc-1", claim_id="claim-1", invocation_id="inv-1"
    )
    delivered = await journal.commit_delivered("esc-1", claim_id="claim-1", invocation_id="inv-1")

    assert completed.status is ExecutionJournalStatus.COMPLETION_AUDITED
    assert claimed.status is ExecutionJournalStatus.POST_PROCESSING_CLAIMED
    assert delivered.status is ExecutionJournalStatus.DELIVERED
    assert (
        await journal.commit_delivered("esc-1", claim_id="claim-1", invocation_id="inv-1")
    ) == delivered


async def test_delivery_denial_is_a_distinct_terminal(journal: ExecutionJournal) -> None:
    await _protect(journal)
    await journal.mark_completion_audited("esc-1", claim_id="claim-1", invocation_id="inv-1")
    await journal.claim_post_processing("esc-1", claim_id="claim-1", invocation_id="inv-1")
    denied = await journal.commit_delivery_denied(
        "esc-1", claim_id="claim-1", invocation_id="inv-1"
    )

    assert denied.status is ExecutionJournalStatus.DELIVERY_DENIED
    with pytest.raises(ExecutionJournalStateError):
        await journal.commit_delivered("esc-1", claim_id="claim-1", invocation_id="inv-1")


@pytest.mark.parametrize(
    ("advance", "classification"),
    [
        (False, InDoubtClassification.CLAIMED_WITHOUT_TERMINAL),
        (True, InDoubtClassification.ADMISSION_WITHOUT_COMPLETION),
        (True, InDoubtClassification.COMPLETION_WITHOUT_PROTECTED_RESULT),
    ],
)
async def test_in_doubt_reconciliation_is_deny_only_idempotent_and_conflict_safe(
    journal: ExecutionJournal,
    advance: bool,
    classification: InDoubtClassification,
) -> None:
    await _claim(journal)
    if advance:
        await journal.mark_admitted("esc-1", claim_id="claim-1", invocation_id="inv-1")
    doubtful = await journal.mark_in_doubt(
        "esc-1",
        claim_id="claim-1",
        invocation_id="inv-1",
        classification=classification,
    )
    prepared = await journal.prepare_reconciliation(
        "esc-1",
        claim_id="claim-1",
        invocation_id="inv-1",
        reconciliation_id="reconcile-1",
        reconciler_id="reviewer-1",
        reason_digest="e" * 64,
    )
    retried = await journal.prepare_reconciliation(
        "esc-1",
        claim_id="claim-1",
        invocation_id="inv-1",
        reconciliation_id="reconcile-1",
        reconciler_id="reviewer-1",
        reason_digest="e" * 64,
    )
    denied = await journal.commit_reconciled_denied(
        "esc-1",
        claim_id="claim-1",
        invocation_id="inv-1",
        reconciliation_id="reconcile-1",
    )

    assert doubtful.status is ExecutionJournalStatus.IN_DOUBT
    assert prepared == retried
    assert denied.status is ExecutionJournalStatus.RECONCILED_DENIED
    assert (
        await journal.commit_reconciled_denied(
            "esc-1",
            claim_id="claim-1",
            invocation_id="inv-1",
            reconciliation_id="reconcile-1",
        )
    ) == denied
    with pytest.raises(ExecutionJournalConflictError):
        await journal.prepare_reconciliation(
            "esc-1",
            claim_id="claim-1",
            invocation_id="inv-1",
            reconciliation_id="reconcile-2",
            reconciler_id="reviewer-1",
            reason_digest="e" * 64,
        )


async def test_in_doubt_prepare_and_commit_are_separate_idempotent_steps(
    journal: ExecutionJournal,
) -> None:
    await _claim(journal)
    prepared = await journal.prepare_in_doubt(
        "esc-1",
        claim_id="claim-1",
        invocation_id="inv-1",
        classification=InDoubtClassification.CLAIMED_WITHOUT_TERMINAL,
    )
    retried = await journal.prepare_in_doubt(
        "esc-1",
        claim_id="claim-1",
        invocation_id="inv-1",
        classification=InDoubtClassification.CLAIMED_WITHOUT_TERMINAL,
    )
    committed = await journal.commit_in_doubt(
        "esc-1",
        claim_id="claim-1",
        invocation_id="inv-1",
        classification=InDoubtClassification.CLAIMED_WITHOUT_TERMINAL,
    )

    assert prepared == retried
    assert prepared.status is ExecutionJournalStatus.IN_DOUBT_PREPARED
    assert committed.status is ExecutionJournalStatus.IN_DOUBT
    assert (
        await journal.commit_in_doubt(
            "esc-1",
            claim_id="claim-1",
            invocation_id="inv-1",
            classification=InDoubtClassification.CLAIMED_WITHOUT_TERMINAL,
        )
    ) == committed


async def test_post_processing_claim_can_be_classified_in_doubt_without_result_replay(
    journal: ExecutionJournal,
) -> None:
    await _protect(journal)
    await journal.mark_completion_audited("esc-1", claim_id="claim-1", invocation_id="inv-1")
    await journal.claim_post_processing("esc-1", claim_id="claim-1", invocation_id="inv-1")
    doubtful = await journal.mark_in_doubt(
        "esc-1",
        claim_id="claim-1",
        invocation_id="inv-1",
        classification=InDoubtClassification.CLAIMED_WITHOUT_TERMINAL,
    )

    assert doubtful.status is ExecutionJournalStatus.IN_DOUBT
    with pytest.raises(ExecutionJournalStateError):
        await journal.open_outcome("esc-1", claim_id="claim-1", invocation_id="inv-1")


async def test_concurrent_transition_has_one_durable_revision(journal: ExecutionJournal) -> None:
    await _claim(journal)
    results = await asyncio.gather(
        *(
            journal.mark_admitted("esc-1", claim_id="claim-1", invocation_id="inv-1")
            for _ in range(8)
        )
    )

    assert {record.status for record in results} == {ExecutionJournalStatus.ADMITTED}
    assert {record.revision for record in results} == {1}


@pytest.mark.parametrize("mutation", ["signed", "unknown", "ciphertext"])
async def test_tampered_records_fail_closed(
    journal: ExecutionJournal, state_dir: Path, mutation: str
) -> None:
    await _protect(journal)
    path = _record_path(state_dir)
    stored = json.loads(path.read_text())
    if mutation == "signed":
        stored["chain_fingerprint"] = "d" * 64
    elif mutation == "unknown":
        stored["unexpected"] = True
    else:
        stored["sealed_outcome"]["ciphertext"] = "AAAA"
    path.write_text(json.dumps(stored))
    os.chmod(path, 0o600)

    with pytest.raises(ExecutionJournalTamperError):
        await journal.get("esc-1", claim_id="claim-1", invocation_id="inv-1")


async def test_illegal_transition_is_rejected(journal: ExecutionJournal) -> None:
    await _claim(journal)
    with pytest.raises(ExecutionJournalStateError):
        await journal.mark_completion_audited("esc-1", claim_id="claim-1", invocation_id="inv-1")
    with pytest.raises(ExecutionJournalStateError):
        await journal.claim_post_processing("esc-1", claim_id="claim-1", invocation_id="inv-1")
