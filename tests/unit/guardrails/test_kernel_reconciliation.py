"""Authenticated execution reconciliation and no-replay contract tests."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
import secrets
from datetime import timedelta
from typing import TYPE_CHECKING, Any, cast

import pytest

from agentguard.compliance.continuation import (
    ApprovalDisposition,
    ApproverPrincipal,
    PostExecutionContinuation,
    SealedContinuation,
)
from agentguard.compliance.engine import PolicyEngine
from agentguard.compliance.escalation_store import (
    ContinuationKind,
    EscalationStateError,
    EscalationStatus,
    EscalationStore,
)
from agentguard.compliance.execution_journal import (
    ExecutionJournal,
    ExecutionJournalRecord,
    ExecutionJournalStatus,
    ExecutionJournalTamperError,
    InDoubtClassification,
)
from agentguard.core.audit import AppendOnlyAuditLog, AuditCheckpoint, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import (
    AuditTamperDetectedError,
    EscalationRequiredError,
    PermissionDeniedError,
)
from agentguard.guardrails import (
    ExecutorRef,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailPayload,
    GuardrailStage,
    RegisteredExecutor,
    StaticExecutorRegistry,
    ToolCallPayload,
)
from agentguard.guardrails.kernel import GovernanceKernel

if TYPE_CHECKING:
    from pathlib import Path

STORE_KEY = b"s" * 32
JOURNAL_KEY = b"j" * 32
PROTECTOR_KEY = b"p" * 32


class _Authenticator:
    def __init__(self, capabilities: frozenset[str] | None = None) -> None:
        self._capabilities = capabilities or frozenset(
            {"hitl:approve", "hitl:deny", "hitl:reconcile"}
        )

    async def authenticate(self, credential: object) -> ApproverPrincipal:
        if credential != b"valid-credential":
            raise ValueError("invalid credential")
        return ApproverPrincipal(
            approver_id="reviewer-1",
            capabilities=self._capabilities,  # type: ignore[arg-type]
        )


class _TestProtector:
    def __init__(self, key: bytes = PROTECTOR_KEY) -> None:
        self._key = key

    async def seal(self, plaintext: bytes, *, aad: bytes) -> SealedContinuation:
        nonce = secrets.token_bytes(16)
        stream = self._stream(nonce, aad, len(plaintext))
        encrypted = bytes(left ^ right for left, right in zip(plaintext, stream, strict=True))
        tag = hmac.new(self._key, aad + nonce + encrypted, hashlib.sha256).digest()
        return SealedContinuation(
            algorithm="test-xor-hmac-sha256",
            key_id="test-key",
            nonce=nonce,
            ciphertext=tag + encrypted,
        )

    async def open(self, sealed: SealedContinuation, *, aad: bytes) -> bytes:
        tag, encrypted = sealed.ciphertext[:32], sealed.ciphertext[32:]
        expected = hmac.new(self._key, aad + sealed.nonce + encrypted, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("invalid protected value")
        stream = self._stream(sealed.nonce, aad, len(encrypted))
        return bytes(left ^ right for left, right in zip(encrypted, stream, strict=True))

    def _stream(self, nonce: bytes, aad: bytes, length: int) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < length:
            output.extend(
                hmac.new(
                    self._key,
                    nonce + aad + counter.to_bytes(8, "big"),
                    hashlib.sha256,
                ).digest()
            )
            counter += 1
        return bytes(output[:length])


class _PreApproval:
    id = "pre-approval"
    version = "1"
    resume_fingerprint = "tests.reconciliation.pre-approval.v1"
    stages = frozenset({GuardrailStage.PRE_TOOL})

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        return GuardrailOutcome(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("HITL.APPROVAL_REQUIRED",),
        )


class _PostApproval:
    id = "post-approval"
    version = "1"
    resume_fingerprint = "tests.reconciliation.post-approval.v1"
    stages = frozenset({GuardrailStage.POST_TOOL})

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        self.calls += 1
        return GuardrailOutcome(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("HITL.POST_APPROVAL_REQUIRED",),
        )


class _PostAllow:
    id = "post-allow"
    version = "1"
    resume_fingerprint = "tests.reconciliation.post-allow.v1"
    stages = frozenset({GuardrailStage.POST_TOOL})

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        self.calls += 1
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


class _PostDeny:
    id = "post-deny"
    version = "1"
    resume_fingerprint = "tests.reconciliation.post-deny.v1"
    stages = frozenset({GuardrailStage.POST_TOOL})

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        return GuardrailOutcome(
            effect=GuardrailEffect.DENY,
            reason_codes=("TEST.OUTPUT_DENIED",),
        )


class _BlockingPost:
    id = "post-blocking"
    version = "1"
    resume_fingerprint = "tests.reconciliation.post-blocking.v1"
    stages = frozenset({GuardrailStage.POST_TOOL})

    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class _ExecutorProbe:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, payload: GuardrailPayload) -> object:
        assert isinstance(payload, ToolCallPayload)
        self.calls += 1
        return {"executed": True, "query": payload.arguments["query"]}


class _FailingExecutor(_ExecutorProbe):
    async def __call__(self, payload: GuardrailPayload) -> object:
        assert isinstance(payload, ToolCallPayload)
        self.calls += 1
        raise RuntimeError("executor failed")


class _InvalidOutputExecutor(_ExecutorProbe):
    async def __call__(self, payload: GuardrailPayload) -> object:
        assert isinstance(payload, ToolCallPayload)
        self.calls += 1
        return object()


class _BlockingExecutor(_ExecutorProbe):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()

    async def __call__(self, payload: GuardrailPayload) -> object:
        assert isinstance(payload, ToolCallPayload)
        self.calls += 1
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


def _rbac() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="operator",
                permissions=[
                    Permission(action="tool:test", resource="allowed/item", effect="allow")
                ],
            )
        ]
    )


def _executor_registry(probe: _ExecutorProbe) -> StaticExecutorRegistry:
    return StaticExecutorRegistry(
        [
            RegisteredExecutor(
                ref=ExecutorRef(
                    executor_id="test-executor",
                    version="1",
                    fingerprint="executor:test:v1",
                ),
                executor=probe,
            )
        ]
    )


def _kernel(
    *,
    registry: AgentRegistry,
    audit_dir: Path,
    store_dir: Path,
    journal_dir: Path,
    policy_dir: Path,
    guardrails: tuple[object, ...],
    probe: _ExecutorProbe | None,
    authenticator: _Authenticator | None = None,
    trusted_checkpoint: AuditCheckpoint | None = None,
) -> tuple[GovernanceKernel, AppendOnlyAuditLog, EscalationStore, ExecutionJournal]:
    policy_dir.mkdir(exist_ok=True)
    protector = _TestProtector()
    audit = AppendOnlyAuditLog(
        FileAuditBackend(audit_dir),
        trusted_checkpoint=trusted_checkpoint,
    )
    store = EscalationStore(store_dir, signing_key=STORE_KEY)
    journal = ExecutionJournal(
        journal_dir,
        signing_key=JOURNAL_KEY,
        protector=protector,
    )
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=_rbac(),
        audit_log=audit,
        policy_engine=PolicyEngine(policy_dirs=[policy_dir]),
        guardrails=guardrails,  # type: ignore[arg-type]
        escalation_store=store,
        escalation_ttl=timedelta(minutes=10),
        approver_authenticator=authenticator or _Authenticator(),
        continuation_protector=protector,
        executor_resolver=_executor_registry(probe) if probe is not None else None,
        execution_journal=journal,
    )
    return kernel, audit, store, journal


async def _register(registry: AgentRegistry) -> str:
    identity = await registry.register(name="Operator", roles=["operator"])
    return identity.agent_id


async def _request(
    kernel: GovernanceKernel,
    agent_id: str,
    *,
    redacted_evidence: object | None = None,
) -> EscalationRequiredError:
    with pytest.raises(EscalationRequiredError) as caught:
        await kernel.guarded_registered_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor_id="test-executor",
            payload=ToolCallPayload.model_validate({"arguments": {"query": "safe-value"}}),
            redacted_evidence=redacted_evidence,
        )
    return caught.value


async def _approve(kernel: GovernanceKernel, escalation: EscalationRequiredError) -> None:
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="approval-1",
        disposition=ApprovalDisposition.APPROVE,
    )


def _journal_json(journal_dir: Path) -> dict[str, Any]:
    path = next(path for path in journal_dir.glob("*.json"))
    return cast("dict[str, Any]", json.loads(path.read_text()))


async def test_journal_enabled_pre_resume_executes_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-pre-once-padded-abcdef")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    probe = _ExecutorProbe()
    kernel, _, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=probe,
    )
    escalation = await _request(kernel, await _register(registry))
    await _approve(kernel, escalation)

    result = await kernel.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )

    assert result == {"executed": True, "query": "safe-value"}
    assert probe.calls == 1


async def test_journal_enabled_pre_resume_protects_result_before_completion_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-protect-order-padded-a")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    probe = _ExecutorProbe()
    kernel, audit, _, journal = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=probe,
    )
    escalation = await _request(kernel, await _register(registry))
    await _approve(kernel, escalation)
    original_write_once = audit.write_once

    async def _fail_completion(event):  # type: ignore[no-untyped-def]
        if event.event_type == "execution_completed":
            assert _journal_json(tmp_path / "journal")["status"] == "outcome_protected"
            raise RuntimeError("completion audit unavailable")
        return await original_write_once(event)

    monkeypatch.setattr(audit, "write_once", _fail_completion)
    with pytest.raises(RuntimeError, match="completion audit unavailable"):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert probe.calls == 1
    assert _journal_json(tmp_path / "journal")["status"] == (
        ExecutionJournalStatus.OUTCOME_PROTECTED
    )
    assert journal is not None


async def test_journal_marker_never_persists_unvalidated_result_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-unvalidated-projection")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    kernel, audit, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(), _PostDeny()),
        probe=_ExecutorProbe(),
    )
    escalation = await _request(
        kernel,
        await _register(registry),
        redacted_evidence={"name": "Ada Lovelace", "address": "1 Secret Lane"},
    )
    await _approve(kernel, escalation)

    with pytest.raises(PermissionDeniedError):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    events = (await audit.read_verified(require_checkpoint=True)).events
    marker = next(
        event for event in events if event.event_type == "execution_post_processing_claimed"
    )
    denial = next(event for event in events if event.event_type == "delivery_denied")
    assert marker.payload_redacted == {"value": {}}
    assert denial.payload_redacted == {"value": {}}
    serialized = "".join(path.read_text() for path in audit_dir.rglob("*.jsonl"))
    assert "Ada Lovelace" not in serialized
    assert "1 Secret Lane" not in serialized


async def test_assessment_requires_checkpoint_attested_audit_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-checkpoint-padded-abcd")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    kernel, audit, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=_ExecutorProbe(),
    )
    escalation = await _request(kernel, await _register(registry))
    called = False

    async def _read_verified(*, require_checkpoint: bool = False):  # type: ignore[no-untyped-def]
        nonlocal called
        called = True
        assert require_checkpoint is True
        raise AuditTamperDetectedError(event_index=0, event_id="<checkpoint>")

    monkeypatch.setattr(audit, "read_verified", _read_verified)
    with pytest.raises(AuditTamperDetectedError):
        await kernel.assess_execution(
            escalation.escalation_id,
            credential=b"valid-credential",
        )

    assert called


@pytest.mark.parametrize(
    ("credential", "authenticator"),
    [
        (b"forged", _Authenticator()),
        (
            b"valid-credential",
            _Authenticator(frozenset({"hitl:approve", "hitl:deny"})),
        ),
    ],
)
async def test_unauthorized_assessment_does_not_mutate_durable_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    credential: bytes,
    authenticator: _Authenticator,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-auth-padded-abcdefghij")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    kernel, audit, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=_ExecutorProbe(),
        authenticator=authenticator,
    )
    escalation = await _request(kernel, await _register(registry))
    before_store = sorted(path.read_bytes() for path in (tmp_path / "store").glob("*.json"))
    before_audit = tuple((await audit.read_verified()).events)

    with pytest.raises((ValueError, PermissionError, EscalationStateError)):
        await kernel.assess_execution(escalation.escalation_id, credential=credential)

    assert sorted(path.read_bytes() for path in (tmp_path / "store").glob("*.json")) == (
        before_store
    )
    assert tuple((await audit.read_verified()).events) == before_audit


async def test_admission_without_protected_result_is_classified_in_doubt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-admission-window-padde")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    probe = _ExecutorProbe()
    kernel, _, _, journal = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=probe,
    )
    escalation = await _request(kernel, await _register(registry))
    await _approve(kernel, escalation)

    async def _fail_protection(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("outcome protection unavailable")

    monkeypatch.setattr(journal, "protect_outcome", _fail_protection)
    with pytest.raises(RuntimeError, match="outcome protection unavailable"):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    assessment = await kernel.assess_execution(
        escalation.escalation_id,
        credential=b"valid-credential",
    )

    assert probe.calls == 1
    assert assessment.classification is (InDoubtClassification.ADMISSION_WITHOUT_COMPLETION)
    assert assessment.status is ExecutionJournalStatus.IN_DOUBT


async def test_known_protected_outcome_recovery_never_resolves_or_replays_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-known-result-padded-ab")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    probe = _ExecutorProbe()
    kernel, audit, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=probe,
    )
    escalation = await _request(kernel, await _register(registry))
    await _approve(kernel, escalation)
    original_write_once = audit.write_once

    async def _fail_completion(event):  # type: ignore[no-untyped-def]
        if event.event_type == "execution_completed":
            raise RuntimeError("completion audit unavailable")
        return await original_write_once(event)

    monkeypatch.setattr(audit, "write_once", _fail_completion)
    with pytest.raises(RuntimeError, match="completion audit unavailable"):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    monkeypatch.setattr(audit, "write_once", original_write_once)

    restarted, _, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=None,
    )
    result = await restarted.reconcile_known_outcome(
        escalation.escalation_id,
        credential=b"valid-credential",
        reconciliation_id="reconcile-1",
        reason="recover protected result",
    )

    assert result == {"executed": True, "query": "safe-value"}
    assert probe.calls == 1


@pytest.mark.parametrize(
    ("failure_mode", "probe"),
    [
        pytest.param("exception", _FailingExecutor(), id="executor-exception"),
        pytest.param("cancellation", _BlockingExecutor(), id="executor-cancellation"),
        pytest.param("invalid-output", _InvalidOutputExecutor(), id="invalid-executor-output"),
    ],
)
async def test_journaled_executor_failure_commits_one_stable_delivery_denial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
    probe: _ExecutorProbe,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", f"reconcile-{failure_mode}-terminal-abcdefghijkl")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    kernel, audit, _, journal = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=probe,
    )
    escalation = await _request(kernel, await _register(registry))
    await _approve(kernel, escalation)

    if isinstance(probe, _BlockingExecutor):
        task = asyncio.create_task(
            kernel.resume_tool_call(
                escalation_id=escalation.escalation_id,
                approval_token=escalation.approval_token,
            )
        )
        await asyncio.wait_for(probe.started.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    elif isinstance(probe, _FailingExecutor):
        with pytest.raises(RuntimeError, match="executor failed"):
            await kernel.resume_tool_call(
                escalation_id=escalation.escalation_id,
                approval_token=escalation.approval_token,
            )
    else:
        with pytest.raises(PermissionDeniedError):
            await kernel.resume_tool_call(
                escalation_id=escalation.escalation_id,
                approval_token=escalation.approval_token,
            )

    record = await journal.find(escalation.escalation_id)
    events = tuple(
        event
        for event in (await audit.read_verified()).events
        if event.invocation_id == record.invocation_id
    )
    terminal = [event for event in events if event.event_type == "delivery_denied"]
    assert probe.calls == 1
    assert record.status is ExecutionJournalStatus.DELIVERY_DENIED
    assert len(terminal) == 1
    assert terminal[0].event_id == f"invocation:{record.invocation_id}:delivery"

    assessment = await kernel.assess_execution(
        escalation.escalation_id,
        credential=b"valid-credential",
    )
    assert assessment.status is ExecutionJournalStatus.DELIVERY_DENIED
    with pytest.raises(EscalationStateError):
        await kernel.deny_in_doubt(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id=f"conflicting-{failure_mode}",
        )
    assert (await journal.find(escalation.escalation_id)).status is (
        ExecutionJournalStatus.DELIVERY_DENIED
    )


async def test_repeated_cancellation_waits_for_durable_execution_denial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-cancellation-ordering-")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    probe = _BlockingExecutor()
    kernel, audit, _, journal = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=probe,
    )
    escalation = await _request(kernel, await _register(registry))
    await _approve(kernel, escalation)
    completion_blocked = asyncio.Event()
    release_completion = asyncio.Event()
    journal_committed = asyncio.Event()
    release_journal_return = asyncio.Event()
    original_write_once = audit.write_once
    original_commit = journal.commit_execution_denied

    async def _block_completion(event):  # type: ignore[no-untyped-def]
        if event.event_type == "execution_completed":
            completion_blocked.set()
            await release_completion.wait()
        return await original_write_once(event)

    async def _pause_after_journal_commit(
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
    ) -> ExecutionJournalRecord:
        record = await original_commit(
            escalation_id,
            claim_id=claim_id,
            invocation_id=invocation_id,
        )
        journal_committed.set()
        await release_journal_return.wait()
        return record

    monkeypatch.setattr(audit, "write_once", _block_completion)
    monkeypatch.setattr(journal, "commit_execution_denied", _pause_after_journal_commit)
    task = asyncio.create_task(
        kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    )
    await asyncio.wait_for(probe.started.wait(), timeout=1)
    task.cancel()
    await asyncio.wait_for(completion_blocked.wait(), timeout=1)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()

    release_completion.set()
    await asyncio.wait_for(journal_committed.wait(), timeout=1)
    record = await journal.find(escalation.escalation_id)
    terminal = next(
        event
        for event in (await audit.read_verified()).events
        if event.event_type == "delivery_denied" and event.invocation_id == record.invocation_id
    )
    assert not task.done()
    assert record.status is ExecutionJournalStatus.DELIVERY_DENIED
    assert terminal.event_id == f"invocation:{record.invocation_id}:delivery"

    release_journal_return.set()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_post_delivery_claim_reconciliation_is_deny_only_without_guardrail_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-post-claim-padded-abcd")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    probe = _ExecutorProbe()
    approval = _PostApproval()
    downstream = _PostAllow()
    kernel, _, store, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(approval, downstream),
        probe=probe,
    )
    escalation = await _request(kernel, await _register(registry))
    await _approve(kernel, escalation)
    await store.claim_post_delivery(
        escalation.escalation_id,
        token=escalation.approval_token,
    )
    calls_before = (approval.calls, downstream.calls)

    assessment = await kernel.assess_execution(
        escalation.escalation_id,
        credential=b"valid-credential",
    )
    await kernel.deny_in_doubt(
        escalation.escalation_id,
        credential=b"valid-credential",
        reconciliation_id="reconcile-post-1",
        reason="post processing outcome unknown",
    )

    assert assessment.classification is InDoubtClassification.CLAIMED_WITHOUT_TERMINAL
    assert (approval.calls, downstream.calls) == calls_before
    assert probe.calls == 1


async def test_same_reconciliation_id_is_idempotent_under_concurrency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-concurrent-same-padded")
    kernel, escalation = await _admission_window(tmp_path, monkeypatch)

    results = await asyncio.gather(
        *(
            kernel.deny_in_doubt(
                escalation.escalation_id,
                credential=b"valid-credential",
                reconciliation_id="reconcile-same",
                reason="unknown side effect",
            )
            for _ in range(2)
        )
    )

    assert results[0] == results[1]


async def test_different_reconciliation_ids_have_one_terminal_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-concurrent-different-p")
    kernel, escalation = await _admission_window(tmp_path, monkeypatch)

    results = await asyncio.gather(
        *(
            kernel.deny_in_doubt(
                escalation.escalation_id,
                credential=b"valid-credential",
                reconciliation_id=reconciliation_id,
                reason="unknown side effect",
            )
            for reconciliation_id in ("reconcile-a", "reconcile-b")
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, BaseException) for result in results) == 1
    assert sum(isinstance(result, EscalationStateError) for result in results) == 1


async def _admission_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    assess: bool = True,
) -> tuple[GovernanceKernel, EscalationRequiredError]:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    kernel, _, _, journal = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=_ExecutorProbe(),
    )
    escalation = await _request(kernel, await _register(registry))
    await _approve(kernel, escalation)

    async def _fail_protection(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("outcome protection unavailable")

    monkeypatch.setattr(journal, "protect_outcome", _fail_protection)
    with pytest.raises(RuntimeError, match="outcome protection unavailable"):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    if assess:
        await kernel.assess_execution(
            escalation.escalation_id,
            credential=b"valid-credential",
        )
    return kernel, escalation


async def _known_outcome_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    recovery_guardrails: tuple[object, ...],
    redacted_evidence: object | None = None,
) -> tuple[
    GovernanceKernel,
    EscalationRequiredError,
    _ExecutorProbe,
    AppendOnlyAuditLog,
    ExecutionJournal,
]:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    probe = _ExecutorProbe()
    first, audit, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(), *recovery_guardrails),
        probe=probe,
    )
    escalation = await _request(
        first,
        await _register(registry),
        redacted_evidence=redacted_evidence,
    )
    await _approve(first, escalation)
    original_write_once = audit.write_once

    async def _fail_completion(event):  # type: ignore[no-untyped-def]
        if event.event_type == "execution_completed":
            raise RuntimeError("completion audit unavailable")
        return await original_write_once(event)

    monkeypatch.setattr(audit, "write_once", _fail_completion)
    with pytest.raises(RuntimeError, match="completion audit unavailable"):
        await first.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    monkeypatch.setattr(audit, "write_once", original_write_once)
    trusted_checkpoint = await audit.export_checkpoint()
    assert trusted_checkpoint is not None
    restarted, restarted_audit, _, journal = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(), *recovery_guardrails),
        probe=None,
        trusted_checkpoint=trusted_checkpoint,
    )
    return restarted, escalation, probe, restarted_audit, journal


async def test_known_outcome_post_denial_never_replays_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-known-denial-padded-ab")
    kernel, escalation, probe, audit, journal = await _known_outcome_window(
        tmp_path,
        monkeypatch,
        recovery_guardrails=(_PostDeny(),),
        redacted_evidence={"name": "Ada Lovelace", "address": "1 Secret Lane"},
    )

    with pytest.raises(PermissionDeniedError):
        await kernel.reconcile_known_outcome(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id="known-denial",
        )

    assert probe.calls == 1
    assert (await journal.find(escalation.escalation_id)).status is (
        ExecutionJournalStatus.DELIVERY_DENIED
    )
    assert (
        sum(event.event_type == "delivery_denied" for event in (await audit.read_verified()).events)
        == 1
    )
    denial = next(
        event
        for event in (await audit.read_verified(require_checkpoint=True)).events
        if event.event_type == "delivery_denied"
    )
    assert denial.payload_redacted == {"value": {}}
    serialized = "".join(path.read_text() for path in (tmp_path / "audit").rglob("*.jsonl"))
    assert "Ada Lovelace" not in serialized
    assert "1 Secret Lane" not in serialized


async def test_known_outcome_post_escalation_hands_off_without_executor_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-known-handoff-padded-a")
    approval = _PostApproval()
    allow = _PostAllow()
    kernel, escalation, probe, audit, journal = await _known_outcome_window(
        tmp_path,
        monkeypatch,
        recovery_guardrails=(approval, allow),
    )
    original_record = await journal.find(escalation.escalation_id)
    original_outcome = await journal.open_outcome(
        escalation.escalation_id,
        claim_id=original_record.claim_id,
        invocation_id=original_record.invocation_id,
    )

    with pytest.raises(EscalationRequiredError) as caught:
        await kernel.reconcile_known_outcome(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id="known-handoff",
        )
    child = caught.value
    store = kernel._require_escalation_store()
    child_record = await store.get(child.escalation_id)
    child_continuation = await kernel._open_continuation(
        child.escalation_id,
        await store.get_sealed_continuation(child.escalation_id),
        child_record.continuation_kind,
    )
    assert isinstance(child_continuation, PostExecutionContinuation)

    assert probe.calls == 1
    assert (await journal.find(escalation.escalation_id)).status is (
        ExecutionJournalStatus.HANDED_OFF
    )
    assert child_record.status is EscalationStatus.PENDING
    assert child_record.continuation_kind is ContinuationKind.POST_DELIVERY
    assert child_continuation.policy_results == original_outcome.continuation.policy_results
    assert child_continuation.prior_outcomes == original_outcome.continuation.prior_outcomes
    child_event = next(
        event
        for event in (await audit.read_verified()).events
        if event.event_type == "escalation_requested"
        and event.hitl_evidence is not None
        and event.hitl_evidence.escalation_id == child.escalation_id
    )
    assert child_event.links[0].relation == "parent"
    assert child_event.links[0].target.value == escalation.escalation_id

    await _approve(kernel, child)
    delivered = await kernel.resume_tool_call(
        escalation_id=child.escalation_id,
        approval_token=child.approval_token,
    )
    assert delivered == {"executed": True, "query": "safe-value"}
    assert probe.calls == 1
    assert approval.calls == allow.calls == 1


async def test_known_outcome_cancellation_finishes_recoverable_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-known-handoff-cancel-p")
    kernel, escalation, probe, _, journal = await _known_outcome_window(
        tmp_path,
        monkeypatch,
        recovery_guardrails=(_PostApproval(), _PostAllow()),
    )
    commit_started = asyncio.Event()
    release = asyncio.Event()
    original_commit = journal.commit_handoff

    async def _paused_commit(
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
    ) -> ExecutionJournalRecord:
        commit_started.set()
        await release.wait()
        return await original_commit(
            escalation_id,
            claim_id=claim_id,
            invocation_id=invocation_id,
        )

    monkeypatch.setattr(journal, "commit_handoff", _paused_commit)
    task = asyncio.create_task(
        kernel.reconcile_known_outcome(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id="known-handoff-cancel",
        )
    )
    await asyncio.wait_for(commit_started.wait(), timeout=1)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    release.set()

    with pytest.raises(EscalationRequiredError) as caught:
        await task

    assert caught.value.escalation_id
    assert caught.value.approval_token
    assert probe.calls == 1
    assert (await journal.find(escalation.escalation_id)).status is (
        ExecutionJournalStatus.HANDED_OFF
    )


async def test_known_outcome_cancellation_commits_denial_without_executor_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-known-cancellation-pad")
    blocking = _BlockingPost()
    kernel, escalation, probe, audit, journal = await _known_outcome_window(
        tmp_path,
        monkeypatch,
        recovery_guardrails=(blocking,),
        redacted_evidence={"name": "Ada Lovelace", "address": "1 Secret Lane"},
    )
    task = asyncio.create_task(
        kernel.reconcile_known_outcome(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id="known-cancellation",
        )
    )
    await asyncio.wait_for(blocking.started.wait(), timeout=1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert probe.calls == 1
    assert (await journal.find(escalation.escalation_id)).status is (
        ExecutionJournalStatus.DELIVERY_DENIED
    )
    assert (
        sum(event.event_type == "delivery_denied" for event in (await audit.read_verified()).events)
        == 1
    )
    denial = next(
        event
        for event in (await audit.read_verified(require_checkpoint=True)).events
        if event.event_type == "delivery_denied"
    )
    assert denial.payload_redacted == {"value": {}}
    serialized = "".join(path.read_text() for path in (tmp_path / "audit").rglob("*.jsonl"))
    assert "Ada Lovelace" not in serialized
    assert "1 Secret Lane" not in serialized


async def test_stale_valid_journal_cannot_replay_post_processing_after_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-signed-journal-rollback")
    post = _PostAllow()
    kernel, escalation, probe, audit, journal = await _known_outcome_window(
        tmp_path,
        monkeypatch,
        recovery_guardrails=(post,),
    )
    journal_path = next((tmp_path / "journal").glob("*.json"))
    earlier_valid_bytes = journal_path.read_bytes()

    delivered = await kernel.reconcile_known_outcome(
        escalation.escalation_id,
        credential=b"valid-credential",
        reconciliation_id="first-delivery",
    )
    assert delivered == {"executed": True, "query": "safe-value"}
    assert post.calls == 1
    assert (await journal.find(escalation.escalation_id)).status is (
        ExecutionJournalStatus.DELIVERED
    )

    journal_path.write_bytes(earlier_valid_bytes)
    with pytest.raises(EscalationStateError, match="audited delivery terminal"):
        await kernel.reconcile_known_outcome(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id="rollback-retry",
        )

    events = tuple((await audit.read_verified()).events)
    recovered_record = await journal.find(escalation.escalation_id)
    delivery_events = [
        event
        for event in events
        if event.event_type == "delivery_completed"
        and event.invocation_id == recovered_record.invocation_id
    ]
    assert probe.calls == 1
    assert post.calls == 1
    assert recovered_record.status is ExecutionJournalStatus.DELIVERED
    assert len(delivery_events) == 1
    assert delivery_events[0].event_id == (
        f"invocation:{delivery_events[0].invocation_id}:delivery"
    )


async def test_tampered_journal_blocks_assessment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-tamper-padded-abcdefgh")
    kernel, escalation = await _admission_window(tmp_path, monkeypatch)
    journal_path = next((tmp_path / "journal").glob("*.json"))
    raw = json.loads(journal_path.read_text())
    raw["revision"] += 1
    journal_path.write_text(json.dumps(raw))

    with pytest.raises(ExecutionJournalTamperError):
        await kernel.assess_execution(
            escalation.escalation_id,
            credential=b"valid-credential",
        )


async def test_in_doubt_audit_append_then_raise_converges_on_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-in-doubt-append-padded")
    kernel, escalation = await _admission_window(tmp_path, monkeypatch, assess=False)
    audit = kernel._audit_log
    original_write_once = audit.write_once
    raised = False

    async def _append_then_raise(event):  # type: ignore[no-untyped-def]
        nonlocal raised
        written = await original_write_once(event)
        if event.event_type == "execution_in_doubt" and not raised:
            raised = True
            raise RuntimeError("caller lost in-doubt acknowledgement")
        return written

    monkeypatch.setattr(audit, "write_once", _append_then_raise)
    with pytest.raises(RuntimeError, match="lost in-doubt acknowledgement"):
        await kernel.assess_execution(
            escalation.escalation_id,
            credential=b"valid-credential",
        )
    assessment = await kernel.assess_execution(
        escalation.escalation_id,
        credential=b"valid-credential",
    )

    events = (await audit.read_verified()).events
    assert assessment.status is ExecutionJournalStatus.IN_DOUBT
    assert sum(event.event_type == "execution_in_doubt" for event in events) == 1


async def test_reconciliation_audit_append_then_raise_converges_on_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-decision-append-padded")
    kernel, escalation = await _admission_window(tmp_path, monkeypatch)
    audit = kernel._audit_log
    original_write_once = audit.write_once
    raised = False

    async def _append_then_raise(event):  # type: ignore[no-untyped-def]
        nonlocal raised
        written = await original_write_once(event)
        if event.event_type == "execution_reconciled" and not raised:
            raised = True
            raise RuntimeError("caller lost reconciliation acknowledgement")
        return written

    monkeypatch.setattr(audit, "write_once", _append_then_raise)
    with pytest.raises(RuntimeError, match="lost reconciliation acknowledgement"):
        await kernel.deny_in_doubt(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id="reconcile-append",
            reason="unknown side effect",
        )
    record = await kernel.deny_in_doubt(
        escalation.escalation_id,
        credential=b"valid-credential",
        reconciliation_id="reconcile-append",
        reason="unknown side effect",
    )

    events = (await audit.read_verified()).events
    assert record.status is ExecutionJournalStatus.RECONCILED_DENIED
    assert sum(event.event_type == "execution_reconciled" for event in events) == 1


async def test_delivery_audit_append_then_raise_converges_on_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-delivery-append-padded")
    kernel, escalation = await _admission_window(tmp_path, monkeypatch)
    audit = kernel._audit_log
    original_write_once = audit.write_once
    raised = False

    async def _append_then_raise(event):  # type: ignore[no-untyped-def]
        nonlocal raised
        written = await original_write_once(event)
        if event.event_type == "delivery_denied" and not raised:
            raised = True
            raise RuntimeError("caller lost delivery acknowledgement")
        return written

    monkeypatch.setattr(audit, "write_once", _append_then_raise)
    with pytest.raises(RuntimeError, match="lost delivery acknowledgement"):
        await kernel.deny_in_doubt(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id="delivery-append",
            reason="unknown side effect",
        )
    record = await kernel.deny_in_doubt(
        escalation.escalation_id,
        credential=b"valid-credential",
        reconciliation_id="delivery-append",
        reason="unknown side effect",
    )

    events = (await audit.read_verified()).events
    assert record.status is ExecutionJournalStatus.RECONCILED_DENIED
    assert sum(event.event_type == "delivery_denied" for event in events) == 1


async def test_reconciliation_persistence_contains_no_plaintext_canaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-no-plaintext-padded-ab")
    kernel, escalation = await _admission_window(tmp_path, monkeypatch)
    await kernel.deny_in_doubt(
        escalation.escalation_id,
        credential=b"valid-credential",
        reconciliation_id="reconcile-secret-check",
        reason="raw reconciliation reason canary",
    )

    control_plane = b"\n".join(
        path.read_bytes()
        for directory in (tmp_path / "store", tmp_path / "journal")
        for path in directory.glob("*.json*")
    )
    all_persistence = (
        control_plane
        + b"\n"
        + b"\n".join(path.read_bytes() for path in (tmp_path / "audit").glob("*.json*"))
    )
    assert b"safe-value" not in control_plane
    assert b"valid-credential" not in all_persistence
    assert b"raw reconciliation reason canary" not in all_persistence


def test_reconciliation_apis_accept_no_replacement_execution_inputs() -> None:
    forbidden = {"result", "payload", "executor", "executor_id", "disposition"}
    for method_name in ("assess_execution", "reconcile_known_outcome", "deny_in_doubt"):
        parameters = set(inspect.signature(getattr(GovernanceKernel, method_name)).parameters)
        assert parameters.isdisjoint(forbidden), method_name


async def test_execution_lifecycle_event_ids_are_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "reconcile-stable-events-padded-a")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    kernel, audit, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        journal_dir=tmp_path / "journal",
        policy_dir=tmp_path / "policy",
        guardrails=(_PreApproval(),),
        probe=_ExecutorProbe(),
    )
    escalation = await _request(kernel, await _register(registry))
    await _approve(kernel, escalation)
    await kernel.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )

    events = (await audit.read_verified()).events
    invocation_id = events[0].invocation_id
    by_type = {event.event_type: event.event_id for event in events}
    assert by_type["admission"] == f"invocation:{invocation_id}:admission"
    assert by_type["execution_completed"] == (f"invocation:{invocation_id}:execution-completed")
    assert by_type["delivery_completed"] == f"invocation:{invocation_id}:delivery"
