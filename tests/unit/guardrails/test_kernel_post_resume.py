"""Protected restart-safe POST_TOOL delivery continuation tests."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from agentguard.compliance.continuation import (
    ApprovalDisposition,
    ApproverPrincipal,
    SealedContinuation,
)
from agentguard.compliance.engine import PolicyEngine
from agentguard.compliance.escalation_store import (
    ContinuationKind,
    EscalationExpiredError,
    EscalationStateError,
    EscalationStatus,
    EscalationStore,
)
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import EscalationRequiredError, PermissionDeniedError
from agentguard.guardrails import (
    DecisionPayload,
    ExecutorRef,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailPayload,
    GuardrailStage,
    MessagePayload,
    RegisteredExecutor,
    StaticExecutorRegistry,
    ToolCallPayload,
)
from agentguard.guardrails.kernel import GovernanceKernel
from agentguard.models import AuditLink, EvidenceRef

if TYPE_CHECKING:
    from pathlib import Path

STORE_KEY = b"s" * 32
PROTECTOR_KEY = b"p" * 32


class _Authenticator:
    async def authenticate(self, credential: object) -> ApproverPrincipal:
        if credential != b"valid-credential":
            raise ValueError("invalid credential")
        return ApproverPrincipal(
            approver_id="reviewer-1",
            capabilities=frozenset({"hitl:approve", "hitl:deny"}),
        )


class _TestProtector:
    """Test-only encrypt-then-MAC provider exercising the injected contract."""

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
            raise ValueError("invalid protected continuation")
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


class _PostApprovalGuardrail:
    id = "post-manual-approval"
    version = "1"
    resume_fingerprint = "tests.post-manual-approval.v1"
    stages = frozenset({GuardrailStage.POST_TOOL})

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        self.calls += 1
        return GuardrailOutcome(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("HITL.APPROVAL_REQUIRED",),
        )


class _SecondPostApprovalGuardrail:
    id = "second-post-manual-approval"
    version = "1"
    resume_fingerprint = "tests.second-post-manual-approval.v1"
    stages = frozenset({GuardrailStage.POST_TOOL})

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        self.calls += 1
        return GuardrailOutcome(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("HITL.SECOND_APPROVAL_REQUIRED",),
        )


class _PostAllowGuardrail:
    id = "post-allow"
    version = "1"
    resume_fingerprint = "tests.post-allow.v1"
    stages = frozenset({GuardrailStage.POST_TOOL})

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        self.calls += 1
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


class _PostDenyGuardrail:
    id = "post-deny"
    version = "1"
    resume_fingerprint = "tests.post-deny.v1"
    stages = frozenset({GuardrailStage.POST_TOOL})

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        return GuardrailOutcome(
            effect=GuardrailEffect.DENY,
            reason_codes=("TEST.POST_DENIED",),
        )


class _PostMessageApprovalGuardrail(_PostApprovalGuardrail):
    id = "post-message-manual-approval"
    resume_fingerprint = "tests.post-message-manual-approval.v1"
    stages = frozenset({GuardrailStage.POST_MESSAGE})


class _DecisionApprovalGuardrail(_PostApprovalGuardrail):
    id = "decision-manual-approval"
    resume_fingerprint = "tests.decision-manual-approval.v1"
    stages = frozenset({GuardrailStage.ON_DECISION})


class _DecisionAllowGuardrail(_PostAllowGuardrail):
    id = "decision-allow"
    resume_fingerprint = "tests.decision-allow.v1"
    stages = frozenset({GuardrailStage.ON_DECISION})


class _ExecutorProbe:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, payload: GuardrailPayload) -> object:
        if isinstance(payload, MessagePayload):
            self.calls += 1
            return {"executed": True, "message": payload.message}
        assert isinstance(payload, ToolCallPayload)
        self.calls += 1
        return {"executed": True, "query": payload.arguments["query"]}


class _DecisionExecutorProbe(_ExecutorProbe):
    async def __call__(self, _payload: GuardrailPayload) -> object:
        self.calls += 1
        return DecisionPayload.model_validate(
            {
                "domain": "credit_risk",
                "decision_id": "decision-001",
                "outcome": "decline",
                "body": {"score": 620},
            }
        )


def _rbac(*, allowed: bool = True) -> RBACEngine:
    permissions = (
        [
            Permission(
                action="tool:test",
                resource="allowed/item",
                effect="allow",
            )
        ]
        if allowed
        else []
    )
    return RBACEngine(
        roles=[
            Role(
                name="operator",
                permissions=permissions,
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
    policy_dir: Path,
    guardrails: tuple[object, ...],
    probe: _ExecutorProbe | None,
    protector: _TestProtector | None = None,
    rbac: RBACEngine | None = None,
) -> tuple[GovernanceKernel, AppendOnlyAuditLog, EscalationStore]:
    policy_dir.mkdir(exist_ok=True)
    audit = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    store = EscalationStore(
        store_dir,
        signing_key=STORE_KEY,
        clock=lambda: datetime.now(UTC),
    )
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=rbac or _rbac(),
        audit_log=audit,
        policy_engine=PolicyEngine(policy_dirs=[policy_dir]),
        guardrails=guardrails,  # type: ignore[arg-type]
        escalation_store=store,
        escalation_ttl=timedelta(minutes=10),
        approver_authenticator=_Authenticator(),
        continuation_protector=protector or _TestProtector(),
        executor_resolver=_executor_registry(probe) if probe is not None else None,
    )
    return kernel, audit, store


async def _request_post(
    kernel: GovernanceKernel,
    *,
    agent_id: str,
    subject_ref: EvidenceRef | None = None,
    links: tuple[AuditLink, ...] = (),
    redacted_evidence: object | None = None,
) -> EscalationRequiredError:
    with pytest.raises(EscalationRequiredError) as caught:
        await kernel.guarded_registered_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor_id="test-executor",
            payload=ToolCallPayload.model_validate({"arguments": {"query": "safe-value"}}),
            subject_ref=subject_ref,
            links=links,
            redacted_evidence=redacted_evidence,
        )
    return caught.value


async def _approve(
    kernel: GovernanceKernel,
    escalation: EscalationRequiredError,
    *,
    decision_id: str = "decision-1",
) -> None:
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id=decision_id,
        disposition=ApprovalDisposition.APPROVE,
    )


async def _registered_agent(registry: AgentRegistry) -> str:
    identity = await registry.register(name="Operator", roles=["operator"])
    return identity.agent_id


async def test_approved_post_tool_request_delivers_after_restart_without_executor_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-happy-padded-")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    policy_dir = tmp_path / "policy"
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    first, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostApprovalGuardrail(), _PostAllowGuardrail()),
        probe=probe,
    )
    escalation = await _request_post(first, agent_id=agent_id)
    assert probe.calls == 1

    restarted, audit, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostApprovalGuardrail(), _PostAllowGuardrail()),
        probe=None,
    )
    await _approve(restarted, escalation)
    result = await restarted.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )

    assert result == {"executed": True, "query": "safe-value"}
    assert probe.calls == 1
    record = await store.get(escalation.escalation_id)
    assert record.continuation_kind is ContinuationKind.POST_DELIVERY
    assert record.status is EscalationStatus.DELIVERED
    events = (await audit.read_verified()).events
    invocation_id = events[0].invocation_id
    invocation_events = [
        event.event_type for event in events if event.invocation_id == invocation_id
    ]
    assert invocation_events == [
        "admission",
        "execution_completed",
        "escalation_requested",
        "approval_granted",
        "escalation_resumed",
        "delivery_completed",
    ]
    assert (
        sum(
            event in {"delivery_completed", "delivery_denied", "delivery_escalated"}
            for event in invocation_events
        )
        == 1
    )


async def test_approved_post_message_request_delivers_without_executor_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-message-resume-padde")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    policy_dir = tmp_path / "policy"
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    first, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostMessageApprovalGuardrail(),),
        probe=probe,
    )
    with pytest.raises(EscalationRequiredError) as caught:
        await first.guarded_registered_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor_id="test-executor",
            payload=MessagePayload(target="peer", message="safe-message"),
        )
    escalation = caught.value
    assert probe.calls == 1

    restarted, _, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostMessageApprovalGuardrail(),),
        probe=None,
    )
    await _approve(restarted, escalation)
    result = await restarted.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )

    assert result == {"executed": True, "message": "safe-message"}
    assert probe.calls == 1
    assert (await store.get(escalation.escalation_id)).status is (EscalationStatus.DELIVERED)


async def test_concurrent_post_tool_resume_has_one_delivery_claimant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-concurrent-pa")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    kernel, audit, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_PostApprovalGuardrail(), _PostAllowGuardrail()),
        probe=probe,
    )
    escalation = await _request_post(kernel, agent_id=agent_id)
    await _approve(kernel, escalation)

    results = await asyncio.gather(
        *(
            kernel.resume_tool_call(
                escalation_id=escalation.escalation_id,
                approval_token=escalation.approval_token,
            )
            for _ in range(2)
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, BaseException) for result in results) == 1
    assert sum(isinstance(result, EscalationStateError) for result in results) == 1
    assert probe.calls == 1
    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.DELIVERED


async def test_denied_post_tool_request_never_reexecutes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-denied-padded")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    kernel, audit, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_PostApprovalGuardrail(),),
        probe=probe,
    )
    escalation = await _request_post(kernel, agent_id=agent_id)

    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-denied",
        disposition=ApprovalDisposition.DENY,
    )

    assert probe.calls == 1
    event_types = [event.event_type for event in (await audit.read_verified()).events]
    assert event_types.count("delivery_denied") == 1


async def test_expired_post_tool_request_never_reexecutes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-expired-padde")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    kernel, audit, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_PostApprovalGuardrail(),),
        probe=probe,
    )
    escalation = await _request_post(kernel, agent_id=agent_id)
    record = await store.get(escalation.escalation_id)
    store._clock = lambda: record.expires_at

    with pytest.raises(EscalationExpiredError):
        await kernel.decide_escalation(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
            credential=b"valid-credential",
            decision_id="decision-expired",
            disposition=ApprovalDisposition.APPROVE,
        )

    assert probe.calls == 1
    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.EXPIRED
    event_types = [event.event_type for event in (await audit.read_verified()).events]
    assert event_types.count("delivery_denied") == 1


async def test_wrong_post_continuation_key_fails_before_delivery_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-key-mismatch-")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    policy_dir = tmp_path / "policy"
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    first, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostApprovalGuardrail(),),
        probe=probe,
    )
    escalation = await _request_post(first, agent_id=agent_id)
    await _approve(first, escalation)
    wrong_key, _, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostApprovalGuardrail(),),
        probe=None,
        protector=_TestProtector(b"x" * 32),
    )

    with pytest.raises(EscalationStateError, match="validation failed"):
        await wrong_key.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert probe.calls == 1
    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.APPROVED


async def test_changed_post_chain_fails_before_delivery_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-chain-mismatch")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    policy_dir = tmp_path / "policy"
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    first, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostApprovalGuardrail(), _PostAllowGuardrail()),
        probe=probe,
    )
    escalation = await _request_post(first, agent_id=agent_id)
    await _approve(first, escalation)
    changed, _, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostApprovalGuardrail(),),
        probe=None,
    )

    with pytest.raises(EscalationStateError, match="chain fingerprint changed"):
        await changed.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert probe.calls == 1
    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.APPROVED


async def test_changed_post_policy_fails_before_delivery_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-policy-mismatch")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    policy_dir = tmp_path / "policy"
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    first, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostApprovalGuardrail(),),
        probe=probe,
    )
    escalation = await _request_post(first, agent_id=agent_id)
    await _approve(first, escalation)

    changed_policy = tmp_path / "changed-policy"
    changed_policy.mkdir()
    (changed_policy / "changed.yaml").write_text(
        """schema_version: 2
name: Changed
version: '1'
rules:
  - id: TEST-CHANGED-POST-001
    name: Changed post policy
    severity: low
    description: Changes the active bundle digest.
    check:
      type: metadata_required
      fields: [changed]
    remediation: none
    stage: post_tool
    applies_to: all
    on_fail: warn
"""
    )
    changed, _, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=changed_policy,
        guardrails=(_PostApprovalGuardrail(),),
        probe=None,
    )

    with pytest.raises(EscalationStateError, match="policy bundle changed"):
        await changed.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert probe.calls == 1
    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.APPROVED


async def test_revoked_rbac_denies_claimed_post_delivery_without_reexecution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-rbac-revoked-")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    policy_dir = tmp_path / "policy"
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    first, _, _ = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostApprovalGuardrail(),),
        probe=probe,
    )
    escalation = await _request_post(first, agent_id=agent_id)
    await _approve(first, escalation)
    revoked, audit, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_PostApprovalGuardrail(),),
        probe=None,
        rbac=_rbac(allowed=False),
    )

    with pytest.raises(PermissionDeniedError):
        await revoked.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert probe.calls == 1
    assert (await store.get(escalation.escalation_id)).status is (EscalationStatus.DELIVERY_DENIED)
    assert [event.event_type for event in (await audit.read_verified()).events].count(
        "delivery_denied"
    ) == 1


async def test_repeated_cancellation_at_post_claim_closes_delivery_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-claim-cancel-")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    kernel, audit, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_PostApprovalGuardrail(), _PostAllowGuardrail()),
        probe=probe,
    )
    escalation = await _request_post(kernel, agent_id=agent_id)
    await _approve(kernel, escalation)
    claimed = asyncio.Event()
    release = asyncio.Event()
    original_claim = store.claim_post_delivery

    async def _paused_claim(escalation_id: str, *, token: str):  # type: ignore[no-untyped-def]
        result = await original_claim(escalation_id, token=token)
        claimed.set()
        await release.wait()
        return result

    monkeypatch.setattr(store, "claim_post_delivery", _paused_claim)
    task = asyncio.create_task(
        kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    )
    await claimed.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert probe.calls == 1
    assert (await store.get(escalation.escalation_id)).status is (EscalationStatus.DELIVERY_DENIED)
    assert [event.event_type for event in (await audit.read_verified()).events].count(
        "delivery_denied"
    ) == 1


async def test_repeated_cancellation_during_denial_commit_closes_delivery_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-denial-commit-cancel")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    kernel, audit, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_PostApprovalGuardrail(), _PostDenyGuardrail()),
        probe=probe,
    )
    escalation = await _request_post(kernel, agent_id=agent_id)
    await _approve(kernel, escalation)
    commit_started = asyncio.Event()
    release = asyncio.Event()
    original_commit = store.commit_delivery_denied

    async def _paused_commit(escalation_id: str, *, claim_id: str):  # type: ignore[no-untyped-def]
        commit_started.set()
        await release.wait()
        return await original_commit(escalation_id, claim_id=claim_id)

    monkeypatch.setattr(store, "commit_delivery_denied", _paused_commit)
    task = asyncio.create_task(
        kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    )
    await commit_started.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert probe.calls == 1
    assert (await store.get(escalation.escalation_id)).status is (EscalationStatus.DELIVERY_DENIED)
    assert [event.event_type for event in (await audit.read_verified()).events].count(
        "delivery_denied"
    ) == 1


async def test_post_resume_denial_uses_digest_only_evidence_after_prior_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-evidence-denial")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    (
        kernel,
        audit,
        _,
    ) = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_PostApprovalGuardrail(), _PostDenyGuardrail()),
        probe=_ExecutorProbe(),
    )
    escalation = await _request_post(
        kernel,
        agent_id=agent_id,
        redacted_evidence={"name": "Ada Lovelace", "address": "1 Secret Lane"},
    )
    await _approve(kernel, escalation)

    with pytest.raises(PermissionDeniedError):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    events = (await audit.read_verified(require_checkpoint=True)).events
    resumed = next(event for event in events if event.event_type == "escalation_resumed")
    denial = events[-1]
    assert resumed.payload_redacted == {"value": {}}
    assert denial.event_type == "delivery_denied"
    assert denial.payload_redacted == {"value": {}}


async def test_second_post_escalation_hands_off_without_executor_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-resume-second-approval")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    first_guard = _PostApprovalGuardrail()
    second_guard = _SecondPostApprovalGuardrail()
    allow_guard = _PostAllowGuardrail()
    kernel, audit, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(first_guard, second_guard, allow_guard),
        probe=probe,
    )
    first_request = await _request_post(kernel, agent_id=agent_id)
    await _approve(kernel, first_request, decision_id="decision-1")

    with pytest.raises(EscalationRequiredError) as caught:
        await kernel.resume_tool_call(
            escalation_id=first_request.escalation_id,
            approval_token=first_request.approval_token,
        )
    second_request = caught.value

    assert probe.calls == 1
    assert (await store.get(first_request.escalation_id)).status is (EscalationStatus.HANDED_OFF)
    await _approve(kernel, second_request, decision_id="decision-2")
    result = await kernel.resume_tool_call(
        escalation_id=second_request.escalation_id,
        approval_token=second_request.approval_token,
    )
    assert result == {"executed": True, "query": "safe-value"}
    assert probe.calls == 1
    assert first_guard.calls == second_guard.calls == allow_guard.calls == 1
    child_event = next(
        event
        for event in (await audit.read_verified()).events
        if event.event_type == "escalation_requested"
        and event.hitl_evidence is not None
        and event.hitl_evidence.escalation_id == second_request.escalation_id
    )
    assert len(child_event.links) == 1
    assert child_event.links[0].relation == "parent"
    assert child_event.links[0].target.namespace == "hitl-escalation"
    assert child_event.links[0].target.value == first_request.escalation_id


async def test_decision_post_escalation_resumes_without_executor_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-decision-post-resume-padd")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _DecisionExecutorProbe()
    approval = _DecisionApprovalGuardrail()
    allow = _DecisionAllowGuardrail()
    kernel, audit, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(approval, allow),
        probe=probe,
    )

    subject_ref = EvidenceRef(namespace="credit-application", value="application-001")
    links = (
        AuditLink(
            relation="decision",
            target=EvidenceRef(namespace="credit-decision", value="decision-001"),
        ),
    )
    safe_evidence = {"decision_id": "decision-001", "outcome": "decline"}
    request = await _request_post(
        kernel,
        agent_id=agent_id,
        subject_ref=subject_ref,
        links=links,
        redacted_evidence=safe_evidence,
    )
    sealed = await store.get_sealed_continuation(request.escalation_id)
    tampered = sealed.model_copy(
        update={"ciphertext": sealed.ciphertext[:-1] + bytes([sealed.ciphertext[-1] ^ 1])}
    )
    with pytest.raises(EscalationStateError, match="protected continuation validation failed"):
        await kernel._open_continuation(  # noqa: SLF001 - verifies protected-state boundary
            request.escalation_id,
            tampered,
            ContinuationKind.POST_DELIVERY,
        )
    assert probe.calls == 1
    await _approve(kernel, request)

    delivered = await kernel.resume_tool_call(
        escalation_id=request.escalation_id,
        approval_token=request.approval_token,
    )

    assert isinstance(delivered, DecisionPayload)
    assert delivered.decision_id == "decision-001"
    assert probe.calls == 1
    assert approval.calls == allow.calls == 1
    assert (await store.get(request.escalation_id)).status is EscalationStatus.DELIVERED
    events = (await audit.read_verified(require_checkpoint=True)).events
    assert [event.event_type for event in events].count("execution_completed") == 1
    assert events[-1].event_type == "delivery_completed"
    assert events[-1].subject_ref == subject_ref
    assert events[-1].links == links
    assert events[-1].payload_redacted == {"value": safe_evidence}
    assert "score" not in events[-1].model_dump_json()


async def test_repeated_cancellation_during_child_handoff_returns_recoverable_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-post-handoff-cancel-padde")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await _registered_agent(registry)
    probe = _ExecutorProbe()
    kernel, _, store = _kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(
            _PostApprovalGuardrail(),
            _SecondPostApprovalGuardrail(),
            _PostAllowGuardrail(),
        ),
        probe=probe,
    )
    first_request = await _request_post(kernel, agent_id=agent_id)
    await _approve(kernel, first_request, decision_id="decision-1")
    commit_started = asyncio.Event()
    release = asyncio.Event()
    original_commit = store.commit_handoff

    async def _paused_commit(escalation_id: str, *, claim_id: str):  # type: ignore[no-untyped-def]
        commit_started.set()
        await release.wait()
        return await original_commit(escalation_id, claim_id=claim_id)

    monkeypatch.setattr(store, "commit_handoff", _paused_commit)
    task = asyncio.create_task(
        kernel.resume_tool_call(
            escalation_id=first_request.escalation_id,
            approval_token=first_request.approval_token,
        )
    )
    await commit_started.wait()
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    release.set()
    with pytest.raises(EscalationRequiredError) as caught:
        await task
    child = caught.value

    assert child.escalation_id
    assert child.approval_token
    assert probe.calls == 1
    assert (await store.get(first_request.escalation_id)).status is (EscalationStatus.HANDED_OFF)
    await _approve(kernel, child, decision_id="decision-2")
    result = await kernel.resume_tool_call(
        escalation_id=child.escalation_id,
        approval_token=child.approval_token,
    )
    assert result == {"executed": True, "query": "safe-value"}
    assert probe.calls == 1
