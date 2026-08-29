"""Authenticated restart-safe PRE_TOOL resume contract tests."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
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

NOW = datetime(2026, 8, 26, 12, tzinfo=UTC)
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


class _ApprovalGuardrail:
    id = "manual-approval"
    version = "1"
    resume_fingerprint = "tests.manual-approval.v1"
    stages = frozenset({GuardrailStage.PRE_TOOL})

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        self.calls += 1
        return GuardrailOutcome(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("HITL.APPROVAL_REQUIRED",),
        )


class _DownstreamGuardrail:
    id = "downstream"
    version = "1"
    resume_fingerprint = "tests.downstream.v1"
    stages = frozenset({GuardrailStage.PRE_TOOL})

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        self.calls += 1
        return GuardrailOutcome(effect=GuardrailEffect.ALLOW)


class _SecondApprovalGuardrail:
    id = "second-manual-approval"
    version = "1"
    resume_fingerprint = "tests.second-manual-approval.v1"
    stages = frozenset({GuardrailStage.PRE_TOOL})

    def __init__(self) -> None:
        self.calls = 0

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        self.calls += 1
        return GuardrailOutcome(
            effect=GuardrailEffect.ESCALATE,
            reason_codes=("HITL.SECOND_APPROVAL_REQUIRED",),
        )


def _rbac(*, allowed: bool = True) -> RBACEngine:
    permissions = (
        [Permission(action="tool:test", resource="allowed/item", effect="allow")] if allowed else []
    )
    return RBACEngine(roles=[Role(name="operator", permissions=permissions)])


async def _executor(payload: GuardrailPayload) -> object:
    assert isinstance(payload, ToolCallPayload)
    _executor.calls += 1
    return {"executed": True, "arguments": dict(payload.arguments)}


_executor.calls = 0  # type: ignore[attr-defined]


def _executor_registry() -> StaticExecutorRegistry:
    return StaticExecutorRegistry(
        [
            RegisteredExecutor(
                ref=ExecutorRef(
                    executor_id="test-executor",
                    version="1",
                    fingerprint="executor:test:v1",
                ),
                executor=_executor,
            )
        ]
    )


def _kernel(
    *,
    registry: AgentRegistry,
    rbac: RBACEngine,
    audit_dir: Path,
    store_dir: Path,
    policy_dir: Path,
    guardrails: tuple[object, ...],
    protector: _TestProtector | None = None,
) -> tuple[GovernanceKernel, AppendOnlyAuditLog, EscalationStore]:
    policy_dir.mkdir(exist_ok=True)
    audit = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    store = EscalationStore(store_dir, signing_key=STORE_KEY, clock=lambda: NOW)
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=rbac,
        audit_log=audit,
        policy_engine=PolicyEngine(policy_dirs=[policy_dir]),
        guardrails=guardrails,  # type: ignore[arg-type]
        escalation_store=store,
        escalation_ttl=timedelta(minutes=10),
        approver_authenticator=_Authenticator(),
        continuation_protector=protector or _TestProtector(),
        executor_resolver=_executor_registry(),
    )
    return kernel, audit, store


async def _request(
    kernel: GovernanceKernel,
    agent_id: str,
) -> EscalationRequiredError:
    with pytest.raises(EscalationRequiredError) as caught:
        await kernel.guarded_registered_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor_id="test-executor",
            payload=ToolCallPayload(arguments={"query": "safe-value"}),
        )
    return caught.value


async def test_approved_request_resumes_after_restart_without_rerunning_trigger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-test-key-padded-ab")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"], agent_id="agent-1")
    first_approval = _ApprovalGuardrail()
    first_downstream = _DownstreamGuardrail()
    first, _, _ = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(first_approval, first_downstream),
    )

    escalation = await _request(first, identity.agent_id)
    assert first_approval.calls == 1
    assert first_downstream.calls == 0
    assert escalation.approval_token
    raw_store = next((tmp_path / "store").glob("*.json")).read_text()
    assert "safe-value" not in raw_store

    second_approval = _ApprovalGuardrail()
    second_downstream = _DownstreamGuardrail()
    restarted, audit, store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(second_approval, second_downstream),
    )
    approved = await restarted.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
        reason="business approval",
    )
    assert approved.status is EscalationStatus.APPROVED

    _executor.calls = 0  # type: ignore[attr-defined]
    result = await restarted.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )

    assert result == {"executed": True, "arguments": {"query": "safe-value"}}
    assert _executor.calls == 1  # type: ignore[attr-defined]
    assert second_approval.calls == 0
    assert second_downstream.calls == 1
    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.CLAIMED
    event_types = [event.event_type for event in (await audit.read_verified()).events]
    assert event_types == [
        "escalation_requested",
        "approval_granted",
        "escalation_resumed",
        "admission",
        "execution_completed",
        "delivery_completed",
    ]
    with pytest.raises(EscalationStateError):
        await restarted.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )


async def test_forged_credential_leaves_request_pending_without_decision_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-forged-padded-abcd")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel, audit, store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(kernel, identity.agent_id)

    with pytest.raises(ValueError, match="invalid credential"):
        await kernel.decide_escalation(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
            credential=b"forged",
            decision_id="decision-1",
            disposition=ApprovalDisposition.APPROVE,
        )

    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.PENDING
    assert [event.event_type for event in (await audit.read_verified()).events] == [
        "escalation_requested"
    ]


async def test_exact_approval_retry_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-idempotent-padded-")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel, audit, _ = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(kernel, identity.agent_id)

    for _ in range(2):
        record = await kernel.decide_escalation(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
            credential=b"valid-credential",
            decision_id="decision-1",
            disposition=ApprovalDisposition.APPROVE,
            reason="same reason",
        )
        assert record.status is EscalationStatus.APPROVED

    assert [event.event_type for event in (await audit.read_verified()).events].count(
        "approval_granted"
    ) == 1


async def test_denied_decision_closes_invocation_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-denied-padded-abcd")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel, audit, store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(kernel, identity.agent_id)

    for _ in range(2):
        denied = await kernel.decide_escalation(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
            credential=b"valid-credential",
            decision_id="decision-denied",
            disposition=ApprovalDisposition.DENY,
            reason="not approved",
        )
        assert denied.status is EscalationStatus.DENIED

    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.DENIED
    assert [event.event_type for event in (await audit.read_verified()).events] == [
        "escalation_requested",
        "approval_denied",
        "delivery_denied",
    ]


async def test_concurrent_resume_claims_once_and_executes_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-concurrent-padded-")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel, _, _ = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(kernel, identity.agent_id)
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )

    _executor.calls = 0  # type: ignore[attr-defined]
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
    assert _executor.calls == 1  # type: ignore[attr-defined]


async def test_changed_policy_or_wrong_protector_fails_before_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-runtime-binding-pa")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    first, _, _ = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(first, identity.agent_id)
    await first.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )

    wrong_key, _, wrong_key_store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
        protector=_TestProtector(b"x" * 32),
    )
    with pytest.raises(EscalationStateError, match="validation failed"):
        await wrong_key.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    assert (await wrong_key_store.get(escalation.escalation_id)).status is (
        EscalationStatus.APPROVED
    )

    changed_policy = tmp_path / "changed-policy"
    changed_policy.mkdir()
    (changed_policy / "changed.yaml").write_text(
        """schema_version: 2
name: Changed
version: '1'
rules:
  - id: TEST-CHANGED-001
    name: Changed policy
    severity: low
    description: Changes the active bundle digest.
    check:
      type: metadata_required
      fields: [changed]
    remediation: none
    stage: pre_tool
    applies_to: all
    on_fail: warn
"""
    )
    changed, _, changed_store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=changed_policy,
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    with pytest.raises(EscalationStateError, match="policy bundle changed"):
        await changed.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    assert (await changed_store.get(escalation.escalation_id)).status is (EscalationStatus.APPROVED)


async def test_policy_reload_during_claim_cannot_change_pinned_resume_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-pinned-policy-padd")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    policy_dir = tmp_path / "policy"
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel, audit, store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=policy_dir,
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(kernel, identity.agent_id)
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )
    original_version = kernel._policy_engine.snapshot().version  # type: ignore[union-attr]
    original_claim = store.claim_approved

    async def _claim_and_reload(escalation_id: str, *, token: str):  # type: ignore[no-untyped-def]
        claimed = await original_claim(escalation_id, token=token)
        (policy_dir / "changed.yaml").write_text(
            """schema_version: 2
name: Changed
version: '1'
rules:
  - id: TEST-CHANGED-001
    name: Changed policy
    severity: low
    description: Changes the active bundle digest.
    check:
      type: metadata_required
      fields: [changed]
    remediation: none
    stage: pre_tool
    applies_to: all
    on_fail: warn
"""
        )
        assert kernel._policy_engine is not None
        await kernel._policy_engine.reload()  # type: ignore[union-attr]
        return claimed

    monkeypatch.setattr(store, "claim_approved", _claim_and_reload)
    _executor.calls = 0  # type: ignore[attr-defined]
    await kernel.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )

    assert _executor.calls == 1  # type: ignore[attr-defined]
    events = (await audit.read_verified()).events
    invocation_versions = {
        event.policy_bundle_version
        for event in events
        if event.invocation_id == events[0].invocation_id
    }
    assert invocation_versions == {original_version}
    assert kernel._policy_engine.snapshot().version != original_version  # type: ignore[union-attr]


async def test_two_sequential_approvals_resume_through_successful_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-two-approvals-padd")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    first = _ApprovalGuardrail()
    second = _SecondApprovalGuardrail()
    downstream = _DownstreamGuardrail()
    kernel, audit, _ = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(first, second, downstream),
    )
    first_request = await _request(kernel, identity.agent_id)
    await kernel.decide_escalation(
        escalation_id=first_request.escalation_id,
        approval_token=first_request.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )

    with pytest.raises(EscalationRequiredError) as caught:
        await kernel.resume_tool_call(
            escalation_id=first_request.escalation_id,
            approval_token=first_request.approval_token,
        )
    second_request = caught.value
    await kernel.decide_escalation(
        escalation_id=second_request.escalation_id,
        approval_token=second_request.approval_token,
        credential=b"valid-credential",
        decision_id="decision-2",
        disposition=ApprovalDisposition.APPROVE,
    )
    _executor.calls = 0  # type: ignore[attr-defined]
    result = await kernel.resume_tool_call(
        escalation_id=second_request.escalation_id,
        approval_token=second_request.approval_token,
    )

    assert result == {"executed": True, "arguments": {"query": "safe-value"}}
    assert _executor.calls == 1  # type: ignore[attr-defined]
    assert first.calls == second.calls == downstream.calls == 1
    assert [event.event_type for event in (await audit.read_verified()).events][-3:] == [
        "admission",
        "execution_completed",
        "delivery_completed",
    ]


async def test_cancellation_at_claim_boundary_closes_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-claim-cancel-padde")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel, audit, store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(kernel, identity.agent_id)
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )
    claimed = asyncio.Event()
    release = asyncio.Event()
    original_claim = store.claim_approved

    async def _paused_claim(escalation_id: str, *, token: str):  # type: ignore[no-untyped-def]
        result = await original_claim(escalation_id, token=token)
        claimed.set()
        await release.wait()
        return result

    monkeypatch.setattr(store, "claim_approved", _paused_claim)
    _executor.calls = 0  # type: ignore[attr-defined]
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

    assert _executor.calls == 0  # type: ignore[attr-defined]
    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.CLAIMED
    assert [event.event_type for event in (await audit.read_verified()).events][-1] == (
        "delivery_denied"
    )


async def test_admission_audit_failure_after_claim_closes_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-admission-failure-")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel, audit, store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(kernel, identity.agent_id)
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )

    class _AdmissionFailAudit:
        async def write(self, event):  # type: ignore[no-untyped-def]
            if event.event_type == "admission":
                raise RuntimeError("admission audit unavailable")
            return await audit.write(event)

        async def write_once(self, event):  # type: ignore[no-untyped-def]
            if event.event_type == "admission":
                raise RuntimeError("admission audit unavailable")
            return await audit.write_once(event)

    kernel._audit_log = _AdmissionFailAudit()  # type: ignore[assignment]
    _executor.calls = 0  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="admission audit unavailable"):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert _executor.calls == 0  # type: ignore[attr-defined]
    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.CLAIMED
    assert [event.event_type for event in (await audit.read_verified()).events][-2:] == [
        "escalation_resumed",
        "delivery_denied",
    ]


async def test_approved_request_expiring_before_resume_is_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-approved-expiry-pa")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel, audit, store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(kernel, identity.agent_id)
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )
    store._clock = lambda: NOW + timedelta(minutes=10)

    with pytest.raises(EscalationExpiredError, match=escalation.escalation_id):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.EXPIRED
    assert [event.event_type for event in (await audit.read_verified()).events][-2:] == [
        "approval_expired",
        "delivery_denied",
    ]
    assert (
        await kernel.expire_escalation(escalation_id=escalation.escalation_id)
    ).status is EscalationStatus.EXPIRED
    assert [event.event_type for event in (await audit.read_verified()).events][-2:] == [
        "approval_expired",
        "delivery_denied",
    ]


async def test_expiry_between_inspection_and_claim_is_reconciled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-claim-expiry-race-")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel, audit, store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(kernel, identity.agent_id)
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )
    original_claim = store.claim_approved

    async def _expiring_claim(escalation_id: str, *, token: str):  # type: ignore[no-untyped-def]
        store._clock = lambda: NOW + timedelta(minutes=10)
        return await original_claim(escalation_id, token=token)

    monkeypatch.setattr(store, "claim_approved", _expiring_claim)
    with pytest.raises(EscalationExpiredError, match=escalation.escalation_id):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.EXPIRED
    assert [event.event_type for event in (await audit.read_verified()).events][-2:] == [
        "approval_expired",
        "delivery_denied",
    ]


async def test_maximum_length_decision_id_can_be_claimed_and_resumed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-max-decision-id-pa")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    kernel, _, store = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(kernel, identity.agent_id)
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="d" * 256,
        disposition=ApprovalDisposition.APPROVE,
    )
    _executor.calls = 0  # type: ignore[attr-defined]
    await kernel.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )

    assert _executor.calls == 1  # type: ignore[attr-defined]
    assert (await store.get(escalation.escalation_id)).status is EscalationStatus.CLAIMED


async def test_rbac_revocation_after_approval_denies_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-resume-rbac-padded-abcdef")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    first, _, _ = _kernel(
        registry=registry,
        rbac=_rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    escalation = await _request(first, identity.agent_id)
    await first.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )

    revoked, audit, _ = _kernel(
        registry=registry,
        rbac=_rbac(allowed=False),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(_ApprovalGuardrail(), _DownstreamGuardrail()),
    )
    _executor.calls = 0  # type: ignore[attr-defined]
    with pytest.raises(PermissionDeniedError):
        await revoked.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    assert _executor.calls == 0  # type: ignore[attr-defined]
    assert [event.event_type for event in (await audit.read_verified()).events][-1] == (
        "delivery_denied"
    )


def test_resume_api_accepts_no_payload_or_executor() -> None:
    assert tuple(inspect.signature(GovernanceKernel.resume_tool_call).parameters) == (
        "self",
        "escalation_id",
        "approval_token",
    )
