"""Sandbox-obligation routing through the governed execution boundary."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.core.sandbox import (
    SANDBOX_BACKEND_REQUIRED,
    SANDBOX_COMMAND_INVALID,
    SANDBOX_INTERNAL_ERROR,
    SANDBOX_OBLIGATION_CONFLICT,
    SANDBOX_PROCESS_EXIT_NONZERO,
    SANDBOX_REQUIRED,
    DockerSandboxBackend,
    NoOpSandboxBackend,
    SandboxConfig,
    SandboxObligation,
)
from agentguard.exceptions import PermissionDeniedError, SandboxError
from agentguard.guardrails import (
    ChainMode,
    GuardrailContext,
    GuardrailEffect,
    GuardrailOutcome,
    GuardrailStage,
    ToolCallPayload,
)
from agentguard.guardrails.kernel import GovernanceKernel
from agentguard.models import SandboxResult

if TYPE_CHECKING:
    from pathlib import Path


class _SandboxGuardrail:
    version = "1"
    stages = frozenset({GuardrailStage.PRE_TOOL})

    def __init__(
        self, obligation: SandboxObligation, *, guardrail_id: str = "sandbox-required"
    ) -> None:
        self.id = guardrail_id
        self._obligation = obligation

    async def evaluate(self, _context: GuardrailContext) -> GuardrailOutcome:
        return GuardrailOutcome(
            effect=GuardrailEffect.ALLOW,
            obligations=(self._obligation,),
        )


class _RecordingDockerBackend(DockerSandboxBackend):
    _agentguard_test_backend = True

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[list[str], SandboxConfig | None]] = []

    async def run(
        self,
        command: list[str],
        config: SandboxConfig | None = None,
    ) -> SandboxResult:
        self.calls.append((command, config))
        return SandboxResult(
            stdout="sandboxed\n",
            stderr="",
            exit_code=0,
            duration_ms=1.0,
            backend="docker",
        )


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


async def _kernel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    backend: DockerSandboxBackend | None,
    chain_mode: ChainMode = ChainMode.ENFORCE,
    obligations: tuple[SandboxObligation, ...] | None = None,
    normalize_test_backend: bool = True,
) -> tuple[GovernanceKernel, str, AppendOnlyAuditLog]:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-sandbox-obligation-key-pa")
    registry = AgentRegistry()
    identity = await registry.register(name="Operator", roles=["operator"])
    audit = AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit"))
    selected = obligations or (
        SandboxObligation(
            config=SandboxConfig(timeout_seconds=7, memory_limit_mb=64),
        ),
    )
    selected_backend = backend
    if normalize_test_backend and backend is not None and type(backend) is not DockerSandboxBackend:
        original_backend = backend
        selected_backend = DockerSandboxBackend()

        def _run_sync(command: list[str], config: SandboxConfig) -> SandboxResult:
            return asyncio.run(original_backend.run(command, config))

        monkeypatch.setattr(selected_backend, "_run_sync", _run_sync)
    return (
        GovernanceKernel(
            registry=registry,
            rbac_engine=_rbac(),
            audit_log=audit,
            policy_engine=None,
            guardrails=tuple(
                _SandboxGuardrail(obligation, guardrail_id=f"sandbox-required-{index}")
                for index, obligation in enumerate(selected)
            ),
            chain_mode=chain_mode,
            sandbox_backend=selected_backend,
        ),
        identity.agent_id,
        audit,
    )


async def test_enforced_sandbox_obligation_routes_to_backend_without_calling_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _RecordingDockerBackend()
    kernel, agent_id, audit = await _kernel(tmp_path, monkeypatch, backend=backend)
    executor_called = False

    async def executor(_payload: object) -> object:
        nonlocal executor_called
        executor_called = True
        return "in-process"

    result = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/item",
        executor=executor,
        payload=ToolCallPayload(arguments={"command": ["python3", "-c", "print('sandboxed')"]}),
    )

    assert result == SandboxResult(
        stdout="sandboxed\n",
        stderr="",
        exit_code=0,
        duration_ms=1.0,
        backend="docker",
    )
    assert not executor_called
    assert backend.calls == [
        (
            ["python3", "-c", "print('sandboxed')"],
            SandboxConfig(timeout_seconds=7, memory_limit_mb=64),
        )
    ]
    events = (await audit.read_verified(require_checkpoint=True)).events
    assert [event.event_type for event in events] == [
        "admission",
        "execution_completed",
        "delivery_completed",
    ]
    assert events[0].reason_codes == (SANDBOX_REQUIRED,)


def test_kernel_rejects_host_subprocess_backend_for_sandbox_obligations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class HostOverride(DockerSandboxBackend):
        async def run(
            self,
            command: list[str],
            config: SandboxConfig | None = None,
        ) -> SandboxResult:
            del command, config
            raise AssertionError("host override must never be invoked")

    with pytest.raises(TypeError, match="hardened DockerSandboxBackend"):
        asyncio.run(
            _kernel(
                tmp_path, monkeypatch, backend=NoOpSandboxBackend(), normalize_test_backend=False
            )
        )
    with pytest.raises(TypeError, match="subclass overrides"):
        asyncio.run(
            _kernel(tmp_path, monkeypatch, backend=HostOverride(), normalize_test_backend=False)
        )


async def test_missing_backend_denies_before_admission_and_never_executes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel, agent_id, audit = await _kernel(tmp_path, monkeypatch, backend=None)
    executor_called = False

    async def executor(_payload: object) -> object:
        nonlocal executor_called
        executor_called = True
        return "unsafe"

    with pytest.raises(PermissionDeniedError) as raised:
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=executor,
            payload=ToolCallPayload(arguments={"command": ["python3", "-c", "print('sandboxed')"]}),
        )

    assert raised.value.reason == SANDBOX_BACKEND_REQUIRED
    assert not executor_called
    events = (await audit.read_verified(require_checkpoint=True)).events
    assert len(events) == 1
    assert events[0].event_type == "denial"
    assert events[0].reason_codes == (SANDBOX_BACKEND_REQUIRED,)


async def test_shadow_sandbox_obligation_is_evidence_only_and_calls_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _RecordingDockerBackend()
    kernel, agent_id, _audit = await _kernel(
        tmp_path,
        monkeypatch,
        backend=backend,
        chain_mode=ChainMode.SHADOW,
    )

    result = await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/item",
        executor=lambda _payload: asyncio.sleep(0, result="in-process"),
        payload=ToolCallPayload(arguments={"command": ["python3", "-c", "print('sandboxed')"]}),
    )

    assert result == "in-process"
    assert backend.calls == []


async def test_invalid_payload_command_denies_without_leaking_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _RecordingDockerBackend()
    kernel, agent_id, audit = await _kernel(tmp_path, monkeypatch, backend=backend)

    with pytest.raises(PermissionDeniedError) as raised:
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="unsafe"),
            payload=ToolCallPayload(arguments={"command": ["python3", ""]}),
        )

    assert raised.value.reason == SANDBOX_COMMAND_INVALID
    assert backend.calls == []
    event = (await audit.read_verified(require_checkpoint=True)).events[0]
    assert event.reason_codes == (SANDBOX_COMMAND_INVALID,)
    assert "python3" not in event.model_dump_json()


async def test_identical_obligations_deduplicate_but_conflicting_limits_deny(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = _RecordingDockerBackend()
    shared = SandboxObligation(config=SandboxConfig(memory_limit_mb=64))
    kernel, agent_id, _audit = await _kernel(
        tmp_path / "same",
        monkeypatch,
        backend=backend,
        obligations=(shared, shared),
    )
    payload = ToolCallPayload(arguments={"command": ["echo", "ok"]})

    await kernel.guarded_tool_call(
        agent_id=agent_id,
        action="tool:test",
        resource="allowed/item",
        executor=lambda _payload: asyncio.sleep(0, result="unsafe"),
        payload=payload,
    )
    assert len(backend.calls) == 1

    conflicting_kernel, conflicting_agent_id, audit = await _kernel(
        tmp_path / "different",
        monkeypatch,
        backend=backend,
        obligations=(
            shared,
            SandboxObligation(config=SandboxConfig(memory_limit_mb=128)),
        ),
    )
    with pytest.raises(PermissionDeniedError) as raised:
        await conflicting_kernel.guarded_tool_call(
            agent_id=conflicting_agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="unsafe"),
            payload=payload,
        )

    assert raised.value.reason == SANDBOX_OBLIGATION_CONFLICT
    assert (await audit.read_verified(require_checkpoint=True)).events[0].reason_codes == (
        SANDBOX_OBLIGATION_CONFLICT,
    )


async def test_nonzero_sandbox_exit_is_audited_execution_failure_not_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FailingDockerBackend(_RecordingDockerBackend):
        async def run(
            self,
            command: list[str],
            config: SandboxConfig | None = None,
        ) -> SandboxResult:
            self.calls.append((command, config))
            return SandboxResult(
                stdout="",
                stderr="permission denied",
                exit_code=1,
                duration_ms=1,
                backend="docker",
                failure_reason=SANDBOX_PROCESS_EXIT_NONZERO,
            )

    backend = FailingDockerBackend()
    kernel, agent_id, audit = await _kernel(tmp_path, monkeypatch, backend=backend)

    with pytest.raises(SandboxError) as raised:
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="unsafe"),
            payload=ToolCallPayload(arguments={"command": ["cat", "/host/etc/passwd"]}),
        )

    assert raised.value.reason_code == SANDBOX_PROCESS_EXIT_NONZERO
    assert isinstance(raised.value.result, SandboxResult)
    events = (await audit.read_verified(require_checkpoint=True)).events
    assert [event.event_type for event in events] == [
        "admission",
        "execution_completed",
        "delivery_denied",
    ]
    assert all(
        event.reason_codes == (SANDBOX_REQUIRED, SANDBOX_PROCESS_EXIT_NONZERO)
        for event in events[1:]
    )
    assert "/host/etc/passwd" not in "".join(event.model_dump_json() for event in events)


async def test_unregistered_backend_failure_reason_is_replaced_before_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class UntrustedReasonBackend(_RecordingDockerBackend):
        async def run(
            self,
            command: list[str],
            config: SandboxConfig | None = None,
        ) -> SandboxResult:
            return SandboxResult(
                stdout="",
                stderr="",
                exit_code=1,
                duration_ms=1,
                backend="docker",
                failure_reason="provider secret detail",
            )

    kernel, agent_id, audit = await _kernel(
        tmp_path,
        monkeypatch,
        backend=UntrustedReasonBackend(),
    )
    with pytest.raises(SandboxError) as raised:
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="unsafe"),
            payload=ToolCallPayload(arguments={"command": ["false"]}),
        )

    assert raised.value.reason_code == SANDBOX_INTERNAL_ERROR
    serialized = "".join(
        event.model_dump_json()
        for event in (await audit.read_verified(require_checkpoint=True)).events
    )
    assert "provider secret detail" not in serialized
