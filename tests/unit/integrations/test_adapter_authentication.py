"""Authentication boundary contracts shared by every first-party adapter."""

from __future__ import annotations

import ast
import asyncio
import hashlib
import inspect
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

from agentguard.compliance.escalation_store import EscalationStateError
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.authentication import (
    AuthenticatedAgentPrincipal,
    AuthenticationAttempt,
)
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.core.registry import AgentRegistryRecord, AgentRegistrySnapshot
from agentguard.exceptions import AuthenticationError, AuthenticationFailure
from agentguard.guardrails.kernel import AdapterRegisteredToolCall, GovernanceKernel
from agentguard.integrations.a2a_middleware import GovernedA2AClient
from agentguard.integrations.crewai import GovernedCrewAITool
from agentguard.integrations.google_adk import GovernedAdkTool
from agentguard.integrations.langgraph import GovernedLangGraphToolNode
from agentguard.integrations.mcp_middleware import GovernedMcpClient
from agentguard.models import UNAUTHENTICATED_AGENT_ID

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


_NOW = datetime.now(UTC)
_AGENT_ID = "adapter-agent"
_ROLE = "adapter-user"


class _McpSession:
    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> object:
        return {"tool": tool_name, "arguments": arguments}


class _A2ATransport:
    async def send(self, target_agent: str, message: dict[str, Any]) -> object:
        return {"target": target_agent, "message": message}


class _LangGraphTool:
    name = "lang"

    async def ainvoke(self, tool_input: Any) -> object:
        return tool_input


class _CrewAITool:
    name = "crew"

    def _run(self, *args: Any, **kwargs: Any) -> object:
        return {"args": args, "kwargs": kwargs}


class _AdkTool:
    name = "adk"

    async def run_async(self, *, args: dict[str, Any], tool_context: Any) -> object:
        return {"args": args, "context": tool_context}


@dataclass(frozen=True)
class _AdapterCase:
    name: str
    construct: Callable[..., object]
    invoke: Callable[[object, object], Awaitable[object]]
    invoke_sensitive: Callable[[object, str], Awaitable[object]]


def _mcp(**identity: object) -> GovernedMcpClient:
    return cast(
        "GovernedMcpClient",
        cast("Any", GovernedMcpClient)(
            session=_McpSession(),
            resources={"mcp": "allowed/mcp"},
            **identity,
        ),
    )


async def _invoke_mcp(adapter: object, request: object) -> object:
    return await cast("Any", adapter).call_tool("mcp", request)


async def _invoke_sensitive_mcp(adapter: object, secret: str) -> object:
    return await cast("Any", adapter).call_tool(secret, {"request": secret})


def _a2a(**identity: object) -> GovernedA2AClient:
    return cast(
        "GovernedA2AClient",
        cast("Any", GovernedA2AClient)(transport=_A2ATransport(), **identity),
    )


async def _invoke_a2a(adapter: object, request: object) -> object:
    return await cast("Any", adapter).send_message("peer", request)


async def _invoke_sensitive_a2a(adapter: object, secret: str) -> object:
    return await cast("Any", adapter).send_message(secret, {"request": secret})


def _langgraph(**identity: object) -> GovernedLangGraphToolNode:
    return cast(
        "GovernedLangGraphToolNode",
        cast("Any", GovernedLangGraphToolNode)(
            tools=[_LangGraphTool()],
            resources={"lang": "allowed/lang"},
            **identity,
        ),
    )


async def _invoke_langgraph(adapter: object, request: object) -> object:
    return await cast("Any", adapter).ainvoke("lang", request)


async def _invoke_sensitive_langgraph(adapter: object, secret: str) -> object:
    return await cast("Any", adapter).ainvoke(secret, {"request": secret})


def _crewai(**identity: object) -> GovernedCrewAITool:
    return cast(
        "GovernedCrewAITool",
        cast("Any", GovernedCrewAITool)(
            tool=_CrewAITool(),
            resource="allowed/crew",
            **identity,
        ),
    )


async def _invoke_crewai(adapter: object, request: object) -> object:
    return await cast("Any", adapter).arun(request)


async def _invoke_sensitive_crewai(adapter: object, secret: str) -> object:
    return await cast("Any", adapter).arun(secret)


def _adk(**identity: object) -> GovernedAdkTool:
    return cast(
        "GovernedAdkTool",
        cast("Any", GovernedAdkTool)(
            tool=_AdkTool(),
            resource="allowed/adk",
            **identity,
        ),
    )


async def _invoke_adk(adapter: object, request: object) -> object:
    return await cast("Any", adapter).run_async(args=request)


async def _invoke_sensitive_adk(adapter: object, secret: str) -> object:
    return await cast("Any", adapter).run_async(args={"request": secret})


_ADAPTERS = (
    _AdapterCase("mcp", _mcp, _invoke_mcp, _invoke_sensitive_mcp),
    _AdapterCase("a2a", _a2a, _invoke_a2a, _invoke_sensitive_a2a),
    _AdapterCase(
        "langgraph",
        _langgraph,
        _invoke_langgraph,
        _invoke_sensitive_langgraph,
    ),
    _AdapterCase("crewai", _crewai, _invoke_crewai, _invoke_sensitive_crewai),
    _AdapterCase("google-adk", _adk, _invoke_adk, _invoke_sensitive_adk),
)


def _digest(credential: object) -> str:
    assert isinstance(credential, bytes)
    return hashlib.sha256(credential).hexdigest()


class _Authenticator:
    def __init__(self) -> None:
        self.observed: list[object] = []

    async def describe_attempt(self, credential: object) -> AuthenticationAttempt:
        return AuthenticationAttempt(method="test-token", credential_digest=_digest(credential))

    async def authenticate(self, credential: object) -> AuthenticatedAgentPrincipal:
        self.observed.append(credential)
        return AuthenticatedAgentPrincipal(
            agent_id=_AGENT_ID,
            method="test-token",
            authority="test-authority",
            credential_digest=_digest(credential),
            issued_at=_NOW - timedelta(minutes=2),
            not_before=_NOW - timedelta(minutes=1),
            authenticated_at=_NOW,
            expires_at=_NOW + timedelta(minutes=5),
        )


class _RejectingAuthenticator(_Authenticator):
    async def authenticate(self, credential: object) -> AuthenticatedAgentPrincipal:
        self.observed.append(credential)
        raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)


class _Registry:
    async def resolve(self, agent_id: str) -> AgentRegistryRecord:
        raise AssertionError(f"secure adapter used split registry resolve: {agent_id}")

    async def get_record(self, agent_id: str) -> AgentRegistryRecord:
        raise AssertionError(f"secure adapter used split registry lookup: {agent_id}")

    async def snapshot(self) -> AgentRegistrySnapshot:
        return AgentRegistrySnapshot(
            registry_id="adapter-registry",
            registry_revision=3,
            records=(
                AgentRegistryRecord(
                    agent_id=_AGENT_ID,
                    name="Adapter Agent",
                    roles=(_ROLE,),
                    credential_epoch=1,
                    record_revision=1,
                    created_at=_NOW - timedelta(days=1),
                    updated_at=_NOW,
                ),
            ),
        )


class _Provider:
    def __init__(self, *credentials: object) -> None:
        self._credentials = iter(credentials)
        self.calls = 0

    async def get_credential(self) -> object:
        self.calls += 1
        return next(self._credentials)


class _FailingProvider:
    def __init__(self, failure: BaseException | None = None) -> None:
        self.failure = failure
        self.calls = 0

    async def get_credential(self) -> object:
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return None


class _UnsignedAuditLog:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def write(self, event: object) -> object:
        self.events.append(event)
        return event

    async def write_once(self, event: object) -> object:
        self.events.append(event)
        return event


class _PoisonRequest:
    def __getattribute__(self, name: str) -> Any:
        if name.startswith("__"):
            return object.__getattribute__(self, name)
        raise AssertionError("request was observed before credential acquisition")

    def __repr__(self) -> str:
        raise AssertionError("request was rendered before credential acquisition")

    def __str__(self) -> str:
        raise AssertionError("request was rendered before credential acquisition")


class _PoisonTracer:
    def span(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("tracer observed provider failure")


class _PoisonExecutorResolver:
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, executor_id: str) -> object:
        self.calls += 1
        raise AssertionError(f"registered executor was probed before authentication: {executor_id}")


def _rbac() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name=_ROLE,
                permissions=[
                    Permission(action="tool:mcp", resource="allowed/mcp", effect="allow"),
                    Permission(action="a2a:send:peer", resource="agent/peer", effect="allow"),
                    Permission(action="tool:lang", resource="allowed/lang", effect="allow"),
                    Permission(action="tool:crew", resource="allowed/crew", effect="allow"),
                    Permission(action="tool:adk", resource="allowed/adk", effect="allow"),
                ],
            )
        ]
    )


def _secure_kernel(
    audit_log: object,
    authenticator: _Authenticator,
    *,
    tracer: object | None = None,
    executor_resolver: object | None = None,
) -> GovernanceKernel:
    return cast(
        "GovernanceKernel",
        cast("Any", GovernanceKernel)(
            authoritative_registry=_Registry(),
            agent_authenticator=authenticator,
            rbac_engine=_rbac(),
            audit_log=audit_log,
            policy_engine=None,
            guardrails=(),
            tracer=tracer,
            executor_resolver=executor_resolver,
        ),
    )


def _legacy_kernel(audit_log: AppendOnlyAuditLog) -> GovernanceKernel:
    return GovernanceKernel(
        registry=AgentRegistry(),
        rbac_engine=_rbac(),
        audit_log=audit_log,
        policy_engine=None,
        guardrails=(),
    )


def _audit_log(tmp_path: Path, name: str) -> AppendOnlyAuditLog:
    directory = tmp_path / name
    directory.mkdir()
    return AppendOnlyAuditLog(FileAuditBackend(directory))


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
def test_adapter_does_not_call_credential_provider_during_construction(
    case: _AdapterCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", f"provider-construction-{case.name}-abcdefghi")
    provider = _Provider(b"credential")
    kernel = _secure_kernel(_audit_log(tmp_path, case.name), _Authenticator())

    case.construct(kernel=kernel, credential_provider=provider)

    assert provider.calls == 0


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
async def test_adapter_calls_credential_provider_once_for_each_attempt(
    case: _AdapterCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", f"provider-per-attempt-{case.name}-abcdefghij")
    provider = _Provider(b"first", b"second")
    kernel = _secure_kernel(_audit_log(tmp_path, case.name), _Authenticator())
    adapter = case.construct(kernel=kernel, credential_provider=provider)

    await case.invoke(adapter, {"attempt": 1})
    await case.invoke(adapter, {"attempt": 2})

    assert provider.calls == 2


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
async def test_adapter_forwards_rotated_credentials_to_authenticator_in_call_order(
    case: _AdapterCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", f"provider-rotation-{case.name}-abcdefghijklm")
    provider = _Provider(b"first", b"second")
    authenticator = _Authenticator()
    kernel = _secure_kernel(_audit_log(tmp_path, case.name), authenticator)
    adapter = case.construct(kernel=kernel, credential_provider=provider)

    await case.invoke(adapter, {"attempt": 1})
    await case.invoke(adapter, {"attempt": 2})

    assert authenticator.observed == [b"first", b"second"]


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
async def test_concurrent_adapter_calls_use_independently_acquired_credentials(
    case: _AdapterCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", f"provider-concurrent-{case.name}-abcdefghijk")
    provider = _Provider(b"first", b"second")
    authenticator = _Authenticator()
    kernel = _secure_kernel(_audit_log(tmp_path, case.name), authenticator)
    adapter = case.construct(kernel=kernel, credential_provider=provider)

    await asyncio.gather(
        case.invoke(adapter, {"attempt": 1}),
        case.invoke(adapter, {"attempt": 2}),
    )

    assert provider.calls == 2
    assert set(authenticator.observed) == {b"first", b"second"}


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
async def test_secure_adapter_stores_neither_claimed_identity_nor_credential_after_call(
    case: _AdapterCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", f"provider-storage-{case.name}-abcdefghijklmn")
    credential = b"must-not-be-stored"
    provider = _Provider(credential)
    kernel = _secure_kernel(_audit_log(tmp_path, case.name), _Authenticator())
    adapter = case.construct(kernel=kernel, credential_provider=provider)

    await case.invoke(adapter, {"value": 1})

    direct_state = vars(adapter)
    bound_caller = direct_state["_caller"]

    assert credential not in direct_state.values()
    assert _AGENT_ID not in direct_state.values()
    assert credential not in (
        bound_caller._agent_id,
        bound_caller._credential_provider,
        bound_caller._kernel,
    )
    assert bound_caller._agent_id is None


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
@pytest.mark.parametrize(
    ("kernel_mode", "identity", "accepted"),
    [
        ("legacy", {"agent_id": "legacy-agent"}, True),
        ("secure", {"credential_provider": _Provider(b"credential")}, True),
        ("legacy", {}, False),
        ("secure", {}, False),
        (
            "legacy",
            {
                "agent_id": "legacy-agent",
                "credential_provider": _Provider(b"credential"),
            },
            False,
        ),
        (
            "secure",
            {
                "agent_id": "legacy-agent",
                "credential_provider": _Provider(b"credential"),
            },
            False,
        ),
        ("legacy", {"credential_provider": _Provider(b"credential")}, False),
        ("secure", {"agent_id": "legacy-agent"}, False),
    ],
    ids=(
        "legacy-id",
        "secure-provider",
        "legacy-missing",
        "secure-missing",
        "legacy-mixed",
        "secure-mixed",
        "provider-with-legacy-kernel",
        "id-with-secure-kernel",
    ),
)
def test_adapter_construction_accepts_exactly_one_identity_mode(
    case: _AdapterCase,
    kernel_mode: str,
    identity: dict[str, object],
    accepted: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit_key = f"provider-matrix-{case.name}-{accepted}-abcdefghijklmn"
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", audit_key)
    kernel = (
        _secure_kernel(_audit_log(tmp_path, case.name), _Authenticator())
        if kernel_mode == "secure"
        else _legacy_kernel(_audit_log(tmp_path, case.name))
    )

    if accepted:
        assert case.construct(kernel=kernel, **identity) is not None
    else:
        with pytest.raises((TypeError, ValueError)):
            case.construct(kernel=kernel, **identity)


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
@pytest.mark.parametrize("returns_none", [False, True], ids=("raises", "returns-none"))
async def test_provider_failure_writes_one_signed_canonical_rejection(
    case: _AdapterCase,
    returns_none: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = f"provider-secret-{case.name}"
    audit_key = f"provider-failure-{case.name}-{returns_none}-abcdefghijklm"
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", audit_key)
    audit_log = _audit_log(tmp_path, case.name)
    provider = _FailingProvider(None if returns_none else RuntimeError(secret))
    kernel = _secure_kernel(audit_log, _Authenticator())
    adapter = case.construct(kernel=kernel, credential_provider=provider)

    with pytest.raises(AuthenticationError) as error:
        await case.invoke_sensitive(adapter, secret)

    snapshot = await audit_log.read_verified(require_checkpoint=True)
    assert error.value.failure is AuthenticationFailure.PROVIDER_FAILURE
    assert len(snapshot.events) == 1
    event = snapshot.events[0]
    assert event.event_hash
    assert event.agent_id == UNAUTHENTICATED_AGENT_ID
    assert event.action == "authenticate"
    assert event.resource == "agent"
    assert event.authentication_evidence is not None
    assert event.authentication_evidence.failure_reason is AuthenticationFailure.PROVIDER_FAILURE
    sentinel = AuthenticationAttempt.for_provider_failure()
    assert event.authentication_evidence.method == sentinel.method
    assert event.authentication_evidence.credential_digest == sentinel.credential_digest
    assert secret not in event.model_dump_json()


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
async def test_provider_failure_precedes_request_factory_resolver_tracer_and_executor_lookup(
    case: _AdapterCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", f"provider-ordering-{case.name}-abcdefghijklm")
    provider = _FailingProvider(RuntimeError("provider exploded"))
    kernel = _secure_kernel(
        _audit_log(tmp_path, case.name),
        _Authenticator(),
        tracer=_PoisonTracer(),
    )
    adapter = case.construct(kernel=kernel, credential_provider=provider)

    with pytest.raises(AuthenticationError) as error:
        await case.invoke(adapter, _PoisonRequest())

    assert error.value.failure is AuthenticationFailure.PROVIDER_FAILURE
    assert provider.calls == 1


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
async def test_provider_internal_error_is_absent_from_public_exception_chain(
    case: _AdapterCase, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", f"provider-exception-{case.name}-abcdefghijkl")
    secret = f"raw-provider-error-{case.name}"
    provider = _FailingProvider(RuntimeError(secret))
    kernel = _secure_kernel(_audit_log(tmp_path, case.name), _Authenticator())
    adapter = case.construct(kernel=kernel, credential_provider=provider)

    with pytest.raises(AuthenticationError) as captured:
        await case.invoke(adapter, {"value": 1})

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert secret not in str(captured.value)


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
@pytest.mark.parametrize("returns_none", [False, True], ids=("raises", "returns-none"))
async def test_unsigned_provider_rejection_fails_closed_before_request_observation(
    case: _AdapterCase,
    returns_none: bool,
) -> None:
    audit_log = _UnsignedAuditLog()
    provider = _FailingProvider(None if returns_none else RuntimeError("raw provider failure"))
    kernel = _secure_kernel(audit_log, _Authenticator(), tracer=_PoisonTracer())
    adapter = case.construct(kernel=kernel, credential_provider=provider)

    with pytest.raises(EscalationStateError, match="not signed"):
        await case.invoke(adapter, _PoisonRequest())

    assert provider.calls == 1
    assert len(audit_log.events) == 1


@pytest.mark.parametrize("case", _ADAPTERS, ids=lambda case: case.name)
async def test_unsigned_authenticator_rejection_fails_closed_before_request_observation(
    case: _AdapterCase,
) -> None:
    audit_log = _UnsignedAuditLog()
    provider = _Provider(b"invalid-credential")
    authenticator = _RejectingAuthenticator()
    kernel = _secure_kernel(audit_log, authenticator, tracer=_PoisonTracer())
    adapter = case.construct(kernel=kernel, credential_provider=provider)

    with pytest.raises(EscalationStateError, match="not signed"):
        await case.invoke(adapter, _PoisonRequest())

    assert provider.calls == 1
    assert authenticator.observed == [b"invalid-credential"]
    assert len(audit_log.events) == 1


async def test_provider_failure_precedes_registered_executor_identifier_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "provider-registered-executor-ordering")
    resolver = _PoisonExecutorResolver()
    provider = _FailingProvider(RuntimeError("provider unavailable"))
    kernel = _secure_kernel(
        _audit_log(tmp_path, "registered"),
        _Authenticator(),
        executor_resolver=resolver,
    )
    caller = kernel.bind_adapter(agent_id=None, credential_provider=provider)
    factory_calls = 0

    def request() -> AdapterRegisteredToolCall:
        nonlocal factory_calls
        factory_calls += 1
        return AdapterRegisteredToolCall(
            action="tool:registered",
            resource="allowed/registered",
            executor_id="secret-executor-id",
        )

    with pytest.raises(AuthenticationError) as captured:
        await caller.guarded_registered_tool_call(request)

    assert captured.value.failure is AuthenticationFailure.PROVIDER_FAILURE
    assert factory_calls == 0
    assert resolver.calls == 0


def test_first_party_adapters_do_not_call_deprecated_run_governed() -> None:
    modules = (
        "agentguard.integrations.mcp_middleware",
        "agentguard.integrations.a2a_middleware",
        "agentguard.integrations.langgraph",
        "agentguard.integrations.crewai",
        "agentguard.integrations.google_adk",
    )

    for module_name in modules:
        module = __import__(module_name, fromlist=["*"])
        tree = ast.parse(inspect.getsource(module))
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "run_governed"
        ]
        assert calls == [], module_name
