"""Authentication-boundary contracts for the governance kernel."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Self, cast

import pytest

from agentguard.compliance.continuation import ApprovalDisposition, canonical_continuation_aad
from agentguard.compliance.engine import PolicyEngine
from agentguard.compliance.escalation_store import (
    EscalationStateError,
    EscalationStatus,
    EscalationStore,
)
from agentguard.compliance.execution_journal import ExecutionJournal, ExecutionJournalStatus
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.authentication import AuthenticatedAgentPrincipal, AuthenticationAttempt
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.core.registry import AgentRegistryRecord, AgentRegistrySnapshot, AgentStatus
from agentguard.exceptions import (
    AuditError,
    AuthenticationError,
    AuthenticationFailure,
    EscalationRequiredError,
    PermissionDeniedError,
)
from agentguard.guardrails import (
    ExecutorRef,
    GuardrailPayload,
    RegisteredExecutor,
    ToolCallPayload,
)
from agentguard.guardrails.kernel import GovernanceKernel
from agentguard.models import UNAUTHENTICATED_AGENT_ID, AgentIdentity, PermissionContext
from tests.unit.guardrails import test_kernel_post_resume as post_fixtures
from tests.unit.guardrails import test_kernel_reconciliation as reconciliation_fixtures
from tests.unit.guardrails import test_kernel_resume as pre_fixtures

if TYPE_CHECKING:
    from pathlib import Path


_NOW = datetime.now(UTC)


def _rbac_engine() -> RBACEngine:
    return RBACEngine(
        roles=[
            Role(
                name="registry-operator",
                permissions=[
                    Permission(
                        action="tool:test",
                        resource="allowed/item",
                        effect="allow",
                    )
                ],
            )
        ]
    )


def _principal(*, agent_id: str = "agent-1") -> AuthenticatedAgentPrincipal:
    return AuthenticatedAgentPrincipal(
        agent_id=agent_id,
        method="test-token",
        authority="test-authority",
        credential_digest="a" * 64,
        issued_at=_NOW - timedelta(minutes=2),
        not_before=_NOW - timedelta(minutes=1),
        authenticated_at=_NOW,
        expires_at=_NOW + timedelta(minutes=5),
    )


def _record(*, roles: tuple[str, ...] = ("registry-operator",)) -> AgentRegistryRecord:
    return AgentRegistryRecord(
        agent_id="agent-1",
        name="Authoritative Agent",
        roles=roles,
        credential_epoch=1,
        record_revision=7,
        created_at=_NOW - timedelta(days=1),
        updated_at=_NOW,
    )


class _Authenticator:
    def __init__(
        self,
        *,
        principal: AuthenticatedAgentPrincipal | None = None,
        failure: AuthenticationFailure | None = None,
        observations: list[str] | None = None,
    ) -> None:
        self.principal = principal or _principal()
        self.failure = failure
        self.observations = observations if observations is not None else []
        self.credentials: list[object] = []

    async def describe_attempt(self, credential: object) -> AuthenticationAttempt:
        self.observations.append("describe_attempt")
        self.credentials.append(credential)
        return AuthenticationAttempt(method="test-token", credential_digest="a" * 64)

    async def authenticate(self, credential: object) -> AuthenticatedAgentPrincipal:
        self.observations.append("authenticate")
        self.credentials.append(credential)
        if self.failure is not None:
            raise AuthenticationError(self.failure)
        return self.principal


class _AuthoritativeRegistry:
    def __init__(
        self,
        record: AgentRegistryRecord | None = None,
        observations: list[str] | None = None,
    ) -> None:
        self.record = record or _record()
        self.registry_revision = 11
        self.observations = observations if observations is not None else []

    async def resolve(self, agent_id: str) -> AgentRegistryRecord:
        raise AssertionError(f"secure kernel used split resolve for {agent_id}")

    async def get_record(self, agent_id: str) -> AgentRegistryRecord:
        raise AssertionError(f"secure kernel used split get_record for {agent_id}")

    async def snapshot(self) -> AgentRegistrySnapshot:
        self.observations.append("registry_snapshot")
        return AgentRegistrySnapshot(
            registry_id="test-registry",
            registry_revision=self.registry_revision,
            records=(self.record,),
        )


class _RbacSpy:
    def __init__(self, observations: list[str]) -> None:
        self.observations = observations
        self.identities: list[AgentIdentity] = []

    async def check_permission(
        self,
        identity: AgentIdentity,
        action: str,
        resource: str,
    ) -> PermissionContext:
        self.observations.append("rbac")
        self.identities.append(identity)
        return PermissionContext(
            agent=identity,
            requested_action=action,
            resource=resource,
            granted=True,
        )


class _ExecutorResolverSpy:
    def __init__(self, observations: list[str]) -> None:
        self.observations = observations

    def resolve(self, executor_id: str) -> RegisteredExecutor:
        self.observations.append("executor_resolver")
        return RegisteredExecutor(
            ref=ExecutorRef(executor_id=executor_id, version="1", fingerprint="b" * 64),
            executor=_return_ok,
        )


async def _return_ok(_payload: GuardrailPayload) -> object:
    return "ok"


class _ObservationTracer:
    def __init__(self, observations: list[str]) -> None:
        self.observations = observations

    def span(self, *_args: object, **_kwargs: object) -> Any:
        self.observations.append("tracer")
        raise AssertionError("tracer observed an unauthenticated call")


class _PoisonValue:
    def __getattribute__(self, _name: str) -> Any:
        raise AssertionError("unauthenticated input was inspected")

    def __str__(self) -> str:
        raise AssertionError("unauthenticated input was rendered")

    def __repr__(self) -> str:
        raise AssertionError("unauthenticated input was rendered")


class _FailingAuditLog:
    async def write(self, _event: object) -> Any:
        raise AuditError("test audit failure")

    async def write_once(self, _event: object) -> Any:
        raise AuditError("test audit failure")


class _RecordingAuditLog:
    def __init__(self) -> None:
        self.events: list[object] = []

    async def write(self, event: object) -> Any:
        self.events.append(event)
        return event

    async def write_once(self, event: object) -> Any:
        signed = cast("Any", event).model_copy(
            update={
                "event_hash": "a" * 64,
                "chain_id": "test-authentication-chain",
                "sequence": len(self.events),
                "key_id": "test-authentication-key",
                "hash_schema_version": 8,
            }
        )
        self.events.append(signed)
        return signed


def _audit_text(directory: Path) -> str:
    return "".join(path.read_text() for path in directory.glob("audit-*.jsonl"))


def _legacy_kernel(**overrides: object) -> GovernanceKernel:
    arguments: dict[str, object] = {
        "registry": AgentRegistry(),
        "rbac_engine": _rbac_engine(),
        "audit_log": _FailingAuditLog(),
        "policy_engine": None,
        "guardrails": (),
    }
    arguments.update(overrides)
    return cast("GovernanceKernel", cast("Any", GovernanceKernel)(**arguments))


def _secure_kernel(**overrides: object) -> GovernanceKernel:
    arguments: dict[str, object] = {
        "authoritative_registry": _AuthoritativeRegistry(),
        "agent_authenticator": _Authenticator(),
        "rbac_engine": _rbac_engine(),
        "audit_log": _RecordingAuditLog(),
        "policy_engine": None,
        "guardrails": (),
    }
    arguments.update(overrides)
    return cast("GovernanceKernel", cast("Any", GovernanceKernel)(**arguments))


def test_kernel_accepts_legacy_registry_without_authenticator() -> None:
    assert _legacy_kernel() is not None


def test_kernel_accepts_complete_secure_configuration() -> None:
    assert _secure_kernel() is not None


@pytest.mark.parametrize(
    "configuration",
    [
        {},
        {"authoritative_registry": _AuthoritativeRegistry()},
        {"agent_authenticator": _Authenticator()},
        {
            "registry": AgentRegistry(),
            "authoritative_registry": _AuthoritativeRegistry(),
            "agent_authenticator": _Authenticator(),
        },
    ],
    ids=("no-registry", "missing-authenticator", "missing-registry", "mixed-modes"),
)
def test_kernel_rejects_ambiguous_or_incomplete_identity_configuration(
    configuration: dict[str, object],
) -> None:
    constructor = cast("Any", GovernanceKernel)
    with pytest.raises((TypeError, ValueError)):
        constructor(
            rbac_engine=_rbac_engine(),
            audit_log=_FailingAuditLog(),
            policy_engine=None,
            guardrails=(),
            **configuration,
        )


@pytest.mark.parametrize(
    ("agent_id", "credential"),
    [(None, None), ("claimed-agent", b"token")],
    ids=("missing-credential", "claimed-id"),
)
async def test_secure_call_rejects_missing_or_claimed_identity_inputs(
    agent_id: str | None,
    credential: object | None,
) -> None:
    kernel = _secure_kernel()

    with pytest.raises((AuthenticationError, ValueError)):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            credential=credential,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="not-called"),
        )


@pytest.mark.parametrize(
    ("agent_id", "credential"),
    [(None, None), ("legacy-agent", b"unexpected")],
    ids=("missing-agent-id", "credential-present"),
)
async def test_legacy_call_rejects_missing_or_credential_identity_inputs(
    agent_id: str | None,
    credential: object | None,
) -> None:
    kernel = _legacy_kernel()

    with pytest.raises((TypeError, ValueError, AuthenticationError)):
        await kernel.guarded_tool_call(
            agent_id=agent_id,
            credential=credential,
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0, result="not-called"),
        )


async def test_authentication_precedes_authoritative_registry_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-order-padded-abcdefg")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    observations: list[str] = []
    kernel = _secure_kernel(
        authoritative_registry=_AuthoritativeRegistry(observations=observations),
        agent_authenticator=_Authenticator(observations=observations),
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_dir)),
    )

    await kernel.guarded_tool_call(
        credential=b"valid",
        action="tool:test",
        resource="allowed/item",
        executor=lambda _payload: asyncio.sleep(0, result="ok"),
    )

    assert observations == ["describe_attempt", "authenticate", "registry_snapshot"]


async def test_authentication_precedes_action_resolution() -> None:
    observations: list[str] = []

    async def action(_payload: object) -> str:
        observations.append("action")
        return "tool:test"

    kernel = _secure_kernel(
        agent_authenticator=_Authenticator(
            failure=AuthenticationFailure.CREDENTIAL_INVALID,
            observations=observations,
        )
    )

    with pytest.raises(AuthenticationError):
        await kernel.guarded_tool_call(
            credential=b"invalid",
            action=action,
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0),
        )

    assert observations == ["describe_attempt", "authenticate"]


async def test_authentication_precedes_resource_resolution() -> None:
    observations: list[str] = []

    async def resource(_payload: object) -> str:
        observations.append("resource")
        return "allowed/item"

    kernel = _secure_kernel(
        agent_authenticator=_Authenticator(
            failure=AuthenticationFailure.CREDENTIAL_INVALID,
            observations=observations,
        )
    )

    with pytest.raises(AuthenticationError):
        await kernel.guarded_tool_call(
            credential=b"invalid",
            action="tool:test",
            resource=resource,
            executor=lambda _payload: asyncio.sleep(0),
        )

    assert observations == ["describe_attempt", "authenticate"]


async def test_authentication_precedes_payload_observation() -> None:
    observations: list[str] = []
    kernel = _secure_kernel(
        agent_authenticator=_Authenticator(
            failure=AuthenticationFailure.CREDENTIAL_INVALID,
            observations=observations,
        )
    )

    with pytest.raises(AuthenticationError):
        await kernel.guarded_tool_call(
            credential=b"invalid",
            action="tool:test",
            resource="allowed/item",
            payload=_PoisonValue(),  # type: ignore[arg-type]
            executor=lambda _payload: asyncio.sleep(0),
        )

    assert observations == ["describe_attempt", "authenticate"]


async def test_authentication_precedes_rbac_observation() -> None:
    observations: list[str] = []
    kernel = _secure_kernel(
        agent_authenticator=_Authenticator(
            failure=AuthenticationFailure.CREDENTIAL_INVALID,
            observations=observations,
        ),
        rbac_engine=_RbacSpy(observations),
    )

    with pytest.raises(AuthenticationError):
        await kernel.guarded_tool_call(
            credential=b"invalid",
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0),
        )

    assert observations == ["describe_attempt", "authenticate"]


async def test_authentication_precedes_executor_invocation() -> None:
    observations: list[str] = []

    async def executor(_payload: GuardrailPayload) -> None:
        observations.append("executor")

    kernel = _secure_kernel(
        agent_authenticator=_Authenticator(
            failure=AuthenticationFailure.CREDENTIAL_INVALID,
            observations=observations,
        )
    )

    with pytest.raises(AuthenticationError):
        await kernel.guarded_tool_call(
            credential=b"invalid",
            action="tool:test",
            resource="allowed/item",
            executor=executor,
        )

    assert observations == ["describe_attempt", "authenticate"]


async def test_authentication_precedes_tracer_observation() -> None:
    observations: list[str] = []
    kernel = _secure_kernel(
        agent_authenticator=_Authenticator(
            failure=AuthenticationFailure.CREDENTIAL_INVALID,
            observations=observations,
        ),
        tracer=_ObservationTracer(observations),
    )

    with pytest.raises(AuthenticationError):
        await kernel.guarded_tool_call(
            credential=b"invalid",
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0),
        )

    assert observations == ["describe_attempt", "authenticate"]


async def test_registered_executor_is_not_resolved_before_authentication() -> None:
    observations: list[str] = []
    kernel = _secure_kernel(
        agent_authenticator=_Authenticator(
            failure=AuthenticationFailure.CREDENTIAL_INVALID,
            observations=observations,
        ),
        executor_resolver=_ExecutorResolverSpy(observations),
    )

    with pytest.raises(AuthenticationError):
        await kernel.guarded_registered_tool_call(
            credential=b"invalid",
            action="tool:test",
            resource="allowed/item",
            executor_id="secret-executor-id",
        )

    assert observations == ["describe_attempt", "authenticate"]


async def test_claimed_agent_id_is_rejected_without_inspecting_its_value() -> None:
    authenticator = _Authenticator()
    kernel = _secure_kernel(agent_authenticator=authenticator)

    with pytest.raises(ValueError):
        await kernel.guarded_tool_call(
            agent_id=_PoisonValue(),  # type: ignore[arg-type]
            credential=b"valid",
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0),
        )

    assert authenticator.credentials == []


async def test_missing_credential_fails_closed_before_authenticator_call() -> None:
    authenticator = _Authenticator()
    kernel = _secure_kernel(agent_authenticator=authenticator)

    with pytest.raises(AuthenticationError) as error:
        await kernel.guarded_tool_call(
            action="tool:test",
            resource="allowed/item",
            executor=lambda _payload: asyncio.sleep(0),
        )

    assert error.value.failure is AuthenticationFailure.CREDENTIAL_MISSING
    assert authenticator.credentials == []


async def test_failed_credential_blocks_execution() -> None:
    executed = False

    async def executor(_payload: GuardrailPayload) -> None:
        nonlocal executed
        executed = True

    kernel = _secure_kernel(
        agent_authenticator=_Authenticator(failure=AuthenticationFailure.CREDENTIAL_REVOKED)
    )

    with pytest.raises(AuthenticationError) as error:
        await kernel.guarded_tool_call(
            credential=b"revoked",
            action="tool:test",
            resource="allowed/item",
            executor=executor,
        )

    assert error.value.failure is AuthenticationFailure.CREDENTIAL_REVOKED
    assert not executed


async def test_registry_roles_are_the_only_rbac_authorization_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-registry-roles-padde")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    observations: list[str] = []
    rbac = _RbacSpy(observations)
    kernel = _secure_kernel(
        authoritative_registry=_AuthoritativeRegistry(_record()),
        agent_authenticator=_Authenticator(principal=_principal()),
        rbac_engine=rbac,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_dir)),
    )

    result = await kernel.guarded_tool_call(
        credential=b"valid",
        action="tool:test",
        resource="allowed/item",
        payload=ToolCallPayload.model_validate({"arguments": {"value": 1}}),
        executor=lambda _payload: asyncio.sleep(0, result="ok"),
    )

    assert result == "ok"
    assert rbac.identities[0].roles == ["registry-operator"]
    assert rbac.identities[0].name == "Authoritative Agent"


async def test_successful_authentication_emits_signed_secret_free_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-success-padded-abcde")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    kernel = _secure_kernel(audit_log=audit_log)

    await kernel.guarded_tool_call(
        credential=b"raw-secret-success",
        action="tool:test",
        resource="allowed/item",
        executor=lambda _payload: asyncio.sleep(0, result="ok"),
    )

    snapshot = await audit_log.read_verified(require_checkpoint=True)
    event = next(item for item in snapshot.events if item.event_type == "authentication_succeeded")
    assert event.hash_schema_version >= 7
    assert event.action == "authenticate"
    assert event.resource == "agent"
    assert not event.payload_digest
    assert not event.payload_redacted
    assert event.authentication_evidence is not None
    assert event.authentication_evidence.state == "verified"
    assert event.authentication_evidence.agent_id == "agent-1"
    assert event.authentication_evidence.registry_revision == 11
    assert "raw-secret-success" not in _audit_text(audit_dir)


async def test_rejected_authentication_emits_signed_secret_free_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-rejected-padded-abcd")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    kernel = _secure_kernel(
        audit_log=audit_log,
        agent_authenticator=_Authenticator(failure=AuthenticationFailure.CREDENTIAL_INVALID),
    )

    with pytest.raises(AuthenticationError):
        await kernel.guarded_tool_call(
            credential=b"raw-secret-rejected",
            action="secret-action",
            resource="secret-resource",
            payload=ToolCallPayload.model_validate({"arguments": {"secret": "payload"}}),
            executor=lambda _payload: asyncio.sleep(0),
        )

    snapshot = await audit_log.read_verified(require_checkpoint=True)
    assert len(snapshot.events) == 1
    event = snapshot.events[0]
    assert event.event_type == "authentication_rejected"
    assert event.hash_schema_version >= 7
    assert event.agent_id == UNAUTHENTICATED_AGENT_ID
    assert event.action == "authenticate"
    assert event.resource == "agent"
    assert event.authentication_evidence is not None
    assert event.authentication_evidence.failure_reason is AuthenticationFailure.CREDENTIAL_INVALID
    serialized = _audit_text(audit_dir)
    assert "raw-secret-rejected" not in serialized
    assert "secret-action" not in serialized
    assert "secret-resource" not in serialized
    assert '"secret":"payload"' not in serialized


async def test_authentication_audit_failure_blocks_execution() -> None:
    executed = False

    async def executor(_payload: GuardrailPayload) -> None:
        nonlocal executed
        executed = True

    kernel = _secure_kernel(audit_log=_FailingAuditLog())

    with pytest.raises(AuditError):
        await kernel.guarded_tool_call(
            credential=b"valid",
            action="tool:test",
            resource="allowed/item",
            executor=executor,
        )

    assert not executed


def _secure_resume_kernel(
    *,
    registry: _AuthoritativeRegistry,
    audit_dir: Path,
    store_dir: Path,
    policy_dir: Path,
    guardrails: tuple[object, ...],
    executor_resolver: object | None,
    rbac_engine: object | None = None,
    execution_journal: ExecutionJournal | None = None,
    approver_authenticator: object | None = None,
) -> GovernanceKernel:
    audit_dir.mkdir(exist_ok=True)
    policy_dir.mkdir(exist_ok=True)
    return GovernanceKernel(
        authoritative_registry=registry,
        agent_authenticator=_Authenticator(),
        rbac_engine=cast("Any", rbac_engine or _rbac_engine()),
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_dir)),
        policy_engine=PolicyEngine(policy_dirs=[policy_dir]),
        guardrails=cast("Any", guardrails),
        escalation_store=EscalationStore(
            store_dir,
            signing_key=pre_fixtures.STORE_KEY,
            clock=lambda: datetime.now(UTC),
        ),
        escalation_ttl=timedelta(minutes=10),
        approver_authenticator=cast("Any", approver_authenticator or pre_fixtures._Authenticator()),
        continuation_protector=pre_fixtures._TestProtector(),
        executor_resolver=cast("Any", executor_resolver),
        execution_journal=execution_journal,
    )


async def _request_secure_escalation(
    kernel: GovernanceKernel,
) -> EscalationRequiredError:
    with pytest.raises(EscalationRequiredError) as caught:
        await kernel.guarded_registered_tool_call(
            credential=b"valid-agent-credential",
            action="tool:test",
            resource="allowed/item",
            executor_id="test-executor",
            payload=ToolCallPayload.model_validate({"arguments": {"query": "safe"}}),
        )
    return caught.value


async def _approve_secure_escalation(
    kernel: GovernanceKernel,
    escalation: EscalationRequiredError,
) -> None:
    await kernel.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )


def _advanced_record(
    *,
    roles: tuple[str, ...] = ("registry-operator",),
    credential_epoch: int = 1,
    revoked: bool = False,
) -> AgentRegistryRecord:
    revision = 12
    changed_at = datetime.now(UTC)
    return AgentRegistryRecord(
        agent_id="agent-1",
        name="Authoritative Agent",
        roles=roles,
        status=AgentStatus.REVOKED if revoked else AgentStatus.ACTIVE,
        credential_epoch=credential_epoch,
        record_revision=revision,
        created_at=_NOW - timedelta(days=1),
        updated_at=changed_at,
        revoked_at=changed_at if revoked else None,
    )


class _FutureDatetime(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> Self:
        current = datetime.now(tz) + timedelta(hours=1)
        return cls.fromtimestamp(current.timestamp(), tz=tz)


async def test_secure_pre_resume_ignores_original_principal_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-pre-expiry-padded-ab")
    observations: list[str] = []
    registry = _AuthoritativeRegistry()
    first = _secure_resume_kernel(
        registry=registry,
        audit_dir=tmp_path / "audit",
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(pre_fixtures._ApprovalGuardrail(), pre_fixtures._DownstreamGuardrail()),
        executor_resolver=_ExecutorResolverSpy(observations),
    )
    escalation = await _request_secure_escalation(first)
    await _approve_secure_escalation(first, escalation)
    observations.clear()
    monkeypatch.setattr("agentguard.guardrails.kernel.datetime", _FutureDatetime)

    result = await first.resume_tool_call(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
    )

    assert result == "ok"
    assert observations == ["executor_resolver"]


async def test_secure_kernel_rejects_legacy_v1_continuation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-v1-to-v2-padded-abcd")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    legacy_registry = AgentRegistry()
    identity = await legacy_registry.register(
        name="Operator", roles=["operator"], agent_id="agent-1"
    )
    legacy, _, legacy_store = pre_fixtures._kernel(
        registry=legacy_registry,
        rbac=pre_fixtures._rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(pre_fixtures._ApprovalGuardrail(),),
    )
    escalation = await pre_fixtures._request(legacy, identity.agent_id)
    sealed = await legacy_store.get_sealed_continuation(escalation.escalation_id)
    plaintext = await pre_fixtures._TestProtector().open(
        sealed,
        aad=canonical_continuation_aad(escalation.escalation_id, schema_version=1),
    )
    assert b'"authentication_binding"' not in plaintext
    await legacy.decide_escalation(
        escalation_id=escalation.escalation_id,
        approval_token=escalation.approval_token,
        credential=b"valid-credential",
        decision_id="decision-1",
        disposition=ApprovalDisposition.APPROVE,
    )
    secure = _secure_resume_kernel(
        registry=_AuthoritativeRegistry(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(pre_fixtures._ApprovalGuardrail(),),
        executor_resolver=_ExecutorResolverSpy([]),
    )

    with pytest.raises(EscalationStateError):
        await secure.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )


async def test_legacy_kernel_rejects_secure_v2_continuation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-v2-to-v1-padded-abcd")
    audit_dir = tmp_path / "audit"
    registry = _AuthoritativeRegistry()
    secure = _secure_resume_kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(pre_fixtures._ApprovalGuardrail(),),
        executor_resolver=_ExecutorResolverSpy([]),
    )
    escalation = await _request_secure_escalation(secure)
    await _approve_secure_escalation(secure, escalation)
    legacy_registry = AgentRegistry()
    await legacy_registry.register(name="Operator", roles=["operator"], agent_id="agent-1")
    legacy, _, _ = pre_fixtures._kernel(
        registry=legacy_registry,
        rbac=pre_fixtures._rbac(),
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(pre_fixtures._ApprovalGuardrail(),),
    )

    with pytest.raises(EscalationStateError):
        await legacy.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )


async def test_legacy_v1_post_plaintext_omits_authentication_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-v1-post-plaintext-pa")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    registry = AgentRegistry()
    agent_id = await post_fixtures._registered_agent(registry)
    kernel, _, store = post_fixtures._kernel(
        registry=registry,
        audit_dir=audit_dir,
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(post_fixtures._PostApprovalGuardrail(),),
        probe=post_fixtures._ExecutorProbe(),
    )
    escalation = await post_fixtures._request_post(kernel, agent_id=agent_id)

    sealed = await store.get_sealed_continuation(escalation.escalation_id)
    plaintext = await post_fixtures._TestProtector().open(
        sealed,
        aad=canonical_continuation_aad(
            escalation.escalation_id,
            kind="post_execution_continuation",
            schema_version=1,
        ),
    )

    assert b'"authentication_binding"' not in plaintext


@pytest.mark.parametrize(
    ("changed_record", "expected_failure"),
    [
        pytest.param(
            _advanced_record(revoked=True, credential_epoch=2),
            AuthenticationFailure.IDENTITY_INACTIVE,
            id="inactive",
        ),
        pytest.param(
            _advanced_record(credential_epoch=2),
            AuthenticationFailure.CREDENTIAL_REVOKED,
            id="credential-epoch",
        ),
    ],
)
async def test_secure_pre_resume_rejects_identity_change_before_executor_resolution(
    changed_record: AgentRegistryRecord,
    expected_failure: AuthenticationFailure,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-pre-identity-change-")
    observations: list[str] = []
    registry = _AuthoritativeRegistry()
    kernel = _secure_resume_kernel(
        registry=registry,
        audit_dir=tmp_path / "audit",
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(pre_fixtures._ApprovalGuardrail(),),
        executor_resolver=_ExecutorResolverSpy(observations),
    )
    escalation = await _request_secure_escalation(kernel)
    await _approve_secure_escalation(kernel, escalation)
    observations.clear()
    registry.record = changed_record
    registry.registry_revision = 12

    with pytest.raises(AuthenticationError) as error:
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert error.value.failure is expected_failure
    assert observations == []
    record = await kernel._require_escalation_store().get(escalation.escalation_id)
    assert record.status is EscalationStatus.CLAIMED
    with pytest.raises(EscalationStateError):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    assert observations == []


async def test_secure_pre_resume_rechecks_rbac_after_same_epoch_role_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-pre-role-removal-pad")
    observations: list[str] = []
    registry = _AuthoritativeRegistry()
    kernel = _secure_resume_kernel(
        registry=registry,
        audit_dir=tmp_path / "audit",
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(pre_fixtures._ApprovalGuardrail(),),
        executor_resolver=_ExecutorResolverSpy(observations),
    )
    escalation = await _request_secure_escalation(kernel)
    await _approve_secure_escalation(kernel, escalation)
    observations.clear()
    registry.record = _advanced_record(roles=())
    registry.registry_revision = 12

    with pytest.raises(PermissionDeniedError):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert observations == []


@pytest.mark.parametrize(
    ("changed_record", "expected_failure"),
    [
        pytest.param(
            _advanced_record(revoked=True, credential_epoch=2),
            AuthenticationFailure.IDENTITY_INACTIVE,
            id="inactive",
        ),
        pytest.param(
            _advanced_record(credential_epoch=2),
            AuthenticationFailure.CREDENTIAL_REVOKED,
            id="credential-epoch",
        ),
    ],
)
async def test_secure_post_resume_rejects_identity_change_before_post_callback(
    changed_record: AgentRegistryRecord,
    expected_failure: AuthenticationFailure,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-post-identity-change")
    observations: list[str] = []
    registry = _AuthoritativeRegistry()
    initial_approval = post_fixtures._PostApprovalGuardrail()
    initial_allow = post_fixtures._PostAllowGuardrail()
    kernel = _secure_resume_kernel(
        registry=registry,
        audit_dir=tmp_path / "audit",
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(initial_approval, initial_allow),
        executor_resolver=_ExecutorResolverSpy(observations),
    )
    escalation = await _request_secure_escalation(kernel)
    await _approve_secure_escalation(kernel, escalation)
    resumed_approval = post_fixtures._PostApprovalGuardrail()
    resumed_allow = post_fixtures._PostAllowGuardrail()
    restarted = _secure_resume_kernel(
        registry=registry,
        audit_dir=tmp_path / "audit",
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(resumed_approval, resumed_allow),
        executor_resolver=None,
    )
    registry.record = changed_record
    registry.registry_revision = 12

    with pytest.raises(AuthenticationError) as error:
        await restarted.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )

    assert error.value.failure is expected_failure
    assert resumed_approval.calls == 0
    assert resumed_allow.calls == 0


async def test_secure_authentication_binding_survives_post_child_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-post-child-binding-p")
    observations: list[str] = []
    kernel = _secure_resume_kernel(
        registry=_AuthoritativeRegistry(),
        audit_dir=tmp_path / "audit",
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(
            post_fixtures._PostApprovalGuardrail(),
            post_fixtures._SecondPostApprovalGuardrail(),
            post_fixtures._PostAllowGuardrail(),
        ),
        executor_resolver=_ExecutorResolverSpy(observations),
    )
    first = await _request_secure_escalation(kernel)
    await _approve_secure_escalation(kernel, first)

    with pytest.raises(EscalationRequiredError) as caught:
        await kernel.resume_tool_call(
            escalation_id=first.escalation_id,
            approval_token=first.approval_token,
        )
    child = caught.value
    await kernel.decide_escalation(
        escalation_id=child.escalation_id,
        approval_token=child.approval_token,
        credential=b"valid-credential",
        decision_id="decision-2",
        disposition=ApprovalDisposition.APPROVE,
    )

    result = await kernel.resume_tool_call(
        escalation_id=child.escalation_id,
        approval_token=child.approval_token,
    )

    assert result == "ok"
    assert observations == ["executor_resolver"]


@pytest.mark.parametrize(
    ("changed_record", "expected_failure"),
    [
        pytest.param(
            _advanced_record(revoked=True, credential_epoch=2),
            AuthenticationFailure.IDENTITY_INACTIVE,
            id="inactive",
        ),
        pytest.param(
            _advanced_record(credential_epoch=2),
            AuthenticationFailure.CREDENTIAL_REVOKED,
            id="credential-epoch",
        ),
    ],
)
async def test_secure_known_outcome_reconciliation_rejects_identity_change_before_post_callback(
    changed_record: AgentRegistryRecord,
    expected_failure: AuthenticationFailure,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-reconciliation-binding")
    observations: list[str] = []
    registry = _AuthoritativeRegistry()
    protector = reconciliation_fixtures._TestProtector()
    journal = ExecutionJournal(
        tmp_path / "journal",
        signing_key=reconciliation_fixtures.JOURNAL_KEY,
        protector=protector,
    )
    post_callback = reconciliation_fixtures._PostAllow()
    kernel = _secure_resume_kernel(
        registry=registry,
        audit_dir=tmp_path / "audit",
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(reconciliation_fixtures._PreApproval(), post_callback),
        executor_resolver=_ExecutorResolverSpy(observations),
        execution_journal=journal,
        approver_authenticator=reconciliation_fixtures._Authenticator(),
    )
    escalation = await _request_secure_escalation(kernel)
    await _approve_secure_escalation(kernel, escalation)
    audit = cast("Any", kernel)._audit_log
    original_write_once = audit.write_once

    async def fail_completion(event: Any) -> Any:
        if event.event_type == "execution_completed":
            raise RuntimeError("completion audit unavailable")
        return await original_write_once(event)

    monkeypatch.setattr(audit, "write_once", fail_completion)
    with pytest.raises(RuntimeError, match="completion audit unavailable"):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    monkeypatch.setattr(audit, "write_once", original_write_once)
    calls_before = post_callback.calls
    observations.clear()
    registry.record = changed_record
    registry.registry_revision = 12

    with pytest.raises(AuthenticationError) as error:
        await kernel.reconcile_known_outcome(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id="reconcile-binding-change",
        )

    assert error.value.failure is expected_failure
    assert post_callback.calls == calls_before
    assert observations == []


async def test_secure_known_outcome_cancellation_after_claim_commit_is_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", "kernel-auth-reconciliation-cancel")
    observations: list[str] = []
    registry = _AuthoritativeRegistry()
    journal = ExecutionJournal(
        tmp_path / "journal",
        signing_key=reconciliation_fixtures.JOURNAL_KEY,
        protector=reconciliation_fixtures._TestProtector(),
    )
    post_callback = reconciliation_fixtures._PostAllow()
    kernel = _secure_resume_kernel(
        registry=registry,
        audit_dir=tmp_path / "audit",
        store_dir=tmp_path / "store",
        policy_dir=tmp_path / "policy",
        guardrails=(reconciliation_fixtures._PreApproval(), post_callback),
        executor_resolver=_ExecutorResolverSpy(observations),
        execution_journal=journal,
        approver_authenticator=reconciliation_fixtures._Authenticator(),
    )
    escalation = await _request_secure_escalation(kernel)
    await _approve_secure_escalation(kernel, escalation)
    audit = cast("Any", kernel)._audit_log
    original_write_once = audit.write_once

    async def fail_completion(event: Any) -> Any:
        if event.event_type == "execution_completed":
            raise RuntimeError("completion audit unavailable")
        return await original_write_once(event)

    monkeypatch.setattr(audit, "write_once", fail_completion)
    with pytest.raises(RuntimeError, match="completion audit unavailable"):
        await kernel.resume_tool_call(
            escalation_id=escalation.escalation_id,
            approval_token=escalation.approval_token,
        )
    monkeypatch.setattr(audit, "write_once", original_write_once)
    calls_before = post_callback.calls
    observations.clear()
    transition_committed = asyncio.Event()
    release_claim = asyncio.Event()
    original_claim = journal.claim_post_processing

    async def paused_claim(
        escalation_id: str,
        *,
        claim_id: str,
        invocation_id: str,
    ) -> Any:
        committed = await original_claim(
            escalation_id,
            claim_id=claim_id,
            invocation_id=invocation_id,
        )
        transition_committed.set()
        await release_claim.wait()
        return committed

    monkeypatch.setattr(journal, "claim_post_processing", paused_claim)
    task = asyncio.create_task(
        kernel.reconcile_known_outcome(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id="reconcile-cancelled-claim",
        )
    )
    await asyncio.wait_for(transition_committed.wait(), timeout=1)
    assert (await journal.find(escalation.escalation_id)).status is (
        ExecutionJournalStatus.POST_PROCESSING_CLAIMED
    )
    task.cancel()
    release_claim.set()

    with pytest.raises(asyncio.CancelledError):
        await task

    record = await journal.find(escalation.escalation_id)
    assert record.status is ExecutionJournalStatus.DELIVERY_DENIED
    events = (await audit.read_verified(require_checkpoint=True)).events
    terminals = [
        event
        for event in events
        if event.invocation_id == record.invocation_id and event.event_type == "delivery_denied"
    ]
    assert len(terminals) == 1
    assert terminals[0].reason_codes == ("DELIVERY.CANCELLED",)
    assert terminals[0].event_hash
    assert terminals[0].sequence is not None
    assert post_callback.calls == calls_before
    assert observations == []
    with pytest.raises(EscalationStateError):
        await kernel.reconcile_known_outcome(
            escalation.escalation_id,
            credential=b"valid-credential",
            reconciliation_id="reconcile-cancelled-retry",
        )
    assert post_callback.calls == calls_before
    assert observations == []
