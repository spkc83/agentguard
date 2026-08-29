"""Authenticated orchestration for authoritative registry mutations."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping  # noqa: TC003 - Pydantic resolves this field at runtime
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, TypeVar
from uuid import uuid4

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.core.registry_state import (
    InMemoryAuthoritativeAgentRegistry,
    RegisterAgentCommand,
    RegistryMutationCommand,
    RegistryOperation,
    RegistryOperationState,
    RegistryPreparationError,
    ReplaceAgentRolesCommand,
    RevokeAgentCommand,
    RotateAgentCredentialsCommand,
    _bind_registry_control_plane,
    canonical_digest,
    principal_digest,
)
from agentguard.exceptions import (
    AuthenticationError,
    AuthenticationFailure,
    RegistryError,
    RegistryFailure,
)
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext, RegistryMutationEvidence

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from agentguard.core.audit import AuditLog
    from agentguard.core.authentication import ControlPlaneAuthenticator, ControlPlanePrincipal
    from agentguard.core.registry import AgentRegistryRecord

_T = TypeVar("_T")
logger = structlog.get_logger()


class RoleGrantPolicy(BaseModel):
    """Exact capabilities required to assign and remove registry-owned roles."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    known_roles: frozenset[str] = frozenset()
    grant_capabilities: Mapping[str, str] = Field(default_factory=dict)
    revoke_capabilities: Mapping[str, str] = Field(default_factory=dict)

    @field_validator("known_roles")
    @classmethod
    def _validate_roles(cls, value: frozenset[str]) -> frozenset[str]:
        if any(not role or role != role.strip() or not role.isprintable() for role in value):
            raise ValueError("known roles must be canonical printable text")
        return value

    @field_validator("grant_capabilities", "revoke_capabilities")
    @classmethod
    def _validate_capabilities(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        copied = dict(value)
        if any(
            not role
            or role != role.strip()
            or not role.isprintable()
            or not capability
            or capability != capability.strip()
            or not capability.isprintable()
            or "*" in capability
            for role, capability in copied.items()
        ):
            raise ValueError("role capabilities must be exact canonical strings")
        return MappingProxyType(copied)

    @model_validator(mode="after")
    def _validate_role_configuration(self) -> RoleGrantPolicy:
        configured = set(self.grant_capabilities) | set(self.revoke_capabilities)
        if not configured <= self.known_roles:
            raise ValueError("capabilities cannot be configured for unknown roles")
        capabilities = [
            *self.grant_capabilities.values(),
            *self.revoke_capabilities.values(),
        ]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("each role grant and revoke must use a distinct capability")
        action_capabilities = {
            "registry:agent:register",
            "registry:agent:roles:replace",
            "registry:credential:rotate",
            "registry:agent:revoke",
        }
        if action_capabilities.intersection(capabilities):
            raise ValueError("role capabilities must be distinct from action capabilities")
        return self

    def required_capabilities(
        self,
        command: RegistryMutationCommand,
        before_roles: tuple[str, ...],
    ) -> frozenset[str]:
        base = {
            "register": "registry:agent:register",
            "replace_roles": "registry:agent:roles:replace",
            "rotate_credentials": "registry:credential:rotate",
            "revoke": "registry:agent:revoke",
        }[command.mutation]
        required = {base}
        if not isinstance(command, RegisterAgentCommand | ReplaceAgentRolesCommand):
            return frozenset(required)
        requested_roles = frozenset(command.roles)
        if not requested_roles <= self.known_roles:
            raise RegistryError(RegistryFailure.UNKNOWN_ROLE)
        if command.mutation == "register":
            for role in requested_roles:
                capability = self.grant_capabilities.get(role)
                if capability is None:
                    raise RegistryError(RegistryFailure.CAPABILITY_DENIED)
                required.add(capability)
        elif command.mutation == "replace_roles":
            previous = frozenset(before_roles)
            for role in requested_roles - previous:
                capability = self.grant_capabilities.get(role)
                if capability is None:
                    raise RegistryError(RegistryFailure.CAPABILITY_DENIED)
                required.add(capability)
            for role in previous - requested_roles:
                capability = self.revoke_capabilities.get(role)
                if capability is None:
                    raise RegistryError(RegistryFailure.CAPABILITY_DENIED)
                required.add(capability)
        return frozenset(required)

    def authorize(
        self,
        principal: ControlPlanePrincipal,
        command: RegistryMutationCommand,
        before_roles: tuple[str, ...],
    ) -> None:
        capabilities = frozenset(principal.capabilities)
        if any("*" in capability for capability in capabilities):
            raise RegistryError(RegistryFailure.CAPABILITY_DENIED)
        if not self.required_capabilities(command, before_roles) <= capabilities:
            raise RegistryError(RegistryFailure.CAPABILITY_DENIED)


class AgentRegistryControlPlane:
    """Authenticate administrators, authorize, audit, then atomically commit."""

    def __init__(
        self,
        registry: InMemoryAuthoritativeAgentRegistry,
        authenticator: ControlPlaneAuthenticator,
        audit_log: AuditLog,
        role_policy: RoleGrantPolicy,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._mutation = _bind_registry_control_plane(registry)
        self._authenticator = authenticator
        self._audit_log = audit_log
        self._role_policy = role_policy
        self._clock = clock or (lambda: datetime.now(UTC))

    async def register(
        self, command: RegisterAgentCommand, credential: object
    ) -> AgentRegistryRecord:
        return await self._mutate(command, credential)

    async def replace_roles(
        self, command: ReplaceAgentRolesCommand, credential: object
    ) -> AgentRegistryRecord:
        return await self._mutate(command, credential)

    async def rotate_credentials(
        self, command: RotateAgentCredentialsCommand, credential: object
    ) -> AgentRegistryRecord:
        return await self._mutate(command, credential)

    async def revoke(self, command: RevokeAgentCommand, credential: object) -> AgentRegistryRecord:
        return await self._mutate(command, credential)

    async def _mutate(
        self, command: RegistryMutationCommand, credential: object
    ) -> AgentRegistryRecord:
        principal = await self._authenticator.authenticate(credential)
        now = self._now()
        self._assert_principal_current(principal, now)

        operation = await self._mutation.get_operation(command.operation_id)
        if operation is not None:
            request_hash = canonical_digest(
                command,
                domain="agentguard.registry.command.v1",
            )
            if (
                operation.request_digest != request_hash
                or operation.principal_digest != principal_digest(principal)
            ):
                await self._write_rejection(
                    command,
                    principal,
                    RegistryFailure.OPERATION_CONFLICT,
                    now=now,
                )
                raise RegistryPreparationError(RegistryFailure.OPERATION_CONFLICT)
            if operation.state is RegistryOperationState.COMMITTED:
                return operation.proposed_record
            if operation.state is RegistryOperationState.CONFLICTED:
                current = (await self._registry.snapshot()).registry_revision
                await self._write_rejection(
                    command,
                    principal,
                    RegistryFailure.REVISION_CONFLICT,
                    now=now,
                    requested_revision=operation.base_registry_revision,
                    observed_revision=current,
                )
                raise RegistryPreparationError(
                    RegistryFailure.REVISION_CONFLICT,
                    requested_revision=operation.base_registry_revision,
                    observed_revision=current,
                )
        else:
            operation = await self._prepare_new(command, principal, now=now)

        async def authorize_and_commit() -> AgentRegistryRecord:
            self._assert_principal_current(principal, self._now())
            event = self._authorized_event(operation)
            signed = await self._audit_log.write_once(event)
            try:
                snapshot = await self._audit_log.read_verified(
                    require_checkpoint=self._mutation.requires_attestable_audit
                )
                verified = tuple(
                    candidate
                    for candidate in snapshot.events
                    if candidate.event_id == signed.event_id
                )
                if not snapshot.verification.valid or verified != (signed,):
                    raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)
                return await self._mutation.commit(operation.operation_id)
            except RegistryPreparationError as error:
                if error.failure is not RegistryFailure.TAMPER_DETECTED:
                    await self._write_rejection(
                        command,
                        principal,
                        error.failure,
                        now=self._now(),
                        requested_revision=error.requested_revision,
                        observed_revision=error.observed_revision,
                    )
                raise

        return await _finish_on_cancellation(authorize_and_commit())

    async def _prepare_new(
        self,
        command: RegistryMutationCommand,
        principal: ControlPlanePrincipal,
        *,
        now: datetime,
    ) -> RegistryOperation:
        """Authorize and prepare a previously unseen operation."""

        try:
            return await self._mutation.prepare(
                command,
                principal,
                prepared_at=now,
                authorize=lambda prepared_command, before_roles: self._role_policy.authorize(
                    principal,
                    prepared_command,
                    before_roles,
                ),
            )
        except RegistryPreparationError as error:
            await self._write_rejection(
                command,
                principal,
                error.failure,
                now=now,
                requested_revision=error.requested_revision,
                observed_revision=error.observed_revision,
            )
            raise
        except RegistryError as error:
            await self._write_rejection(command, principal, error.failure, now=now)
            raise

    def _authorized_event(self, operation: RegistryOperation) -> AuditEvent:
        return self._event(
            evidence=operation.evidence,
            event_id=operation.event_id,
            trace_id=operation.trace_id,
            timestamp=operation.prepared_at,
        )

    async def _write_rejection(
        self,
        command: RegistryMutationCommand,
        principal: ControlPlanePrincipal,
        failure: RegistryFailure,
        *,
        now: datetime,
        requested_revision: int | None = None,
        observed_revision: int | None = None,
    ) -> AuditEvent:
        request_hash = canonical_digest(command, domain="agentguard.registry.command.v1")
        actor_hash = principal_digest(principal)
        event_seed = canonical_digest(
            {
                "registry_id": self._registry.registry_id,
                "operation_id": command.operation_id,
                "request_digest": request_hash,
                "principal_digest": actor_hash,
                "failure": failure.value,
                "requested_revision": requested_revision,
                "observed_revision": observed_revision,
                "attempt_id": uuid4().hex,
                "attempted_at": now.isoformat(),
            },
            domain="agentguard.registry.rejection-event-id.v1",
        )
        event_id = event_seed
        trace_id = canonical_digest(
            {"event_id": event_id},
            domain="agentguard.registry.rejection-trace-id.v1",
        )
        evidence = RegistryMutationEvidence(
            state="rejected",
            operation_id=command.operation_id,
            registry_id=self._registry.registry_id,
            mutation=command.mutation,
            principal_id=principal.principal_id,
            authentication_method=principal.method,
            authentication_authority=principal.authority,
            credential_digest=principal.credential_digest,
            capabilities_digest=canonical_digest(
                sorted(principal.capabilities),
                domain="agentguard.registry.capabilities.v1",
            ),
            target_agent_id=command.target_agent_id,
            request_digest=request_hash,
            requested_registry_revision=requested_revision,
            observed_registry_revision=observed_revision,
            prepared_at=now,
            failure_reason=failure,
        )
        signed = await self._audit_log.write(
            self._event(evidence=evidence, event_id=event_id, trace_id=trace_id, timestamp=now)
        )
        snapshot = await self._audit_log.read_verified(
            require_checkpoint=self._mutation.requires_attestable_audit
        )
        if signed not in snapshot.events:
            raise RegistryPreparationError(RegistryFailure.TAMPER_DETECTED)
        await self._mutation.anchor_audit_event(signed.event_id)
        return signed

    @staticmethod
    def _event(
        *,
        evidence: RegistryMutationEvidence,
        event_id: str,
        trace_id: str,
        timestamp: datetime,
    ) -> AuditEvent:
        authorized = evidence.state == "authorized"
        action = f"registry.{evidence.mutation}"
        resource = f"agent_registry:{evidence.registry_id}"
        failure = evidence.failure_reason.value if evidence.failure_reason is not None else ""
        return AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            agent_id=evidence.principal_id,
            action=action,
            resource=resource,
            permission_context=PermissionContext(
                agent=AgentIdentity(
                    agent_id=evidence.principal_id,
                    name=evidence.principal_id,
                    roles=[],
                ),
                requested_action=action,
                resource=resource,
                granted=authorized,
                reason=failure,
            ),
            result="allowed" if authorized else "rejected",
            duration_ms=0,
            trace_id=trace_id,
            invocation_id=evidence.operation_id,
            event_type=(
                "registry_mutation_authorized" if authorized else "registry_mutation_rejected"
            ),
            reason_codes=() if authorized else (failure,),
            registry_mutation_evidence=evidence,
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("control-plane clock must return a timezone-aware timestamp")
        return value.astimezone(UTC)

    @staticmethod
    def _assert_principal_current(
        principal: ControlPlanePrincipal,
        now: datetime,
    ) -> None:
        if now < principal.not_before or now < principal.authenticated_at:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_NOT_YET_VALID)
        if now >= principal.expires_at:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_EXPIRED)


async def _finish_on_cancellation(operation: Coroutine[object, object, _T]) -> _T:
    """Drain audit+commit through repeated cancellation before propagating it."""

    task = asyncio.create_task(operation)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.cancelled():
                raise
            cancelled = True
        except Exception:
            if not cancelled:
                raise
            break
    if cancelled:
        if task.done() and not task.cancelled():
            error = task.exception()
            if error is not None:
                _log_cancelled_mutation_failure(error)
        raise asyncio.CancelledError
    return task.result()


def _log_cancelled_mutation_failure(error: BaseException) -> None:
    fields: dict[str, str] = {"error_type": type(error).__name__}
    if isinstance(error, AuthenticationError | RegistryError):
        fields["reason_code"] = error.reason_code
    logger.error("registry_mutation_failed_during_cancellation", **fields)


__all__ = ["AgentRegistryControlPlane", "RoleGrantPolicy"]
