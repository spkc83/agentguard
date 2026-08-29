"""Mechanism-neutral contracts for an authoritative agent registry."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Protocol, runtime_checkable

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    GetCoreSchemaHandler,
    field_validator,
    model_validator,
)
from pydantic_core import CoreSchema, core_schema

from agentguard.exceptions import RegistryError, RegistryFailure


def _canonical(value: str) -> str:
    if value != value.strip() or not value.isprintable():
        raise ValueError("registry identifiers must be canonical printable text")
    return value


class _FrozenMetadata(Mapping[str, str]):
    """Private-copy string mapping with deterministic JSON serialization."""

    __slots__ = ("__data",)

    def __init__(self, values: Mapping[str, str]) -> None:
        self.__data = dict(values)

    def __getitem__(self, key: str) -> str:
        return self.__data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.__data)

    def __len__(self) -> int:
        return len(self.__data)

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: object,
        _handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        serializer = core_schema.plain_serializer_function_ser_schema(
            dict,
            when_used="json",
        )
        return core_schema.is_instance_schema(cls, serialization=serializer)


def _freeze_metadata(value: object) -> _FrozenMetadata:
    if not isinstance(value, Mapping):
        raise ValueError("metadata must be a string mapping")
    copied: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ValueError("metadata keys and values must be strings")
        copied[_canonical(key)] = _canonical(item)
    return _FrozenMetadata(copied)


FrozenMetadata = Annotated[_FrozenMetadata, BeforeValidator(_freeze_metadata)]


class AgentStatus(StrEnum):
    """Lifecycle state assigned only by the authoritative registry."""

    ACTIVE = "active"
    REVOKED = "revoked"


class AgentRegistryRecord(BaseModel):
    """Frozen registry-owned identity and authorization state."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    agent_id: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    roles: tuple[str, ...]
    metadata: FrozenMetadata = Field(default_factory=lambda: _FrozenMetadata({}))
    status: AgentStatus = AgentStatus.ACTIVE
    credential_epoch: int = Field(ge=1)
    record_revision: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    revoked_at: datetime | None = None

    @field_validator("agent_id", "name")
    @classmethod
    def _validate_identifier(cls, value: str) -> str:
        return _canonical(value)

    @field_validator("roles")
    @classmethod
    def _validate_roles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        canonical = tuple(_canonical(role) for role in value)
        return tuple(sorted(set(canonical)))

    @field_validator("created_at", "updated_at", "revoked_at")
    @classmethod
    def _normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("registry timestamps must be timezone-aware")
            return value.astimezone(UTC)
        return None

    @model_validator(mode="after")
    def _validate_lifecycle(self) -> AgentRegistryRecord:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot predate created_at")
        if self.credential_epoch > self.record_revision:
            raise ValueError("credential_epoch cannot exceed record_revision")
        if self.status is AgentStatus.ACTIVE and self.revoked_at is not None:
            raise ValueError("active records cannot have revoked_at")
        if self.status is AgentStatus.REVOKED:
            if self.revoked_at is None or self.revoked_at < self.created_at:
                raise ValueError("revoked records require a valid revoked_at")
            if self.credential_epoch < 2 or self.record_revision < 2:
                raise ValueError("revocation must advance record revision and credential epoch")
            if self.updated_at < self.revoked_at:
                raise ValueError("updated_at cannot predate revoked_at")
        return self


class AgentRegistrySnapshot(BaseModel):
    """Defensive full snapshot of one authoritative registry revision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    registry_id: str = Field(min_length=1, max_length=256)
    registry_revision: int = Field(ge=0)
    records: tuple[AgentRegistryRecord, ...] = ()

    @field_validator("registry_id")
    @classmethod
    def _validate_registry_id(cls, value: str) -> str:
        return _canonical(value)

    @field_validator("records")
    @classmethod
    def _validate_records(
        cls, value: tuple[AgentRegistryRecord, ...]
    ) -> tuple[AgentRegistryRecord, ...]:
        by_id = {record.agent_id: record for record in value}
        if len(by_id) != len(value):
            raise ValueError("snapshot records must have unique agent IDs")
        return tuple(by_id[agent_id] for agent_id in sorted(by_id))

    @model_validator(mode="after")
    def _validate_revision(self) -> AgentRegistrySnapshot:
        if any(record.record_revision > self.registry_revision for record in self.records):
            raise ValueError("record revision cannot exceed registry revision")
        return self


@runtime_checkable
class AgentIdentityResolver(Protocol):
    """Resolve deeply immutable authorization state for an authenticated agent ID."""

    async def resolve(self, agent_id: str) -> AgentRegistryRecord: ...


@runtime_checkable
class AuthoritativeAgentRegistry(AgentIdentityResolver, Protocol):
    """Read boundary for registry-owned identity and authorization state."""

    async def get_record(self, agent_id: str) -> AgentRegistryRecord: ...

    async def snapshot(self) -> AgentRegistrySnapshot: ...


__all__ = [
    "AgentIdentityResolver",
    "AgentRegistryRecord",
    "AgentRegistrySnapshot",
    "AgentStatus",
    "AuthoritativeAgentRegistry",
    "RegistryError",
    "RegistryFailure",
]
