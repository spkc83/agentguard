"""Mechanism-neutral authentication contracts for AgentGuard trust boundaries."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Protocol, Self, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentguard.exceptions import AuthenticationError, AuthenticationFailure


class _AuthenticatedPrincipal(BaseModel):
    """Shared validated credential facts without authorization state."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str = Field(min_length=1, max_length=256)
    authority: str = Field(min_length=1, max_length=2048)
    credential_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    not_before: datetime
    authenticated_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "not_before", "authenticated_at", "expires_at")
    @classmethod
    def _normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authentication timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("method", "authority")
    @classmethod
    def _validate_descriptor(cls, value: str) -> str:
        if value != value.strip() or not value.isprintable():
            raise ValueError("authentication descriptors must be canonical printable text")
        return value

    @model_validator(mode="after")
    def _validate_validity_window(self) -> _AuthenticatedPrincipal:
        if not self.issued_at <= self.not_before <= self.authenticated_at < self.expires_at:
            raise ValueError(
                "authentication timestamps must satisfy "
                "issued_at <= not_before <= authenticated_at < expires_at"
            )
        return self


class AuthenticatedAgentPrincipal(_AuthenticatedPrincipal):
    """Trusted agent identity established from an opaque credential.

    Roles and capabilities are intentionally absent: authentication establishes
    identity only, while the authoritative registry supplies authorization state.
    """

    agent_id: str = Field(min_length=1, max_length=256)

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, value: str) -> str:
        if value != value.strip() or not value.isprintable():
            raise ValueError("agent_id must be canonical printable text")
        return value


class AuthenticationAttempt(BaseModel):
    """Secret-free description of one opaque credential authentication attempt."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str = Field(min_length=1, max_length=256)
    credential_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def for_provider_failure(cls) -> Self:
        """Describe credential-provider failure without accepting sensitive context."""

        return cls(
            method="agentguard.credential-provider.unavailable",
            credential_digest=hashlib.sha256(
                b"agentguard.authentication.provider-failure.no-credential.v1"
            ).hexdigest(),
        )

    @field_validator("method")
    @classmethod
    def _validate_method(cls, value: str) -> str:
        if value != value.strip() or not value.isprintable():
            raise ValueError("authentication method must be canonical printable text")
        return value


class ControlPlanePrincipal(_AuthenticatedPrincipal):
    """Distinct administrator identity for authenticated control-plane calls."""

    principal_id: str = Field(min_length=1, max_length=256)
    capabilities: tuple[str, ...] = ()

    @field_validator("principal_id")
    @classmethod
    def _validate_principal_id(cls, value: str) -> str:
        if value != value.strip() or not value.isprintable():
            raise ValueError("principal_id must be canonical printable text")
        return value

    @field_validator("capabilities")
    @classmethod
    def _validate_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not capability or capability != capability.strip() or not capability.isprintable()
            for capability in value
        ):
            raise ValueError("control-plane capabilities must be canonical printable text")
        if len(value) != len(set(value)):
            raise ValueError("control-plane capabilities must be unique")
        return value


@runtime_checkable
class AgentAuthenticator(Protocol):
    """Authenticate one opaque credential into a trusted agent principal."""

    async def describe_attempt(self, credential: object) -> AuthenticationAttempt: ...

    async def authenticate(self, credential: object) -> AuthenticatedAgentPrincipal: ...


@runtime_checkable
class AgentCredentialProvider(Protocol):
    """Provide a fresh opaque agent credential for one governed call."""

    async def get_credential(self) -> object: ...


@runtime_checkable
class ControlPlaneAuthenticator(Protocol):
    """Authenticate one opaque credential in the separate administrator domain."""

    async def authenticate(self, credential: object) -> ControlPlanePrincipal: ...


__all__ = [
    "AgentAuthenticator",
    "AgentCredentialProvider",
    "AuthenticatedAgentPrincipal",
    "AuthenticationAttempt",
    "AuthenticationError",
    "AuthenticationFailure",
    "ControlPlaneAuthenticator",
    "ControlPlanePrincipal",
]
