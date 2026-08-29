"""Tests for mechanism-neutral authentication contracts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agentguard.core import (
    AgentAuthenticator,
    AgentCredentialProvider,
    AuthenticatedAgentPrincipal,
    AuthenticationAttempt,
    AuthenticationError,
    AuthenticationFailure,
    ControlPlaneAuthenticator,
    ControlPlanePrincipal,
)
from agentguard.guardrails.reason_codes import RUNTIME_REASON_CODES, is_valid_reason_code

NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)


def _agent_principal(**updates: object) -> AuthenticatedAgentPrincipal:
    values: dict[str, object] = {
        "agent_id": "agent-1",
        "method": "signed-workload-token",
        "authority": "https://identity.example.test",
        "credential_digest": "a" * 64,
        "issued_at": NOW - timedelta(minutes=1),
        "not_before": NOW - timedelta(seconds=30),
        "authenticated_at": NOW,
        "expires_at": NOW + timedelta(minutes=4),
    }
    values.update(updates)
    return AuthenticatedAgentPrincipal.model_validate(values)


def test_authenticated_agent_principal_is_frozen_and_contains_no_authority_roles() -> None:
    principal = _agent_principal()

    assert principal.agent_id == "agent-1"
    assert "roles" not in type(principal).model_fields
    assert "capabilities" not in type(principal).model_fields
    with pytest.raises(ValidationError):
        principal.agent_id = "agent-2"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("credential_digest", "not-a-digest"),
        ("credential_digest", "A" * 64),
        ("issued_at", NOW.replace(tzinfo=None)),
        ("not_before", NOW.replace(tzinfo=None)),
        ("authenticated_at", NOW.replace(tzinfo=None)),
        ("expires_at", NOW.replace(tzinfo=None)),
    ],
)
def test_authenticated_agent_principal_rejects_untrusted_boundary_values(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        _agent_principal(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", " "),
        ("agent_id", " agent-1"),
        ("method", "signed-token "),
        ("authority", "issuer\nforged"),
    ],
)
def test_agent_principal_rejects_noncanonical_identifiers(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        _agent_principal(**{field: value})


@pytest.mark.parametrize(
    "updates",
    [
        {"not_before": NOW - timedelta(minutes=2)},
        {"authenticated_at": NOW - timedelta(minutes=2)},
        {"expires_at": NOW},
    ],
)
def test_authenticated_agent_principal_rejects_invalid_validity_order(
    updates: dict[str, datetime],
) -> None:
    with pytest.raises(ValidationError):
        _agent_principal(**updates)


def test_principal_timestamps_are_normalized_to_utc() -> None:
    offset = NOW.astimezone(timezone(timedelta(hours=-5)))
    principal = _agent_principal(authenticated_at=offset)

    assert principal.authenticated_at.tzinfo is UTC
    assert principal.authenticated_at == NOW


def test_control_plane_principal_is_distinct_and_has_immutable_capabilities() -> None:
    principal = ControlPlanePrincipal(
        principal_id="administrator-1",
        method="hardware-backed-token",
        authority="https://admin-identity.example.test",
        credential_digest="b" * 64,
        issued_at=NOW - timedelta(minutes=1),
        not_before=NOW - timedelta(minutes=1),
        authenticated_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
        capabilities=("registry:register", "registry:revoke"),
    )

    assert principal.capabilities == ("registry:register", "registry:revoke")
    assert "agent_id" not in type(principal).model_fields
    with pytest.raises(ValidationError):
        principal.capabilities = ()


def test_control_plane_principal_rejects_duplicate_or_blank_capabilities() -> None:
    base = {
        "principal_id": "administrator-1",
        "method": "test",
        "authority": "test-authority",
        "credential_digest": "b" * 64,
        "issued_at": NOW - timedelta(minutes=1),
        "not_before": NOW - timedelta(minutes=1),
        "authenticated_at": NOW,
        "expires_at": NOW + timedelta(minutes=1),
    }
    with pytest.raises(ValidationError):
        ControlPlanePrincipal.model_validate(
            {**base, "capabilities": ("registry:register", "registry:register")}
        )
    with pytest.raises(ValidationError):
        ControlPlanePrincipal.model_validate({**base, "capabilities": ("",)})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("principal_id", " "),
        ("principal_id", "administrator-1\n"),
        ("capabilities", (" registry:register",)),
        ("capabilities", ("registry:register\x00",)),
    ],
)
def test_control_plane_principal_rejects_noncanonical_identifiers(
    field: str, value: object
) -> None:
    base = {
        "principal_id": "administrator-1",
        "method": "test",
        "authority": "test-authority",
        "credential_digest": "b" * 64,
        "issued_at": NOW - timedelta(minutes=1),
        "not_before": NOW - timedelta(minutes=1),
        "authenticated_at": NOW,
        "expires_at": NOW + timedelta(minutes=1),
    }
    with pytest.raises(ValidationError):
        ControlPlanePrincipal.model_validate({**base, field: value})


class _AgentAuthenticator:
    async def describe_attempt(self, credential: object) -> AuthenticationAttempt:
        assert credential == b"credential"
        return AuthenticationAttempt(
            method="signed-workload-token",
            credential_digest="c" * 64,
        )

    async def authenticate(self, credential: object) -> AuthenticatedAgentPrincipal:
        assert credential == b"credential"
        return _agent_principal()


class _CredentialProvider:
    async def get_credential(self) -> object:
        return b"credential"


class _ControlPlaneAuthenticator:
    async def authenticate(self, credential: object) -> ControlPlanePrincipal:
        raise NotImplementedError


def test_protocols_are_runtime_checkable_without_selecting_a_mechanism() -> None:
    assert isinstance(_AgentAuthenticator(), AgentAuthenticator)
    assert isinstance(_CredentialProvider(), AgentCredentialProvider)
    assert isinstance(_ControlPlaneAuthenticator(), ControlPlaneAuthenticator)


@pytest.mark.asyncio
async def test_authentication_attempt_description_is_secret_free_and_frozen() -> None:
    attempt = await _AgentAuthenticator().describe_attempt(b"credential")

    assert attempt == AuthenticationAttempt(
        method="signed-workload-token",
        credential_digest="c" * 64,
    )
    assert set(type(attempt).model_fields) == {"method", "credential_digest"}
    with pytest.raises(ValidationError):
        attempt.method = "changed"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("method", " signed-workload-token"),
        ("method", "signed\nworkload-token"),
        ("credential_digest", "C" * 64),
        ("credential_digest", "not-a-digest"),
    ],
)
def test_authentication_attempt_rejects_noncanonical_description(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        AuthenticationAttempt.model_validate(
            {
                "method": "signed-workload-token",
                "credential_digest": "c" * 64,
                field: value,
            }
        )


def test_provider_failure_attempt_is_stable_secret_free_and_input_independent() -> None:
    attempt = AuthenticationAttempt.for_provider_failure()

    assert attempt.method == "agentguard.credential-provider.unavailable"
    assert (
        attempt.credential_digest
        == "f70315c0edd4435c1fe821ee1a03e3e2e1c019890b8c211654f23805ea72aba6"
    )
    assert attempt == AuthenticationAttempt.for_provider_failure()
    assert set(attempt.model_dump()) == {"method", "credential_digest"}
    with pytest.raises(TypeError):
        AuthenticationAttempt.for_provider_failure("provider error")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        attempt.credential_digest = "0" * 64


@pytest.mark.parametrize("failure", list(AuthenticationFailure))
def test_authentication_failures_are_reserved_reason_codes_and_messages_are_safe(
    failure: AuthenticationFailure,
) -> None:
    error = AuthenticationError(failure)

    assert error.failure is failure
    assert error.reason_code == failure.value
    assert failure.value in RUNTIME_REASON_CODES
    assert str(error) == f"Authentication failed: {failure.value}"
    assert error.__cause__ is None


def test_authentication_error_has_no_detail_or_credential_channel() -> None:
    raw_provider_error = "sensitive provider diagnostic"

    with pytest.raises(TypeError):
        AuthenticationError(  # type: ignore[call-arg]
            AuthenticationFailure.PROVIDER_FAILURE, detail=raw_provider_error
        )
    assert raw_provider_error not in str(
        AuthenticationError(AuthenticationFailure.PROVIDER_FAILURE)
    )


def test_unregistered_authentication_reason_codes_cannot_be_spoofed() -> None:
    assert not is_valid_reason_code("AUTH.UNREGISTERED_FAILURE")
