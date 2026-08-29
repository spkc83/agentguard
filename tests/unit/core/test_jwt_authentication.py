"""Adversarial tests for the concrete RS256 workload authenticator."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jwt.warnings import InsecureKeyLengthWarning

from agentguard.core.jwt_authentication import (
    CredentialUseDisposition,
    CredentialUseStore,
    InMemoryCredentialUseStore,
    InMemoryJwtKeySetProvider,
    JwtAgentAuthenticator,
    JwtKeySetProvider,
    JwtKeySetSnapshot,
    JwtTrustPolicy,
)
from agentguard.exceptions import AuthenticationError, AuthenticationFailure

NOW = datetime(2026, 8, 27, 12, tzinfo=UTC)
ISSUER = "https://issuer.example.test"
AUDIENCE = "agentguard-runtime"
SUBJECT = "workload-agent-7"
KID = "key-current"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _rsa_jwk(
    private_key: rsa.RSAPrivateKey,
    *,
    kid: str = KID,
    alg: str = "RS256",
    use: str = "sig",
    kty: str = "RSA",
) -> dict[str, object]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": kty,
        "kid": kid,
        "use": use,
        "alg": alg,
        "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def policy() -> JwtTrustPolicy:
    return JwtTrustPolicy(
        issuer=ISSUER,
        audience=AUDIENCE,
        leeway_seconds=30,
    )


def _claims(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": SUBJECT,
        "jti": "credential-use-1",
        "iat": NOW - timedelta(seconds=5),
        "nbf": NOW - timedelta(seconds=5),
        "exp": NOW + timedelta(minutes=2),
    }
    values.update(updates)
    return values


def _token(
    key: rsa.RSAPrivateKey,
    *,
    claims: Mapping[str, object] | None = None,
    headers: Mapping[str, object] | None = None,
    algorithm: str = "RS256",
) -> str:
    return jwt.encode(
        dict(claims or _claims()),
        key,
        algorithm=algorithm,
        headers={"kid": KID, "typ": "JWT", **dict(headers or {})},
    )


def _compact_token(
    key: rsa.RSAPrivateKey,
    *,
    header_json: str,
    payload_json: str,
) -> str:
    encoded_header = _b64url(header_json.encode())
    encoded_payload = _b64url(payload_json.encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{encoded_header}.{encoded_payload}.{_b64url(signature)}"


def _authenticator(
    policy: JwtTrustPolicy,
    key: rsa.RSAPrivateKey,
    *,
    jwk: Mapping[str, object] | None = None,
    use_store: Any | None = None,
    provider: Any | None = None,
) -> JwtAgentAuthenticator:
    snapshot = JwtKeySetSnapshot(
        revision=1,
        current_keys=(dict(jwk or _rsa_jwk(key)),),
    )
    key_provider = provider or InMemoryJwtKeySetProvider(
        snapshot,
        monotonic_clock=lambda: 0.0,
    )
    return JwtAgentAuthenticator(
        policy,
        key_provider,
        use_store or InMemoryCredentialUseStore(clock=lambda: NOW),
        clock=lambda: NOW,
    )


def test_in_memory_backends_implement_public_extension_protocols(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    snapshot = JwtKeySetSnapshot(
        revision=1,
        current_keys=(_rsa_jwk(signing_key),),
    )

    assert isinstance(InMemoryJwtKeySetProvider(snapshot), JwtKeySetProvider)
    assert isinstance(InMemoryCredentialUseStore(), CredentialUseStore)


def test_key_snapshot_rejects_unbounded_key_sets(signing_key: rsa.RSAPrivateKey) -> None:
    keys = tuple(_rsa_jwk(signing_key, kid=f"key-{index}") for index in range(65))

    with pytest.raises(ValueError, match="cannot exceed 64"):
        JwtKeySetSnapshot(revision=1, current_keys=keys)


async def _failure(
    authenticator: JwtAgentAuthenticator, credential: object
) -> AuthenticationFailure:
    with pytest.raises(AuthenticationError) as caught:
        await authenticator.authenticate(credential)
    return caught.value.failure


@pytest.mark.asyncio
async def test_authenticates_valid_rs256_workload_token(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = _token(signing_key)

    principal = await _authenticator(policy, signing_key).authenticate(token)

    assert principal.agent_id == SUBJECT
    assert principal.method == "agentguard.jwt.rs256"
    assert principal.authority == ISSUER
    assert principal.credential_digest == hashlib.sha256(token.encode()).hexdigest()


@pytest.mark.asyncio
async def test_describe_attempt_returns_secret_free_stable_digest(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = _token(signing_key)

    attempt = await _authenticator(policy, signing_key).describe_attempt(token)

    assert attempt.method == "agentguard.jwt.rs256"
    assert attempt.credential_digest == hashlib.sha256(token.encode()).hexdigest()
    assert token not in repr(attempt)


@pytest.mark.asyncio
async def test_authenticated_subject_comes_from_signed_token_not_claimed_actor(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = _token(signing_key, claims=_claims(sub="signed-subject"))

    principal = await _authenticator(policy, signing_key).authenticate(token)

    assert principal.agent_id == "signed-subject"


@pytest.mark.asyncio
async def test_rejects_alg_none_token(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = jwt.encode(_claims(), key="", algorithm="none", headers={"kid": KID})

    failure = await _failure(_authenticator(policy, signing_key), token)

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.asyncio
async def test_rejects_wrong_asymmetric_algorithm(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = _token(signing_key, algorithm="RS512")

    failure = await _failure(_authenticator(policy, signing_key), token)

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.asyncio
async def test_rejects_token_signed_by_untrusted_key(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    failure = await _failure(_authenticator(policy, signing_key), _token(attacker_key))

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.asyncio
async def test_rejects_hmac_rsa_algorithm_confusion(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    public_der = signing_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    token = jwt.encode(_claims(), public_der, algorithm="HS256", headers={"kid": KID, "typ": "JWT"})

    failure = await _failure(_authenticator(policy, signing_key), token)

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.parametrize("header", ["jwk", "jku", "x5u", "x5c", "crit", "b64"])
@pytest.mark.asyncio
async def test_rejects_token_controlled_key_source_or_processing_header(
    header: str, signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    value: object = False if header == "b64" else ["exp"] if header == "crit" else "attacker"
    token = _token(signing_key, headers={header: value})

    failure = await _failure(_authenticator(policy, signing_key), token)

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.parametrize(
    "header_json",
    [
        '{"alg":"RS256","typ":"JWT"}',
        '{"alg":"RS256","typ":"JWT","kid":"unknown"}',
        '{"alg":"RS256","typ":"JWT","kid":"a","kid":"key-current"}',
        '{"alg":"RS256","typ":"JWT","kid":7}',
        '{"alg":"RS256","typ":"JWT","kid":" key-current"}',
    ],
)
@pytest.mark.asyncio
async def test_rejects_unusable_key_identifier(
    header_json: str, signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = _compact_token(
        signing_key,
        header_json=header_json,
        payload_json=json.dumps(_claims(), default=lambda value: value.timestamp()),
    )

    failure = await _failure(_authenticator(policy, signing_key), token)

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.parametrize(
    "jwk_update",
    [
        {"use": "enc"},
        {"alg": "RS512"},
        {"kty": "EC"},
        {"n": "%%%"},
        {"key_ops": ["sign"]},
        {"d": "private-key-material"},
    ],
)
@pytest.mark.asyncio
async def test_rejects_jwk_that_is_not_a_valid_rs256_signing_key(
    jwk_update: Mapping[str, object],
    signing_key: rsa.RSAPrivateKey,
    policy: JwtTrustPolicy,
) -> None:
    jwk = {**_rsa_jwk(signing_key), **jwk_update}

    failure = await _failure(_authenticator(policy, signing_key, jwk=jwk), _token(signing_key))

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.asyncio
async def test_rejects_rsa_key_below_minimum_size(policy: JwtTrustPolicy) -> None:
    weak_key = rsa.generate_private_key(  # noqa: S505 - deliberately weak adversarial fixture
        public_exponent=65537,
        key_size=1024,  # noqa: S505
    )
    with pytest.warns(InsecureKeyLengthWarning):
        token = _token(weak_key)

    failure = await _failure(_authenticator(policy, weak_key), token)

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.parametrize(
    "claims",
    [
        _claims(iss="https://attacker.example"),
        _claims(aud="different-runtime"),
        {key: value for key, value in _claims().items() if key != "iss"},
        {key: value for key, value in _claims().items() if key != "aud"},
        {key: value for key, value in _claims().items() if key != "sub"},
        {key: value for key, value in _claims().items() if key != "jti"},
        _claims(sub=""),
        _claims(sub=" agent"),
        _claims(jti=""),
    ],
)
@pytest.mark.asyncio
async def test_rejects_wrong_missing_or_noncanonical_identity_claims(
    claims: Mapping[str, object],
    signing_key: rsa.RSAPrivateKey,
    policy: JwtTrustPolicy,
) -> None:
    failure = await _failure(
        _authenticator(policy, signing_key), _token(signing_key, claims=claims)
    )

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.parametrize("missing_claim", ["iat", "nbf", "exp"])
@pytest.mark.asyncio
async def test_rejects_missing_required_time_claim(
    missing_claim: str,
    signing_key: rsa.RSAPrivateKey,
    policy: JwtTrustPolicy,
) -> None:
    claims = {key: value for key, value in _claims().items() if key != missing_claim}

    failure = await _failure(
        _authenticator(policy, signing_key), _token(signing_key, claims=claims)
    )

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.parametrize(
    "claims",
    [
        _claims(iat=True),
        _claims(nbf="not-a-date"),
        _claims(exp=NOW.timestamp() + 120.5),
    ],
)
@pytest.mark.asyncio
async def test_rejects_malformed_numeric_date(
    claims: Mapping[str, object],
    signing_key: rsa.RSAPrivateKey,
    policy: JwtTrustPolicy,
) -> None:
    failure = await _failure(
        _authenticator(policy, signing_key), _token(signing_key, claims=claims)
    )

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.asyncio
async def test_rejects_expired_token(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = _token(
        signing_key,
        claims=_claims(
            iat=NOW - timedelta(minutes=2),
            nbf=NOW - timedelta(minutes=2),
            exp=NOW - timedelta(seconds=31),
        ),
    )

    failure = await _failure(_authenticator(policy, signing_key), token)

    assert failure is AuthenticationFailure.CREDENTIAL_EXPIRED


@pytest.mark.parametrize(
    "claims",
    [
        _claims(iat=NOW + timedelta(seconds=31), nbf=NOW + timedelta(seconds=31)),
        _claims(nbf=NOW + timedelta(seconds=31)),
    ],
)
@pytest.mark.asyncio
async def test_rejects_token_not_yet_valid_beyond_allowed_skew(
    claims: Mapping[str, object], signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = _token(signing_key, claims=claims)

    failure = await _failure(_authenticator(policy, signing_key), token)

    assert failure is AuthenticationFailure.CREDENTIAL_NOT_YET_VALID


@pytest.mark.parametrize(
    "claims",
    [
        _claims(
            iat=NOW - timedelta(minutes=2),
            nbf=NOW - timedelta(minutes=2),
            exp=NOW - timedelta(seconds=29),
        ),
        _claims(iat=NOW + timedelta(seconds=29), nbf=NOW + timedelta(seconds=29)),
    ],
)
@pytest.mark.asyncio
async def test_accepts_time_claim_at_allowed_skew_edge(
    claims: Mapping[str, object], signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    principal = await _authenticator(policy, signing_key).authenticate(
        _token(signing_key, claims=claims)
    )

    assert principal.agent_id == SUBJECT


@pytest.mark.asyncio
async def test_rejects_token_exceeding_maximum_lifetime(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    claims = _claims(iat=NOW, nbf=NOW, exp=NOW + timedelta(seconds=301))

    failure = await _failure(
        _authenticator(policy, signing_key), _token(signing_key, claims=claims)
    )

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.asyncio
async def test_rejects_token_exceeding_maximum_encoded_size(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = _token(signing_key, claims=_claims(padding="x" * 9000))

    failure = await _failure(_authenticator(policy, signing_key), token)

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.parametrize("credential", ["not-a-jwt", b"not-a-jwt", object(), None])
@pytest.mark.asyncio
async def test_rejects_malformed_or_non_text_credential(
    credential: object, signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    failure = await _failure(_authenticator(policy, signing_key), credential)

    assert failure in {
        AuthenticationFailure.CREDENTIAL_INVALID,
        AuthenticationFailure.CREDENTIAL_MISSING,
    }


@pytest.mark.parametrize("duplicate_member", ["sub", "jti", "iss", "aud"])
@pytest.mark.asyncio
async def test_rejects_duplicate_security_relevant_payload_member(
    duplicate_member: str,
    signing_key: rsa.RSAPrivateKey,
    policy: JwtTrustPolicy,
) -> None:
    claims = _claims()
    encoded = json.dumps(claims, default=lambda value: value.timestamp())
    original = json.dumps(claims[duplicate_member], default=lambda value: value.timestamp())
    payload_json = encoded[:-1] + f',"{duplicate_member}":{original}' + "}"
    token = _compact_token(
        signing_key,
        header_json='{"alg":"RS256","typ":"JWT","kid":"key-current"}',
        payload_json=payload_json,
    )

    failure = await _failure(_authenticator(policy, signing_key), token)

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.asyncio
async def test_previous_key_is_accepted_during_rotation_overlap(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    provider = InMemoryJwtKeySetProvider(
        JwtKeySetSnapshot(revision=1, current_keys=(_rsa_jwk(signing_key),)),
        monotonic_clock=lambda: 0.0,
    )
    await provider.rotate(
        JwtKeySetSnapshot(
            revision=2,
            current_keys=(_rsa_jwk(new_key, kid="key-new"),),
        ),
        expected_revision=1,
        overlap_for_seconds=60,
    )
    auth = JwtAgentAuthenticator(
        policy,
        provider,
        InMemoryCredentialUseStore(clock=lambda: NOW),
        clock=lambda: NOW,
    )

    principal = await auth.authenticate(_token(signing_key))

    assert principal.agent_id == SUBJECT


def test_key_provider_rejects_unmanaged_initial_overlap(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    second_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    snapshot = JwtKeySetSnapshot(
        revision=2,
        current_keys=(_rsa_jwk(second_key, kid="key-second"),),
        previous_keys=(_rsa_jwk(signing_key),),
    )

    with pytest.raises(ValueError, match="unmanaged overlap"):
        InMemoryJwtKeySetProvider(snapshot)


@pytest.mark.asyncio
async def test_removed_rotation_key_is_rejected(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    auth = _authenticator(policy, new_key, jwk=_rsa_jwk(new_key, kid="key-new"))

    failure = await _failure(auth, _token(signing_key))

    assert failure is AuthenticationFailure.CREDENTIAL_INVALID


@pytest.mark.asyncio
async def test_rotation_provider_removes_previous_key_when_overlap_expires(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    elapsed = 0.0
    provider = InMemoryJwtKeySetProvider(
        JwtKeySetSnapshot(
            revision=1,
            current_keys=(_rsa_jwk(signing_key),),
        ),
        monotonic_clock=lambda: elapsed,
    )
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    await provider.rotate(
        JwtKeySetSnapshot(
            revision=2,
            current_keys=(_rsa_jwk(new_key, kid="key-new"),),
        ),
        expected_revision=1,
        overlap_for_seconds=60,
    )

    assert len((await provider.snapshot()).previous_keys) == 1
    elapsed = 60.0
    assert (await provider.snapshot()).previous_keys == ()


@pytest.mark.asyncio
async def test_rotation_provider_rejects_stale_expected_revision(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    provider = InMemoryJwtKeySetProvider(
        JwtKeySetSnapshot(
            revision=1,
            current_keys=(_rsa_jwk(signing_key),),
        ),
        monotonic_clock=lambda: 0.0,
    )
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with pytest.raises(ValueError, match="revision conflict"):
        await provider.rotate(
            JwtKeySetSnapshot(
                revision=2,
                current_keys=(_rsa_jwk(new_key, kid="key-new"),),
            ),
            expected_revision=0,
            overlap_for_seconds=60,
        )


@pytest.mark.asyncio
async def test_rotation_provider_rejects_unbounded_overlap(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    provider = InMemoryJwtKeySetProvider(
        JwtKeySetSnapshot(revision=1, current_keys=(_rsa_jwk(signing_key),)),
        max_overlap_seconds=60,
    )
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with pytest.raises(ValueError, match="configured maximum"):
        await provider.rotate(
            JwtKeySetSnapshot(
                revision=2,
                current_keys=(_rsa_jwk(new_key, kid="key-new"),),
            ),
            expected_revision=1,
            overlap_for_seconds=61,
        )


@pytest.mark.asyncio
async def test_rotation_provider_requires_a_new_revision(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    provider = InMemoryJwtKeySetProvider(
        JwtKeySetSnapshot(revision=2, current_keys=(_rsa_jwk(signing_key),))
    )

    with pytest.raises(ValueError, match="must advance revision"):
        await provider.rotate(
            JwtKeySetSnapshot(revision=2, current_keys=(_rsa_jwk(signing_key),)),
            expected_revision=2,
            overlap_for_seconds=0,
        )


@pytest.mark.asyncio
async def test_rotation_provider_rejects_revision_aba(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    provider = InMemoryJwtKeySetProvider(
        JwtKeySetSnapshot(revision=1, current_keys=(_rsa_jwk(signing_key),))
    )
    second_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    await provider.rotate(
        JwtKeySetSnapshot(
            revision=2,
            current_keys=(_rsa_jwk(second_key, kid="key-second"),),
        ),
        expected_revision=1,
        overlap_for_seconds=0,
    )

    with pytest.raises(ValueError, match="must advance revision"):
        await provider.rotate(
            JwtKeySetSnapshot(revision=1, current_keys=(_rsa_jwk(signing_key),)),
            expected_revision=2,
            overlap_for_seconds=0,
        )


@pytest.mark.asyncio
async def test_rotation_provider_drops_overlap_if_monotonic_clock_regresses(
    signing_key: rsa.RSAPrivateKey,
) -> None:
    elapsed = 10.0
    provider = InMemoryJwtKeySetProvider(
        JwtKeySetSnapshot(revision=1, current_keys=(_rsa_jwk(signing_key),)),
        monotonic_clock=lambda: elapsed,
    )
    second_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    await provider.rotate(
        JwtKeySetSnapshot(
            revision=2,
            current_keys=(_rsa_jwk(second_key, kid="key-second"),),
        ),
        expected_revision=1,
        overlap_for_seconds=60,
    )
    assert (await provider.snapshot()).previous_keys

    elapsed = 9.0

    assert (await provider.snapshot()).previous_keys == ()


@pytest.mark.parametrize("dimension", ["issuer", "kid", "subject", "jti", "credential_digest"])
@pytest.mark.asyncio
async def test_emergency_revocation_blocks_each_supported_dimension(
    dimension: str, signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = _token(signing_key)
    values: dict[str, str] = {
        "issuer": ISSUER,
        "kid": KID,
        "subject": SUBJECT,
        "jti": "credential-use-1",
        "credential_digest": hashlib.sha256(token.encode()).hexdigest(),
    }
    store = InMemoryCredentialUseStore(clock=lambda: NOW)
    await store.revoke(**{dimension: values[dimension]})

    failure = await _failure(_authenticator(policy, signing_key, use_store=store), token)

    assert failure is AuthenticationFailure.CREDENTIAL_REVOKED


@pytest.mark.asyncio
async def test_replay_of_same_jti_is_rejected(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    auth = _authenticator(policy, signing_key)
    token = _token(signing_key)
    await auth.authenticate(token)

    failure = await _failure(auth, token)

    assert failure is AuthenticationFailure.CREDENTIAL_REPLAYED


@pytest.mark.asyncio
async def test_concurrent_duplicate_jti_allows_exactly_one_authentication(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    auth = _authenticator(policy, signing_key)
    credentials = [
        _token(signing_key, claims=_claims(jti="one-use", nonce=index)) for index in range(12)
    ]

    results = await asyncio.gather(
        *(auth.authenticate(credential) for credential in credentials),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, BaseException) for result in results) == 1


class _FailingUseStore:
    async def consume_once(self, **_: object) -> CredentialUseDisposition:
        raise RuntimeError("store detail including raw-token-secret")


class _FailingKeyProvider:
    async def snapshot(self) -> JwtKeySetSnapshot:
        raise RuntimeError("provider detail including raw-token-secret")


@pytest.mark.parametrize("backend", ["store", "provider"])
@pytest.mark.asyncio
async def test_backend_failure_is_sanitized_and_fails_closed(
    backend: str, signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = _token(signing_key)
    auth = _authenticator(
        policy,
        signing_key,
        use_store=_FailingUseStore() if backend == "store" else None,
        provider=_FailingKeyProvider() if backend == "provider" else None,
    )

    with pytest.raises(AuthenticationError) as caught:
        await auth.authenticate(token)

    assert caught.value.failure is AuthenticationFailure.INTERNAL_ERROR
    assert token not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.asyncio
async def test_missing_optional_jwt_dependency_fails_closed_without_import_detail(
    monkeypatch: pytest.MonkeyPatch,
    signing_key: rsa.RSAPrivateKey,
    policy: JwtTrustPolicy,
) -> None:
    token = _token(signing_key)

    def missing_dependency(_name: str) -> None:
        raise ImportError("sensitive import path")

    monkeypatch.setattr(
        "agentguard.core.jwt_authentication.importlib.import_module",
        missing_dependency,
    )

    with pytest.raises(AuthenticationError) as caught:
        await _authenticator(policy, signing_key).authenticate(token)

    assert caught.value.failure is AuthenticationFailure.INTERNAL_ERROR
    assert "sensitive import path" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.asyncio
async def test_raw_token_is_absent_from_invalid_credential_error(
    signing_key: rsa.RSAPrivateKey, policy: JwtTrustPolicy
) -> None:
    token = f"raw-token-secret.{_token(signing_key)}"

    with pytest.raises(AuthenticationError) as caught:
        await _authenticator(policy, signing_key).authenticate(token)

    assert token not in str(caught.value)
    assert token not in repr(caught.value)


@pytest.mark.asyncio
async def test_signature_verification_does_not_block_event_loop(
    monkeypatch: pytest.MonkeyPatch,
    signing_key: rsa.RSAPrivateKey,
    policy: JwtTrustPolicy,
) -> None:
    original_decode = jwt.decode

    def slow_decode(*args: object, **kwargs: object) -> Any:
        time.sleep(0.08)
        return original_decode(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(jwt, "decode", slow_decode)
    auth_task = asyncio.create_task(
        _authenticator(policy, signing_key).authenticate(_token(signing_key))
    )
    heartbeat = asyncio.Event()
    asyncio.get_running_loop().call_later(0.02, heartbeat.set)

    await asyncio.wait_for(heartbeat.wait(), timeout=0.06)
    await auth_task


@pytest.mark.asyncio
async def test_cancelling_signature_verification_propagates_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    signing_key: rsa.RSAPrivateKey,
    policy: JwtTrustPolicy,
) -> None:
    original_decode = jwt.decode
    started = threading.Event()
    release = threading.Event()

    def controlled_decode(*args: object, **kwargs: object) -> Any:
        started.set()
        release.wait(timeout=1)
        return original_decode(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(jwt, "decode", controlled_decode)
    task = asyncio.create_task(
        _authenticator(policy, signing_key).authenticate(_token(signing_key))
    )
    for _ in range(100):
        if started.is_set():
            break
        await asyncio.sleep(0)
    assert started.is_set()

    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_cancelled_verification_holds_crypto_slot_until_worker_drains(
    monkeypatch: pytest.MonkeyPatch,
    signing_key: rsa.RSAPrivateKey,
    policy: JwtTrustPolicy,
) -> None:
    original_decode = jwt.decode
    first_started = threading.Event()
    first_release = threading.Event()
    second_started = threading.Event()
    lock = threading.Lock()
    active = 0
    max_active = 0
    calls = 0

    def controlled_decode(*args: object, **kwargs: object) -> Any:
        nonlocal active, calls, max_active
        with lock:
            calls += 1
            call_number = calls
            active += 1
            max_active = max(max_active, active)
        try:
            if call_number == 1:
                first_started.set()
                first_release.wait(timeout=1)
            else:
                second_started.set()
            return original_decode(*args, **kwargs)  # type: ignore[arg-type]
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(jwt, "decode", controlled_decode)
    bounded_policy = JwtTrustPolicy(
        issuer=policy.issuer,
        audience=policy.audience,
        max_crypto_concurrency=1,
    )
    auth = _authenticator(bounded_policy, signing_key)
    first = asyncio.create_task(auth.authenticate(_token(signing_key, claims=_claims(jti="first"))))
    for _ in range(100):
        if first_started.is_set():
            break
        await asyncio.sleep(0)
    assert first_started.is_set()

    first.cancel()
    second = asyncio.create_task(
        auth.authenticate(_token(signing_key, claims=_claims(jti="second")))
    )
    await asyncio.sleep(0.03)
    assert not second_started.is_set()

    first_release.set()
    with pytest.raises(asyncio.CancelledError):
        await first
    await second

    assert second_started.is_set()
    assert max_active == 1


@pytest.mark.asyncio
async def test_in_memory_use_store_reports_capacity_exhaustion() -> None:
    store = InMemoryCredentialUseStore(max_entries=1, clock=lambda: NOW)
    first = await store.consume_once(
        issuer=ISSUER,
        kid=KID,
        subject=SUBJECT,
        jti="first",
        credential_digest="a" * 64,
        expires_at=NOW + timedelta(minutes=1),
    )
    second = await store.consume_once(
        issuer=ISSUER,
        kid=KID,
        subject=SUBJECT,
        jti="second",
        credential_digest="b" * 64,
        expires_at=NOW + timedelta(minutes=1),
    )

    assert first is CredentialUseDisposition.ACCEPTED
    assert second is CredentialUseDisposition.CAPACITY_EXCEEDED


@pytest.mark.asyncio
async def test_in_memory_use_store_fails_closed_after_clock_rollback() -> None:
    store_time = NOW
    store = InMemoryCredentialUseStore(clock=lambda: store_time)
    common = {
        "issuer": ISSUER,
        "kid": KID,
        "subject": SUBJECT,
        "credential_digest": "a" * 64,
    }
    first = await store.consume_once(
        **common,
        jti="first",
        expires_at=NOW + timedelta(seconds=60),
    )
    store_time = NOW + timedelta(seconds=61)
    forward = await store.consume_once(
        **common,
        jti="second",
        expires_at=NOW + timedelta(seconds=120),
    )
    store_time = NOW + timedelta(seconds=30)
    rolled_back = await store.consume_once(
        **common,
        jti="first",
        expires_at=NOW + timedelta(seconds=60),
    )

    assert first is CredentialUseDisposition.ACCEPTED
    assert forward is CredentialUseDisposition.ACCEPTED
    assert rolled_back is CredentialUseDisposition.CLOCK_ROLLBACK
