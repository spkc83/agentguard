"""Offline RS256 workload authentication with pinned operator-managed keys."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import importlib
import json
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType, ModuleType
from typing import TYPE_CHECKING, Final, Protocol, cast, runtime_checkable

from agentguard.core.authentication import AuthenticatedAgentPrincipal, AuthenticationAttempt
from agentguard.exceptions import AuthenticationError, AuthenticationFailure

if TYPE_CHECKING:
    from collections.abc import Callable

_METHOD: Final = "agentguard.jwt.rs256"
_FORBIDDEN_HEADERS: Final = frozenset({"jwk", "jku", "x5u", "x5c", "crit", "b64"})
_PRIVATE_JWK_MEMBERS: Final = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})
_MAX_PINNED_KEYS: Final = 64


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _canonical_text(value: object, *, max_length: int = 2048) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or value != value.strip()
        or not value.isprintable()
    ):
        raise ValueError("value must be canonical printable text")
    return value


def _freeze_jwk(value: Mapping[str, object]) -> Mapping[str, object]:
    copy = {key: _freeze_json(member) for key, member in value.items()}
    if any(not isinstance(key, str) for key in copy):
        raise TypeError("JWK member names must be strings")
    return MappingProxyType(copy)


def _freeze_json(value: object) -> object:
    if value is None or isinstance(value, str | int | bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JWK values must be finite JSON values")
        return value
    if isinstance(value, list | tuple):
        return tuple(_freeze_json(member) for member in value)
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(member) for key, member in value.items()})
    raise TypeError("JWK values must be JSON-compatible")


@dataclass(frozen=True, slots=True)
class JwtTrustPolicy:
    """Fixed trust parameters for one workload-token issuer and audience."""

    issuer: str
    audience: str
    max_token_bytes: int = 8192
    max_lifetime_seconds: float = 300.0
    leeway_seconds: float = 30.0
    accepted_typ: tuple[str, ...] = ("JWT", "at+jwt")
    min_rsa_bits: int = 2048
    max_crypto_concurrency: int = 8

    def __post_init__(self) -> None:
        _canonical_text(self.issuer)
        _canonical_text(self.audience)
        if self.max_token_bytes <= 0:
            raise ValueError("max_token_bytes must be positive")
        if not math.isfinite(self.max_lifetime_seconds) or self.max_lifetime_seconds <= 0:
            raise ValueError("max_lifetime_seconds must be finite and positive")
        if not math.isfinite(self.leeway_seconds) or self.leeway_seconds < 0:
            raise ValueError("leeway_seconds must be finite and non-negative")
        accepted_typ = tuple(self.accepted_typ)
        object.__setattr__(self, "accepted_typ", accepted_typ)
        if not accepted_typ or len(accepted_typ) != len(set(accepted_typ)):
            raise ValueError("accepted_typ must contain unique values")
        for token_type in accepted_typ:
            _canonical_text(token_type, max_length=64)
        if self.min_rsa_bits < 2048:
            raise ValueError("min_rsa_bits cannot weaken the 2048-bit minimum")
        if self.max_crypto_concurrency <= 0:
            raise ValueError("max_crypto_concurrency must be positive")


@dataclass(frozen=True, slots=True)
class JwtKeySetSnapshot:
    """Immutable, operator-pinned current and overlap RSA JWKs."""

    revision: int
    current_keys: tuple[Mapping[str, object], ...]
    previous_keys: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.revision, bool) or not isinstance(self.revision, int):
            raise TypeError("key-set revision must be an integer")
        if self.revision < 1:
            raise ValueError("key-set revision must be positive")
        if not self.current_keys:
            raise ValueError("at least one current JWK is required")
        current = tuple(_freeze_jwk(value) for value in self.current_keys)
        previous = tuple(_freeze_jwk(value) for value in self.previous_keys)
        key_ids = [
            _canonical_text(value.get("kid"), max_length=256) for value in current + previous
        ]
        if len(key_ids) > _MAX_PINNED_KEYS:
            raise ValueError(f"a key-set snapshot cannot exceed {_MAX_PINNED_KEYS} keys")
        if len(key_ids) != len(set(key_ids)):
            raise ValueError("JWK kid values must be unique across the snapshot")
        object.__setattr__(self, "current_keys", current)
        object.__setattr__(self, "previous_keys", previous)

    @property
    def keys(self) -> tuple[Mapping[str, object], ...]:
        """Return every key eligible for verification in this snapshot."""

        return self.current_keys + self.previous_keys


class InMemoryJwtKeySetProvider:
    """Atomic, network-free key rotation with one explicitly bounded overlap."""

    def __init__(
        self,
        initial_snapshot: JwtKeySetSnapshot,
        *,
        monotonic_clock: Callable[[], float] = time.monotonic,
        max_overlap_seconds: float = 330.0,
    ) -> None:
        if not math.isfinite(max_overlap_seconds) or max_overlap_seconds < 0:
            raise ValueError("max_overlap_seconds must be finite and non-negative")
        if initial_snapshot.previous_keys:
            raise ValueError("initial key-set snapshots cannot contain unmanaged overlap keys")
        self._snapshot = initial_snapshot
        self._overlap_expires_at: float | None = None
        self._monotonic_clock = monotonic_clock
        self._observed_monotonic: float | None = None
        self._max_overlap_seconds = max_overlap_seconds
        self._lock = asyncio.Lock()

    async def snapshot(self) -> JwtKeySetSnapshot:
        async with self._lock:
            now = self._monotonic_now()
            if self._observed_monotonic is not None and now < self._observed_monotonic:
                self._drop_previous_keys()
                return self._snapshot
            self._observed_monotonic = now
            if (
                self._snapshot.previous_keys
                and self._overlap_expires_at is not None
                and now >= self._overlap_expires_at
            ):
                self._drop_previous_keys()
            return self._snapshot

    async def rotate(
        self,
        new_snapshot: JwtKeySetSnapshot,
        *,
        expected_revision: int,
        overlap_for_seconds: float,
    ) -> JwtKeySetSnapshot:
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
            raise TypeError("expected_revision must be an integer")
        if new_snapshot.previous_keys:
            raise ValueError("rotation overlap is managed by the key-set provider")
        if not math.isfinite(overlap_for_seconds) or overlap_for_seconds < 0:
            raise ValueError("overlap_for_seconds must be finite and non-negative")
        if overlap_for_seconds > self._max_overlap_seconds:
            raise ValueError("overlap_for_seconds exceeds the configured maximum")
        async with self._lock:
            now = self._monotonic_now()
            if self._observed_monotonic is not None and now < self._observed_monotonic:
                self._drop_previous_keys()
                raise ValueError("monotonic clock moved backwards")
            self._observed_monotonic = now
            if self._snapshot.revision != expected_revision:
                raise ValueError("key-set revision conflict")
            if new_snapshot.revision <= expected_revision:
                raise ValueError("key-set rotation must advance revision")
            previous = self._snapshot.current_keys if overlap_for_seconds > 0 else ()
            self._snapshot = JwtKeySetSnapshot(
                revision=new_snapshot.revision,
                current_keys=new_snapshot.current_keys,
                previous_keys=previous,
            )
            self._overlap_expires_at = now + overlap_for_seconds if previous else None
            return self._snapshot

    def _monotonic_now(self) -> float:
        value = self._monotonic_clock()
        if not math.isfinite(value) or value < 0:
            raise ValueError("monotonic_clock must return a finite non-negative value")
        return value

    def _drop_previous_keys(self) -> None:
        if self._snapshot.previous_keys:
            self._snapshot = JwtKeySetSnapshot(
                revision=self._snapshot.revision,
                current_keys=self._snapshot.current_keys,
            )
        self._overlap_expires_at = None


class CredentialUseDisposition(StrEnum):
    """Atomic outcome of consuming a one-use workload credential."""

    ACCEPTED = "accepted"
    REPLAYED = "replayed"
    REVOKED = "revoked"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    CLOCK_ROLLBACK = "clock_rollback"
    EXPIRED = "expired"


@runtime_checkable
class JwtKeySetProvider(Protocol):
    """Provide one immutable, operator-pinned key snapshot without network access."""

    async def snapshot(self) -> JwtKeySetSnapshot: ...


@runtime_checkable
class CredentialUseStore(Protocol):
    """Atomically enforce replay prevention and emergency revocation."""

    async def consume_once(
        self,
        *,
        issuer: str,
        kid: str,
        subject: str,
        jti: str,
        credential_digest: str,
        expires_at: datetime,
    ) -> CredentialUseDisposition: ...


@dataclass(frozen=True, slots=True)
class _CredentialUse:
    issuer: str
    kid: str
    subject: str
    jti: str
    credential_digest: str
    expires_at: datetime


@dataclass(slots=True)
class _Revocations:
    issuers: set[str] = field(default_factory=set)
    kids: set[str] = field(default_factory=set)
    subjects: set[str] = field(default_factory=set)
    jtis: set[str] = field(default_factory=set)
    digests: set[str] = field(default_factory=set)

    def count(self) -> int:
        return sum(
            len(values)
            for values in (self.issuers, self.kids, self.subjects, self.jtis, self.digests)
        )


class InMemoryCredentialUseStore:
    """Bounded process-local replay and emergency-revocation state."""

    def __init__(
        self,
        max_entries: int = 100_000,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._clock = clock
        self._uses: dict[tuple[str, str], _CredentialUse] = {}
        self._revocations = _Revocations()
        self._observed_at: datetime | None = None
        self._lock = asyncio.Lock()

    async def consume_once(
        self,
        *,
        issuer: str,
        kid: str,
        subject: str,
        jti: str,
        credential_digest: str,
        expires_at: datetime,
    ) -> CredentialUseDisposition:
        use = _CredentialUse(
            issuer=_canonical_text(issuer),
            kid=_canonical_text(kid, max_length=256),
            subject=_canonical_text(subject, max_length=256),
            jti=_canonical_text(jti, max_length=512),
            credential_digest=_credential_digest(credential_digest),
            expires_at=_aware_utc(expires_at),
        )
        async with self._lock:
            observed_at = self._now()
            if self._observed_at is not None and observed_at < self._observed_at:
                return CredentialUseDisposition.CLOCK_ROLLBACK
            self._observed_at = observed_at
            self._prune_expired(observed_at)
            if use.expires_at <= observed_at:
                return CredentialUseDisposition.EXPIRED
            if self._is_revoked(use):
                return CredentialUseDisposition.REVOKED
            replay_key = (issuer, jti)
            if replay_key in self._uses:
                return CredentialUseDisposition.REPLAYED
            if len(self._uses) + self._revocations.count() >= self._max_entries:
                return CredentialUseDisposition.CAPACITY_EXCEEDED
            self._uses[replay_key] = use
            return CredentialUseDisposition.ACCEPTED

    def _now(self) -> datetime:
        return _aware_utc(self._clock())

    async def revoke(
        self,
        *,
        issuer: str | None = None,
        kid: str | None = None,
        subject: str | None = None,
        jti: str | None = None,
        credential_digest: str | None = None,
    ) -> None:
        candidates = (
            (self._revocations.issuers, issuer, 2048),
            (self._revocations.kids, kid, 256),
            (self._revocations.subjects, subject, 256),
            (self._revocations.jtis, jti, 512),
            (self._revocations.digests, credential_digest, 64),
        )
        additions = [
            (values, _canonical_text(value, max_length=limit))
            for values, value, limit in candidates
            if value is not None
        ]
        if not additions:
            raise ValueError("at least one revocation selector is required")
        for values, value in additions:
            if values is self._revocations.digests:
                _credential_digest(value)
        async with self._lock:
            additional_count = sum(value not in values for values, value in additions)
            if len(self._uses) + self._revocations.count() + additional_count > self._max_entries:
                raise RuntimeError("credential-use store capacity exceeded")
            for values, value in additions:
                values.add(value)

    async def revoke_issuer(self, issuer: str) -> None:
        await self.revoke(issuer=issuer)

    async def revoke_kid(self, kid: str) -> None:
        await self.revoke(kid=kid)

    async def revoke_subject(self, subject: str) -> None:
        await self.revoke(subject=subject)

    async def revoke_jti(self, jti: str) -> None:
        await self.revoke(jti=jti)

    async def revoke_digest(self, credential_digest: str) -> None:
        await self.revoke(credential_digest=credential_digest)

    def _prune_expired(self, now: datetime) -> None:
        self._uses = {key: use for key, use in self._uses.items() if now < use.expires_at}

    def _is_revoked(self, use: _CredentialUse) -> bool:
        return (
            use.issuer in self._revocations.issuers
            or use.kid in self._revocations.kids
            or use.subject in self._revocations.subjects
            or use.jti in self._revocations.jtis
            or use.credential_digest in self._revocations.digests
        )


class JwtAgentAuthenticator:
    """Verify one-use, short-lived RS256 JWTs without network key discovery."""

    def __init__(
        self,
        policy: JwtTrustPolicy,
        key_provider: JwtKeySetProvider,
        use_store: CredentialUseStore,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._policy = policy
        self._key_provider = key_provider
        self._use_store = use_store
        self._clock = clock
        self._crypto_slots = asyncio.Semaphore(policy.max_crypto_concurrency)

    async def describe_attempt(self, credential: object) -> AuthenticationAttempt:
        token = self._credential_bytes(credential)
        return AuthenticationAttempt(
            method=_METHOD,
            credential_digest=hashlib.sha256(token).hexdigest(),
        )

    async def authenticate(self, credential: object) -> AuthenticatedAgentPrincipal:
        token = self._credential_bytes(credential)
        digest = hashlib.sha256(token).hexdigest()
        header, untrusted_claims = self._parse_compact(token)
        kid = self._validate_header(header)
        self._validate_claim_shape(untrusted_claims)
        snapshot: JwtKeySetSnapshot | None = None
        snapshot_failed = False
        try:
            snapshot = await self._key_provider.snapshot()
        except asyncio.CancelledError:
            raise
        except Exception:
            snapshot_failed = True
        if snapshot_failed:
            raise AuthenticationError(AuthenticationFailure.INTERNAL_ERROR)
        if not isinstance(snapshot, JwtKeySetSnapshot):
            raise AuthenticationError(AuthenticationFailure.INTERNAL_ERROR)
        jwk = self._select_and_validate_jwk(snapshot, kid)
        claims: Mapping[str, object] | None = None
        verification_failure: AuthenticationFailure | None = None
        try:
            claims = await self._verify_bounded(token, jwk)
        except asyncio.CancelledError:
            raise
        except AuthenticationError as error:
            verification_failure = error.failure
        except Exception:
            verification_failure = AuthenticationFailure.CREDENTIAL_INVALID
        if verification_failure is not None:
            raise AuthenticationError(verification_failure)
        assert claims is not None

        clock_failed = False
        try:
            now = self._now()
        except Exception:
            clock_failed = True
            now = datetime.min.replace(tzinfo=UTC)
        if clock_failed:
            raise AuthenticationError(AuthenticationFailure.INTERNAL_ERROR)
        issuer, subject, jti, issued_at, not_before, expires_at = self._validated_claims(
            claims, now
        )
        effective_expires_at = datetime.fromtimestamp(
            expires_at.timestamp() + self._policy.leeway_seconds, UTC
        )
        disposition: CredentialUseDisposition | None = None
        store_failed = False
        try:
            disposition = await self._use_store.consume_once(
                issuer=issuer,
                kid=kid,
                subject=subject,
                jti=jti,
                credential_digest=digest,
                expires_at=effective_expires_at,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            store_failed = True
        if store_failed:
            raise AuthenticationError(AuthenticationFailure.INTERNAL_ERROR)
        assert disposition is not None
        if disposition is CredentialUseDisposition.REVOKED:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_REVOKED)
        if disposition is CredentialUseDisposition.REPLAYED:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_REPLAYED)
        if disposition is CredentialUseDisposition.CAPACITY_EXCEEDED:
            raise AuthenticationError(AuthenticationFailure.INTERNAL_ERROR)
        if disposition is CredentialUseDisposition.CLOCK_ROLLBACK:
            raise AuthenticationError(AuthenticationFailure.INTERNAL_ERROR)
        if disposition is CredentialUseDisposition.EXPIRED:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_EXPIRED)
        if disposition is not CredentialUseDisposition.ACCEPTED:
            raise AuthenticationError(AuthenticationFailure.INTERNAL_ERROR)

        effective_issued_at = min(issued_at, now)
        effective_not_before = max(effective_issued_at, min(not_before, now))
        return AuthenticatedAgentPrincipal(
            agent_id=subject,
            method=_METHOD,
            authority=issuer,
            credential_digest=digest,
            issued_at=effective_issued_at,
            not_before=effective_not_before,
            authenticated_at=now,
            expires_at=effective_expires_at,
        )

    async def _verify_bounded(
        self,
        token: bytes,
        jwk: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Hold one crypto slot until its worker drains, even under cancellation."""

        async with self._crypto_slots:
            task = asyncio.create_task(asyncio.to_thread(self._verify, token, jwk))
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
                    task.exception()
                raise asyncio.CancelledError
            return task.result()

    def _credential_bytes(self, credential: object) -> bytes:
        if isinstance(credential, str):
            encoding_failed = False
            try:
                token = credential.encode("ascii")
            except UnicodeEncodeError:
                encoding_failed = True
                token = b""
            if encoding_failed:
                raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        elif isinstance(credential, bytes):
            token = credential
        else:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        if not token or len(token) > self._policy.max_token_bytes:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        return token

    def _parse_compact(self, token: bytes) -> tuple[Mapping[str, object], Mapping[str, object]]:
        parts = token.split(b".")
        if len(parts) != 3 or any(not part for part in parts):
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        header: Mapping[str, object] | None = None
        claims: Mapping[str, object] | None = None
        parsing_failed = False
        try:
            header = _decode_json_object(parts[0])
            claims = _decode_json_object(parts[1])
            _decode_base64url(parts[2])
        except (ValueError, UnicodeError, json.JSONDecodeError, binascii.Error):
            parsing_failed = True
        if parsing_failed:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        assert header is not None
        assert claims is not None
        return header, claims

    def _validate_header(self, header: Mapping[str, object]) -> str:
        if _FORBIDDEN_HEADERS.intersection(header):
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        if header.get("alg") != "RS256" or header.get("typ") not in self._policy.accepted_typ:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        try:
            return _canonical_text(header.get("kid"), max_length=256)
        except ValueError:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID) from None

    def _validate_claim_shape(self, claims: Mapping[str, object]) -> None:
        try:
            if _canonical_text(claims.get("iss")) != self._policy.issuer:
                raise ValueError
            if _canonical_text(claims.get("aud")) != self._policy.audience:
                raise ValueError
            _canonical_text(claims.get("sub"), max_length=256)
            _canonical_text(claims.get("jti"), max_length=512)
            for name in ("iat", "nbf", "exp"):
                _numeric_date(claims.get(name))
        except ValueError:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID) from None

    def _select_and_validate_jwk(
        self, snapshot: JwtKeySetSnapshot, kid: str
    ) -> Mapping[str, object]:
        matches = [jwk for jwk in snapshot.keys if jwk.get("kid") == kid]
        if len(matches) != 1:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        jwk = matches[0]
        if (
            jwk.get("kty") != "RSA"
            or jwk.get("use") != "sig"
            or jwk.get("alg") != "RS256"
            or jwk.get("kid") != kid
            or _PRIVATE_JWK_MEMBERS.intersection(jwk)
            or ("key_ops" in jwk and jwk.get("key_ops") != ("verify",))
        ):
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        try:
            modulus = int.from_bytes(_decode_base64url(_canonical_text(jwk.get("n"))), "big")
            exponent = int.from_bytes(_decode_base64url(_canonical_text(jwk.get("e"))), "big")
        except (ValueError, binascii.Error):
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID) from None
        if modulus.bit_length() < self._policy.min_rsa_bits or exponent < 3 or exponent % 2 == 0:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        return jwk

    def _verify(self, token: bytes, jwk: Mapping[str, object]) -> Mapping[str, object]:
        jwt = _load_pyjwt()
        key = jwt.PyJWK.from_dict(dict(jwk)).key
        result = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            issuer=self._policy.issuer,
            audience=self._policy.audience,
            options={
                "require": ["iss", "aud", "sub", "iat", "nbf", "exp", "jti"],
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
                "verify_sub": True,
                "verify_jti": True,
                "strict_aud": True,
            },
        )
        if not isinstance(result, dict):
            raise ValueError("JWT payload must be an object")
        return cast("dict[str, object]", result)

    def _validated_claims(
        self, claims: Mapping[str, object], now: datetime
    ) -> tuple[str, str, str, datetime, datetime, datetime]:
        try:
            issuer = _canonical_text(claims.get("iss"))
            audience = _canonical_text(claims.get("aud"))
            subject = _canonical_text(claims.get("sub"), max_length=256)
            jti = _canonical_text(claims.get("jti"), max_length=512)
            iat_value = _numeric_date(claims.get("iat"))
            nbf_value = _numeric_date(claims.get("nbf"))
            exp_value = _numeric_date(claims.get("exp"))
            issued_at = datetime.fromtimestamp(iat_value, UTC)
            not_before = datetime.fromtimestamp(nbf_value, UTC)
            expires_at = datetime.fromtimestamp(exp_value, UTC)
        except (ValueError, OverflowError, OSError):
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID) from None
        if issuer != self._policy.issuer or audience != self._policy.audience:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        if not issued_at <= not_before < expires_at:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        if exp_value - iat_value > self._policy.max_lifetime_seconds:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_INVALID)
        leeway = self._policy.leeway_seconds
        if iat_value > now.timestamp() + leeway or nbf_value > now.timestamp() + leeway:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_NOT_YET_VALID)
        if exp_value <= now.timestamp() - leeway:
            raise AuthenticationError(AuthenticationFailure.CREDENTIAL_EXPIRED)
        return issuer, subject, jti, issued_at, not_before, expires_at

    def _now(self) -> datetime:
        return _aware_utc(self._clock())


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(UTC)


def _numeric_date(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("integer numeric date required")
    return value


def _credential_digest(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("credential_digest must be a lowercase SHA-256 digest")
    return value


def _decode_base64url(value: str | bytes) -> bytes:
    encoded = value.encode("ascii") if isinstance(value, str) else value
    if not encoded or b"=" in encoded:
        raise ValueError("base64url value must be unpadded and nonempty")
    if any(
        byte not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for byte in encoded
    ):
        raise ValueError("invalid base64url alphabet")
    decoded = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    # Reject non-canonical encodings: the final character may carry non-zero
    # slack bits that decode to the same bytes, so one signature would have
    # multiple valid encodings — and since credential_digest = sha256(raw
    # token), one credential would yield multiple digests, defeating
    # digest-based revocation. Require the input to be the canonical encoding.
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=")
    if canonical != encoded:
        raise ValueError("base64url value is not canonically encoded")
    return decoded


def _decode_json_object(segment: bytes) -> Mapping[str, object]:
    raw = _decode_base64url(segment)

    def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicate,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON number")),
    )
    if not isinstance(value, dict):
        raise ValueError("JWT segment must contain a JSON object")
    return cast("dict[str, object]", value)


def _load_pyjwt() -> ModuleType:
    try:
        return importlib.import_module("jwt")
    except ImportError:
        raise AuthenticationError(AuthenticationFailure.INTERNAL_ERROR) from None


__all__ = [
    "CredentialUseStore",
    "CredentialUseDisposition",
    "InMemoryCredentialUseStore",
    "InMemoryJwtKeySetProvider",
    "JwtAgentAuthenticator",
    "JwtKeySetSnapshot",
    "JwtKeySetProvider",
    "JwtTrustPolicy",
]
