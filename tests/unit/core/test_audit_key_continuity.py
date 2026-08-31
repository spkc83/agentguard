"""Restart continuity for rotated audit signing epochs."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003 -- pytest resolves fixture annotations at runtime

import pytest

from agentguard.core.audit import (
    AppendOnlyAuditLog,
    AuditKeyEpoch,
    AuditKeyring,
    FileAuditBackend,
)
from agentguard.core.audit_collector import AuditCollectorServer, SigningAuditBackend
from agentguard.exceptions import (
    AuditCollectorOwnershipError,
    AuditError,
    AuditKeyEnvironmentError,
    AuditKeyRotationRefusedError,
    AuditKeyUnavailableError,
    AuditKeyWeakError,
)
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext

_PRIMARY = "continuity-primary-key-0123456789abcdef"
_SECOND = "continuity-second-key-0123456789abcdef0"
_SECOND_ID = "epoch-2"


def _event(event_id: str) -> AuditEvent:
    identity = AgentIdentity(agent_id="continuity-client", name="Continuity client", roles=[])
    permission = PermissionContext(
        agent=identity,
        requested_action="tool:test",
        resource="resource",
        granted=True,
    )
    return AuditEvent(
        event_id=event_id,
        timestamp=datetime(2026, 8, 28, tzinfo=UTC),
        agent_id=identity.agent_id,
        action="tool:test",
        resource="resource",
        permission_context=permission,
        result="allowed",
        duration_ms=1.0,
        trace_id=f"trace-{event_id}",
    )


def _primary_id() -> str:
    return hashlib.sha256(_PRIMARY.encode()).hexdigest()[:16]


def _cert(
    key_id: str,
    key: str,
    activation: int,
    *,
    predecessor_id: str | None = None,
    predecessor_key: str = _PRIMARY,
) -> str:
    return AuditKeyring._epoch_activation_certificate(
        predecessor_key=predecessor_key.encode(),
        predecessor_key_id=predecessor_id or _primary_id(),
        key_id=key_id,
        key=key.encode(),
        activation_sequence=activation,
    )


def _entry(
    activation: int,
    *,
    key: str = _SECOND,
    key_id: str = _SECOND_ID,
    primary_key_id: str | None = None,
    certificate: str | None = None,
) -> dict[str, object]:
    return {
        "key": key,
        "activation_sequence": activation,
        "activation_certificate": certificate
        or _cert(key_id, key, activation, predecessor_id=primary_key_id),
    }


def _declare(
    activation: int,
    *,
    key: str = _SECOND,
    key_id: str = _SECOND_ID,
    primary_key_id: str | None = None,
    certificate: str | None = None,
) -> str:
    return json.dumps(
        {
            key_id: _entry(
                activation,
                key=key,
                key_id=key_id,
                primary_key_id=primary_key_id,
                certificate=certificate,
            )
        }
    )


def _injected_keyring(key: bytes, *, key_id: str = "injected-legacy") -> AuditKeyring:
    return AuditKeyring(
        keys={key_id: key},
        epochs=(
            AuditKeyEpoch(
                key_id=key_id,
                activation_sequence=1,
                key_fingerprint=hashlib.sha256(key).hexdigest(),
            ),
        ),
        legacy_key_id=key_id,
    )


def test_environment_keyring_declares_additional_epochs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY_ID", "epoch-1")
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(7, primary_key_id="epoch-1"))

    keyring = AuditKeyring.from_environment()

    assert keyring.environment_sourced is True
    assert [(epoch.key_id, epoch.activation_sequence) for epoch in keyring.epochs] == [
        ("epoch-1", 1),
        (_SECOND_ID, 7),
    ]
    assert keyring.legacy_key_id == "epoch-1"


def test_environment_keyring_orders_declared_epochs_by_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY_ID", "epoch-1")
    monkeypatch.setenv(
        "AGENTGUARD_AUDIT_KEYS",
        json.dumps(
            {
                "epoch-late": {
                    "key": _SECOND,
                    "activation_sequence": 9,
                    "activation_certificate": _cert(
                        "epoch-late",
                        _SECOND,
                        9,
                        predecessor_id="epoch-early",
                        predecessor_key=_SECOND + "x",
                    ),
                },
                "epoch-early": _entry(
                    4, key=_SECOND + "x", key_id="epoch-early", primary_key_id="epoch-1"
                ),
            }
        ),
    )

    keyring = AuditKeyring.from_environment()

    assert [epoch.activation_sequence for epoch in keyring.epochs] == [1, 4, 9]


def test_absent_audit_keys_variable_keeps_the_single_legacy_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.delenv("AGENTGUARD_AUDIT_KEYS", raising=False)

    keyring = AuditKeyring.from_environment()

    assert len(keyring.epochs) == 1
    assert keyring.epochs[0].activation_sequence == 1


def test_weak_declared_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2, key="too-short"))

    with pytest.raises(AuditKeyWeakError):
        AuditKeyring.from_environment()


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("{not json", "not valid JSON"),
        ('["epoch-2"]', "JSON object"),
        (json.dumps({_SECOND_ID: {"key": _SECOND}}), "exactly"),
        (
            json.dumps({_SECOND_ID: {"key": _SECOND, "activation_sequence": 2, "extra": 1}}),
            "exactly",
        ),
        (
            json.dumps(
                {_SECOND_ID: {"key": 7, "activation_sequence": 2, "activation_certificate": "x"}}
            ),
            "non-string key",
        ),
        (
            json.dumps(
                {
                    _SECOND_ID: {
                        "key": _SECOND,
                        "activation_sequence": "2",
                        "activation_certificate": "x",
                    }
                }
            ),
            "non-integer",
        ),
        (
            json.dumps(
                {
                    _SECOND_ID: {
                        "key": _SECOND,
                        "activation_sequence": True,
                        "activation_certificate": "x",
                    }
                }
            ),
            "non-integer",
        ),
        (
            json.dumps(
                {
                    _SECOND_ID: {
                        "key": _SECOND,
                        "activation_sequence": 0,
                        "activation_certificate": "x",
                    }
                }
            ),
            "non-positive",
        ),
        (
            json.dumps(
                {
                    _SECOND_ID: {
                        "key": _SECOND,
                        "activation_sequence": 1,
                        "activation_certificate": "x",
                    }
                }
            ),
            "reuses activation_sequence",
        ),
        (
            json.dumps(
                {
                    "epoch-a": {
                        "key": _SECOND,
                        "activation_sequence": 5,
                        "activation_certificate": "0" * 64,
                    },
                    "epoch-b": {
                        "key": _SECOND + "x",
                        "activation_sequence": 5,
                        "activation_certificate": "0" * 64,
                    },
                }
            ),
            "reuses activation_sequence",
        ),
        (
            json.dumps(
                {
                    "epoch-1": {
                        "key": _SECOND,
                        "activation_sequence": 2,
                        "activation_certificate": "x",
                    }
                }
            ),
            "primary key",
        ),
        (
            json.dumps(
                {
                    _SECOND_ID: {
                        "key": _SECOND,
                        "activation_sequence": 2,
                        "activation_certificate": "",
                    }
                }
            ),
            "non-string activation_certificate",
        ),
        (
            json.dumps(
                {
                    _SECOND_ID: {
                        "key": _SECOND,
                        "activation_sequence": 2,
                        "activation_certificate": "é" * 64,
                    }
                }
            ),
            "malformed activation_certificate",
        ),
        (
            json.dumps(
                {
                    _SECOND_ID: {
                        "key": _SECOND,
                        "activation_sequence": 2,
                        "activation_certificate": "AB" * 32,
                    }
                }
            ),
            "malformed activation_certificate",
        ),
        (
            json.dumps(
                {
                    _SECOND_ID: {
                        "key": _SECOND,
                        "activation_sequence": 2,
                        "activation_certificate": "ab" * 30,
                    }
                }
            ),
            "malformed activation_certificate",
        ),
    ],
)
def test_malformed_audit_keys_environment_is_refused(
    monkeypatch: pytest.MonkeyPatch, raw: str, reason: str
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY_ID", "epoch-1")
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", raw)

    with pytest.raises(AuditKeyEnvironmentError, match=reason):
        AuditKeyring.from_environment()


def test_environment_failure_never_discloses_key_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.setenv(
        "AGENTGUARD_AUDIT_KEYS",
        json.dumps(
            {
                _SECOND_ID: {
                    "key": _SECOND,
                    "activation_sequence": 0,
                    "activation_certificate": "x",
                }
            }
        ),
    )

    with pytest.raises(AuditKeyEnvironmentError) as failure:
        AuditKeyring.from_environment()
    assert _SECOND not in str(failure.value)
    assert _SECOND[:8] not in str(failure.value)


async def test_declared_epoch_verifies_pre_and_post_rotation_events_across_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2))
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"

    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    await server.start()
    try:
        client = SigningAuditBackend(socket_path)
        before = await client.write(_event("evt-before-rotation"))
        epoch = await server.rotate_key(_SECOND_ID, _SECOND.encode())
        after = await client.write(_event("evt-after-rotation"))
    finally:
        await server.close()

    assert epoch.key_id == _SECOND_ID
    assert epoch.activation_sequence == 2
    assert before.key_id != after.key_id
    assert after.key_id == _SECOND_ID

    # Simulated restart: only the environment reconstructs the keyring.
    restarted = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    await restarted.start()
    try:
        snapshot = await SigningAuditBackend(socket_path).read_verified(require_checkpoint=True)
    finally:
        await restarted.close()

    assert snapshot.events == (before, after)
    assert snapshot.verification.valid is True


async def test_restart_without_the_declared_epoch_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2))
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"

    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    await server.start()
    try:
        client = SigningAuditBackend(socket_path)
        await client.write(_event("evt-lost-1"))
        await server.rotate_key(_SECOND_ID, _SECOND.encode())
        await client.write(_event("evt-lost-2"))
    finally:
        await server.close()

    monkeypatch.delenv("AGENTGUARD_AUDIT_KEYS")
    stranded = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    with pytest.raises(AuditKeyUnavailableError):
        await stranded.start()


async def test_rotation_to_an_undeclared_epoch_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.delenv("AGENTGUARD_AUDIT_KEYS", raising=False)
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
        state_path=tmp_path / "anchor" / "state.json",
    )
    await server.start()
    try:
        await SigningAuditBackend(socket_path).write(_event("evt-undeclared"))
        with pytest.raises(AuditKeyRotationRefusedError) as failure:
            await server.rotate_key(_SECOND_ID, _SECOND.encode())
    finally:
        await server.close()

    assert "AGENTGUARD_AUDIT_KEYS" in str(failure.value)
    assert _SECOND not in str(failure.value)


async def test_rotation_with_key_bytes_that_contradict_the_declaration_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2))
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(tmp_path / "audit")),
        state_path=tmp_path / "anchor" / "state.json",
    )
    await server.start()
    try:
        with pytest.raises(AuditKeyRotationRefusedError):
            await server.rotate_key(_SECOND_ID, b"a-different-key-0123456789abcdef01")
    finally:
        await server.close()


async def test_restart_commits_a_newly_declared_future_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.delenv("AGENTGUARD_AUDIT_KEYS", raising=False)
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"

    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    await server.start()
    try:
        await SigningAuditBackend(socket_path).write(_event("evt-pre-declaration"))
    finally:
        await server.close()

    # The operator declares the next epoch and restarts. Committing an
    # unauthenticated declaration into signed state is a deliberate act.
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2))
    unadopted = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    with pytest.raises(AuditCollectorOwnershipError, match="explicit adoption required"):
        await unadopted.start()

    restarted = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        adopt_declared_epochs=True,
    )
    await restarted.start()
    try:
        assert restarted._state is not None
        assert [epoch.key_id for epoch in restarted._state.key_epochs][-1] == _SECOND_ID
        rotated = await SigningAuditBackend(socket_path).write(_event("evt-post-declaration"))
    finally:
        await restarted.close()

    assert rotated.key_id == _SECOND_ID


async def test_restart_refuses_a_declared_epoch_that_rewrites_committed_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.delenv("AGENTGUARD_AUDIT_KEYS", raising=False)
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"

    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    await server.start()
    try:
        client = SigningAuditBackend(socket_path)
        for index in range(3):
            await client.write(_event(f"evt-committed-{index}"))
    finally:
        await server.close()

    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2))
    replacement = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        adopt_declared_epochs=True,
    )
    with pytest.raises(AuditError):
        await replacement.start()


async def test_restart_refuses_a_rebound_declared_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(5))
    audit_directory = tmp_path / "audit"
    state_path = tmp_path / "anchor" / "state.json"
    socket_path = tmp_path / "run" / "collector.sock"

    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
    )
    await server.start()
    try:
        await SigningAuditBackend(socket_path).write(_event("evt-rebind"))
    finally:
        await server.close()

    # Same epoch ID, different activation: not an extension of committed state.
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(6))
    replacement = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(FileAuditBackend(audit_directory)),
        state_path=state_path,
        adopt_declared_epochs=True,
    )
    with pytest.raises(AuditCollectorOwnershipError, match="differ from signed state"):
        await replacement.start()


async def test_caller_injected_keyring_rotates_without_an_environment_declaration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AGENTGUARD_AUDIT_KEY", raising=False)
    monkeypatch.delenv("AGENTGUARD_AUDIT_KEYS", raising=False)
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(
            FileAuditBackend(tmp_path / "audit"),
            keyring=_injected_keyring(_PRIMARY.encode()),
        ),
        state_path=tmp_path / "anchor" / "state.json",
    )
    await server.start()
    try:
        client = SigningAuditBackend(socket_path)
        before = await client.write(_event("evt-injected-before"))
        epoch = await server.rotate_key("injected-2", _SECOND.encode())
        after = await client.write(_event("evt-injected-after"))
    finally:
        await server.close()

    assert epoch.activation_sequence == 2
    assert before.key_id != after.key_id


async def test_caller_injected_rotation_state_write_failure_keeps_previous_key_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AGENTGUARD_AUDIT_KEY", raising=False)
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(
            FileAuditBackend(tmp_path / "audit"),
            keyring=_injected_keyring(_PRIMARY.encode()),
        ),
        state_path=tmp_path / "anchor" / "state.json",
    )
    await server.start()
    try:
        client = SigningAuditBackend(socket_path)
        before = await client.write(_event("evt-before-failed-rotation"))
        with monkeypatch.context() as patcher:
            patcher.setattr(
                server,
                "_write_state_sync",
                lambda _state: (_ for _ in ()).throw(OSError("state storage unavailable")),
            )
            with pytest.raises(OSError, match="state storage unavailable"):
                await server.rotate_key("uncommitted-key", _SECOND.encode())
        after = await client.write(_event("evt-after-failed-rotation"))
        snapshot = await client.read_verified(require_checkpoint=True)
    finally:
        await server.close()

    assert after.key_id == before.key_id
    assert snapshot.verification.valid is True


async def test_caller_injected_second_rotation_before_next_event_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AGENTGUARD_AUDIT_KEY", raising=False)
    socket_path = tmp_path / "run" / "collector.sock"
    server = AuditCollectorServer(
        socket_path=socket_path,
        audit_log=AppendOnlyAuditLog(
            FileAuditBackend(tmp_path / "audit"),
            keyring=_injected_keyring(_PRIMARY.encode()),
        ),
        state_path=tmp_path / "anchor" / "state.json",
    )
    await server.start()
    try:
        await SigningAuditBackend(socket_path).write(_event("evt-injected-pending"))
        await server.rotate_key("injected-first", _SECOND.encode())
        with pytest.raises(ValueError, match="strictly increase"):
            await server.rotate_key("injected-second", (_SECOND + "x").encode())
    finally:
        await server.close()


class TestActivationCertificates:
    """An epoch is trusted only with proof of authorization by its predecessor."""

    def test_env_write_alone_cannot_introduce_an_epoch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A declaration with a fabricated certificate is refused.

        This is the attack the certificate exists to stop: environment write
        access without any existing signing key must not mint a signing epoch.
        """
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        monkeypatch.setenv(
            "AGENTGUARD_AUDIT_KEYS",
            _declare(2, certificate="0" * 64),
        )
        with pytest.raises(AuditKeyEnvironmentError, match="does not verify under predecessor"):
            AuditKeyring.from_environment()

    def test_self_signed_certificate_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A certificate keyed by the NEW key itself proves nothing."""
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        forged = _cert(_SECOND_ID, _SECOND, 2, predecessor_key=_SECOND)
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2, certificate=forged))
        with pytest.raises(AuditKeyEnvironmentError, match="does not verify"):
            AuditKeyring.from_environment()

    def test_certificate_binds_the_activation_sequence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        wrong_activation = _cert(_SECOND_ID, _SECOND, 3)
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2, certificate=wrong_activation))
        with pytest.raises(AuditKeyEnvironmentError, match="does not verify"):
            AuditKeyring.from_environment()

    def test_certificate_binds_the_key_material(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A valid certificate cannot be reused for a substituted key."""
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        for_other_key = _cert(_SECOND_ID, _SECOND + "swap", 2)
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2, certificate=for_other_key))
        with pytest.raises(AuditKeyEnvironmentError, match="does not verify"):
            AuditKeyring.from_environment()

    def test_second_epoch_must_be_certified_by_the_first_not_the_primary(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The chain is sequential: skipping a link would let a stolen primary
        key mint epochs after the primary was rotated away."""
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        third = "continuity-third-key-0123456789abcdefgh"
        entries = {
            _SECOND_ID: _entry(2),
            "epoch-3": {
                "key": third,
                "activation_sequence": 5,
                # certified by the PRIMARY instead of epoch-2 — must be refused
                "activation_certificate": _cert("epoch-3", third, 5),
            },
        }
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", json.dumps(entries))
        with pytest.raises(AuditKeyEnvironmentError, match="does not verify"):
            AuditKeyring.from_environment()

    def test_a_full_certificate_chain_verifies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        third = "continuity-third-key-0123456789abcdefgh"
        entries = {
            _SECOND_ID: _entry(2),
            "epoch-3": {
                "key": third,
                "activation_sequence": 5,
                "activation_certificate": _cert(
                    "epoch-3", third, 5, predecessor_id=_SECOND_ID, predecessor_key=_SECOND
                ),
            },
        }
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", json.dumps(entries))
        keyring = AuditKeyring.from_environment()
        assert [epoch.activation_sequence for epoch in keyring.epochs] == [1, 2, 5]

    def test_certificate_failure_never_discloses_key_material(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2, certificate="f" * 64))
        with pytest.raises(AuditKeyEnvironmentError) as failure:
            AuditKeyring.from_environment()
        text = str(failure.value)
        assert _SECOND not in text
        assert _PRIMARY not in text
        assert _SECOND[:8] not in text

    def test_certificate_covers_the_fingerprint_not_the_key(self) -> None:
        """The certificate must not act as an oracle over new key material."""
        cert_a = _cert(_SECOND_ID, _SECOND, 2)
        cert_b = _cert(_SECOND_ID, _SECOND, 2)
        assert cert_a == cert_b  # deterministic
        assert _SECOND not in cert_a
        assert len(cert_a) == 64  # a single HMAC-SHA256, nothing else


class TestMintActivationCertificate:
    def _keyring(self, monkeypatch: pytest.MonkeyPatch) -> AuditKeyring:
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        monkeypatch.delenv("AGENTGUARD_AUDIT_KEYS", raising=False)
        return AuditKeyring.from_environment()

    def test_minted_certificate_round_trips_through_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        keyring = self._keyring(monkeypatch)
        certificate = keyring.mint_activation_certificate(
            key_id=_SECOND_ID, key=_SECOND.encode(), activation_sequence=2
        )
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2, certificate=certificate))
        rebuilt = AuditKeyring.from_environment()
        assert [epoch.key_id for epoch in rebuilt.epochs] == [keyring.legacy_key_id, _SECOND_ID]

    def test_minting_from_the_latest_epoch_chains_correctly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Certificates minted from a grown keyring bind to the LATEST epoch."""
        keyring = self._keyring(monkeypatch)
        cert2 = keyring.mint_activation_certificate(
            key_id=_SECOND_ID, key=_SECOND.encode(), activation_sequence=2
        )
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2, certificate=cert2))
        grown = AuditKeyring.from_environment()
        third = "continuity-third-key-0123456789abcdefgh"
        cert3 = grown.mint_activation_certificate(
            key_id="epoch-3", key=third.encode(), activation_sequence=7
        )
        entries = json.loads(_declare(2, certificate=cert2))
        entries["epoch-3"] = {
            "key": third,
            "activation_sequence": 7,
            "activation_certificate": cert3,
        }
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", json.dumps(entries))
        full = AuditKeyring.from_environment()
        assert [epoch.activation_sequence for epoch in full.epochs] == [1, 2, 7]

    def test_rebinding_an_existing_id_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        keyring = self._keyring(monkeypatch)
        with pytest.raises(ValueError, match="cannot be rebound"):
            keyring.mint_activation_certificate(
                key_id=keyring.legacy_key_id, key=_SECOND.encode(), activation_sequence=2
            )

    def test_non_monotonic_activation_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        keyring = self._keyring(monkeypatch)
        with pytest.raises(ValueError, match="strictly follow"):
            keyring.mint_activation_certificate(
                key_id=_SECOND_ID, key=_SECOND.encode(), activation_sequence=1
            )

    def test_weak_new_key_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        keyring = self._keyring(monkeypatch)
        with pytest.raises(AuditKeyWeakError):
            keyring.mint_activation_certificate(
                key_id=_SECOND_ID, key=b"short", activation_sequence=2
            )

    def test_empty_key_id_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        keyring = self._keyring(monkeypatch)
        with pytest.raises(ValueError, match="must not be empty"):
            keyring.mint_activation_certificate(
                key_id="", key=_SECOND.encode(), activation_sequence=2
            )


class TestMintCertificateCli:
    def test_cli_mints_an_entry_that_round_trips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from agentguard.cli import app

        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        monkeypatch.delenv("AGENTGUARD_AUDIT_KEYS", raising=False)
        monkeypatch.setenv("AGENTGUARD_NEW_AUDIT_KEY", _SECOND)
        result = CliRunner().invoke(
            app,
            [
                "audit",
                "mint-epoch-certificate",
                "--key-id",
                _SECOND_ID,
                "--activation-sequence",
                "2",
            ],
        )
        assert result.exit_code == 0, result.output
        entry = json.loads(result.output.strip())
        monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", json.dumps(entry))
        rebuilt = AuditKeyring.from_environment()
        assert rebuilt.epochs[-1].key_id == _SECOND_ID
        assert rebuilt.epochs[-1].activation_sequence == 2

    def test_cli_refuses_without_the_new_key_variable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from agentguard.cli import app

        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        monkeypatch.delenv("AGENTGUARD_AUDIT_KEYS", raising=False)
        monkeypatch.delenv("AGENTGUARD_NEW_AUDIT_KEY", raising=False)
        result = CliRunner().invoke(
            app,
            ["audit", "mint-epoch-certificate", "--key-id", "x", "--activation-sequence", "2"],
        )
        assert result.exit_code == 1
        assert "AGENTGUARD_NEW_AUDIT_KEY" in result.output

    def test_cli_refuses_a_weak_new_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from agentguard.cli import app

        monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
        monkeypatch.delenv("AGENTGUARD_AUDIT_KEYS", raising=False)
        monkeypatch.setenv("AGENTGUARD_NEW_AUDIT_KEY", "short")
        result = CliRunner().invoke(
            app,
            ["audit", "mint-epoch-certificate", "--key-id", "x", "--activation-sequence", "2"],
        )
        assert result.exit_code == 1
        assert "refused" in result.output.lower()


def test_non_ascii_certificate_is_a_clean_environment_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-ASCII certificate must be an AuditKeyEnvironmentError, not a TypeError.

    hmac.compare_digest raises TypeError on non-ASCII input; that would escape
    every ``except AuditError`` fail-closed handler. Reject the malformed
    certificate structurally before the comparison.
    """
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", _PRIMARY)
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEYS", _declare(2, certificate="é" * 64))
    with pytest.raises(AuditKeyEnvironmentError, match="malformed activation_certificate"):
        AuditKeyring.from_environment()
