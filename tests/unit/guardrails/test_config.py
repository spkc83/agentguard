from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from agentguard.guardrails import ChainMode, Guardrail, PiiEgressGuardrail, PiiInputGuardrail
from agentguard.guardrails.config import (
    BUILTIN_GUARDRAIL_REGISTRY,
    GuardrailChainConfig,
    GuardrailFactoryRegistration,
    GuardrailRegistry,
    dump_guardrail_config,
    load_guardrail_config,
)


def test_yaml_round_trip_preserves_mode_timeout_order_and_config(tmp_path: Path) -> None:
    source = tmp_path / "guardrails.yaml"
    source.write_text(
        """\
schema_version: 1
mode: shadow
timeout_ms: 750
guardrails:
  - id: pii-input
    config:
      timeout_ms: 125
  - id: pii-egress
    config: {}
""",
        encoding="utf-8",
    )

    config = load_guardrail_config(source)
    chain = config.build_chain()
    dumped = tmp_path / "round-trip.yaml"
    dump_guardrail_config(config, dumped)

    assert load_guardrail_config(dumped) == config
    assert config == GuardrailChainConfig.from_chain(chain)
    assert chain.mode is ChainMode.SHADOW
    assert chain.descriptor.timeout_ms == 750
    assert [item.guardrail_id for item in chain.descriptor.guardrails] == [
        "pii-input",
        "pii-egress",
    ]
    assert chain.descriptor.guardrails[0].timeout_ms == 125
    assert chain.descriptor.guardrails[0].config == {"timeout_ms": 125}
    assert chain.descriptor.guardrails[1].config == {}


def test_to_yaml_is_safe_loadable_and_deterministic() -> None:
    config = GuardrailChainConfig.model_validate(
        {
            "schema_version": 1,
            "mode": "enforce",
            "timeout_ms": 1000,
            "guardrails": [{"id": "secret-egress", "config": {}}],
        }
    )

    first = config.to_yaml()

    assert yaml.safe_load(first) == config.model_dump(mode="json")
    assert config.to_yaml() == first


@pytest.mark.parametrize("mode", list(ChainMode))
def test_all_chain_modes_survive_yaml_round_trip(mode: ChainMode) -> None:
    config = GuardrailChainConfig.model_validate(
        {
            "schema_version": 1,
            "mode": mode,
            "timeout_ms": 37,
            "guardrails": [],
        }
    )

    assert GuardrailChainConfig.from_yaml(config.to_yaml()) == config


@pytest.mark.parametrize(
    "payload",
    [
        {"schema_version": 1, "mode": "enforce", "timeout_ms": 0, "guardrails": []},
        {"schema_version": 1, "mode": "enforce", "timeout_ms": True, "guardrails": []},
        {"schema_version": 2, "mode": "enforce", "timeout_ms": 10, "guardrails": []},
        {"schema_version": 1, "mode": "invalid", "timeout_ms": 10, "guardrails": []},
        {
            "schema_version": 1,
            "mode": "enforce",
            "timeout_ms": 10,
            "guardrails": [],
            "class_path": "package.Guardrail",
        },
        {
            "schema_version": 1,
            "mode": "enforce",
            "timeout_ms": 10,
            "guardrails": [{"id": "pii-input", "config": {}, "enabled": True}],
        },
        {
            "schema_version": 1,
            "mode": "enforce",
            "timeout_ms": 10,
            "guardrails": [{"id": " pii-input", "config": {}}],
        },
    ],
)
def test_schema_rejects_invalid_or_ambiguous_fields(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        GuardrailChainConfig.model_validate(payload)


def test_schema_rejects_duplicate_guardrail_ids() -> None:
    with pytest.raises(ValidationError, match="duplicate guardrail id"):
        GuardrailChainConfig.model_validate(
            {
                "schema_version": 1,
                "mode": "enforce",
                "timeout_ms": 10,
                "guardrails": [
                    {"id": "pii-input", "config": {}},
                    {"id": "pii-input", "config": {}},
                ],
            }
        )


@pytest.mark.parametrize(
    "text",
    [
        "- not\n- a\n- mapping\n",
        "guardrails: [\n",
        "!!python/object:builtins.object {}\n",
        ("schema_version: 1\nmode: enforce\nmode: shadow\ntimeout_ms: 10\nguardrails: []\n"),
        (
            "schema_version: 1\nmode: enforce\ntimeout_ms: 10\nguardrails:\n"
            "  - id: pii-input\n    id: pii-egress\n    config: {}\n"
        ),
    ],
)
def test_yaml_loader_fails_closed_for_malformed_or_duplicate_mappings(
    tmp_path: Path,
    text: str,
) -> None:
    path = tmp_path / "guardrails.yaml"
    path.write_text(text, encoding="utf-8")

    with pytest.raises((TypeError, ValueError, yaml.YAMLError)):
        load_guardrail_config(path)


def test_build_chain_rejects_unknown_builtin_and_unknown_builtin_config() -> None:
    unknown = GuardrailChainConfig.model_validate(
        {
            "schema_version": 1,
            "mode": "enforce",
            "timeout_ms": 10,
            "guardrails": [{"id": "package.Guardrail", "config": {}}],
        }
    )
    invalid_config = GuardrailChainConfig.model_validate(
        {
            "schema_version": 1,
            "mode": "enforce",
            "timeout_ms": 10,
            "guardrails": [{"id": "pii-input", "config": {"threshold": 2}}],
        }
    )

    with pytest.raises(ValueError, match="unknown guardrail id"):
        unknown.build_chain()
    with pytest.raises(ValidationError, match="threshold"):
        invalid_config.build_chain()


@pytest.mark.parametrize("timeout_ms", [0, -1, True, 1.5])
def test_builtin_config_rejects_invalid_timeout(timeout_ms: object) -> None:
    config = GuardrailChainConfig.model_validate(
        {
            "schema_version": 1,
            "mode": "enforce",
            "timeout_ms": 10,
            "guardrails": [{"id": "pii-input", "config": {"timeout_ms": timeout_ms}}],
        }
    )

    with pytest.raises(ValidationError, match="timeout_ms"):
        config.build_chain()


def test_builtin_registry_is_explicit_and_excludes_callable_schema_validator() -> None:
    assert BUILTIN_GUARDRAIL_REGISTRY.ids == (
        "pii-egress",
        "pii-input",
        "secret-egress",
    )
    assert "output-schema" not in BUILTIN_GUARDRAIL_REGISTRY.ids


def test_registry_rejects_duplicate_and_mismatched_factory_entries() -> None:
    def pii_input(_config: Mapping[str, object]) -> Guardrail:
        return PiiInputGuardrail()

    with pytest.raises(ValueError, match="duplicate guardrail registry id"):
        GuardrailRegistry(
            [
                GuardrailFactoryRegistration("pii-input", pii_input),
                GuardrailFactoryRegistration("pii-input", pii_input),
            ]
        )

    mismatched = GuardrailRegistry(
        [GuardrailFactoryRegistration("pii-input", lambda _config: PiiEgressGuardrail())]
    )
    config = GuardrailChainConfig.model_validate(
        {
            "schema_version": 1,
            "mode": "enforce",
            "timeout_ms": 10,
            "guardrails": [{"id": "pii-input", "config": {}}],
        }
    )

    with pytest.raises(ValueError, match="returned guardrail id"):
        config.build_chain(registry=mismatched)


def test_registry_rejects_factory_that_drops_declared_config() -> None:
    registry = GuardrailRegistry(
        [GuardrailFactoryRegistration("pii-input", lambda _config: PiiInputGuardrail())]
    )
    config = GuardrailChainConfig.model_validate(
        {
            "schema_version": 1,
            "mode": "enforce",
            "timeout_ms": 10,
            "guardrails": [{"id": "pii-input", "config": {"custom": True}}],
        }
    )

    with pytest.raises(ValueError, match="did not preserve its config"):
        config.build_chain(registry=registry)
