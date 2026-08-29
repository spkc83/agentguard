"""Strict declarative construction of built-in guardrail chains."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal, Protocol, cast

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    field_serializer,
    field_validator,
    model_validator,
)

from .chain import ChainMode, GuardrailChain
from .content import PiiEgressGuardrail, PiiInputGuardrail, SecretEgressGuardrail
from .contracts import Guardrail
from .normalization import _FrozenMapping, normalize_payload, thaw_payload

GuardrailFactory = Callable[[Mapping[str, object]], Guardrail]


def _canonical_id(value: str) -> str:
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError("guardrail id must be canonical printable text")
    return value


class _ConfigurableGuardrail(Guardrail, Protocol):
    timeout_ms: int
    config: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class GuardrailFactoryRegistration:
    """One explicit ID-to-factory binding accepted by declarative config."""

    guardrail_id: str
    factory: GuardrailFactory


class GuardrailRegistry:
    """Immutable allowlist of factories available to declarative configuration."""

    def __init__(self, registrations: Iterable[GuardrailFactoryRegistration]) -> None:
        factories: dict[str, GuardrailFactory] = {}
        for registration in registrations:
            guardrail_id = _canonical_id(registration.guardrail_id)
            if guardrail_id in factories:
                raise ValueError(f"duplicate guardrail registry id: {guardrail_id}")
            if not callable(registration.factory):
                raise TypeError(f"guardrail factory {guardrail_id!r} must be callable")
            factories[guardrail_id] = registration.factory
        self._factories = MappingProxyType(factories)

    @property
    def ids(self) -> tuple[str, ...]:
        """Return the registered IDs in stable lexical order."""

        return tuple(sorted(self._factories))

    def create(self, guardrail_id: str, config: Mapping[str, object]) -> Guardrail:
        """Construct one allowlisted guardrail and bind it to its registered ID."""

        factory = self._factories.get(guardrail_id)
        if factory is None:
            raise ValueError(f"unknown guardrail id: {guardrail_id}")
        expected_config = normalize_payload(config)
        if not isinstance(expected_config, _FrozenMapping):
            raise TypeError("guardrail config must be a mapping")
        factory_config = cast("Mapping[str, object]", thaw_payload(expected_config))
        guardrail = factory(factory_config)
        if not isinstance(guardrail, Guardrail):
            raise TypeError(f"guardrail factory {guardrail_id!r} returned an invalid guardrail")
        if guardrail.id != guardrail_id:
            raise ValueError(
                f"guardrail factory {guardrail_id!r} returned guardrail id {guardrail.id!r}"
            )
        actual_config = normalize_payload(getattr(guardrail, "config", {}))
        if actual_config != expected_config:
            raise ValueError(f"guardrail factory {guardrail_id!r} did not preserve its config")
        return guardrail


class _StatelessBuiltinConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    timeout_ms: Annotated[StrictInt, Field(gt=0)] | None = None


class GuardrailEntryConfig(BaseModel):
    """One ordered declarative guardrail entry."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    id: str
    config: _FrozenMapping

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        return _canonical_id(value)

    @field_validator("config", mode="before")
    @classmethod
    def _freeze_config(cls, value: object) -> _FrozenMapping:
        normalized = normalize_payload(value)
        if not isinstance(normalized, _FrozenMapping):
            raise TypeError("guardrail config must be a mapping")
        return normalized

    @field_serializer("config", when_used="json")
    def _serialize_config(self, value: _FrozenMapping) -> object:
        return thaw_payload(value)


class GuardrailChainConfig(BaseModel):
    """Versioned, strict ``guardrails.yaml`` schema."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1]
    mode: ChainMode
    timeout_ms: Annotated[StrictInt, Field(gt=0)]
    guardrails: tuple[GuardrailEntryConfig, ...]

    @field_validator("schema_version", mode="before")
    @classmethod
    def _validate_schema_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be integer 1")
        return value

    @model_validator(mode="after")
    def _reject_duplicate_ids(self) -> GuardrailChainConfig:
        seen: set[str] = set()
        for entry in self.guardrails:
            if entry.id in seen:
                raise ValueError(f"duplicate guardrail id: {entry.id}")
            seen.add(entry.id)
        return self

    @classmethod
    def from_yaml(cls, text: str) -> GuardrailChainConfig:
        """Parse strict YAML text without accepting duplicate mapping keys."""

        data = yaml.load(text, Loader=_UniqueKeySafeLoader)  # noqa: S506
        if not isinstance(data, Mapping):
            raise TypeError("guardrails YAML root must be a mapping")
        return cls.model_validate(data)

    @classmethod
    def from_chain(cls, chain: GuardrailChain) -> GuardrailChainConfig:
        """Project a chain's declarative fields into the versioned schema."""

        descriptor = chain.descriptor
        return cls.model_validate(
            {
                "schema_version": 1,
                "mode": descriptor.mode,
                "timeout_ms": descriptor.timeout_ms,
                "guardrails": [
                    {
                        "id": guardrail.guardrail_id,
                        "config": thaw_payload(guardrail.config),
                    }
                    for guardrail in descriptor.guardrails
                ],
            }
        )

    def to_yaml(self) -> str:
        """Serialize deterministically using only safe YAML primitives."""

        return yaml.safe_dump(
            self.model_dump(mode="json"),
            allow_unicode=True,
            sort_keys=False,
        )

    def build_chain(
        self,
        *,
        registry: GuardrailRegistry | None = None,
    ) -> GuardrailChain:
        """Resolve this config through an explicit registry and build a chain."""

        selected_registry = BUILTIN_GUARDRAIL_REGISTRY if registry is None else registry
        guardrails = [
            selected_registry.create(
                entry.id,
                cast("Mapping[str, object]", thaw_payload(entry.config)),
            )
            for entry in self.guardrails
        ]
        return GuardrailChain(guardrails, mode=self.mode, timeout_ms=self.timeout_ms)


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _stateless_factory(constructor: Callable[[], Guardrail]) -> GuardrailFactory:
    def build(config: Mapping[str, object]) -> Guardrail:
        parsed = _StatelessBuiltinConfig.model_validate(config)
        guardrail = cast("_ConfigurableGuardrail", constructor())
        guardrail.config = parsed.model_dump(exclude_none=True)
        if parsed.timeout_ms is not None:
            guardrail.timeout_ms = parsed.timeout_ms
        return guardrail

    return build


BUILTIN_GUARDRAIL_REGISTRY = GuardrailRegistry(
    [
        # OutputSchemaGuardrail deliberately stays code-only because its validator is a
        # trusted callable or model type, neither of which may be resolved from YAML.
        GuardrailFactoryRegistration("pii-input", _stateless_factory(PiiInputGuardrail)),
        GuardrailFactoryRegistration("pii-egress", _stateless_factory(PiiEgressGuardrail)),
        GuardrailFactoryRegistration("secret-egress", _stateless_factory(SecretEgressGuardrail)),
    ]
)


def load_guardrail_config(path: str | Path) -> GuardrailChainConfig:
    """Load and validate a ``guardrails.yaml`` file."""

    return GuardrailChainConfig.from_yaml(Path(path).read_text(encoding="utf-8"))


def dump_guardrail_config(config: GuardrailChainConfig, path: str | Path) -> None:
    """Write a validated config as deterministic safe YAML."""

    Path(path).write_text(config.to_yaml(), encoding="utf-8")


__all__ = [
    "BUILTIN_GUARDRAIL_REGISTRY",
    "GuardrailChainConfig",
    "GuardrailEntryConfig",
    "GuardrailFactory",
    "GuardrailFactoryRegistration",
    "GuardrailRegistry",
    "dump_guardrail_config",
    "load_guardrail_config",
]
