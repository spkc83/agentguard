"""Bounded, canonical, recursively immutable JSON payload values."""

from __future__ import annotations

import json
import math
import unicodedata
from collections.abc import Iterator, Mapping
from types import MappingProxyType
from typing import Any, TypeAlias, Union

from pydantic import BaseModel, GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

MAX_PAYLOAD_DEPTH = 20
MAX_PAYLOAD_ITEMS = 10_000
MAX_CANONICAL_BYTES = 1024 * 1024

JsonPrimitive: TypeAlias = str | int | float | bool | None
FrozenValue: TypeAlias = Union[JsonPrimitive, "_FrozenMapping", tuple["FrozenValue", ...]]


class _FrozenMapping(Mapping[str, FrozenValue]):
    """Private-copy mapping used inside public frozen guardrail contracts."""

    __slots__ = ("__data",)

    def __init__(self, values: Mapping[str, FrozenValue]) -> None:
        self.__data = MappingProxyType(dict(values))

    def __getitem__(self, key: str) -> FrozenValue:
        return self.__data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.__data)

    def __len__(self) -> int:
        return len(self.__data)

    def __copy__(self) -> _FrozenMapping:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> _FrozenMapping:
        memo[id(self)] = self
        return self

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        _source_type: Any,
        _handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        serializer = core_schema.plain_serializer_function_ser_schema(
            thaw_payload,
            when_used="json",
        )
        return core_schema.is_instance_schema(cls, serialization=serializer)


class _Budget:
    __slots__ = ("items",)

    def __init__(self) -> None:
        self.items = 0

    def add(self, count: int) -> None:
        self.items += count
        if self.items > MAX_PAYLOAD_ITEMS:
            raise ValueError(f"payload exceeds maximum items ({MAX_PAYLOAD_ITEMS})")


def normalize_payload(value: object) -> FrozenValue:
    """Copy and freeze a finite JSON value while enforcing resource bounds."""

    budget = _Budget()
    normalized = _normalize(value, depth=0, active=set(), budget=budget)
    encoded = _encode(normalized)
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ValueError(f"payload exceeds maximum canonical bytes ({MAX_CANONICAL_BYTES})")
    return normalized


def canonical_json_bytes(value: object) -> bytes:
    """Return deterministic UTF-8 JSON bytes after full payload validation."""

    return _encode(normalize_payload(value))


def thaw_payload(value: FrozenValue) -> object:
    """Create a fresh, recursively mutable executor-facing payload copy."""

    if isinstance(value, _FrozenMapping):
        return {key: thaw_payload(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_payload(item) for item in value]
    return value


def _normalize(value: object, *, depth: int, active: set[int], budget: _Budget) -> FrozenValue:
    if depth > MAX_PAYLOAD_DEPTH:
        raise ValueError(f"payload exceeds maximum depth ({MAX_PAYLOAD_DEPTH})")
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("payload numbers must be finite")
        return value
    if isinstance(value, BaseModel):
        try:
            value = value.model_dump(mode="json")
        except ValueError as exc:
            raise ValueError("payload contains a cycle") from exc
    if isinstance(value, Mapping):
        marker = id(value)
        if marker in active:
            raise ValueError("payload contains a cycle")
        active.add(marker)
        try:
            budget.add(len(value))
            result: dict[str, FrozenValue] = {}
            for raw_key, item in value.items():
                if not isinstance(raw_key, str):
                    raise TypeError("payload mapping keys must be strings")
                key = unicodedata.normalize("NFKC", raw_key)
                if key in result:
                    raise ValueError("payload key normalization collision")
                result[key] = _normalize(
                    item,
                    depth=depth + 1,
                    active=active,
                    budget=budget,
                )
            return _FrozenMapping(result)
        finally:
            active.remove(marker)
    if isinstance(value, list | tuple):
        marker = id(value)
        if marker in active:
            raise ValueError("payload contains a cycle")
        active.add(marker)
        try:
            budget.add(len(value))
            return tuple(
                _normalize(item, depth=depth + 1, active=active, budget=budget) for item in value
            )
        finally:
            active.remove(marker)
    raise TypeError(f"payload value of type {type(value).__name__} is not JSON-compatible")


def _encode(value: FrozenValue) -> bytes:
    return json.dumps(
        thaw_payload(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
