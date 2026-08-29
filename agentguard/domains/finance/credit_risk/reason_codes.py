"""Versioned ECOA reason and FCRA score-factor vocabularies.

The bundled IDs are AgentGuard-local identifiers for wording derived from
Regulation B Appendix C. They are not government-issued reason codes, and a
deployer must explicitly bind its model's transformed features to them.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, TypeVar

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from agentguard.domains.finance.credit_risk.attribution import (
    AdverseContribution,
    AttributionMethod,
    AttributionResult,
)
from agentguard.exceptions import AdverseActionError, AdverseActionFailure

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

_CODE_PATTERN = re.compile(r"^[A-Z0-9]+(?:[._-][A-Z0-9]+)+$")
_APPENDIX_C_REFERENCE = "12 CFR pt. 1002, app. C, Form C-1"

# Appendix C supplies illustrative wording, not a closed mandatory taxonomy.
# These identifiers are intentionally local to AgentGuard.
_APPENDIX_C_REASON_TEXT: tuple[tuple[str, str], ...] = (
    ("AG-RB-C1-01", "Credit application incomplete"),
    ("AG-RB-C1-02", "Insufficient number of credit references provided"),
    ("AG-RB-C1-03", "Unacceptable type of credit references provided"),
    ("AG-RB-C1-04", "Unable to verify credit references"),
    ("AG-RB-C1-05", "Temporary or irregular employment"),
    ("AG-RB-C1-06", "Unable to verify employment"),
    ("AG-RB-C1-07", "Length of employment"),
    ("AG-RB-C1-08", "Income insufficient for amount of credit requested"),
    ("AG-RB-C1-09", "Excessive obligations in relation to income"),
    ("AG-RB-C1-10", "Unable to verify income"),
    ("AG-RB-C1-11", "Length of residence"),
    ("AG-RB-C1-12", "Temporary residence"),
    ("AG-RB-C1-13", "Unable to verify residence"),
    ("AG-RB-C1-14", "No credit file"),
    ("AG-RB-C1-15", "Limited credit experience"),
    ("AG-RB-C1-16", "Poor credit performance with us"),
    ("AG-RB-C1-17", "Delinquent past or present credit obligations with others"),
    ("AG-RB-C1-18", "Collection action or judgment"),
    ("AG-RB-C1-19", "Garnishment or attachment"),
    ("AG-RB-C1-20", "Foreclosure or repossession"),
    ("AG-RB-C1-21", "Bankruptcy"),
    ("AG-RB-C1-22", "Number of recent inquiries on credit bureau report"),
    ("AG-RB-C1-23", "Value or type of collateral not sufficient"),
)


def _canonical_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError(f"{field_name} must be canonical nonempty printable text")
    return value


def _canonical_code(value: object) -> str:
    code = _canonical_text(value, field_name="code")
    if _CODE_PATTERN.fullmatch(code) is None:
        raise ValueError("code must be an uppercase stable local identifier")
    return code


class ReasonCode(BaseModel):
    """One versioned ECOA principal-reason code."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str
    code_set_version: str
    consumer_text: str
    reg_b_ref: str

    _validate_code = field_validator("code", mode="before")(_canonical_code)

    @field_validator("code_set_version", "consumer_text", "reg_b_ref", mode="before")
    @classmethod
    def _validate_text(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))


class BureauFactorCode(BaseModel):
    """A deployer-supplied FCRA credit-score key-factor code."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str
    code_set_version: str
    consumer_text: str
    fcra_ref: str
    inquiry_related: bool = False

    _validate_code = field_validator("code", mode="before")(_canonical_code)

    @field_validator("code_set_version", "consumer_text", "fcra_ref", mode="before")
    @classmethod
    def _validate_text(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))

    @field_validator("inquiry_related", mode="before")
    @classmethod
    def _validate_inquiry_marker(cls, value: object) -> bool:
        if not isinstance(value, bool):
            raise TypeError("inquiry_related must be a boolean")
        return value


CodeT = TypeVar("CodeT", ReasonCode, BureauFactorCode)


def _index_codes(
    codes: Iterable[CodeT],
    *,
    expected_type: type[CodeT],
    expected_version: str,
) -> dict[str, CodeT]:
    indexed: dict[str, CodeT] = {}
    for code in codes:
        if (
            not isinstance(code, expected_type)
            or code.code_set_version != expected_version
            or code.code in indexed
        ):
            raise AdverseActionError(AdverseActionFailure.TAXONOMY_MISMATCH)
        indexed[code.code] = code
    return indexed


def _bind_features(
    bindings: Mapping[str, str],
    codes: Mapping[str, object],
) -> Mapping[str, str]:
    copied: dict[str, str] = {}
    canonical_seen: set[str] = set()
    for raw_feature, raw_code in bindings.items():
        feature = _canonical_text(raw_feature, field_name="feature_name")
        canonical = feature.strip()
        if canonical in canonical_seen:
            raise AdverseActionError(AdverseActionFailure.TAXONOMY_MISMATCH)
        canonical_seen.add(canonical)
        code = _canonical_code(raw_code)
        if code not in codes:
            raise AdverseActionError(AdverseActionFailure.TAXONOMY_MISMATCH)
        copied[feature] = code
    return MappingProxyType(copied)


class MappedReason(BaseModel):
    """A principal reason traced to one or more model features."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: ReasonCode
    source_features: tuple[str, ...]
    adverse_contribution: float
    rank: int

    @field_validator("source_features", mode="before")
    @classmethod
    def _validate_source_features(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("source_features must be a sequence")
        features = tuple(_canonical_text(item, field_name="source_feature") for item in value)
        if not features or features != tuple(sorted(set(features))):
            raise ValueError("source_features must be unique, nonempty, and sorted")
        return features

    @field_validator("adverse_contribution", mode="before")
    @classmethod
    def _validate_contribution(cls, value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise TypeError("adverse_contribution must be a finite number")
        number = float(value)
        if not math.isfinite(number) or number <= 0:
            raise ValueError("adverse_contribution must be finite and greater than zero")
        return number

    @field_validator("rank", mode="before")
    @classmethod
    def _validate_rank(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("rank must be a positive integer")
        return value


class ReasonCodeSelection(BaseModel):
    """Versioned principal reasons plus the attribution provenance they came from."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    taxonomy_version: str
    model_id: str
    model_version: str
    reference_id: str
    attribution_method: AttributionMethod
    feature_names: tuple[str, ...]
    reasons: tuple[MappedReason, ...]

    @field_validator("taxonomy_version", "model_id", "model_version", "reference_id", mode="before")
    @classmethod
    def _validate_identifier(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))

    @field_validator("feature_names", mode="before")
    @classmethod
    def _validate_feature_names(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("feature_names must be a sequence")
        features = tuple(_canonical_text(item, field_name="feature_name") for item in value)
        if not features or features != tuple(sorted(set(features))):
            raise ValueError("feature_names must be unique, nonempty, and sorted")
        return features

    @model_validator(mode="after")
    def _validate_reasons(self) -> ReasonCodeSelection:
        if not self.reasons:
            raise ValueError("reasons must contain at least one principal reason")
        if tuple(reason.rank for reason in self.reasons) != tuple(range(1, len(self.reasons) + 1)):
            raise ValueError("reason ranks must be contiguous and ordered")
        if any(reason.code.code_set_version != self.taxonomy_version for reason in self.reasons):
            raise ValueError("reason code version must match taxonomy_version")
        if len({reason.code.code for reason in self.reasons}) != len(self.reasons):
            raise ValueError("reason codes must be unique after consolidation")
        known_features = set(self.feature_names)
        observed_features: set[str] = set()
        for reason in self.reasons:
            source_features = set(reason.source_features)
            if not source_features <= known_features:
                raise ValueError("every source feature must belong to feature_names")
            if source_features & observed_features:
                raise ValueError("a source feature cannot support multiple principal reasons")
            observed_features.update(source_features)
        expected = tuple(
            sorted(
                self.reasons,
                key=lambda reason: (-reason.adverse_contribution, reason.code.code),
            )
        )
        if self.reasons != expected:
            raise ValueError("reasons must use deterministic contribution and code ordering")
        return self


class MappedBureauFactor(BaseModel):
    """One FCRA credit-score factor traced to its model features."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: BureauFactorCode
    source_features: tuple[str, ...]
    adverse_contribution: float
    rank: int

    @field_validator("source_features", mode="before")
    @classmethod
    def _validate_source_features(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("source_features must be a sequence")
        features = tuple(_canonical_text(item, field_name="source_feature") for item in value)
        if not features or features != tuple(sorted(set(features))):
            raise ValueError("source_features must be unique, nonempty, and sorted")
        return features

    @field_validator("adverse_contribution", mode="before")
    @classmethod
    def _validate_contribution(cls, value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise TypeError("adverse_contribution must be a finite number")
        number = float(value)
        if not math.isfinite(number) or number <= 0:
            raise ValueError("adverse_contribution must be finite and greater than zero")
        return number

    @field_validator("rank", mode="before")
    @classmethod
    def _validate_rank(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("rank must be a positive integer")
        return value


class BureauFactorSelection(BaseModel):
    """Versioned FCRA score factors plus their attribution provenance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code_set_version: str
    model_id: str
    model_version: str
    reference_id: str
    attribution_method: AttributionMethod
    feature_names: tuple[str, ...]
    factors: tuple[MappedBureauFactor, ...]

    @field_validator("code_set_version", "model_id", "model_version", "reference_id", mode="before")
    @classmethod
    def _validate_identifier(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))

    @field_validator("feature_names", mode="before")
    @classmethod
    def _validate_feature_names(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("feature_names must be a sequence")
        features = tuple(_canonical_text(item, field_name="feature_name") for item in value)
        if not features or features != tuple(sorted(set(features))):
            raise ValueError("feature_names must be unique, nonempty, and sorted")
        return features

    @model_validator(mode="after")
    def _validate_factors(self) -> BureauFactorSelection:
        if not self.factors:
            raise ValueError("factors must contain at least one credit-score factor")
        if tuple(factor.rank for factor in self.factors) != tuple(range(1, len(self.factors) + 1)):
            raise ValueError("factor ranks must be contiguous and ordered")
        if any(factor.code.code_set_version != self.code_set_version for factor in self.factors):
            raise ValueError("factor code version must match code_set_version")
        if len({factor.code.code for factor in self.factors}) != len(self.factors):
            raise ValueError("factor codes must be unique after consolidation")
        known_features = set(self.feature_names)
        observed_features: set[str] = set()
        for factor in self.factors:
            source_features = set(factor.source_features)
            if not source_features <= known_features:
                raise ValueError("every source feature must belong to feature_names")
            if source_features & observed_features:
                raise ValueError("a source feature cannot support multiple credit-score factors")
            observed_features.update(source_features)
        expected = tuple(
            sorted(
                self.factors,
                key=lambda factor: (-factor.adverse_contribution, factor.code.code),
            )
        )
        if self.factors != expected:
            raise ValueError("factors must use deterministic contribution and code ordering")
        inquiry_count = sum(factor.code.inquiry_related for factor in self.factors)
        if (
            len(self.factors) > 5
            or inquiry_count > 1
            or (len(self.factors) == 5 and inquiry_count != 1)
        ):
            raise ValueError(
                "at most four factors are allowed unless exactly one of five is inquiry-related"
            )
        return self


class ReasonCodeRegistry:
    """Immutable ECOA principal-reason vocabulary and feature bindings."""

    def __init__(
        self,
        *,
        taxonomy_version: str,
        ecoa_reason_codes: Iterable[ReasonCode],
        ecoa_feature_codes: Mapping[str, str],
    ) -> None:
        self._taxonomy_version = _canonical_text(taxonomy_version, field_name="taxonomy_version")
        ecoa_codes = _index_codes(
            ecoa_reason_codes,
            expected_type=ReasonCode,
            expected_version=self._taxonomy_version,
        )
        self._ecoa_codes = MappingProxyType(ecoa_codes)
        self._ecoa_feature_codes = _bind_features(ecoa_feature_codes, ecoa_codes)

    @classmethod
    def with_appendix_c(
        cls,
        *,
        taxonomy_version: str,
        ecoa_feature_codes: Mapping[str, str],
        additional_ecoa_codes: Iterable[ReasonCode] = (),
    ) -> ReasonCodeRegistry:
        """Build a registry seeded with AgentGuard-local Appendix C wording."""

        seed = tuple(
            ReasonCode(
                code=code,
                code_set_version=taxonomy_version,
                consumer_text=text,
                reg_b_ref=_APPENDIX_C_REFERENCE,
            )
            for code, text in _APPENDIX_C_REASON_TEXT
        )
        return cls(
            taxonomy_version=taxonomy_version,
            ecoa_reason_codes=(*seed, *tuple(additional_ecoa_codes)),
            ecoa_feature_codes=ecoa_feature_codes,
        )

    @property
    def taxonomy_version(self) -> str:
        return self._taxonomy_version

    @property
    def ecoa_feature_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._ecoa_feature_codes))

    @property
    def ecoa_code_ids(self) -> tuple[str, ...]:
        """Return the immutable sorted ECOA vocabulary identifiers."""

        return tuple(sorted(self._ecoa_codes))

    def ecoa_code_for_feature(self, feature_name: str) -> ReasonCode:
        feature = _canonical_text(feature_name, field_name="feature_name")
        code = self._ecoa_feature_codes.get(feature)
        if code is None:
            raise AdverseActionError(AdverseActionFailure.UNMAPPED_FEATURES)
        return self._ecoa_codes[code]


@dataclass(frozen=True, slots=True)
class BureauFactorRegistry:
    """Immutable FCRA credit-score factor vocabulary and model binding."""

    _code_set_version: str
    _codes: Mapping[str, BureauFactorCode]
    _feature_codes: Mapping[str, str]

    def __init__(
        self,
        *,
        code_set_version: str,
        factor_codes: Iterable[BureauFactorCode],
        feature_codes: Mapping[str, str],
    ) -> None:
        version = _canonical_text(code_set_version, field_name="code_set_version")
        codes = _index_codes(
            factor_codes,
            expected_type=BureauFactorCode,
            expected_version=version,
        )
        object.__setattr__(self, "_code_set_version", version)
        object.__setattr__(self, "_codes", MappingProxyType(codes))
        object.__setattr__(self, "_feature_codes", _bind_features(feature_codes, codes))

    @property
    def code_set_version(self) -> str:
        return self._code_set_version

    @property
    def feature_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._feature_codes))

    def factor_for_feature(self, feature_name: str) -> BureauFactorCode:
        feature = _canonical_text(feature_name, field_name="feature_name")
        code = self._feature_codes.get(feature)
        if code is None:
            raise AdverseActionError(AdverseActionFailure.UNMAPPED_FEATURES)
        return self._codes[code]

    def select(self, attribution: AttributionResult) -> BureauFactorSelection:
        """Resolve the complete score schema before selecting displayed factors."""

        if not isinstance(attribution, AttributionResult):
            raise AdverseActionError(AdverseActionFailure.INVALID_ATTRIBUTION)
        if tuple(attribution.feature_names) != self.feature_names:
            raise AdverseActionError(AdverseActionFailure.UNMAPPED_FEATURES)
        resolved = {
            feature: self.factor_for_feature(feature) for feature in attribution.feature_names
        }
        if not attribution.contributions:
            raise AdverseActionError(AdverseActionFailure.NO_TRUE_FACTORS)

        grouped: dict[str, list[AdverseContribution]] = defaultdict(list)
        for contribution in attribution.contributions:
            grouped[resolved[contribution.feature_name].code].append(contribution)

        ranked: list[tuple[float, str, tuple[str, ...], BureauFactorCode]] = []
        for code_id, contributions in grouped.items():
            total = sum(item.value for item in contributions)
            if not math.isfinite(total) or total <= 0:
                raise AdverseActionError(AdverseActionFailure.INVALID_ATTRIBUTION)
            features = tuple(sorted(item.feature_name for item in contributions))
            ranked.append((total, code_id, features, resolved[features[0]]))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        inquiry_factors = [item for item in ranked if item[3].inquiry_related]
        if len(inquiry_factors) > 1:
            raise AdverseActionError(AdverseActionFailure.INVALID_ATTRIBUTION)
        displayed = ranked[:4]
        if inquiry_factors and inquiry_factors[0] not in displayed:
            displayed.append(inquiry_factors[0])

        factors = tuple(
            MappedBureauFactor(
                code=code,
                source_features=features,
                adverse_contribution=total,
                rank=rank,
            )
            for rank, (total, _code_id, features, code) in enumerate(displayed, 1)
        )
        return BureauFactorSelection(
            code_set_version=self.code_set_version,
            model_id=attribution.model_id,
            model_version=attribution.model_version,
            reference_id=attribution.reference_id,
            attribution_method=attribution.method,
            feature_names=attribution.feature_names,
            factors=factors,
        )


class ReasonCodeMapper:
    """Map one complete attribution envelope to truthful principal reasons."""

    def __init__(
        self,
        registry: ReasonCodeRegistry,
        *,
        max_principal_reasons: int | None = None,
    ) -> None:
        if not isinstance(registry, ReasonCodeRegistry):
            raise TypeError("registry must be a ReasonCodeRegistry")
        if max_principal_reasons is not None and (
            isinstance(max_principal_reasons, bool)
            or not isinstance(max_principal_reasons, int)
            or max_principal_reasons < 1
        ):
            raise ValueError("max_principal_reasons must be a positive integer or None")
        self._registry = registry
        self._max_principal_reasons = max_principal_reasons

    def map(self, attribution: AttributionResult) -> ReasonCodeSelection:
        """Resolve all model features before selecting any displayed reasons."""

        if not isinstance(attribution, AttributionResult):
            raise AdverseActionError(AdverseActionFailure.INVALID_ATTRIBUTION)
        if tuple(attribution.feature_names) != self._registry.ecoa_feature_names:
            raise AdverseActionError(AdverseActionFailure.UNMAPPED_FEATURES)
        resolved = {
            feature: self._registry.ecoa_code_for_feature(feature)
            for feature in attribution.feature_names
        }
        if not attribution.contributions:
            raise AdverseActionError(AdverseActionFailure.NO_TRUE_FACTORS)

        grouped: dict[str, list[AdverseContribution]] = defaultdict(list)
        for contribution in attribution.contributions:
            grouped[resolved[contribution.feature_name].code].append(contribution)

        ranked: list[tuple[float, str, tuple[str, ...], ReasonCode]] = []
        for code_id, contributions in grouped.items():
            total = sum(item.value for item in contributions)
            if not math.isfinite(total) or total <= 0:
                raise AdverseActionError(AdverseActionFailure.INVALID_ATTRIBUTION)
            features = tuple(sorted(item.feature_name for item in contributions))
            ranked.append((total, code_id, features, resolved[features[0]]))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        if self._max_principal_reasons is not None:
            ranked = ranked[: self._max_principal_reasons]

        reasons = tuple(
            MappedReason(
                code=code,
                source_features=features,
                adverse_contribution=total,
                rank=rank,
            )
            for rank, (total, _code_id, features, code) in enumerate(ranked, 1)
        )
        return ReasonCodeSelection(
            taxonomy_version=self._registry.taxonomy_version,
            model_id=attribution.model_id,
            model_version=attribution.model_version,
            reference_id=attribution.reference_id,
            attribution_method=attribution.method,
            feature_names=attribution.feature_names,
            reasons=reasons,
        )
