"""Typed, immutable Regulation B and FCRA credit-notice artifacts.

These models preserve the facts needed to produce source-grounded notices.
They do not replace institution-specific legal review, delivery controls, or
the governed evidence emission implemented by the credit workflow.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal  # noqa: TC003 - Pydantic resolves this annotation at runtime
from enum import StrEnum
from typing import Annotated, Literal, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from agentguard.domains.finance.credit_risk.attribution import (  # noqa: TC001
    AttributionMethod,
)
from agentguard.domains.finance.credit_risk.reason_codes import (
    BureauFactorSelection,
    ReasonCode,
    ReasonCodeSelection,
)
from agentguard.exceptions import AdverseActionError, AdverseActionFailure

_ECOA_NOTICE_TEXT = (
    "The Federal Equal Credit Opportunity Act prohibits creditors from discriminating "
    "against credit applicants on the basis of race, color, religion, national origin, "
    "sex, marital status, age (provided the applicant has the capacity to enter into a "
    "binding contract); because all or part of the applicant's income derives from any "
    "public assistance program; or because the applicant has in good faith exercised any "
    "right under the Consumer Credit Protection Act. The federal agency that administers "
    "compliance with this law concerning this creditor is:"
)
ECOA_DISCLOSURE_VERSION = "reg-b-appendix-c-2026-01-01"


def _canonical_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or value != value.strip() or not value.isprintable():
        raise ValueError(f"{field_name} must be canonical nonempty printable text")
    return value


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _notice_incomplete() -> None:
    raise AdverseActionError(AdverseActionFailure.NOTICE_INCOMPLETE)


def _window_exceeded() -> None:
    raise AdverseActionError(AdverseActionFailure.NOTICE_WINDOW_EXCEEDED)


class _RegulatoryModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class DecisionType(StrEnum):
    DENIED = "denied"
    COUNTEROFFER = "counteroffer"
    INCOMPLETE = "incomplete"
    WITHDRAWN = "withdrawn"


class MailingAddress(_RegulatoryModel):
    line1: str
    line2: str | None = None
    city: str
    region: str
    postal_code: str

    @field_validator("line1", "city", "region", "postal_code", mode="before")
    @classmethod
    def _validate_required_text(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))

    @field_validator("line2", mode="before")
    @classmethod
    def _validate_optional_text(cls, value: object) -> str | None:
        if value is None:
            return None
        return _canonical_text(value, field_name="line2")


class ApplicantDetails(_RegulatoryModel):
    applicant_id: str
    full_name: str
    address: MailingAddress

    @field_validator("applicant_id", "full_name", mode="before")
    @classmethod
    def _validate_text(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))


class CreditorDetails(_RegulatoryModel):
    name: str
    address: MailingAddress
    telephone: str

    @field_validator("name", "telephone", mode="before")
    @classmethod
    def _validate_text(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))


class EnforcementAgency(_RegulatoryModel):
    name: str
    address: MailingAddress

    _validate_name = field_validator("name", mode="before")(
        lambda value: _canonical_text(value, field_name="name")
    )


class CreditTerms(_RegulatoryModel):
    product_name: str
    principal_amount: Decimal = Field(gt=0)
    annual_percentage_rate: Decimal = Field(ge=0, le=100)
    term_months: int = Field(gt=0)

    _validate_product_name = field_validator("product_name", mode="before")(
        lambda value: _canonical_text(value, field_name="product_name")
    )

    @field_validator("term_months", mode="before")
    @classmethod
    def _validate_term_months(cls, value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("term_months must be an integer")
        return value


class CreditRequestDetails(_RegulatoryModel):
    application_id: str
    received_at: datetime
    requested_terms: CreditTerms

    _validate_application_id = field_validator("application_id", mode="before")(
        lambda value: _canonical_text(value, field_name="application_id")
    )

    @field_validator("received_at")
    @classmethod
    def _validate_received_at(cls, value: datetime) -> datetime:
        return _utc(value, field_name="received_at")


class EqualCreditOpportunityDisclosure(_RegulatoryModel):
    text_version: str = ECOA_DISCLOSURE_VERSION
    notice_text: str = _ECOA_NOTICE_TEXT
    enforcement_agency: EnforcementAgency

    @field_validator("text_version", mode="before")
    @classmethod
    def _validate_text_version(cls, value: object) -> str:
        if value != ECOA_DISCLOSURE_VERSION:
            _notice_incomplete()
        return ECOA_DISCLOSURE_VERSION

    @field_validator("notice_text", mode="before")
    @classmethod
    def _validate_notice_text(cls, value: object) -> str:
        if value != _ECOA_NOTICE_TEXT:
            _notice_incomplete()
        return _ECOA_NOTICE_TEXT


class WrittenNotificationEvent(_RegulatoryModel):
    method: Literal["mailed", "delivered"]
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def _validate_occurred_at(cls, value: datetime) -> datetime:
        return _utc(value, field_name="occurred_at")


class CounterofferNotificationEvent(_RegulatoryModel):
    method: Literal["mailed", "delivered", "oral"]
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def _validate_occurred_at(cls, value: datetime) -> datetime:
        return _utc(value, field_name="occurred_at")


class WrittenInformationRequest(_RegulatoryModel):
    method: Literal["written"] = "written"
    received_at: datetime

    @field_validator("received_at")
    @classmethod
    def _validate_received_at(cls, value: datetime) -> datetime:
        return _utc(value, field_name="received_at")


class ThirtyDayNoticeTiming(_RegulatoryModel):
    basis: Literal["completed_application", "action_taken", "incomplete_application"]
    trigger_at: datetime
    notification: WrittenNotificationEvent

    @field_validator("trigger_at")
    @classmethod
    def _validate_trigger_at(cls, value: datetime) -> datetime:
        return _utc(value, field_name="trigger_at")

    @property
    def deadline_at(self) -> datetime:
        return self.trigger_at + timedelta(days=30)

    @model_validator(mode="after")
    def _validate_window(self) -> ThirtyDayNoticeTiming:
        if not self.trigger_at <= self.notification.occurred_at <= self.deadline_at:
            _window_exceeded()
        return self


class StandaloneCounterofferTiming(_RegulatoryModel):
    trigger_at: datetime
    notification: CounterofferNotificationEvent
    accept_by: datetime

    @field_validator("trigger_at", "accept_by")
    @classmethod
    def _validate_datetime(cls, value: datetime, info: object) -> datetime:
        return _utc(value, field_name=getattr(info, "field_name", "value"))

    @property
    def notice_deadline_at(self) -> datetime:
        return self.trigger_at + timedelta(days=30)

    @property
    def outer_deadline_at(self) -> datetime:
        return self.trigger_at + timedelta(days=90)

    @model_validator(mode="after")
    def _validate_window(self) -> StandaloneCounterofferTiming:
        if not self.trigger_at <= self.notification.occurred_at <= self.notice_deadline_at:
            _window_exceeded()
        if not self.notification.occurred_at < self.accept_by <= self.outer_deadline_at:
            _window_exceeded()
        return self


class CounterofferFollowupTiming(_RegulatoryModel):
    original_counteroffer_notice_id: str
    counteroffer_notification: CounterofferNotificationEvent
    notification: WrittenNotificationEvent

    _validate_notice_id = field_validator("original_counteroffer_notice_id", mode="before")(
        lambda value: _canonical_text(value, field_name="original_counteroffer_notice_id")
    )

    @property
    def deadline_at(self) -> datetime:
        return self.counteroffer_notification.occurred_at + timedelta(days=90)

    @model_validator(mode="after")
    def _validate_window(self) -> CounterofferFollowupTiming:
        if not (
            self.counteroffer_notification.occurred_at
            <= self.notification.occurred_at
            <= self.deadline_at
        ):
            _window_exceeded()
        return self


class ModelReasonOrigin(_RegulatoryModel):
    kind: Literal["model"] = "model"
    model_id: str
    model_version: str
    reference_id: str
    attribution_method: AttributionMethod
    evaluated_feature_names: tuple[str, ...]
    source_features: tuple[str, ...]
    adverse_contribution: float = Field(gt=0, allow_inf_nan=False)

    @field_validator("model_id", "model_version", "reference_id", mode="before")
    @classmethod
    def _validate_identifier(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))

    @field_validator("evaluated_feature_names", "source_features", mode="before")
    @classmethod
    def _validate_features(cls, value: object, info: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError(f"{getattr(info, 'field_name', 'features')} must be a sequence")
        field_name = getattr(info, "field_name", "features")
        features = tuple(_canonical_text(item, field_name=field_name) for item in value)
        if not features or features != tuple(sorted(set(features))):
            raise ValueError(f"{field_name} must be unique, nonempty, and sorted")
        return features

    @model_validator(mode="after")
    def _validate_feature_provenance(self) -> ModelReasonOrigin:
        if not set(self.source_features) <= set(self.evaluated_feature_names):
            raise ValueError("source_features must belong to evaluated_feature_names")
        return self


class DecisionComponentOrigin(_RegulatoryModel):
    kind: Literal["decision_component"] = "decision_component"
    component_kind: Literal["policy_rule", "human_review"]
    component_id: str
    component_version: str

    @field_validator("component_id", "component_version", mode="before")
    @classmethod
    def _validate_identifier(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))


ReasonOrigin: TypeAlias = Annotated[
    ModelReasonOrigin | DecisionComponentOrigin,
    Field(discriminator="kind"),
]


class PrincipalReason(_RegulatoryModel):
    code: ReasonCode
    rank: int = Field(gt=0)
    origin: ReasonOrigin


class PrincipalReasonSelection(_RegulatoryModel):
    taxonomy_version: str
    reasons: tuple[PrincipalReason, ...]

    _validate_taxonomy_version = field_validator("taxonomy_version", mode="before")(
        lambda value: _canonical_text(value, field_name="taxonomy_version")
    )

    @classmethod
    def from_attribution(cls, selection: ReasonCodeSelection) -> PrincipalReasonSelection:
        if not isinstance(selection, ReasonCodeSelection):
            raise AdverseActionError(AdverseActionFailure.INVALID_ATTRIBUTION)
        return cls(
            taxonomy_version=selection.taxonomy_version,
            reasons=tuple(
                PrincipalReason(
                    code=mapped.code,
                    rank=mapped.rank,
                    origin=ModelReasonOrigin(
                        model_id=selection.model_id,
                        model_version=selection.model_version,
                        reference_id=selection.reference_id,
                        attribution_method=selection.attribution_method,
                        evaluated_feature_names=selection.feature_names,
                        source_features=mapped.source_features,
                        adverse_contribution=mapped.adverse_contribution,
                    ),
                )
                for mapped in selection.reasons
            ),
        )

    @model_validator(mode="after")
    def _validate_reasons(self) -> PrincipalReasonSelection:
        if not self.reasons:
            _notice_incomplete()
        if tuple(reason.rank for reason in self.reasons) != tuple(range(1, len(self.reasons) + 1)):
            raise ValueError("principal reason ranks must be contiguous and ordered")
        if len({reason.code.code for reason in self.reasons}) != len(self.reasons):
            raise ValueError("principal reason codes must be unique")
        if any(reason.code.code_set_version != self.taxonomy_version for reason in self.reasons):
            raise ValueError("principal reason taxonomy must match taxonomy_version")
        return self


class CraContact(_RegulatoryModel):
    name: str
    address: MailingAddress
    toll_free_telephone: str

    @field_validator("name", "toll_free_telephone", mode="before")
    @classmethod
    def _validate_text(cls, value: object, info: object) -> str:
        return _canonical_text(value, field_name=getattr(info, "field_name", "value"))


class CreditScoreDisclosure(_RegulatoryModel):
    provider_name: str
    score: int
    score_min: int
    score_max: int
    created_at: datetime
    factors: BureauFactorSelection

    _validate_provider = field_validator("provider_name", mode="before")(
        lambda value: _canonical_text(value, field_name="provider_name")
    )

    @field_validator("score", "score_min", "score_max", mode="before")
    @classmethod
    def _validate_score_integer(cls, value: object, info: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{getattr(info, 'field_name', 'score')} must be an integer")
        return value

    @field_validator("created_at")
    @classmethod
    def _validate_created_at(cls, value: datetime) -> datetime:
        return _utc(value, field_name="created_at")

    @model_validator(mode="after")
    def _validate_score(self) -> CreditScoreDisclosure:
        if self.score_min >= self.score_max or not self.score_min <= self.score <= self.score_max:
            _notice_incomplete()
        return self


class NoFCRA(_RegulatoryModel):
    kind: Literal["none"] = "none"


class ConsumerReportSource(_RegulatoryModel):
    kind: Literal["consumer_report"] = "consumer_report"
    agencies: tuple[CraContact, ...]
    score_used: bool
    score_disclosure: CreditScoreDisclosure | None = None

    @model_validator(mode="after")
    def _validate_applicability(self) -> ConsumerReportSource:
        if not self.agencies:
            _notice_incomplete()
        identities = {
            (agency.name, agency.address.model_dump_json(), agency.toll_free_telephone)
            for agency in self.agencies
        }
        if len(identities) != len(self.agencies):
            _notice_incomplete()
        if self.score_used != (self.score_disclosure is not None):
            _notice_incomplete()
        return self


class NonCraThirdPartyDisclosure(_RegulatoryModel):
    kind: Literal["non_cra_third_party"] = "non_cra_third_party"
    source_name: str
    address: MailingAddress
    request_period_days: Literal[60] = 60
    response_rule: Literal["reasonable_period"] = "reasonable_period"
    information_request: WrittenInformationRequest | None = None
    response_sent_at: datetime | None = None

    _validate_source_name = field_validator("source_name", mode="before")(
        lambda value: _canonical_text(value, field_name="source_name")
    )

    @field_validator("response_sent_at")
    @classmethod
    def _validate_optional_datetime(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _utc(value, field_name="response_sent_at")

    @model_validator(mode="after")
    def _validate_response_sequence(self) -> NonCraThirdPartyDisclosure:
        if self.response_sent_at is not None and self.information_request is None:
            _notice_incomplete()
        if (
            self.information_request is not None
            and self.response_sent_at is not None
            and self.response_sent_at < self.information_request.received_at
        ):
            _window_exceeded()
        return self


class AffiliateDisclosure(_RegulatoryModel):
    kind: Literal["affiliate"] = "affiliate"
    affiliate_name: str
    address: MailingAddress
    request_period_days: Literal[60] = 60
    response_period_days: Literal[30] = 30
    information_request: WrittenInformationRequest | None = None
    response_sent_at: datetime | None = None

    _validate_affiliate_name = field_validator("affiliate_name", mode="before")(
        lambda value: _canonical_text(value, field_name="affiliate_name")
    )

    @field_validator("response_sent_at")
    @classmethod
    def _validate_optional_datetime(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _utc(value, field_name="response_sent_at")

    @model_validator(mode="after")
    def _validate_response_sequence(self) -> AffiliateDisclosure:
        if self.response_sent_at is not None and self.information_request is None:
            _notice_incomplete()
        if self.information_request is not None and self.response_sent_at is not None:
            request_at = self.information_request.received_at
            deadline = request_at + timedelta(days=30)
            if not request_at <= self.response_sent_at <= deadline:
                _window_exceeded()
        return self


OutsideDisclosure: TypeAlias = Annotated[
    NonCraThirdPartyDisclosure | AffiliateDisclosure,
    Field(discriminator="kind"),
]


class OutsideSources(_RegulatoryModel):
    kind: Literal["outside_sources"] = "outside_sources"
    sources: tuple[OutsideDisclosure, ...]

    @model_validator(mode="after")
    def _validate_sources(self) -> OutsideSources:
        if not self.sources:
            _notice_incomplete()
        identities = tuple(
            (
                source.kind,
                source.source_name
                if source.kind == "non_cra_third_party"
                else source.affiliate_name,
            )
            for source in self.sources
        )
        if len(set(identities)) != len(identities):
            _notice_incomplete()
        return self


class BothSources(_RegulatoryModel):
    kind: Literal["both_sources"] = "both_sources"
    consumer_report: ConsumerReportSource
    outside_sources: OutsideSources


InformationSource: TypeAlias = Annotated[
    NoFCRA
    | ConsumerReportSource
    | NonCraThirdPartyDisclosure
    | AffiliateDisclosure
    | OutsideSources
    | BothSources,
    Field(discriminator="kind"),
]


def _outside_disclosures(source: InformationSource) -> tuple[OutsideDisclosure, ...]:
    if isinstance(source, NonCraThirdPartyDisclosure | AffiliateDisclosure):
        return (source,)
    if isinstance(source, OutsideSources):
        return source.sources
    if isinstance(source, BothSources):
        return source.outside_sources.sources
    return ()


def _consumer_report(source: InformationSource) -> ConsumerReportSource | None:
    if isinstance(source, ConsumerReportSource):
        return source
    if isinstance(source, BothSources):
        return source.consumer_report
    return None


class _CommonNotice(_RegulatoryModel):
    notice_id: str
    applicant: ApplicantDetails
    creditor: CreditorDetails
    credit_request: CreditRequestDetails

    _validate_notice_id = field_validator("notice_id", mode="before")(
        lambda value: _canonical_text(value, field_name="notice_id")
    )

    def _validate_trigger_after_receipt(self, trigger_at: datetime) -> None:
        if trigger_at < self.credit_request.received_at:
            _window_exceeded()


class _AdverseNotice(_CommonNotice):
    principal_reasons: PrincipalReasonSelection
    ecoa_disclosure: EqualCreditOpportunityDisclosure
    information_source: InformationSource

    def _validate_source_timing(self, notification_at: datetime) -> None:
        consumer_report = _consumer_report(self.information_source)
        if (
            consumer_report is not None
            and consumer_report.score_disclosure is not None
            and consumer_report.score_disclosure.created_at > notification_at
        ):
            _window_exceeded()
        for source in _outside_disclosures(self.information_source):
            if source.information_request is not None and not (
                notification_at
                <= source.information_request.received_at
                <= notification_at + timedelta(days=60)
            ):
                _window_exceeded()


class DeniedApplicationNotice(_AdverseNotice):
    decision_type: Literal[DecisionType.DENIED] = DecisionType.DENIED
    timing: ThirtyDayNoticeTiming
    credit_scoring_applicable: bool = False

    @model_validator(mode="after")
    def _validate_notice(self) -> DeniedApplicationNotice:
        if self.timing.basis not in {"completed_application", "action_taken"}:
            _notice_incomplete()
        self._validate_trigger_after_receipt(self.timing.trigger_at)
        if self.credit_scoring_applicable and not any(
            isinstance(reason.origin, ModelReasonOrigin)
            for reason in self.principal_reasons.reasons
        ):
            _notice_incomplete()
        self._validate_source_timing(self.timing.notification.occurred_at)
        return self


class StandaloneCounterofferNotice(_CommonNotice):
    decision_type: Literal[DecisionType.COUNTEROFFER] = DecisionType.COUNTEROFFER
    timing: StandaloneCounterofferTiming
    offered_terms: CreditTerms
    principal_reasons: PrincipalReasonSelection
    information_source: NoFCRA

    @model_validator(mode="after")
    def _validate_notice(self) -> StandaloneCounterofferNotice:
        self._validate_trigger_after_receipt(self.timing.trigger_at)
        return self


class CounterofferAcceptanceInstructions(_RegulatoryModel):
    method: Literal["written_notice"] = "written_notice"
    recipient: str
    address: MailingAddress
    accept_by: datetime

    _validate_recipient = field_validator("recipient", mode="before")(
        lambda value: _canonical_text(value, field_name="recipient")
    )

    @field_validator("accept_by")
    @classmethod
    def _validate_accept_by(cls, value: datetime) -> datetime:
        return _utc(value, field_name="accept_by")


class CombinedCounterofferAdverseActionNotice(_AdverseNotice):
    decision_type: Literal[DecisionType.COUNTEROFFER] = DecisionType.COUNTEROFFER
    timing: ThirtyDayNoticeTiming
    offered_terms: CreditTerms
    acceptance: CounterofferAcceptanceInstructions
    credit_scoring_applicable: bool = False

    @model_validator(mode="after")
    def _validate_notice(self) -> CombinedCounterofferAdverseActionNotice:
        if self.timing.basis != "completed_application":
            _notice_incomplete()
        self._validate_trigger_after_receipt(self.timing.trigger_at)
        if self.acceptance.accept_by <= self.timing.notification.occurred_at:
            _window_exceeded()
        if self.credit_scoring_applicable and not any(
            isinstance(reason.origin, ModelReasonOrigin)
            for reason in self.principal_reasons.reasons
        ):
            _notice_incomplete()
        self._validate_source_timing(self.timing.notification.occurred_at)
        return self


class CounterofferNonAcceptanceNotice(_AdverseNotice):
    decision_type: Literal[DecisionType.DENIED] = DecisionType.DENIED
    timing: CounterofferFollowupTiming
    offered_terms: CreditTerms
    credit_scoring_applicable: bool = False

    @model_validator(mode="after")
    def _validate_notice(self) -> CounterofferNonAcceptanceNotice:
        self._validate_trigger_after_receipt(self.timing.counteroffer_notification.occurred_at)
        if self.credit_scoring_applicable and not any(
            isinstance(reason.origin, ModelReasonOrigin)
            for reason in self.principal_reasons.reasons
        ):
            _notice_incomplete()
        self._validate_source_timing(self.timing.notification.occurred_at)
        return self


class IncompleteApplicationNotice(_CommonNotice):
    decision_type: Literal[DecisionType.INCOMPLETE] = DecisionType.INCOMPLETE
    timing: ThirtyDayNoticeTiming
    information_needed: tuple[str, ...]
    respond_by: datetime

    @field_validator("information_needed", mode="before")
    @classmethod
    def _validate_information_needed(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple):
            raise TypeError("information_needed must be a sequence")
        items = tuple(_canonical_text(item, field_name="information_needed") for item in value)
        if not items or len(set(items)) != len(items):
            _notice_incomplete()
        return items

    @field_validator("respond_by")
    @classmethod
    def _validate_respond_by(cls, value: datetime) -> datetime:
        return _utc(value, field_name="respond_by")

    @model_validator(mode="after")
    def _validate_notice(self) -> IncompleteApplicationNotice:
        if self.timing.basis != "incomplete_application":
            _notice_incomplete()
        self._validate_trigger_after_receipt(self.timing.trigger_at)
        if self.respond_by <= self.timing.notification.occurred_at:
            _window_exceeded()
        return self


class WithdrawalRecord(_RegulatoryModel):
    record_id: str
    decision_type: Literal[DecisionType.WITHDRAWN] = DecisionType.WITHDRAWN
    applicant: ApplicantDetails
    creditor: CreditorDetails
    credit_request: CreditRequestDetails
    withdrawn_at: datetime

    _validate_record_id = field_validator("record_id", mode="before")(
        lambda value: _canonical_text(value, field_name="record_id")
    )

    @field_validator("withdrawn_at")
    @classmethod
    def _validate_withdrawn_at(cls, value: datetime) -> datetime:
        return _utc(value, field_name="withdrawn_at")

    @model_validator(mode="after")
    def _validate_sequence(self) -> WithdrawalRecord:
        if self.withdrawn_at < self.credit_request.received_at:
            _window_exceeded()
        return self


RenderableNotice: TypeAlias = (
    DeniedApplicationNotice
    | StandaloneCounterofferNotice
    | CombinedCounterofferAdverseActionNotice
    | CounterofferNonAcceptanceNotice
    | IncompleteApplicationNotice
)

CreditDecisionArtifact: TypeAlias = RenderableNotice | WithdrawalRecord
