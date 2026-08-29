"""Deterministic plain-text rendering for typed credit-notice artifacts."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentguard.domains.finance.credit_risk.adverse_action import (
    AffiliateDisclosure,
    BothSources,
    CombinedCounterofferAdverseActionNotice,
    ConsumerReportSource,
    CounterofferNonAcceptanceNotice,
    CreditTerms,
    DeniedApplicationNotice,
    IncompleteApplicationNotice,
    MailingAddress,
    NoFCRA,
    NonCraThirdPartyDisclosure,
    OutsideSources,
    RenderableNotice,
    StandaloneCounterofferNotice,
    WithdrawalRecord,
)
from agentguard.exceptions import AdverseActionError, AdverseActionFailure

TEMPLATE_VERSION: Final = "2026.08"


class NoticeProfile(StrEnum):
    """Versioned rendering profiles grounded in current Appendix C forms."""

    REG_B_C1 = "reg_b_c1"
    REG_B_C3 = "reg_b_c3"
    REG_B_C4 = "reg_b_c4"
    REG_B_C6 = "reg_b_c6"
    AGENTGUARD_COUNTEROFFER = "agentguard_counteroffer"


class RenderedNotice(BaseModel):
    """Canonical rendered bytes represented as immutable text plus exact digest."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    notice_id: str
    profile: NoticeProfile
    template_version: str
    body: str
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def _validate_canonical_digest(self) -> RenderedNotice:
        canonical = NoticeRenderer._canonical_body(self.body.splitlines())
        expected_digest = hashlib.sha256(self.body.encode("utf-8")).hexdigest()
        expected_heading = {
            NoticeProfile.REG_B_C1: "NOTICE OF ACTION TAKEN",
            NoticeProfile.REG_B_C3: "NOTICE OF ACTION TAKEN — CREDIT SCORING",
            NoticeProfile.REG_B_C4: "NOTICE OF ACTION TAKEN AND COUNTEROFFER",
            NoticeProfile.REG_B_C6: "NOTICE OF INCOMPLETE APPLICATION",
            NoticeProfile.AGENTGUARD_COUNTEROFFER: "COUNTEROFFER",
        }[self.profile]
        if (
            self.notice_id != self.notice_id.strip()
            or not self.notice_id
            or not self.notice_id.isprintable()
            or self.template_version != TEMPLATE_VERSION
            or not self.body.startswith(f"{expected_heading}\n")
            or f"\nNotice ID: {self.notice_id}\n" not in self.body
            or self.body != canonical
            or self.body_sha256 != expected_digest
        ):
            raise AdverseActionError(AdverseActionFailure.NOTICE_INCOMPLETE)
        return self


class NoticeRenderer:
    """Render complete artifacts without adding timestamps or other ambient state."""

    def render(
        self,
        notice: RenderableNotice | WithdrawalRecord,
        *,
        profile: NoticeProfile | None = None,
    ) -> RenderedNotice:
        if isinstance(notice, WithdrawalRecord) or not isinstance(
            notice,
            DeniedApplicationNotice
            | StandaloneCounterofferNotice
            | CombinedCounterofferAdverseActionNotice
            | CounterofferNonAcceptanceNotice
            | IncompleteApplicationNotice,
        ):
            raise AdverseActionError(AdverseActionFailure.NOTICE_INCOMPLETE)
        selected = profile or self._default_profile(notice)
        self._validate_profile(notice, selected)
        body = self._canonical_body(self._render_lines(notice, selected))
        return RenderedNotice(
            notice_id=notice.notice_id,
            profile=selected,
            template_version=TEMPLATE_VERSION,
            body=body,
            body_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        )

    @staticmethod
    def _default_profile(notice: RenderableNotice) -> NoticeProfile:
        if isinstance(notice, CombinedCounterofferAdverseActionNotice):
            return NoticeProfile.REG_B_C4
        if isinstance(notice, IncompleteApplicationNotice):
            return NoticeProfile.REG_B_C6
        if isinstance(notice, StandaloneCounterofferNotice):
            return NoticeProfile.AGENTGUARD_COUNTEROFFER
        if isinstance(notice, DeniedApplicationNotice | CounterofferNonAcceptanceNotice):
            c3_eligible = (
                isinstance(notice, DeniedApplicationNotice)
                and notice.credit_scoring_applicable
                and notice.timing.basis == "completed_application"
            )
            return NoticeProfile.REG_B_C3 if c3_eligible else NoticeProfile.REG_B_C1
        raise AdverseActionError(AdverseActionFailure.NOTICE_INCOMPLETE)

    @staticmethod
    def _validate_profile(notice: RenderableNotice, profile: NoticeProfile) -> None:
        valid = (
            profile is NoticeProfile.REG_B_C4
            and isinstance(notice, CombinedCounterofferAdverseActionNotice)
            or profile is NoticeProfile.REG_B_C6
            and isinstance(notice, IncompleteApplicationNotice)
            or profile is NoticeProfile.AGENTGUARD_COUNTEROFFER
            and isinstance(notice, StandaloneCounterofferNotice)
            or profile is NoticeProfile.REG_B_C1
            and isinstance(notice, DeniedApplicationNotice | CounterofferNonAcceptanceNotice)
            or profile is NoticeProfile.REG_B_C3
            and isinstance(notice, DeniedApplicationNotice)
            and notice.credit_scoring_applicable
            and notice.timing.basis == "completed_application"
        )
        if not valid:
            raise AdverseActionError(AdverseActionFailure.NOTICE_INCOMPLETE)

    def _render_lines(
        self,
        notice: RenderableNotice,
        profile: NoticeProfile,
    ) -> list[str]:
        if isinstance(notice, IncompleteApplicationNotice):
            return self._render_incomplete(notice)
        if isinstance(notice, StandaloneCounterofferNotice):
            return self._render_standalone_counteroffer(notice)
        return self._render_adverse(notice, profile)

    def _render_adverse(
        self,
        notice: (
            DeniedApplicationNotice
            | CombinedCounterofferAdverseActionNotice
            | CounterofferNonAcceptanceNotice
        ),
        profile: NoticeProfile,
    ) -> list[str]:
        if profile is NoticeProfile.REG_B_C3:
            if not isinstance(notice, DeniedApplicationNotice):
                raise AdverseActionError(AdverseActionFailure.NOTICE_INCOMPLETE)
            return self._render_c3(notice)
        if profile is NoticeProfile.REG_B_C4:
            if not isinstance(notice, CombinedCounterofferAdverseActionNotice):
                raise AdverseActionError(AdverseActionFailure.NOTICE_INCOMPLETE)
            return self._render_c4(notice)
        heading = {
            NoticeProfile.REG_B_C1: "NOTICE OF ACTION TAKEN",
        }[profile]
        lines = [heading, ""]
        lines.extend(
            self._common_lines(
                notice,
                notice.timing.notification.occurred_at.date().isoformat(),
            )
        )
        lines.extend(["", "Action taken:"])
        if isinstance(notice, CounterofferNonAcceptanceNotice):
            lines.append(
                "We are unable to approve your original request because our "
                "counteroffer was not accepted."
            )
            lines.append(
                f"Original counteroffer notice: {notice.timing.original_counteroffer_notice_id}"
            )
            lines.extend(self._terms_lines("Counteroffer", notice.offered_terms))
        else:
            lines.append("We are unable to approve your application.")
        lines.extend(["", "Principal reasons:"])
        lines.extend(
            f"{reason.rank}. {reason.code.consumer_text} [{reason.code.code}]"
            for reason in notice.principal_reasons.reasons
        )
        lines.extend(self._ecoa_lines(notice))
        lines.extend(self._information_source_lines(notice.information_source))
        return lines

    def _render_c3(
        self,
        notice: DeniedApplicationNotice,
    ) -> list[str]:
        lines = ["NOTICE OF ACTION TAKEN — CREDIT SCORING", ""]
        lines.extend(
            self._common_lines(
                notice,
                notice.timing.notification.occurred_at.date().isoformat(),
            )
        )
        lines.extend(
            [
                "",
                "Action taken:",
                "We are unable to approve your request.",
                "",
                "Your application was evaluated by a credit scoring system that assigns "
                "numerical values to information considered in the application. Those "
                "values are based on analyses of repayment histories across many customers.",
                "The information in your application did not receive enough points for "
                "approval. The principal factors were:",
            ]
        )
        lines.extend(
            f"{reason.rank}. {reason.code.consumer_text} [{reason.code.code}]"
            for reason in notice.principal_reasons.reasons
        )
        lines.extend(self._ecoa_lines(notice))
        lines.extend(self._information_source_lines(notice.information_source))
        return lines

    def _render_c4(self, notice: CombinedCounterofferAdverseActionNotice) -> list[str]:
        lines = ["NOTICE OF ACTION TAKEN AND COUNTEROFFER", ""]
        lines.extend(
            self._common_lines(
                notice,
                notice.timing.notification.occurred_at.date().isoformat(),
            )
        )
        lines.extend(
            [
                "",
                "We are unable to offer credit on the terms you requested for these reasons:",
            ]
        )
        lines.extend(
            f"{reason.rank}. {reason.code.consumer_text} [{reason.code.code}]"
            for reason in notice.principal_reasons.reasons
        )
        lines.extend(["", "We can offer credit on these terms:"])
        lines.extend(self._terms_lines("Counteroffer", notice.offered_terms))
        lines.extend(
            [
                "",
                "To accept this counteroffer, send written notice to "
                f"{notice.acceptance.recipient} by "
                f"{notice.acceptance.accept_by.date().isoformat()} at:",
            ]
        )
        lines.extend(_address_lines(notice.acceptance.address))
        lines.extend(self._information_source_lines(notice.information_source))
        lines.extend(self._ecoa_lines(notice))
        return lines

    def _render_incomplete(self, notice: IncompleteApplicationNotice) -> list[str]:
        lines = ["NOTICE OF INCOMPLETE APPLICATION", ""]
        lines.extend(
            self._common_lines(
                notice,
                notice.timing.notification.occurred_at.date().isoformat(),
            )
        )
        lines.extend(
            [
                "",
                "Your application is incomplete. We need the following information:",
            ]
        )
        lines.extend(f"- {item}" for item in notice.information_needed)
        lines.extend(
            [
                "",
                f"Please provide this information by {notice.respond_by.date().isoformat()}.",
                "If we do not receive it by that date, we will take no further "
                "action on your application.",
            ]
        )
        return lines

    def _render_standalone_counteroffer(self, notice: StandaloneCounterofferNotice) -> list[str]:
        lines = ["COUNTEROFFER", ""]
        lines.extend(
            self._common_lines(
                notice,
                notice.timing.notification.occurred_at.date().isoformat(),
            )
        )
        lines.extend(
            [
                "",
                "We cannot approve the credit terms you requested, but we can offer these terms:",
            ]
        )
        lines.extend(self._terms_lines("Counteroffer", notice.offered_terms))
        lines.extend(
            [
                "",
                f"Accept this counteroffer by {notice.timing.accept_by.date().isoformat()}.",
            ]
        )
        lines.extend(["", "Reasons for the different terms:"])
        lines.extend(
            f"{reason.rank}. {reason.code.consumer_text} [{reason.code.code}]"
            for reason in notice.principal_reasons.reasons
        )
        return lines

    @staticmethod
    def _common_lines(notice: RenderableNotice, notice_date: str) -> list[str]:
        lines = [
            f"Notice date: {notice_date}",
            f"Notice ID: {notice.notice_id}",
            "",
            "Creditor:",
            notice.creditor.name,
        ]
        lines.extend(_address_lines(notice.creditor.address))
        lines.append(f"Telephone: {notice.creditor.telephone}")
        lines.extend(["", "Applicant:", notice.applicant.full_name])
        lines.extend(_address_lines(notice.applicant.address))
        lines.extend(
            [
                "",
                f"Application: {notice.credit_request.application_id}",
            ]
        )
        lines.extend(
            NoticeRenderer._terms_lines(
                "Credit requested",
                notice.credit_request.requested_terms,
            )
        )
        return lines

    @staticmethod
    def _terms_lines(label: str, terms: CreditTerms) -> list[str]:
        return [
            f"{label}: {terms.product_name}",
            f"Amount: ${terms.principal_amount:,.2f}",
            f"Annual percentage rate: {terms.annual_percentage_rate:.2f}%",
            f"Term: {terms.term_months} months",
        ]

    @staticmethod
    def _ecoa_lines(
        notice: (
            DeniedApplicationNotice
            | CombinedCounterofferAdverseActionNotice
            | CounterofferNonAcceptanceNotice
        ),
    ) -> list[str]:
        disclosure = notice.ecoa_disclosure
        lines = ["", "Equal Credit Opportunity Act notice:", disclosure.notice_text]
        lines.extend([disclosure.enforcement_agency.name])
        lines.extend(_address_lines(disclosure.enforcement_agency.address))
        return lines

    def _information_source_lines(
        self,
        source: NoFCRA
        | ConsumerReportSource
        | NonCraThirdPartyDisclosure
        | AffiliateDisclosure
        | OutsideSources
        | BothSources,
    ) -> list[str]:
        if isinstance(source, NoFCRA):
            return []
        lines = ["", "Fair Credit Reporting Act information:"]
        if isinstance(source, ConsumerReportSource):
            lines.extend(self._consumer_report_lines(source))
        elif isinstance(source, NonCraThirdPartyDisclosure | AffiliateDisclosure):
            lines.extend(self._outside_source_lines(source))
        elif isinstance(source, OutsideSources):
            for item in source.sources:
                lines.extend(self._outside_source_lines(item))
        else:
            lines.extend(self._consumer_report_lines(source.consumer_report))
            for item in source.outside_sources.sources:
                lines.extend(self._outside_source_lines(item))
        return lines

    @staticmethod
    def _consumer_report_lines(source: ConsumerReportSource) -> list[str]:
        lines = [
            "Our decision was based in whole or in part on information from the "
            "consumer reporting agency or agencies below.",
            "A consumer reporting agency did not make our decision and cannot "
            "explain the specific reasons for it.",
            "You may obtain a free copy of your report from each listed agency if "
            "requested within 60 days, and you may dispute inaccurate or incomplete "
            "report information.",
        ]
        for agency in source.agencies:
            lines.extend(["", agency.name])
            lines.extend(_address_lines(agency.address))
            lines.append(f"Toll-free telephone: {agency.toll_free_telephone}")
        if source.score_disclosure is not None:
            score = source.score_disclosure
            lines.extend(
                [
                    "",
                    "Credit score used:",
                    f"Score: {score.score}",
                    f"Score range: {score.score_min}–{score.score_max}",
                    f"Score date: {score.created_at.date().isoformat()}",
                    f"Score provider: {score.provider_name}",
                    "Key factors that adversely affected the score:",
                ]
            )
            lines.extend(
                f"{factor.rank}. {factor.code.consumer_text} [{factor.code.code}]"
                for factor in score.factors.factors
            )
        return lines

    @staticmethod
    def _outside_source_lines(
        source: NonCraThirdPartyDisclosure | AffiliateDisclosure,
    ) -> list[str]:
        if isinstance(source, NonCraThirdPartyDisclosure):
            lines = [
                "Our decision was based in whole or in part on information from an "
                "outside source other than a consumer reporting agency.",
                f"Source: {source.source_name}",
            ]
            lines.extend(_address_lines(source.address))
            lines.append(
                "If you request it in writing within 60 days, we will disclose the "
                "nature of that information within a reasonable period."
            )
            return lines
        lines = [
            "Our decision was based in whole or in part on information from an affiliated company.",
            f"Affiliate: {source.affiliate_name}",
        ]
        lines.extend(_address_lines(source.address))
        lines.append(
            "If you make a written request within 60 days, we will disclose the nature "
            "of that information no later than 30 days after receiving the timely "
            "written request."
        )
        return lines

    @staticmethod
    def _canonical_body(lines: list[str]) -> str:
        return "\n".join(line.rstrip() for line in lines).rstrip("\n") + "\n"


def _address_lines(address: MailingAddress) -> list[str]:
    lines = [address.line1]
    if address.line2 is not None:
        lines.append(address.line2)
    lines.append(f"{address.city}, {address.region} {address.postal_code}")
    return lines
