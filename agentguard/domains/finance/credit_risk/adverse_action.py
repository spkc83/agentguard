"""ECOA/Regulation B adverse action notice generation.

When credit is denied (or offered on less favorable terms), the applicant
must receive a notice stating the specific principal reasons. This module:

- Accepts feature importance output from a PD model
- Ranks adverse factors by contribution magnitude
- Maps model features to consumer-readable reason codes
- Ensures deterministic ordering (same input always produces same output)
- Produces an AdverseActionNotice Pydantic model

Regulation B requires the reasons to be specific and ordered by impact.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from pydantic import BaseModel, ConfigDict

logger = structlog.get_logger()

# Standard FCRA adverse action reason codes mapped to model features
DEFAULT_REASON_MAP: dict[str, str] = {
    "fico_score": "Credit score below threshold",
    "dti_ratio": "Debt-to-income ratio too high",
    "ltv_ratio": "Loan-to-value ratio too high",
    "annual_income": "Insufficient income",
    "employment_status": "Employment status does not meet requirements",
    "delinquency_24m": "Recent delinquencies on credit report",
    "credit_utilization": "Credit utilization too high",
    "num_open_accounts": "Number of open accounts outside acceptable range",
    "months_employed": "Insufficient employment history",
    "loan_amount": "Requested loan amount exceeds qualification",
}

# Maximum number of reasons in an adverse action notice (Regulation B)
MAX_REASONS = 4


class AdverseActionNotice(BaseModel):
    """ECOA/Regulation B compliant adverse action notice.

    Args:
        notice_id: Unique notice identifier.
        applicant_id: The applicant this notice is for.
        decision: The credit decision (denied, counteroffer, etc.).
        reasons: Ordered list of adverse action reasons (most impactful first).
        reason_codes: Feature names mapped to their reason strings.
        creditor_name: Name of the creditor issuing the notice.
        decision_date: When the decision was made.
        pd_score: The probability of default score.
        disclosure_text: Required regulatory disclosure text.
    """

    model_config = ConfigDict(frozen=True)

    notice_id: str
    applicant_id: str
    decision: str
    reasons: list[str]
    reason_codes: dict[str, str]
    creditor_name: str = ""
    decision_date: datetime = datetime.now(UTC)
    pd_score: float = 0.0
    disclosure_text: str = (
        "This notice is provided to you in accordance with the Equal Credit "
        "Opportunity Act (ECOA) and Regulation B. You have the right to request "
        "a copy of the appraisal report, if applicable, and to know the specific "
        "reasons for the denial of your credit application."
    )


class AdverseActionGenerator:
    """Generates ECOA-compliant adverse action notices.

    Takes model feature importances and maps them to consumer-readable
    reason codes. Ensures deterministic ordering: same input always
    produces the same reasons in the same order.

    Args:
        reason_map: Custom feature-to-reason mapping.
            Defaults to standard FCRA reason codes.
        max_reasons: Maximum reasons per notice (default 4, per Reg B).
    """

    def __init__(
        self,
        reason_map: dict[str, str] | None = None,
        max_reasons: int = MAX_REASONS,
    ) -> None:
        self._reason_map = reason_map or DEFAULT_REASON_MAP
        self._max_reasons = max_reasons

    def generate(
        self,
        notice_id: str,
        applicant_id: str,
        feature_importances: dict[str, float],
        pd_score: float = 0.0,
        creditor_name: str = "",
        decision: str = "denied",
    ) -> AdverseActionNotice:
        """Generate an adverse action notice from model feature importances.

        Args:
            notice_id: Unique identifier for this notice.
            applicant_id: The applicant ID.
            feature_importances: Dict of feature_name -> importance score.
                Higher absolute values indicate more impact on the decision.
            pd_score: The PD model's predicted probability of default.
            creditor_name: Name of the creditor.
            decision: Credit decision string.

        Returns:
            AdverseActionNotice with deterministically ordered reasons.
        """
        # Sort by absolute importance (descending), then by feature name
        # for deterministic ordering when importances are equal
        sorted_features = sorted(
            feature_importances.items(),
            key=lambda x: (-abs(x[1]), x[0]),
        )

        # Map to reason codes, take top N
        reasons: list[str] = []
        reason_codes: dict[str, str] = {}

        for feature_name, _importance in sorted_features:
            if len(reasons) >= self._max_reasons:
                break
            reason = self._reason_map.get(feature_name)
            if reason:
                reasons.append(reason)
                reason_codes[feature_name] = reason

        notice = AdverseActionNotice(
            notice_id=notice_id,
            applicant_id=applicant_id,
            decision=decision,
            reasons=reasons,
            reason_codes=reason_codes,
            creditor_name=creditor_name,
            pd_score=pd_score,
        )

        logger.info(
            "adverse_action_notice_generated",
            notice_id=notice_id,
            applicant_id=applicant_id,
            reasons_count=len(reasons),
        )
        return notice
