"""Credit decisioning agent templates.

Pre-built, AgentGuard-wrapped agent configurations for automated credit
decisioning workflows. The template defines the decision logic; the
actual governance (RBAC, audit, sandbox) is provided by the AgentGuard
runtime.

Decision flow:
  Application -> PD Model Score -> Decision Band -> Action
    - PD < auto_approve_threshold: AUTO_APPROVE
    - PD in [auto_approve_threshold, decline_threshold): REVIEW (HITL)
    - PD >= decline_threshold: DECLINE -> Adverse Action Notice
"""

from __future__ import annotations

from typing import Any, Literal

import structlog
from pydantic import BaseModel, ConfigDict

logger = structlog.get_logger()


class CreditDecisionConfig(BaseModel):
    """Configuration for credit decisioning agent.

    Args:
        auto_approve_threshold: PD below this -> auto-approve.
        decline_threshold: PD at or above this -> auto-decline.
        max_loan_amount: Maximum loan amount for auto-approval.
        min_fico_score: Minimum FICO for auto-approval.
        max_dti_ratio: Maximum DTI for auto-approval.
    """

    model_config = ConfigDict(frozen=True)

    auto_approve_threshold: float = 0.05
    decline_threshold: float = 0.20
    max_loan_amount: float = 500000.0
    min_fico_score: int = 620
    max_dti_ratio: float = 0.43


class CreditDecision(BaseModel):
    """Result of a credit decision evaluation.

    Args:
        applicant_id: The applicant's identifier.
        decision: The decision outcome.
        pd_score: Probability of default.
        reasons: Reasons for the decision.
        requires_review: Whether HITL review is needed.
        feature_importances: Model feature importance scores.
    """

    model_config = ConfigDict(frozen=True)

    applicant_id: str
    decision: Literal["approved", "declined", "review"]
    pd_score: float
    reasons: list[str] = []
    requires_review: bool = False
    feature_importances: dict[str, float] = {}


class CreditDecisioningAgent:
    """Credit decisioning agent template.

    Evaluates loan applications against configurable thresholds and
    produces structured decisions. Designed to be wrapped with
    AgentGuard governance (RBAC, audit, circuit breaker).

    Args:
        config: Decision configuration with thresholds.
    """

    def __init__(self, config: CreditDecisionConfig | None = None) -> None:
        self._config = config or CreditDecisionConfig()

    def evaluate(
        self,
        applicant_id: str,
        pd_score: float,
        application: dict[str, Any] | None = None,
    ) -> CreditDecision:
        """Evaluate a credit application.

        Args:
            applicant_id: Applicant identifier.
            pd_score: Model-predicted probability of default.
            application: Application data dict with optional fields:
                fico_score, dti_ratio, loan_amount, etc.

        Returns:
            CreditDecision with outcome and reasoning.
        """
        app = application or {}
        reasons: list[str] = []
        cfg = self._config

        # Hard cutoff checks
        fico = app.get("fico_score")
        if fico is not None and fico < cfg.min_fico_score:
            reasons.append(f"FICO score {fico} below minimum {cfg.min_fico_score}")

        dti = app.get("dti_ratio")
        if dti is not None and dti > cfg.max_dti_ratio:
            reasons.append(f"DTI ratio {dti:.2f} exceeds maximum {cfg.max_dti_ratio:.2f}")

        loan_amount = app.get("loan_amount")
        if loan_amount is not None and loan_amount > cfg.max_loan_amount:
            reasons.append(
                f"Loan amount ${loan_amount:,.0f} exceeds maximum ${cfg.max_loan_amount:,.0f}"
            )

        # PD-based decision banding
        if pd_score >= cfg.decline_threshold or len(reasons) >= 2:
            decision_type: Literal["approved", "declined", "review"] = "declined"
            reasons.insert(0, f"PD score {pd_score:.4f} exceeds decline threshold")
        elif pd_score < cfg.auto_approve_threshold and not reasons:
            decision_type = "approved"
            reasons = [f"PD score {pd_score:.4f} within auto-approve band"]
        else:
            decision_type = "review"
            reasons.insert(0, f"PD score {pd_score:.4f} in review band")

        # Compute simple feature importances from application data
        feature_importances: dict[str, float] = {}
        if fico is not None:
            # Lower FICO = higher adverse impact
            feature_importances["fico_score"] = max(0, (700 - fico) / 100)
        if dti is not None:
            feature_importances["dti_ratio"] = max(0, (dti - 0.35) / 0.1)
        feature_importances["pd_score"] = pd_score

        decision = CreditDecision(
            applicant_id=applicant_id,
            decision=decision_type,
            pd_score=pd_score,
            reasons=reasons,
            requires_review=decision_type == "review",
            feature_importances=feature_importances,
        )

        logger.info(
            "credit_decision_made",
            applicant_id=applicant_id,
            decision=decision_type,
            pd_score=pd_score,
        )
        return decision
