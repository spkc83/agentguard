"""End-to-end governed credit decisioning with a bounded stub PD model.

The demo scores synthetic applications, emits decisions through the Phase 4.2
credit API, treats review-band results as HITL escalations, analyzes typed
per-decision fairness observations, and verifies the signed audit chain. It uses no LLM or real
customer data.

Prerequisites:
    pip install agentguard
    export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

Run:
    python examples/credit_decisioning/end_to_end_demo.py
"""

from __future__ import annotations

import asyncio
import secrets
import shutil
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from agentguard.compliance.engine import PolicyEngine
from agentguard.compliance.escalation_store import EscalationStore
from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.domains.finance.credit_risk import (
    AttributionIntegrityGuardrail,
    CoefficientAttributor,
    CreditDecisionOutcome,
    CreditDecisionPolicy,
    CreditDecisionPolicyConfig,
    CreditModelScore,
    DecisionBandGuardrail,
    DecisionEvidenceGuardrail,
    FairnessAnalyzer,
    FairnessObservation,
    GovernedCreditAgent,
    InMemoryPreparedNoticeProvider,
    ModelFairnessStatus,
    ModelGovernanceEvidence,
    ModelProvenanceGuardrail,
    ModelValidationStatus,
    NoticeCompletenessGuardrail,
    OutputDirection,
    ProtectedAttributeGuardrail,
    ReasonCode,
    ReasonCodeGuardrail,
    ReasonCodeMapper,
    ReasonCodeRegistry,
    StaticModelGovernanceEvidenceProvider,
    feature_schema_digest,
)
from agentguard.domains.finance.synthetic.generators import SyntheticCreditGenerator
from agentguard.exceptions import EscalationRequiredError
from agentguard.guardrails.kernel import GovernanceKernel
from agentguard.observability.dashboard import MetricsDashboard
from agentguard.observability.tracer import AgentTracer

if TYPE_CHECKING:
    from collections.abc import Mapping
    from numbers import Real

N_APPLICATIONS = 200
MODEL_ID = "stub-pd-model"
MODEL_VERSION = "1.0"
MODEL_REFERENCE_ID = "zero-adverse-term-reference-v1"
REASON_TAXONOMY_VERSION = "demo-pd-reasons-v1"
FEATURE_NAMES = (
    "delinquency_count_capped",
    "dti_excess",
    "fico_shortfall",
    "utilization_excess",
)


def _pd_explanatory_features(application: dict[str, Any]) -> dict[str, float]:
    """Return the exact transformed terms used by the stub before clipping."""

    return {
        "delinquency_count_capped": float(min(application["delinquency_24m"], 5)),
        "dti_excess": max(0.0, float(application["dti_ratio"]) - 0.30),
        "fico_shortfall": max(0.0, 720.0 - float(application["fico_score"])),
        "utilization_excess": max(0.0, float(application["credit_utilization"]) - 0.60),
    }


def _build_reason_mapper() -> tuple[ReasonCodeMapper, CoefficientAttributor, ReasonCodeRegistry]:
    registry = ReasonCodeRegistry.with_appendix_c(
        taxonomy_version=REASON_TAXONOMY_VERSION,
        ecoa_feature_codes={
            "delinquency_count_capped": "AG-RB-C1-17",
            "dti_excess": "AG-RB-C1-09",
            "fico_shortfall": "AG-DEMO-PD-001",
            "utilization_excess": "AG-DEMO-PD-002",
        },
        additional_ecoa_codes=(
            ReasonCode(
                code="AG-DEMO-PD-001",
                code_set_version=REASON_TAXONOMY_VERSION,
                consumer_text="Credit score did not meet the required level",
                reg_b_ref="12 CFR 1002.9(b)(2)",
            ),
            ReasonCode(
                code="AG-DEMO-PD-002",
                code_set_version=REASON_TAXONOMY_VERSION,
                consumer_text="Revolving account utilization was too high",
                reg_b_ref="12 CFR 1002.9(b)(2)",
            ),
        ),
    )
    attributor = CoefficientAttributor(
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        reference_id=MODEL_REFERENCE_ID,
        coefficients=cast(
            "Mapping[str, Real]",
            {
                "delinquency_count_capped": 0.03,
                "dti_excess": 0.30,
                "fico_shortfall": 1 / 3000,
                "utilization_excess": 0.15,
            },
        ),
        reference_values=cast(
            "Mapping[str, Real]",
            dict.fromkeys(FEATURE_NAMES, 0.0),
        ),
        output_direction=OutputDirection.HIGHER_IS_MORE_ADVERSE,
    )
    return ReasonCodeMapper(registry), attributor, registry


def _score_pd(application: dict[str, Any]) -> float:
    """Map the same transformed risk terms used by the attributor to a stub PD."""

    terms = _pd_explanatory_features(application)
    pd_score = 0.015
    pd_score += terms["fico_shortfall"] / 3000
    pd_score += terms["dti_excess"] * 0.30
    pd_score += terms["delinquency_count_capped"] * 0.03
    pd_score += terms["utilization_excess"] * 0.15
    return float(max(0.001, min(0.95, pd_score)))


def _model_evidence(now: datetime) -> ModelGovernanceEvidence:
    """Pin validation and fairness evidence to this exact demo model/schema."""

    return ModelGovernanceEvidence(
        model_id=MODEL_ID,
        model_version=MODEL_VERSION,
        validation_status=ModelValidationStatus.VALIDATED,
        fairness_status=ModelFairnessStatus.PASSED,
        feature_schema_digest=feature_schema_digest(FEATURE_NAMES),
        validation_ref="a" * 64,
        fairness_ref="b" * 64,
        validated_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=1),
    )


async def main() -> None:
    audit_dir = Path("./credit-decisioning-audit")
    if audit_dir.exists():
        shutil.rmtree(audit_dir)
    audit_dir.mkdir()

    generator = SyntheticCreditGenerator(seed=42, default_rate=0.08)
    applications = generator.generate(n_samples=N_APPLICATIONS)
    print(f"Generated {len(applications)} synthetic applications")

    registry = AgentRegistry()
    identity = await registry.register(
        name="Credit Decisioning Agent",
        roles=["credit-analyst"],
        metadata={"workflow": "credit_decisioning_demo"},
    )
    governed_actions = (
        "model:score",
        "decision:approve",
        "decision:review",
        "decision:decline",
        "decision:override",
        "notice:issue",
    )
    rbac = RBACEngine(
        roles=[
            Role(
                name="credit-analyst",
                permissions=[
                    Permission(action=action, resource="*", effect="allow")
                    for action in governed_actions
                ],
            )
        ]
    )
    audit_log = AppendOnlyAuditLog(FileAuditBackend(audit_dir))
    tracer = AgentTracer(service_name="credit-decisioning-demo")
    policy_dir = audit_dir / "policies"
    policy_dir.mkdir()

    reason_mapper, pd_attributor, reason_registry = _build_reason_mapper()
    notice_provider = InMemoryPreparedNoticeProvider()
    now = datetime.now(UTC)
    guardrails = (
        DecisionEvidenceGuardrail(),
        ProtectedAttributeGuardrail({"race", "sex", "national_origin"}),
        ModelProvenanceGuardrail(StaticModelGovernanceEvidenceProvider((_model_evidence(now),))),
        DecisionBandGuardrail(),
        ReasonCodeGuardrail(reason_registry),
        AttributionIntegrityGuardrail(reason_mapper, reason_registry),
        NoticeCompletenessGuardrail(notice_provider),
    )
    kernel = GovernanceKernel(
        registry=registry,
        rbac_engine=rbac,
        audit_log=audit_log,
        policy_engine=PolicyEngine(policy_dirs=[policy_dir]),
        guardrails=guardrails,
        escalation_store=EscalationStore(
            audit_dir / "escalations",
            signing_key=secrets.token_bytes(32),
        ),
        tracer=tracer,
    )
    decision_policy = CreditDecisionPolicy(
        CreditDecisionPolicyConfig(
            policy_id="demo-pd-bands",
            policy_version="1",
            auto_approve_threshold=0.05,
            decline_threshold=0.09,
        )
    )
    credit_agent = GovernedCreditAgent(
        kernel,
        policy=decision_policy,
        notice_provider=notice_provider,
    )

    outcome_counts: Counter[str] = Counter()
    fairness_observations: list[FairnessObservation] = []
    declined_reason_codes: list[tuple[str, ...]] = []
    reviews = 0

    for app in applications:
        application_ref = str(app["application_id"])

        async def score_application(
            application: dict[str, Any] = app,
        ) -> CreditModelScore:
            attribution = pd_attributor.attribute(
                cast("Mapping[str, Real]", _pd_explanatory_features(application))
            )
            return CreditModelScore(
                pd_score=_score_pd(application),
                attribution=attribution,
            )

        score = await credit_agent.score(
            application_ref=application_ref,
            model_id=MODEL_ID,
            model_version=MODEL_VERSION,
            scorer=score_application,
            agent_id=identity.agent_id,
        )
        reason_selection = (
            reason_mapper.map(score.attribution)
            if score.pd_score >= decision_policy.config.decline_threshold
            else None
        )
        try:
            decision = await credit_agent.decide(
                decision_id=f"decision:{application_ref}",
                application_ref=application_ref,
                score=score,
                reason_selection=reason_selection,
                agent_id=identity.agent_id,
            )
        except EscalationRequiredError as exc:
            if exc.action != "decision:review":
                raise
            reviews += 1
            decision = None

        if decision is None:
            continue
        outcome_counts[decision.outcome.value] += 1
        group = str(app["synthetic_demographic_proxy"])
        if group in {"group_a", "group_b"}:
            fairness_outcome: Literal["approve", "decline"] = (
                "approve" if decision.outcome is CreditDecisionOutcome.APPROVE else "decline"
            )
            fairness_observations.append(
                FairnessObservation(
                    decision_ref=decision.decision_id,
                    group_name=group,
                    outcome=fairness_outcome,
                    predicted_pd=score.pd_score,
                    observed_default=bool(app["is_default"]),
                )
            )
        if decision.outcome is CreditDecisionOutcome.DECLINE:
            assert decision.reason_selection is not None
            declined_reason_codes.append(
                tuple(item.code.code for item in decision.reason_selection.reasons)
            )

    approved_total = outcome_counts[CreditDecisionOutcome.APPROVE.value]
    denied_total = outcome_counts[CreditDecisionOutcome.DECLINE.value]
    print(f"Decisions: {approved_total} approved, {denied_total} declined, {reviews} review")
    print(f"Mapped decline reason selections: {len(declined_reason_codes)}")
    if declined_reason_codes:
        print(f"  sample versioned reason codes: {declined_reason_codes[0]}")

    report = FairnessAnalyzer(
        disadvantaged_group="group_a",
        reference_group="group_b",
        min_group_size=100,
    ).analyze(fairness_observations)
    print("\n=== Fairness ===")
    print(
        f"Disparate impact ratio: {report.disparate_impact_ratio} "
        f"({report.disparate_impact_verdict})"
    )
    print(
        f"Equalized odds (TPR diff): {report.equalized_odds_tpr_diff} "
        f"({report.equalized_odds_verdict})"
    )
    print(f"Calibration max ECE:     {report.calibration_max_ece} ({report.calibration_verdict})")
    print(f"Overall verdict:         {report.overall_verdict}")

    events = await FileAuditBackend(audit_dir).read_all()
    metrics = MetricsDashboard().compute(events)
    print("\n=== Dashboard ===")
    print(f"Audit events:   {metrics.total_events}")
    print(f"Allowed:        {metrics.allowed_count}")
    print(f"Denied:         {metrics.denied_count}")
    print(f"Errors:         {metrics.error_count}")
    print(f"p50 latency:    {metrics.latency_p50_ms:.2f}ms")

    verification = await audit_log.verify_chain()
    print(f"\nAudit chain valid: {verification.valid} ({verification.event_count} events)")


if __name__ == "__main__":
    asyncio.run(main())
