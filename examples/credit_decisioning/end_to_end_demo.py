"""End-to-end credit decisioning demo.

Walks through the full governed credit workflow:
    1. Generate synthetic credit applications.
    2. Stand up AgentGuard governance (identity, RBAC, audit, tracer).
    3. Score each application with a stub PD model.
    4. Run the CreditDecisioningAgent inside the governed pipeline.
    5. For declined applications, generate ECOA/Regulation B adverse action notices.
    6. Aggregate approval metrics across synthetic demographic groups and run
       a disparate-impact / equalized-odds / calibration fairness analysis.
    7. Verify the audit chain and dump a metrics dashboard.

Prerequisites:
    pip install agentguard
    export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

Run:
    python examples/credit_decisioning/end_to_end_demo.py
"""

from __future__ import annotations

import asyncio
import shutil
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.domains.finance.credit_risk.adverse_action import AdverseActionGenerator
from agentguard.domains.finance.credit_risk.agent_templates import (
    CreditDecisionConfig,
    CreditDecisioningAgent,
)
from agentguard.domains.finance.credit_risk.fairness import FairnessAnalyzer
from agentguard.domains.finance.synthetic.generators import SyntheticCreditGenerator
from agentguard.integrations._pipeline import run_governed
from agentguard.observability.dashboard import MetricsDashboard
from agentguard.observability.tracer import AgentTracer

N_APPLICATIONS = 200


def _score_pd(application: dict[str, Any]) -> float:
    """Simple stub PD model — maps risk factors to a probability of default.

    A real deployment would call a trained scorecard or ML model here. The
    formula is tuned so a typical 720-FICO / 0.30-DTI applicant lands well
    below the 0.05 auto-approve threshold.
    """
    fico = application["fico_score"]
    dti = application["dti_ratio"]
    delinq = application["delinquency_24m"]
    util = application["credit_utilization"]
    pd = 0.015
    pd += max(0.0, (720 - fico)) / 3000
    pd += max(0.0, dti - 0.30) * 0.30
    pd += min(delinq, 5) * 0.03
    pd += max(0.0, util - 0.60) * 0.15
    return max(0.001, min(0.95, pd))


async def main() -> None:
    audit_dir = Path("./credit-decisioning-audit")
    if audit_dir.exists():
        shutil.rmtree(audit_dir)
    audit_dir.mkdir()

    # 1. Synthetic applications (with demographic proxies for fairness testing).
    generator = SyntheticCreditGenerator(seed=42, default_rate=0.08)
    applications = generator.generate(n_samples=N_APPLICATIONS)
    print(f"Generated {len(applications)} synthetic applications")  # noqa: T201

    # 2. Governance stack.
    registry = AgentRegistry()
    agent = await registry.register(
        name="Credit Decisioning Agent",
        roles=["credit-analyst"],
        metadata={"workflow": "credit_decisioning_demo"},
    )

    rbac = RBACEngine(
        roles=[
            Role(
                name="credit-analyst",
                permissions=[
                    Permission(
                        action="tool:score_application", resource="model/pd_v1", effect="allow"
                    ),
                ],
            ),
        ]
    )
    audit_log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    tracer = AgentTracer(service_name="credit-decisioning-demo")

    # 3. Credit decisioning agent (template with PD bands + hard cutoffs).
    decision_agent = CreditDecisioningAgent(
        CreditDecisionConfig(
            auto_approve_threshold=0.05,
            decline_threshold=0.20,
            min_fico_score=620,
            max_dti_ratio=0.43,
        )
    )

    adverse = AdverseActionGenerator()

    # Per-demographic counters for fairness analysis.
    group_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "total": 0,
            "approved": 0,
            "denied": 0,
            "true_positives": 0,
            "false_positives": 0,
            "actual_positives": 0,
            "actual_negatives": 0,
        }
    )
    declined_notices: list[dict[str, Any]] = []
    reviews = 0

    # 4. Score + decide every application through the governed pipeline.
    for app in applications:
        pd_score = _score_pd(app)

        async def _score_and_decide(_app: dict[str, Any] = app, _pd: float = pd_score) -> Any:
            return decision_agent.evaluate(
                applicant_id=_app["application_id"],
                pd_score=_pd,
                application=_app,
            )

        decision = await run_governed(
            agent_id=agent.agent_id,
            action="tool:score_application",
            resource="model/pd_v1",
            registry=registry,
            rbac_engine=rbac,
            audit_log=audit_log,
            executor=_score_and_decide,
            tracer=tracer,
        )

        group = app["synthetic_demographic_proxy"]
        buckets = group_counts[group]
        buckets["total"] += 1
        if app["is_default"]:
            buckets["actual_positives"] += 1
        else:
            buckets["actual_negatives"] += 1

        if decision.decision == "approved":
            buckets["approved"] += 1
        elif decision.decision == "declined":
            buckets["denied"] += 1
            # Treat the PD model's "declined" call as the positive prediction:
            # TP = declined AND actually defaulted, FP = declined AND did not.
            if app["is_default"]:
                buckets["true_positives"] += 1
            else:
                buckets["false_positives"] += 1
            notice = adverse.generate(
                notice_id=str(uuid.uuid4()),
                applicant_id=decision.applicant_id,
                feature_importances=decision.feature_importances,
                pd_score=decision.pd_score,
                creditor_name="Acme Bank",
            )
            declined_notices.append({"applicant": decision.applicant_id, "reasons": notice.reasons})
        else:
            reviews += 1

    approved_total = sum(b["approved"] for b in group_counts.values())
    denied_total = sum(b["denied"] for b in group_counts.values())
    print(  # noqa: T201
        f"Decisions: {approved_total} approved, {denied_total} declined, {reviews} review"
    )
    print(f"Adverse action notices generated: {len(declined_notices)}")  # noqa: T201
    if declined_notices:
        sample = declined_notices[0]
        print(f"  sample: {sample['applicant']} -> {sample['reasons']}")  # noqa: T201

    # 5. Fairness analysis across demographic groups.
    fairness_input: dict[str, dict[str, Any]] = {}
    for group, buckets in group_counts.items():
        total = buckets["total"]
        if total == 0:
            continue
        fairness_input[group] = {
            **buckets,
            "predicted_default_rate": buckets["denied"] / total,
            "observed_default_rate": buckets["actual_positives"] / total,
        }
    report = FairnessAnalyzer().analyze(fairness_input)
    di_pass = report.disparate_impact_passed
    eo_pass = report.equalized_odds_passed
    print("\n=== Fairness ===")  # noqa: T201
    cal_pass = report.calibration_passed
    print(f"Disparate impact ratio: {report.disparate_impact_ratio} (pass={di_pass})")  # noqa: T201
    print(f"Equalized odds (TPR diff): {report.equalized_odds_tpr_diff} (pass={eo_pass})")  # noqa: T201
    print(f"Calibration max diff:    {report.calibration_max_diff} (pass={cal_pass})")  # noqa: T201
    print(f"Overall passed:          {report.overall_passed}")  # noqa: T201

    # 6. Metrics dashboard + tamper-evidence check.
    events = await FileAuditBackend(directory=audit_dir).read_all()
    metrics = MetricsDashboard().compute(events)
    print("\n=== Dashboard ===")  # noqa: T201
    print(f"Audit events:   {metrics.total_events}")  # noqa: T201
    print(f"Allowed:        {metrics.allowed_count}")  # noqa: T201
    print(f"Denied:         {metrics.denied_count}")  # noqa: T201
    print(f"Errors:         {metrics.error_count}")  # noqa: T201
    print(f"p50 latency:    {metrics.latency_p50_ms:.2f}ms")  # noqa: T201

    verification = await audit_log.verify_chain()
    print(f"\nAudit chain valid: {verification.valid} ({verification.event_count} events)")  # noqa: T201


if __name__ == "__main__":
    asyncio.run(main())
