"""AgentGuard v1.0.0 full-stack demo -- integrations + observability.

Simulates a credit agent running governed tool calls (success, denial, and
failure) through a LangGraph-style adapter, then generates a metrics
dashboard and filtered replay from the resulting audit log.

Prerequisites:
    pip install agentguard
    export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

Run:
    python examples/observability/monitoring_demo.py
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from unittest.mock import AsyncMock

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.exceptions import PermissionDeniedError
from agentguard.integrations.langgraph import GovernedLangGraphToolNode
from agentguard.observability.dashboard import MetricsDashboard
from agentguard.observability.replay import ReplayDebugger
from agentguard.observability.tracer import AgentTracer


class FakeTool:
    """Stand-in for a LangChain tool used in this demo."""

    def __init__(self, name: str, result: object, fails: bool = False) -> None:
        self.name = name
        if fails:
            self.ainvoke = AsyncMock(side_effect=RuntimeError(f"{name} downstream error"))
        else:
            self.ainvoke = AsyncMock(return_value=result)


async def main() -> None:
    audit_dir = Path("./observability-demo-audit")
    if audit_dir.exists():
        shutil.rmtree(audit_dir)
    audit_dir.mkdir()

    # --- Governance stack -----------------------------------------------------
    registry = AgentRegistry()
    agent = await registry.register(
        name="Credit Analyst",
        roles=["credit-analyst"],
        metadata={"team": "risk", "framework": "langgraph"},
    )

    engine = RBACEngine(
        roles=[
            Role(
                name="credit-analyst",
                permissions=[
                    Permission(action="tool:credit_check", resource="bureau/*", effect="allow"),
                    Permission(action="tool:score_model", resource="model/*", effect="allow"),
                    Permission(action="tool:unreliable_api", resource="bureau/*", effect="allow"),
                    Permission(action="tool:delete_customer", resource="*", effect="deny"),
                ],
            ),
        ]
    )

    audit_log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))

    # Optional OTel tracer. When opentelemetry is not installed this falls back
    # to no-op spans, so the demo runs in a vanilla install too.
    tracer = AgentTracer(service_name="credit-analyst-demo")
    print(f"Tracer active (OTel installed): {tracer.is_active}")  # noqa: T201

    # --- Integration adapter (LangGraph-style) --------------------------------
    tools = [
        FakeTool("credit_check", {"fico": 720}),
        FakeTool("score_model", {"pd": 0.03}),
        FakeTool("delete_customer", None),
        FakeTool("unreliable_api", None, fails=True),
    ]

    governed = GovernedLangGraphToolNode(
        tools=tools,
        agent_id=agent.agent_id,
        registry=registry,
        rbac_engine=engine,
        audit_log=audit_log,
        tracer=tracer,
    )

    # 1. Allowed call
    result = await governed.ainvoke(
        "credit_check", {"applicant_id": "A-001"}, resource="bureau/experian"
    )
    print(f"1. credit_check result: {result}")  # noqa: T201

    # 2. Allowed call (model scoring)
    result = await governed.ainvoke(
        "score_model", {"features": [720, 0.3]}, resource="model/pd_v1"
    )
    print(f"2. score_model result: {result}")  # noqa: T201

    # 3. Denied call — RBAC deny-override
    try:
        await governed.ainvoke("delete_customer", {"id": "A-001"}, resource="customers/A-001")
    except PermissionDeniedError as exc:
        print(f"3. delete_customer blocked: {exc}")  # noqa: T201

    # 4. Allowed call that fails downstream — error event is logged
    try:
        await governed.ainvoke(
            "unreliable_api", {"payload": 1}, resource="bureau/unreliable"
        )
    except RuntimeError as exc:
        print(f"4. unreliable_api errored: {exc}")  # noqa: T201

    # --- Observability: dashboard metrics -------------------------------------
    events = await FileAuditBackend(directory=audit_dir).read_all()
    dashboard = MetricsDashboard()
    metrics = dashboard.compute(events)

    print("\n=== Dashboard ===")  # noqa: T201
    print(f"Total events:  {metrics.total_events}")  # noqa: T201
    print(f"Allowed:       {metrics.allowed_count}")  # noqa: T201
    print(f"Denied:        {metrics.denied_count}")  # noqa: T201
    print(f"Errors:        {metrics.error_count}")  # noqa: T201
    print(f"Denial rate:   {metrics.denial_rate * 100:.1f}%")  # noqa: T201
    print(f"p50 latency:   {metrics.latency_p50_ms:.2f}ms")  # noqa: T201
    print(f"Top actions:   {metrics.top_actions[:3]}")  # noqa: T201

    # --- Observability: filtered replay ---------------------------------------
    debugger = ReplayDebugger()
    problems = debugger.filter(events, result=None)  # pull all
    denied = debugger.filter(events, result="denied")
    errored = debugger.filter(events, result="error")

    print("\n=== Replay: denied ===")  # noqa: T201
    for entry in debugger.timeline(denied):
        print(f"  {entry.index + 1}. {entry.decision_summary}")  # noqa: T201

    print("\n=== Replay: errors ===")  # noqa: T201
    for entry in debugger.timeline(errored):
        print(f"  {entry.index + 1}. {entry.decision_summary}")  # noqa: T201

    # --- Tamper-evidence check (chain verification) ---------------------------
    verification = await audit_log.verify_chain()
    print(f"\nAudit chain valid: {verification.valid} ({verification.event_count} events)")  # noqa: T201

    _ = problems  # silence unused-variable linter


if __name__ == "__main__":
    asyncio.run(main())
