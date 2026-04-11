"""AgentGuard Quickstart -- 5 minutes to governed agent execution.

Prerequisites:
    pip install agentguard
    export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

Run:
    python examples/quickstart.py
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from pathlib import Path

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.models import AuditEvent


async def main() -> None:
    """Run the AgentGuard quickstart demo."""
    # 1. Register an agent
    registry = AgentRegistry()
    agent = await registry.register(name="Credit Bot", roles=["credit-analyst"])
    print(f"Registered: {agent.name} ({agent.agent_id})")  # noqa: T201

    # 2. Define roles with deny-override RBAC
    engine = RBACEngine(
        roles=[
            Role(
                name="credit-analyst",
                permissions=[
                    Permission(action="tool:credit_check", resource="bureau/*", effect="allow"),
                    Permission(action="data:read:pii", resource="*", effect="deny"),
                ],
            ),
        ]
    )

    # 3. Check permission (allowed)
    ctx = await engine.check_permission(agent, "tool:credit_check", "bureau/experian")
    print(f"Credit check: granted={ctx.granted} -- {ctx.reason}")  # noqa: T201

    # 4. Check permission (denied -- PII access blocked)
    ctx_pii = await engine.check_permission(agent, "data:read:pii", "customer_ssn")
    print(f"PII access:   granted={ctx_pii.granted} -- {ctx_pii.reason}")  # noqa: T201

    # 5. Write to tamper-evident audit log
    audit_dir = Path("./quickstart-audit")
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    event = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC),
        agent_id=agent.agent_id,
        action="tool:credit_check",
        resource="bureau/experian",
        permission_context=ctx,
        result="allowed",
        duration_ms=5.0,
        trace_id=str(uuid.uuid4()),
    )
    await audit.write(event)

    # 6. Verify chain integrity
    result = await audit.verify_chain()
    print(f"Audit chain: valid={result.valid}, events={result.event_count}")  # noqa: T201


if __name__ == "__main__":
    asyncio.run(main())
