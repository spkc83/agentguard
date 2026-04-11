"""End-to-end integration test: register -> check permission -> audit -> verify chain."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.models import AuditEvent


@pytest.mark.usefixtures("_set_audit_key")
async def test_full_governance_flow(tmp_audit_dir: Path) -> None:
    """Simulate: register agent -> check permission -> write audit event -> verify chain."""

    # 1. Set up identity registry
    registry = AgentRegistry()
    identity = await registry.register(
        name="Credit Analyst Bot",
        roles=["credit-analyst"],
        metadata={"framework": "test"},
    )

    # 2. Set up RBAC engine
    readonly = Role(
        name="readonly",
        permissions=[Permission(action="data:read:*", resource="*", effect="allow")],
    )
    analyst = Role(
        name="credit-analyst",
        permissions=[
            Permission(action="tool:credit_check", resource="bureau/*", effect="allow"),
            Permission(action="data:read:pii", resource="*", effect="deny"),
        ],
        inherited_roles=["readonly"],
    )
    engine = RBACEngine(roles=[readonly, analyst])

    # 3. Set up audit log
    audit_log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

    # 4. Simulate allowed action: credit check
    resolved = await registry.resolve(identity.agent_id)
    ctx_allowed = await engine.check_permission(
        resolved, action="tool:credit_check", resource="bureau/experian"
    )
    assert ctx_allowed.granted is True

    event_allowed = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC),
        agent_id=resolved.agent_id,
        action="tool:credit_check",
        resource="bureau/experian",
        permission_context=ctx_allowed,
        result="allowed",
        duration_ms=12.5,
        trace_id=str(uuid.uuid4()),
    )
    await audit_log.write(event_allowed)

    # 5. Simulate denied action: PII access
    ctx_denied = await engine.check_permission(
        resolved, action="data:read:pii", resource="customer_ssn"
    )
    assert ctx_denied.granted is False

    event_denied = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(UTC),
        agent_id=resolved.agent_id,
        action="data:read:pii",
        resource="customer_ssn",
        permission_context=ctx_denied,
        result="denied",
        duration_ms=0.5,
        trace_id=str(uuid.uuid4()),
    )
    await audit_log.write(event_denied)

    # 6. Verify audit chain integrity
    verification = await audit_log.verify_chain()
    assert verification.valid is True
    assert verification.event_count == 2
