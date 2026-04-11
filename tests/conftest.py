"""Shared test fixtures for AgentGuard test suite."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from agentguard.models import AgentIdentity, AuditEvent, PermissionContext

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def audit_key() -> str:
    """A deterministic HMAC key for tests."""
    return "test-audit-key-0123456789abcdef0123456789abcdef"


@pytest.fixture
def _set_audit_key(audit_key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Set AGENTGUARD_AUDIT_KEY env var for tests that need it."""
    monkeypatch.setenv("AGENTGUARD_AUDIT_KEY", audit_key)


@pytest.fixture
def tmp_audit_dir(tmp_path: Path) -> Path:
    """Temporary directory for audit log files."""
    d = tmp_path / "audit"
    d.mkdir()
    return d


@pytest.fixture
def sample_identity() -> AgentIdentity:
    """A sample agent identity for tests."""
    return AgentIdentity(
        agent_id="test-agent-001",
        name="Test Credit Analyst",
        roles=["credit-analyst", "readonly"],
        metadata={"framework": "test"},
    )


@pytest.fixture
def sample_permission_context(sample_identity: AgentIdentity) -> PermissionContext:
    """A sample granted permission context."""
    return PermissionContext(
        agent=sample_identity,
        requested_action="tool:credit_check",
        resource="bureau/experian",
        granted=True,
        reason="credit-analyst role grants tool:credit_check",
    )


@pytest.fixture
def sample_audit_event(
    sample_identity: AgentIdentity,
    sample_permission_context: PermissionContext,
) -> AuditEvent:
    """A sample audit event for tests."""
    return AuditEvent(
        event_id="evt-test-001",
        timestamp=datetime(2026, 4, 10, 12, 0, 0, tzinfo=UTC),
        agent_id=sample_identity.agent_id,
        action="tool:credit_check",
        resource="bureau/experian",
        permission_context=sample_permission_context,
        result="allowed",
        duration_ms=5.0,
        trace_id="trace-test-001",
    )
