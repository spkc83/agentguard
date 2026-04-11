"""Tests for agentguard.models — shared Pydantic contracts."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from agentguard.models import (
    AgentIdentity,
    AuditEvent,
    PermissionContext,
    PolicyResult,
    SandboxResult,
)


class TestAgentIdentity:
    def test_create_minimal(self) -> None:
        identity = AgentIdentity(agent_id="agent-1", name="Test Agent", roles=["readonly"])
        assert identity.agent_id == "agent-1"
        assert identity.name == "Test Agent"
        assert identity.roles == ["readonly"]
        assert identity.metadata == {}

    def test_create_with_metadata(self) -> None:
        identity = AgentIdentity(
            agent_id="agent-2",
            name="Credit Agent",
            roles=["credit-analyst", "readonly"],
            metadata={"framework": "langgraph", "version": "0.2"},
        )
        assert identity.metadata["framework"] == "langgraph"

    def test_frozen(self) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=[])
        with pytest.raises(ValidationError):
            identity.agent_id = "b"  # type: ignore[misc]


class TestPermissionContext:
    def test_defaults(self) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=["readonly"])
        ctx = PermissionContext(
            agent=identity,
            requested_action="tool:web_search",
            resource="https://example.com",
        )
        assert ctx.granted is False
        assert ctx.reason == ""
        assert ctx.context == {}

    def test_granted(self) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=["system-agent"])
        ctx = PermissionContext(
            agent=identity,
            requested_action="tool:web_search",
            resource="*",
            granted=True,
            reason="system-agent has wildcard access",
        )
        assert ctx.granted is True


class TestPolicyResult:
    def test_create(self) -> None:
        result = PolicyResult(
            rule_id="OWASP-AGENT-01",
            rule_name="Prompt Injection Detection",
            passed=False,
            severity="critical",
            evidence={"matched_pattern": "ignore previous instructions"},
            remediation="Sanitize user inputs before prompt interpolation.",
        )
        assert result.passed is False
        assert result.severity == "critical"

    def test_severity_validation(self) -> None:
        """Severity must be one of: critical, high, medium, low."""
        with pytest.raises(ValidationError):
            PolicyResult(
                rule_id="X",
                rule_name="X",
                passed=True,
                severity="banana",  # type: ignore[arg-type]
                evidence={},
                remediation="",
            )


class TestAuditEvent:
    def test_create_minimal(self) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=["readonly"])
        ctx = PermissionContext(
            agent=identity, requested_action="tool:read", resource="file.txt", granted=True
        )
        event = AuditEvent(
            event_id="evt-001",
            timestamp=datetime.now(UTC),
            agent_id="a",
            action="tool:read",
            resource="file.txt",
            permission_context=ctx,
            result="allowed",
            duration_ms=1.5,
            trace_id="trace-abc",
        )
        assert event.result == "allowed"
        assert event.policy_results == []
        assert event.event_hash == ""
        assert event.prev_hash == ""

    def test_result_validation(self) -> None:
        """Result must be one of: allowed, denied, escalated, error."""
        identity = AgentIdentity(agent_id="a", name="A", roles=[])
        ctx = PermissionContext(agent=identity, requested_action="x", resource="y")
        with pytest.raises(ValidationError):
            AuditEvent(
                event_id="evt-002",
                timestamp=datetime.now(UTC),
                agent_id="a",
                action="x",
                resource="y",
                permission_context=ctx,
                result="banana",  # type: ignore[arg-type]
                duration_ms=0,
                trace_id="t",
            )


class TestSandboxResult:
    def test_create(self) -> None:
        result = SandboxResult(
            stdout="hello",
            stderr="",
            exit_code=0,
            duration_ms=42.0,
            backend="docker",
        )
        assert result.exit_code == 0
        assert result.success is True

    def test_failure(self) -> None:
        result = SandboxResult(
            stdout="",
            stderr="error: timeout",
            exit_code=1,
            duration_ms=30000.0,
            backend="docker",
        )
        assert result.success is False
