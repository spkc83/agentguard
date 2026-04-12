"""Tests for agentguard.exceptions — exception hierarchy constructors."""

from __future__ import annotations

from agentguard.exceptions import (
    AuditError,
    AuditKeyMissingError,
    AuditTamperDetectedError,
    CircuitOpenError,
    DuplicateAgentError,
    IdentityNotFoundError,
    PermissionDeniedError,
    PolicyViolationError,
    SandboxError,
)


class TestPermissionDeniedError:
    def test_basic(self) -> None:
        err = PermissionDeniedError("agent-1", "tool:write", "secrets/*")
        assert err.agent_id == "agent-1"
        assert err.action == "tool:write"
        assert err.resource == "secrets/*"
        assert "agent-1" in str(err)
        assert "tool:write" in str(err)

    def test_with_reason(self) -> None:
        err = PermissionDeniedError("a", "act", "res", reason="explicit deny")
        assert err.reason == "explicit deny"
        assert "explicit deny" in str(err)


class TestPolicyViolationError:
    def test_basic(self) -> None:
        err = PolicyViolationError("OWASP-01", "Prompt Injection")
        assert err.rule_id == "OWASP-01"
        assert err.rule_name == "Prompt Injection"
        assert "OWASP-01" in str(err)

    def test_with_remediation(self) -> None:
        err = PolicyViolationError("R1", "Rule", remediation="Fix it")
        assert err.remediation == "Fix it"


class TestAuditErrors:
    def test_audit_error_base(self) -> None:
        err = AuditError("generic audit failure")
        assert "generic audit failure" in str(err)

    def test_audit_key_missing(self) -> None:
        err = AuditKeyMissingError()
        assert "AGENTGUARD_AUDIT_KEY" in str(err)

    def test_audit_tamper_detected(self) -> None:
        err = AuditTamperDetectedError(event_index=5, event_id="evt-abc")
        assert err.event_index == 5
        assert err.event_id == "evt-abc"
        assert "index=5" in str(err)


class TestIdentityErrors:
    def test_identity_not_found(self) -> None:
        err = IdentityNotFoundError("missing-agent")
        assert err.agent_id == "missing-agent"
        assert "missing-agent" in str(err)

    def test_duplicate_agent(self) -> None:
        err = DuplicateAgentError("dup-id")
        assert err.agent_id == "dup-id"
        assert "dup-id" in str(err)


class TestOtherErrors:
    def test_sandbox_error(self) -> None:
        err = SandboxError("container timeout")
        assert "container timeout" in str(err)

    def test_circuit_open_error(self) -> None:
        err = CircuitOpenError("credit-bureau-breaker")
        assert err.breaker_name == "credit-bureau-breaker"
        assert "credit-bureau-breaker" in str(err)
