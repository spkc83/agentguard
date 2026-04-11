"""Shared Pydantic models — the API contracts between AgentGuard layers.

These models are locked contracts. Breaking changes require a major version bump.
See AGENTS.md "Shared Contracts" section for the design rationale.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 — Pydantic needs this at runtime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class AgentIdentity(BaseModel):
    """An agent's identity as registered with AgentGuard.

    Args:
        agent_id: Stable UUID assigned at registration.
        name: Human-readable agent name.
        roles: List of role names assigned to this agent.
        metadata: Arbitrary key-value metadata (framework, version, owner, etc.).
    """

    model_config = ConfigDict(frozen=True)

    agent_id: str
    name: str
    roles: list[str]
    metadata: dict[str, str] = {}


class PermissionContext(BaseModel):
    """Result of an RBAC permission check.

    Args:
        agent: The agent requesting the action.
        requested_action: Action pattern (e.g. "tool:web_search", "data:read:pii").
        resource: Target resource (file path, URL, agent ID, etc.).
        context: Additional context for condition-based permission checks.
        granted: Whether the action was allowed.
        reason: Human-readable explanation of the decision.
    """

    model_config = ConfigDict(frozen=True)

    agent: AgentIdentity
    requested_action: str
    resource: str
    context: dict[str, Any] = {}
    granted: bool = False
    reason: str = ""


class PolicyResult(BaseModel):
    """Result of evaluating a single compliance policy rule.

    Args:
        rule_id: Unique rule identifier (e.g. "OWASP-AGENT-01", "FINOS-AIGF-012").
        rule_name: Human-readable rule name.
        passed: Whether the rule check passed.
        severity: Rule severity — critical, high, medium, or low.
        evidence: Data collected during evaluation (matched patterns, values, etc.).
        remediation: Recommended action if the rule failed.
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_name: str
    passed: bool
    severity: Literal["critical", "high", "medium", "low"]
    evidence: dict[str, Any]
    remediation: str


class AuditEvent(BaseModel):
    """A single entry in the immutable audit log.

    Frozen after creation — use model_copy(update={...}) to create modified copies.
    Every tool call, permission check, and policy evaluation produces an AuditEvent.
    Events are written BEFORE execution (log-first, act-second).

    Args:
        event_id: UUID for this event.
        timestamp: UTC timestamp.
        agent_id: The acting agent's ID.
        action: The action being performed.
        resource: The target resource.
        permission_context: Full RBAC decision context.
        result: Outcome — allowed, denied, escalated, or error.
        policy_results: Results from compliance policy evaluation.
        duration_ms: Time taken for the governed action (0 if pre-execution log).
        trace_id: OpenTelemetry trace ID for correlation.
        event_hash: HMAC-SHA256 hash of this event (set by audit logger).
        prev_hash: HMAC-SHA256 hash of the previous event in the chain.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str
    timestamp: datetime
    agent_id: str
    action: str
    resource: str
    permission_context: PermissionContext
    result: Literal["allowed", "denied", "escalated", "error"]
    policy_results: list[PolicyResult] = []
    duration_ms: float
    trace_id: str
    event_hash: str = ""
    prev_hash: str = ""


class SandboxResult(BaseModel):
    """Result from sandboxed tool execution.

    Args:
        stdout: Standard output from the tool.
        stderr: Standard error from the tool.
        exit_code: Process exit code (0 = success).
        duration_ms: Execution time in milliseconds.
        backend: Sandbox backend used — "docker", "wasm", or "none".
    """

    model_config = ConfigDict(frozen=True)

    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float
    backend: Literal["docker", "wasm", "none"]

    @property
    def success(self) -> bool:
        """True if exit_code is 0."""
        return self.exit_code == 0
