# AgentGuard M0+M1 Implementation Plan — Scaffolding + Audit Logger + RBAC MVP

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a working Python package with immutable HMAC-chained audit logging, agent identity registry, and deny-override RBAC — the security foundation that every other AgentGuard layer depends on.

**Architecture:** Log-first, act-second, fail-closed. Every action is audit-logged before execution. RBAC uses deny-override semantics (like AWS IAM explicit-deny). The audit log is an append-only JSONL file with HMAC-SHA256 chain for tamper evidence. Identity is an in-memory registry (file-backed in M2). All core functions are async with sync wrappers.

**Tech Stack:** Python 3.11+, Pydantic v2, structlog, typer, pytest, pytest-asyncio, ruff, mypy

---

## File Structure

### New files to create (in order)

```
agentguard/
├── __init__.py                      # Package version, __all__ exports
├── exceptions.py                    # Base exception hierarchy
├── models.py                        # Shared Pydantic models (AgentIdentity, AuditEvent, etc.)
├── _logging.py                      # structlog configuration helper
├── core/
│   ├── __init__.py                  # Re-exports from core modules
│   ├── audit.py                     # AppendOnlyAuditLog, AuditBackend protocol, FileAuditBackend
│   ├── identity.py                  # AgentRegistry — in-memory agent identity store
│   └── rbac.py                      # Permission, Role, RBACEngine with deny-override
├── compliance/
│   └── __init__.py                  # Empty — placeholder for M3
├── domains/
│   └── __init__.py                  # Empty — placeholder for M4
├── integrations/
│   └── __init__.py                  # Empty — placeholder for M2/M5
├── observability/
│   └── __init__.py                  # Empty — placeholder for M6
└── cli.py                           # Typer CLI with audit subcommands

tests/
├── conftest.py                      # Shared fixtures (tmp dirs, sample identities, audit keys)
├── unit/
│   ├── __init__.py
│   └── core/
│       ├── __init__.py
│       ├── test_audit.py            # Audit log: write, read, HMAC chain, tamper detection
│       ├── test_identity.py         # Identity: register, resolve, not-found, list
│       └── test_rbac.py             # RBAC: grant, deny, deny-override, inheritance, wildcards
└── integration/
    ├── __init__.py
    └── test_core_e2e.py             # End-to-end: register → check permission → audit → verify chain

examples/
└── quickstart.py                    # 10-line working example

.github/
└── workflows/
    └── ci.yml                       # lint → type check → test
```

### Files to modify

- `CLAUDE.md` — Update repo layout section to match ADR-014 (credit risk, remove fraud references)
- `pyproject.toml` — Move z3-solver to lazy import pattern (keep in deps but document lazy usage)

---

## Task 1: Package skeleton and exceptions

**Files:**
- Create: `agentguard/__init__.py`
- Create: `agentguard/exceptions.py`
- Create: `agentguard/core/__init__.py`
- Create: `agentguard/compliance/__init__.py`
- Create: `agentguard/domains/__init__.py`
- Create: `agentguard/integrations/__init__.py`
- Create: `agentguard/observability/__init__.py`

- [ ] **Step 1: Create package directory structure**

```bash
mkdir -p agentguard/core agentguard/compliance agentguard/domains agentguard/integrations agentguard/observability
```

- [ ] **Step 2: Write `agentguard/exceptions.py`**

```python
"""AgentGuard exception hierarchy.

All custom exceptions inherit from AgentGuardError so callers can
catch the base class for broad error handling.
"""

from __future__ import annotations


class AgentGuardError(Exception):
    """Base exception for all AgentGuard errors."""


class PermissionDeniedError(AgentGuardError):
    """Raised when an agent lacks permission for the requested action."""

    def __init__(self, agent_id: str, action: str, resource: str, reason: str = "") -> None:
        self.agent_id = agent_id
        self.action = action
        self.resource = resource
        self.reason = reason
        msg = f"Permission denied: agent={agent_id} action={action} resource={resource}"
        if reason:
            msg += f" reason={reason}"
        super().__init__(msg)


class PolicyViolationError(AgentGuardError):
    """Raised when a policy evaluation finds a critical violation."""

    def __init__(self, rule_id: str, rule_name: str, remediation: str = "") -> None:
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.remediation = remediation
        super().__init__(f"Policy violation: {rule_id} ({rule_name})")


class AuditError(AgentGuardError):
    """Raised when the audit log cannot be written. Blocks action execution."""


class AuditKeyMissingError(AuditError):
    """Raised when AGENTGUARD_AUDIT_KEY env var is not set."""

    def __init__(self) -> None:
        super().__init__(
            "AGENTGUARD_AUDIT_KEY environment variable is required but not set. "
            "Generate a key with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )


class AuditTamperDetectedError(AuditError):
    """Raised when HMAC chain verification detects log tampering."""

    def __init__(self, event_index: int, event_id: str) -> None:
        self.event_index = event_index
        self.event_id = event_id
        super().__init__(
            f"Audit log tamper detected at index={event_index} event_id={event_id}"
        )


class IdentityNotFoundError(AgentGuardError):
    """Raised when an agent identity cannot be resolved."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        super().__init__(f"Agent identity not found: {agent_id}")


class SandboxError(AgentGuardError):
    """Raised when sandboxed tool execution fails."""


class CircuitOpenError(AgentGuardError):
    """Raised when a circuit breaker is in OPEN state and rejects the call."""

    def __init__(self, breaker_name: str) -> None:
        self.breaker_name = breaker_name
        super().__init__(f"Circuit breaker open: {breaker_name}")
```

- [ ] **Step 3: Write `agentguard/__init__.py`**

```python
"""AgentGuard — Framework-agnostic agent governance and security runtime."""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = [
    "__version__",
]
```

- [ ] **Step 4: Write placeholder `__init__.py` files for subpackages**

Each of these is the same minimal content:

```python
# agentguard/core/__init__.py
"""AgentGuard core security runtime."""
```

```python
# agentguard/compliance/__init__.py
"""AgentGuard compliance engine — policy evaluation, HITL, reporting."""
```

```python
# agentguard/domains/__init__.py
"""AgentGuard domain toolkits — pluggable industry modules."""
```

```python
# agentguard/integrations/__init__.py
"""AgentGuard framework integrations — MCP, A2A, LangGraph, CrewAI, ADK."""
```

```python
# agentguard/observability/__init__.py
"""AgentGuard observability — OTel traces, replay, dashboard."""
```

- [ ] **Step 5: Verify package installs**

Run: `pip install -e ".[dev]"`
Expected: Installs successfully, no errors.

- [ ] **Step 6: Verify import works**

Run: `python -c "import agentguard; print(agentguard.__version__)"`
Expected: `0.1.0`

- [ ] **Step 7: Commit**

```bash
git init
git add agentguard/ pyproject.toml CLAUDE.md AGENTS.md ARCHITECTURE.md DECISIONS.md PROJECT_PLAN.md
git commit -m "feat: initialize agentguard package with exception hierarchy"
```

---

## Task 2: Shared Pydantic models

**Files:**
- Create: `agentguard/models.py`
- Test: `tests/unit/test_models.py`
- Create: `tests/__init__.py`
- Create: `tests/unit/__init__.py`
- Create: `tests/unit/core/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Write the failing test**

Create `tests/__init__.py`, `tests/unit/__init__.py`, `tests/unit/core/__init__.py` as empty files.

Create `tests/unit/test_models.py`:

```python
"""Tests for agentguard.models — shared Pydantic contracts."""

from datetime import datetime, timezone

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
        # Pydantic model should be frozen (immutable after creation)
        try:
            identity.agent_id = "b"  # type: ignore[misc]
            assert False, "Should have raised"
        except Exception:
            pass


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
        try:
            PolicyResult(
                rule_id="X",
                rule_name="X",
                passed=True,
                severity="banana",  # type: ignore[arg-type]
                evidence={},
                remediation="",
            )
            assert False, "Should have raised validation error"
        except Exception:
            pass


class TestAuditEvent:
    def test_create_minimal(self) -> None:
        identity = AgentIdentity(agent_id="a", name="A", roles=["readonly"])
        ctx = PermissionContext(
            agent=identity, requested_action="tool:read", resource="file.txt", granted=True
        )
        event = AuditEvent(
            event_id="evt-001",
            timestamp=datetime.now(timezone.utc),
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
        ctx = PermissionContext(
            agent=identity, requested_action="x", resource="y"
        )
        try:
            AuditEvent(
                event_id="evt-002",
                timestamp=datetime.now(timezone.utc),
                agent_id="a",
                action="x",
                resource="y",
                permission_context=ctx,
                result="banana",  # type: ignore[arg-type]
                duration_ms=0,
                trace_id="t",
            )
            assert False, "Should have raised"
        except Exception:
            pass


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agentguard.models'`

- [ ] **Step 3: Write `agentguard/models.py`**

```python
"""Shared Pydantic models — the API contracts between AgentGuard layers.

These models are locked contracts. Breaking changes require a major version bump.
See AGENTS.md "Shared Contracts" section for the design rationale.
"""

from __future__ import annotations

from datetime import datetime
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
```

- [ ] **Step 4: Write `tests/conftest.py`**

```python
"""Shared test fixtures for AgentGuard test suite."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentguard.models import AgentIdentity, AuditEvent, PermissionContext


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
        timestamp=datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc),
        agent_id=sample_identity.agent_id,
        action="tool:credit_check",
        resource="bureau/experian",
        permission_context=sample_permission_context,
        result="allowed",
        duration_ms=5.0,
        trace_id="trace-test-001",
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/unit/test_models.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add agentguard/models.py tests/
git commit -m "feat: add shared Pydantic models and test fixtures"
```

---

## Task 3: structlog configuration and CI workflow

**Files:**
- Create: `agentguard/_logging.py`
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write `agentguard/_logging.py`**

```python
"""Structured logging configuration for AgentGuard.

Usage in any module:
    import structlog
    logger = structlog.get_logger()
    logger.info("event_name", key="value")
"""

from __future__ import annotations

import structlog


def configure_logging(*, json_output: bool = False) -> None:
    """Configure structlog for AgentGuard.

    Args:
        json_output: If True, output JSON lines. If False, output human-readable console format.
    """
    processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(0),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
```

- [ ] **Step 2: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: ruff format --check .

  typecheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e ".[dev]"
      - run: mypy agentguard/

  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -e ".[dev]"
      - name: Run unit tests
        env:
          AGENTGUARD_AUDIT_KEY: ci-test-key-0123456789abcdef0123456789abcdef
        run: pytest tests/unit/ -v --cov=agentguard --cov-report=term-missing --cov-fail-under=80
```

- [ ] **Step 3: Verify lint passes locally**

Run: `ruff check . && ruff format --check .`
Expected: No errors (fix any issues before proceeding).

- [ ] **Step 4: Commit**

```bash
mkdir -p .github/workflows
git add agentguard/_logging.py .github/workflows/ci.yml
git commit -m "chore: add structlog config and GitHub Actions CI"
```

---

## Task 4: Audit logger — tests first

**Files:**
- Create: `tests/unit/core/test_audit.py`
- Create: `agentguard/core/audit.py`

This is the most important module in the entire project. Everything depends on audit.
Build order: tests first, then implementation, per log-first-act-second philosophy.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/core/test_audit.py`:

```python
"""Tests for agentguard.core.audit — immutable HMAC-chained audit log."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.exceptions import AuditKeyMissingError, AuditTamperDetectedError
from agentguard.models import AgentIdentity, AuditEvent, PermissionContext


def _make_event(event_id: str = "evt-001", agent_id: str = "a") -> AuditEvent:
    """Helper to create a minimal AuditEvent for testing."""
    identity = AgentIdentity(agent_id=agent_id, name="Test", roles=["readonly"])
    ctx = PermissionContext(
        agent=identity, requested_action="tool:test", resource="res", granted=True
    )
    return AuditEvent(
        event_id=event_id,
        timestamp=datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc),
        agent_id=agent_id,
        action="tool:test",
        resource="res",
        permission_context=ctx,
        result="allowed",
        duration_ms=1.0,
        trace_id="trace-001",
    )


class TestFileAuditBackend:
    """Tests for the JSONL file-based audit storage."""

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_append_creates_file(self, tmp_audit_dir: Path) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        event = _make_event()
        await backend.append(event)

        files = list(tmp_audit_dir.glob("*.jsonl"))
        assert len(files) == 1

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_append_and_read_back(self, tmp_audit_dir: Path) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        event = _make_event()
        await backend.append(event)

        events = await backend.read_all()
        assert len(events) == 1
        assert events[0].event_id == "evt-001"

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_append_multiple(self, tmp_audit_dir: Path) -> None:
        backend = FileAuditBackend(directory=tmp_audit_dir)
        for i in range(5):
            await backend.append(_make_event(event_id=f"evt-{i:03d}"))

        events = await backend.read_all()
        assert len(events) == 5


class TestAppendOnlyAuditLog:
    """Tests for the HMAC-chained audit log."""

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_write_sets_hashes(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        event = _make_event()
        written = await log.write(event)

        assert written.event_hash != ""
        assert written.prev_hash == ""  # First event has no predecessor

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_chain_links(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        e1 = await log.write(_make_event(event_id="evt-001"))
        e2 = await log.write(_make_event(event_id="evt-002"))

        assert e2.prev_hash == e1.event_hash
        assert e2.event_hash != e1.event_hash

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_verify_chain_passes(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        for i in range(10):
            await log.write(_make_event(event_id=f"evt-{i:03d}"))

        result = await log.verify_chain()
        assert result.valid is True
        assert result.event_count == 10

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_verify_detects_tampering(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

        for i in range(5):
            await log.write(_make_event(event_id=f"evt-{i:03d}"))

        # Tamper with the log file: modify event at index 2
        log_files = list(tmp_audit_dir.glob("*.jsonl"))
        assert len(log_files) == 1
        lines = log_files[0].read_text().strip().split("\n")
        tampered = json.loads(lines[2])
        tampered["action"] = "tool:HACKED"
        lines[2] = json.dumps(tampered)
        log_files[0].write_text("\n".join(lines) + "\n")

        with pytest.raises(AuditTamperDetectedError) as exc_info:
            await log.verify_chain()
        assert exc_info.value.event_index == 2

    async def test_missing_key_raises(self, tmp_audit_dir: Path) -> None:
        """Without AGENTGUARD_AUDIT_KEY, constructing the log should fail."""
        with pytest.raises(AuditKeyMissingError):
            AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))

    @pytest.mark.usefixtures("_set_audit_key")
    async def test_empty_log_verifies(self, tmp_audit_dir: Path) -> None:
        log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=tmp_audit_dir))
        result = await log.verify_chain()
        assert result.valid is True
        assert result.event_count == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/core/test_audit.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agentguard.core.audit'`

- [ ] **Step 3: Write `agentguard/core/audit.py`**

```python
"""Immutable, HMAC-chained append-only audit log.

Design principle: log-first, act-second. If the audit write fails,
the action MUST be blocked. The HMAC chain provides tamper evidence —
modifying any past event breaks the chain, detectable via verify_chain().

The audit key is read from the AGENTGUARD_AUDIT_KEY environment variable.
This is required — there is no default key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import date
from pathlib import Path
from typing import Protocol, runtime_checkable

import structlog
from pydantic import BaseModel

from agentguard.exceptions import AuditKeyMissingError, AuditTamperDetectedError
from agentguard.models import AuditEvent

logger = structlog.get_logger()


class ChainVerificationResult(BaseModel):
    """Result of verifying the HMAC chain integrity."""

    valid: bool
    event_count: int
    error_index: int | None = None
    error_event_id: str | None = None


@runtime_checkable
class AuditBackend(Protocol):
    """Protocol for pluggable audit log storage backends."""

    async def append(self, event: AuditEvent) -> None:
        """Append a single event to the log."""
        ...

    async def read_all(self) -> list[AuditEvent]:
        """Read all events from the log, in insertion order."""
        ...


class FileAuditBackend:
    """JSONL file-based audit storage.

    Events are written one-per-line to a date-stamped JSONL file
    in the configured directory. Files are named audit-YYYY-MM-DD.jsonl.

    Args:
        directory: Path to the directory where audit log files are stored.
    """

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._directory.mkdir(parents=True, exist_ok=True)

    def _log_file(self) -> Path:
        return self._directory / f"audit-{date.today().isoformat()}.jsonl"

    async def append(self, event: AuditEvent) -> None:
        """Append event as a JSON line to today's audit file."""
        line = event.model_dump_json() + "\n"
        log_file = self._log_file()
        with open(log_file, "a") as f:
            f.write(line)
        logger.debug("audit_event_written", event_id=event.event_id, file=str(log_file))

    async def read_all(self) -> list[AuditEvent]:
        """Read all events from all JSONL files in the directory, sorted by filename."""
        events: list[AuditEvent] = []
        for log_file in sorted(self._directory.glob("audit-*.jsonl")):
            with open(log_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(AuditEvent.model_validate_json(line))
        return events


class AppendOnlyAuditLog:
    """HMAC-chained immutable audit log.

    Each event's hash covers its content + the hash of the previous event,
    forming a tamper-evident chain. Modifying any event invalidates all
    subsequent hashes.

    Args:
        backend: Storage backend (default: FileAuditBackend).

    Raises:
        AuditKeyMissingError: If AGENTGUARD_AUDIT_KEY env var is not set.
    """

    def __init__(self, backend: AuditBackend) -> None:
        key = os.environ.get("AGENTGUARD_AUDIT_KEY", "")
        if not key:
            raise AuditKeyMissingError()
        self._key = key.encode("utf-8")
        self._backend = backend
        self._prev_hash = ""

    def _compute_hash(self, event: AuditEvent) -> str:
        """Compute HMAC-SHA256 over event content + prev_hash."""
        # Serialize event without hash fields for deterministic hashing
        data = event.model_copy(update={"event_hash": "", "prev_hash": event.prev_hash})
        payload = data.model_dump_json().encode("utf-8")
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    async def write(self, event: AuditEvent) -> AuditEvent:
        """Write an event to the audit log with HMAC chain linking.

        Args:
            event: The audit event to write. event_hash and prev_hash
                   will be set automatically.

        Returns:
            The event with event_hash and prev_hash populated.
        """
        chained = event.model_copy(update={"prev_hash": self._prev_hash})
        event_hash = self._compute_hash(chained)
        chained = chained.model_copy(update={"event_hash": event_hash})

        await self._backend.append(chained)
        self._prev_hash = event_hash

        logger.info(
            "audit_event_logged",
            event_id=chained.event_id,
            action=chained.action,
            result=chained.result,
        )
        return chained

    async def verify_chain(self) -> ChainVerificationResult:
        """Verify the HMAC chain integrity of the entire audit log.

        Returns:
            ChainVerificationResult with valid=True if chain is intact.

        Raises:
            AuditTamperDetectedError: If tampering is detected.
        """
        events = await self._backend.read_all()
        if not events:
            return ChainVerificationResult(valid=True, event_count=0)

        prev_hash = ""
        for i, event in enumerate(events):
            # Reconstruct what the hash should be
            check_event = event.model_copy(
                update={"event_hash": "", "prev_hash": prev_hash}
            )
            expected_hash = self._compute_hash(check_event)

            if event.prev_hash != prev_hash:
                raise AuditTamperDetectedError(event_index=i, event_id=event.event_id)

            if event.event_hash != expected_hash:
                raise AuditTamperDetectedError(event_index=i, event_id=event.event_id)

            prev_hash = event.event_hash

        return ChainVerificationResult(valid=True, event_count=len(events))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/core/test_audit.py -v`
Expected: All 7 tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass (models + audit).

- [ ] **Step 6: Commit**

```bash
git add agentguard/core/audit.py tests/unit/core/test_audit.py
git commit -m "feat: add HMAC-chained append-only audit logger with tamper detection"
```

---

## Task 5: Agent identity registry

**Files:**
- Create: `tests/unit/core/test_identity.py`
- Create: `agentguard/core/identity.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/core/test_identity.py`:

```python
"""Tests for agentguard.core.identity — agent identity registry."""

from __future__ import annotations

import pytest

from agentguard.core.identity import AgentRegistry
from agentguard.exceptions import IdentityNotFoundError
from agentguard.models import AgentIdentity


class TestAgentRegistry:
    async def test_register_returns_identity(self) -> None:
        registry = AgentRegistry()
        identity = await registry.register(
            name="Credit Analyst Bot",
            roles=["credit-analyst"],
            metadata={"framework": "langgraph"},
        )
        assert isinstance(identity, AgentIdentity)
        assert identity.name == "Credit Analyst Bot"
        assert identity.roles == ["credit-analyst"]
        assert identity.agent_id  # should be a non-empty UUID

    async def test_register_generates_unique_ids(self) -> None:
        registry = AgentRegistry()
        id1 = await registry.register(name="A", roles=[])
        id2 = await registry.register(name="B", roles=[])
        assert id1.agent_id != id2.agent_id

    async def test_resolve_existing(self) -> None:
        registry = AgentRegistry()
        registered = await registry.register(name="Bot", roles=["readonly"])
        resolved = await registry.resolve(registered.agent_id)
        assert resolved.agent_id == registered.agent_id
        assert resolved.name == "Bot"

    async def test_resolve_not_found_raises(self) -> None:
        registry = AgentRegistry()
        with pytest.raises(IdentityNotFoundError) as exc_info:
            await registry.resolve("nonexistent-id")
        assert exc_info.value.agent_id == "nonexistent-id"

    async def test_list_agents_empty(self) -> None:
        registry = AgentRegistry()
        agents = await registry.list_agents()
        assert agents == []

    async def test_list_agents(self) -> None:
        registry = AgentRegistry()
        await registry.register(name="A", roles=["readonly"])
        await registry.register(name="B", roles=["credit-analyst"])
        agents = await registry.list_agents()
        assert len(agents) == 2
        names = {a.name for a in agents}
        assert names == {"A", "B"}

    async def test_register_with_explicit_id(self) -> None:
        registry = AgentRegistry()
        identity = await registry.register(
            name="Explicit",
            roles=["readonly"],
            agent_id="my-custom-id",
        )
        assert identity.agent_id == "my-custom-id"
        resolved = await registry.resolve("my-custom-id")
        assert resolved.name == "Explicit"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/core/test_identity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agentguard.core.identity'`

- [ ] **Step 3: Write `agentguard/core/identity.py`**

```python
"""Agent identity registry.

In-memory registry for v0.1. Stores AgentIdentity instances keyed by agent_id.
Thread-safe via asyncio.Lock. File-backed persistence planned for v0.2.

Usage:
    registry = AgentRegistry()
    identity = await registry.register(name="My Agent", roles=["readonly"])
    resolved = await registry.resolve(identity.agent_id)
"""

from __future__ import annotations

import asyncio
import uuid

import structlog

from agentguard.exceptions import IdentityNotFoundError
from agentguard.models import AgentIdentity

logger = structlog.get_logger()


class AgentRegistry:
    """In-memory agent identity registry.

    Stores agent identities in a dict. Thread-safe for concurrent async access.
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentIdentity] = {}
        self._lock = asyncio.Lock()

    async def register(
        self,
        name: str,
        roles: list[str],
        metadata: dict[str, str] | None = None,
        agent_id: str | None = None,
    ) -> AgentIdentity:
        """Register a new agent identity.

        Args:
            name: Human-readable agent name.
            roles: List of role names to assign.
            metadata: Optional key-value metadata.
            agent_id: Optional explicit ID. If None, a UUID4 is generated.

        Returns:
            The created AgentIdentity.
        """
        if agent_id is None:
            agent_id = str(uuid.uuid4())

        identity = AgentIdentity(
            agent_id=agent_id,
            name=name,
            roles=roles,
            metadata=metadata or {},
        )

        async with self._lock:
            self._agents[agent_id] = identity

        logger.info("agent_registered", agent_id=agent_id, name=name, roles=roles)
        return identity

    async def resolve(self, agent_id: str) -> AgentIdentity:
        """Resolve an agent identity by ID.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            The resolved AgentIdentity.

        Raises:
            IdentityNotFoundError: If no agent with this ID is registered.
        """
        async with self._lock:
            identity = self._agents.get(agent_id)

        if identity is None:
            raise IdentityNotFoundError(agent_id)

        return identity

    async def list_agents(self) -> list[AgentIdentity]:
        """List all registered agent identities.

        Returns:
            List of all registered AgentIdentity objects.
        """
        async with self._lock:
            return list(self._agents.values())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/core/test_identity.py -v`
Expected: All 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add agentguard/core/identity.py tests/unit/core/test_identity.py
git commit -m "feat: add in-memory agent identity registry"
```

---

## Task 6: RBAC engine — tests first

**Files:**
- Create: `tests/unit/core/test_rbac.py`
- Create: `agentguard/core/rbac.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/core/test_rbac.py`:

```python
"""Tests for agentguard.core.rbac — deny-override RBAC engine."""

from __future__ import annotations

import pytest

from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.models import AgentIdentity


def _identity(roles: list[str]) -> AgentIdentity:
    return AgentIdentity(agent_id="test", name="Test", roles=roles)


class TestPermission:
    def test_exact_match(self) -> None:
        perm = Permission(action="tool:credit_check", resource="bureau/experian", effect="allow")
        assert perm.matches("tool:credit_check", "bureau/experian") is True

    def test_no_match_action(self) -> None:
        perm = Permission(action="tool:credit_check", resource="*", effect="allow")
        assert perm.matches("tool:web_search", "anything") is False

    def test_wildcard_action(self) -> None:
        perm = Permission(action="tool:*", resource="*", effect="allow")
        assert perm.matches("tool:credit_check", "bureau/experian") is True
        assert perm.matches("tool:web_search", "google.com") is True

    def test_wildcard_resource(self) -> None:
        perm = Permission(action="tool:credit_check", resource="*", effect="allow")
        assert perm.matches("tool:credit_check", "bureau/experian") is True
        assert perm.matches("tool:credit_check", "bureau/equifax") is True

    def test_prefix_wildcard(self) -> None:
        perm = Permission(action="tool:credit_*", resource="bureau/*", effect="allow")
        assert perm.matches("tool:credit_check", "bureau/experian") is True
        assert perm.matches("tool:credit_score", "bureau/equifax") is True
        assert perm.matches("tool:web_search", "bureau/experian") is False

    def test_data_action(self) -> None:
        perm = Permission(action="data:read:pii", resource="*", effect="deny")
        assert perm.matches("data:read:pii", "customer_records") is True


class TestRole:
    def test_role_with_permissions(self) -> None:
        role = Role(
            name="credit-analyst",
            permissions=[
                Permission(action="tool:credit_check", resource="*", effect="allow"),
                Permission(action="data:read:pii", resource="*", effect="deny"),
            ],
        )
        assert role.name == "credit-analyst"
        assert len(role.permissions) == 2

    def test_role_with_inheritance(self) -> None:
        readonly = Role(
            name="readonly",
            permissions=[Permission(action="data:read:*", resource="*", effect="allow")],
        )
        analyst = Role(
            name="credit-analyst",
            permissions=[Permission(action="tool:credit_check", resource="*", effect="allow")],
            inherited_roles=["readonly"],
        )
        assert analyst.inherited_roles == ["readonly"]


class TestRBACEngine:
    def _build_engine(self) -> RBACEngine:
        """Build an engine with the built-in credit-risk roles."""
        readonly = Role(
            name="readonly",
            permissions=[
                Permission(action="data:read:*", resource="*", effect="allow"),
            ],
        )
        analyst = Role(
            name="credit-analyst",
            permissions=[
                Permission(action="tool:credit_check", resource="bureau/*", effect="allow"),
                Permission(action="tool:income_verify", resource="*", effect="allow"),
                Permission(action="data:read:pii", resource="*", effect="deny"),
            ],
            inherited_roles=["readonly"],
        )
        reviewer = Role(
            name="credit-reviewer",
            permissions=[
                Permission(action="tool:*", resource="*", effect="allow"),
                Permission(action="data:write:*", resource="*", effect="allow"),
            ],
            inherited_roles=["credit-analyst"],
        )
        system = Role(
            name="system-agent",
            permissions=[
                Permission(action="*", resource="*", effect="allow"),
            ],
        )
        return RBACEngine(roles=[readonly, analyst, reviewer, system])

    async def test_allow_simple(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["credit-analyst"]),
            action="tool:credit_check",
            resource="bureau/experian",
        )
        assert ctx.granted is True

    async def test_deny_no_matching_role(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["readonly"]),
            action="tool:credit_check",
            resource="bureau/experian",
        )
        assert ctx.granted is False
        assert "no matching" in ctx.reason.lower() or "denied" in ctx.reason.lower()

    async def test_deny_override(self) -> None:
        """Explicit deny beats allow — credit-analyst cannot read PII."""
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["credit-analyst"]),
            action="data:read:pii",
            resource="customer_records",
        )
        assert ctx.granted is False
        assert "deny" in ctx.reason.lower()

    async def test_deny_override_even_with_inherited_allow(self) -> None:
        """credit-analyst inherits data:read:* from readonly, but has explicit deny on data:read:pii."""
        engine = self._build_engine()
        # data:read:reports should be allowed via inherited readonly
        ctx_reports = await engine.check_permission(
            _identity(["credit-analyst"]),
            action="data:read:reports",
            resource="monthly",
        )
        assert ctx_reports.granted is True

        # data:read:pii should be denied via explicit deny on credit-analyst
        ctx_pii = await engine.check_permission(
            _identity(["credit-analyst"]),
            action="data:read:pii",
            resource="customer_records",
        )
        assert ctx_pii.granted is False

    async def test_role_inheritance(self) -> None:
        """credit-analyst inherits data:read from readonly."""
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["credit-analyst"]),
            action="data:read:reports",
            resource="monthly",
        )
        assert ctx.granted is True

    async def test_multi_level_inheritance(self) -> None:
        """credit-reviewer inherits from credit-analyst which inherits from readonly."""
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["credit-reviewer"]),
            action="data:read:reports",
            resource="monthly",
        )
        assert ctx.granted is True

    async def test_system_agent_wildcard(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["system-agent"]),
            action="anything:at_all",
            resource="any/resource",
        )
        assert ctx.granted is True

    async def test_no_roles_denies(self) -> None:
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity([]),
            action="tool:credit_check",
            resource="bureau/experian",
        )
        assert ctx.granted is False

    async def test_unknown_role_ignored(self) -> None:
        """Roles not registered in the engine are silently ignored (deny by default)."""
        engine = self._build_engine()
        ctx = await engine.check_permission(
            _identity(["nonexistent-role"]),
            action="tool:credit_check",
            resource="bureau/experian",
        )
        assert ctx.granted is False

    async def test_permission_context_fields(self) -> None:
        engine = self._build_engine()
        identity = _identity(["credit-analyst"])
        ctx = await engine.check_permission(
            identity,
            action="tool:credit_check",
            resource="bureau/experian",
        )
        assert ctx.agent == identity
        assert ctx.requested_action == "tool:credit_check"
        assert ctx.resource == "bureau/experian"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/core/test_rbac.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agentguard.core.rbac'`

- [ ] **Step 3: Write `agentguard/core/rbac.py`**

```python
"""Role-based access control with deny-override semantics.

Design: mirrors AWS IAM's explicit-deny model. If any matching permission
has effect="deny", the action is denied regardless of other allow permissions.
This is the deny-override combination algorithm (XACML standard).

Resolution order:
1. Collect all permissions from all of the agent's roles (including inherited roles).
2. Find permissions whose action and resource patterns match the request.
3. If ANY matching permission has effect="deny" → DENIED.
4. If at least one matching permission has effect="allow" → ALLOWED.
5. If no matching permissions at all → DENIED (deny by default).
"""

from __future__ import annotations

import fnmatch

import structlog
from pydantic import BaseModel, ConfigDict

from agentguard.models import AgentIdentity, PermissionContext

logger = structlog.get_logger()


class Permission(BaseModel):
    """A single permission rule.

    Args:
        action: Action pattern — supports fnmatch wildcards (e.g. "tool:*", "data:read:*").
        resource: Resource pattern — supports fnmatch wildcards (e.g. "bureau/*", "*").
        effect: "allow" or "deny".
    """

    model_config = ConfigDict(frozen=True)

    action: str
    resource: str
    effect: str  # "allow" | "deny"

    def matches(self, action: str, resource: str) -> bool:
        """Check if this permission matches the given action and resource.

        Uses fnmatch for glob-style pattern matching.
        """
        return fnmatch.fnmatch(action, self.action) and fnmatch.fnmatch(
            resource, self.resource
        )


class Role(BaseModel):
    """A named role with permissions and optional inheritance.

    Args:
        name: Unique role name (e.g. "credit-analyst").
        permissions: List of permission rules attached to this role.
        inherited_roles: Names of roles whose permissions this role inherits.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    permissions: list[Permission] = []
    inherited_roles: list[str] = []


class RBACEngine:
    """Deny-override RBAC permission checker.

    Args:
        roles: List of Role definitions. Roles reference each other by name
               via inherited_roles.
    """

    def __init__(self, roles: list[Role]) -> None:
        self._roles: dict[str, Role] = {r.name: r for r in roles}

    def _collect_permissions(self, role_name: str, visited: set[str] | None = None) -> list[Permission]:
        """Recursively collect permissions from a role and its ancestors.

        Args:
            role_name: The role to collect permissions for.
            visited: Set of already-visited role names (cycle protection).

        Returns:
            Flat list of all permissions from this role and inherited roles.
        """
        if visited is None:
            visited = set()

        if role_name in visited:
            return []
        visited.add(role_name)

        role = self._roles.get(role_name)
        if role is None:
            return []

        perms = list(role.permissions)
        for parent_name in role.inherited_roles:
            perms.extend(self._collect_permissions(parent_name, visited))

        return perms

    async def check_permission(
        self,
        identity: AgentIdentity,
        action: str,
        resource: str,
    ) -> PermissionContext:
        """Check whether an agent has permission for the given action on the resource.

        Uses deny-override semantics:
        1. Collect all permissions from all of the agent's roles.
        2. Find matching permissions.
        3. If any deny → denied. If any allow → allowed. Otherwise → denied.

        Args:
            identity: The agent's identity.
            action: The action being attempted (e.g. "tool:credit_check").
            resource: The target resource (e.g. "bureau/experian").

        Returns:
            PermissionContext with granted=True/False and a reason string.
        """
        all_permissions: list[Permission] = []
        for role_name in identity.roles:
            all_permissions.extend(self._collect_permissions(role_name))

        matching = [p for p in all_permissions if p.matches(action, resource)]

        # Deny-override: any deny wins
        denies = [p for p in matching if p.effect == "deny"]
        if denies:
            reason = f"Explicit deny from permission: action={denies[0].action} resource={denies[0].resource}"
            logger.info(
                "permission_denied",
                agent_id=identity.agent_id,
                action=action,
                resource=resource,
                reason=reason,
            )
            return PermissionContext(
                agent=identity,
                requested_action=action,
                resource=resource,
                granted=False,
                reason=reason,
            )

        # Any allow?
        allows = [p for p in matching if p.effect == "allow"]
        if allows:
            reason = f"Allowed by permission: action={allows[0].action} resource={allows[0].resource}"
            logger.info(
                "permission_granted",
                agent_id=identity.agent_id,
                action=action,
                resource=resource,
            )
            return PermissionContext(
                agent=identity,
                requested_action=action,
                resource=resource,
                granted=True,
                reason=reason,
            )

        # Default deny
        reason = "No matching permissions found (deny by default)"
        logger.info(
            "permission_denied",
            agent_id=identity.agent_id,
            action=action,
            resource=resource,
            reason=reason,
        )
        return PermissionContext(
            agent=identity,
            requested_action=action,
            resource=resource,
            granted=False,
            reason=reason,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/core/test_rbac.py -v`
Expected: All 11 tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass (models + audit + identity + RBAC).

- [ ] **Step 6: Commit**

```bash
git add agentguard/core/rbac.py tests/unit/core/test_rbac.py
git commit -m "feat: add deny-override RBAC engine with role inheritance"
```

---

## Task 7: End-to-end integration test

**Files:**
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/test_core_e2e.py`

- [ ] **Step 1: Write the integration test**

Create `tests/integration/__init__.py` (empty file).

Create `tests/integration/test_core_e2e.py`:

```python
"""End-to-end integration test: register → check permission → audit → verify chain.

This test exercises the full M1 stack without Docker or external services.
"""

from __future__ import annotations

import pytest

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.models import AuditEvent

from datetime import datetime, timezone
from pathlib import Path
import uuid


@pytest.mark.usefixtures("_set_audit_key")
async def test_full_governance_flow(tmp_audit_dir: Path) -> None:
    """Simulate: register agent → check permission → write audit event → verify chain."""

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
        timestamp=datetime.now(timezone.utc),
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
        timestamp=datetime.now(timezone.utc),
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
```

- [ ] **Step 2: Run the integration test**

Run: `pytest tests/integration/test_core_e2e.py -v`
Expected: PASS — full governance flow works end-to-end.

- [ ] **Step 3: Run entire test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/
git commit -m "test: add end-to-end integration test for identity → RBAC → audit flow"
```

---

## Task 8: CLI skeleton with audit commands

**Files:**
- Create: `agentguard/cli.py`

- [ ] **Step 1: Write `agentguard/cli.py`**

```python
"""AgentGuard CLI — command-line interface for audit, policy, and verification.

Entry point: `agentguard` (configured in pyproject.toml).

Usage:
    agentguard audit show --log-dir ./audit-logs
    agentguard audit verify --log-dir ./audit-logs
    agentguard policy validate --file policies/owasp.yaml   (coming in M3)
    agentguard verify rbac --config rbac.yaml                (coming in M3)
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from agentguard._logging import configure_logging

app = typer.Typer(
    name="agentguard",
    help="Agent governance and security runtime for AI agents.",
    no_args_is_help=True,
)
audit_app = typer.Typer(help="Audit log operations.")
policy_app = typer.Typer(help="Policy management. (Coming in v0.3.0)")
verify_app = typer.Typer(help="Formal verification. (Coming in v0.3.0)")

app.add_typer(audit_app, name="audit")
app.add_typer(policy_app, name="policy")
app.add_typer(verify_app, name="verify")

console = Console()


@app.callback()
def main(
    json_output: bool = typer.Option(False, "--json", help="Output in JSON format."),
) -> None:
    """AgentGuard — governance runtime for AI agents."""
    configure_logging(json_output=json_output)


@audit_app.command("show")
def audit_show(
    log_dir: Path = typer.Option("./audit-logs", help="Audit log directory."),
    agent_id: str | None = typer.Option(None, help="Filter by agent ID."),
) -> None:
    """Show audit log events."""
    from agentguard.core.audit import FileAuditBackend

    async def _show() -> None:
        backend = FileAuditBackend(directory=log_dir)
        events = await backend.read_all()

        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]

        if not events:
            console.print("[yellow]No audit events found.[/yellow]")
            return

        table = Table(title=f"Audit Events ({len(events)} total)")
        table.add_column("Event ID", style="dim")
        table.add_column("Timestamp")
        table.add_column("Agent")
        table.add_column("Action")
        table.add_column("Resource")
        table.add_column("Result", style="bold")

        for event in events:
            result_style = {
                "allowed": "green",
                "denied": "red",
                "escalated": "yellow",
                "error": "red bold",
            }.get(event.result, "white")
            table.add_row(
                event.event_id[:12] + "...",
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                event.agent_id[:12] + "...",
                event.action,
                event.resource,
                f"[{result_style}]{event.result}[/{result_style}]",
            )

        console.print(table)

    asyncio.run(_show())


@audit_app.command("verify")
def audit_verify(
    log_dir: Path = typer.Option("./audit-logs", help="Audit log directory."),
) -> None:
    """Verify audit log HMAC chain integrity."""
    from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
    from agentguard.exceptions import AuditTamperDetectedError

    async def _verify() -> None:
        try:
            log = AppendOnlyAuditLog(backend=FileAuditBackend(directory=log_dir))
            result = await log.verify_chain()
            if result.valid:
                console.print(
                    f"[green]✓ Audit chain verified.[/green] {result.event_count} events, no tampering detected."
                )
            else:
                console.print("[red]✗ Audit chain verification failed.[/red]")
        except AuditTamperDetectedError as e:
            console.print(
                f"[red bold]✗ TAMPER DETECTED[/red bold] at event index {e.event_index} "
                f"(event_id={e.event_id})"
            )
            raise typer.Exit(code=1)

    asyncio.run(_verify())


@policy_app.command("validate")
def policy_validate() -> None:
    """Validate a policy YAML file. (Coming in v0.3.0)"""
    console.print("[yellow]Policy validation will be available in v0.3.0.[/yellow]")


@verify_app.command("rbac")
def verify_rbac() -> None:
    """Formally verify RBAC configuration. (Coming in v0.3.0)"""
    console.print("[yellow]Formal RBAC verification will be available in v0.3.0.[/yellow]")
```

- [ ] **Step 2: Verify CLI loads**

Run: `python -m agentguard.cli --help`
Expected: Shows help text with `audit`, `policy`, `verify` subcommands.

Run: `python -m agentguard.cli audit --help`
Expected: Shows `show` and `verify` commands.

- [ ] **Step 3: Commit**

```bash
git add agentguard/cli.py
git commit -m "feat: add Typer CLI with audit show/verify commands"
```

---

## Task 9: Quickstart example and CLAUDE.md update

**Files:**
- Create: `examples/quickstart.py`
- Modify: `CLAUDE.md` — update repo layout for ADR-014

- [ ] **Step 1: Write `examples/quickstart.py`**

```python
"""AgentGuard Quickstart — 5 minutes to governed agent execution.

Prerequisites:
    pip install agentguard
    export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

Run:
    python examples/quickstart.py
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role
from agentguard.models import AuditEvent


async def main() -> None:
    # 1. Register an agent
    registry = AgentRegistry()
    agent = await registry.register(name="Credit Bot", roles=["credit-analyst"])
    print(f"Registered: {agent.name} ({agent.agent_id})")

    # 2. Define roles with deny-override RBAC
    engine = RBACEngine(roles=[
        Role(name="credit-analyst", permissions=[
            Permission(action="tool:credit_check", resource="bureau/*", effect="allow"),
            Permission(action="data:read:pii", resource="*", effect="deny"),
        ]),
    ])

    # 3. Check permission (allowed)
    ctx = await engine.check_permission(agent, "tool:credit_check", "bureau/experian")
    print(f"Credit check: granted={ctx.granted} — {ctx.reason}")

    # 4. Check permission (denied — PII access blocked)
    ctx_pii = await engine.check_permission(agent, "data:read:pii", "customer_ssn")
    print(f"PII access:   granted={ctx_pii.granted} — {ctx_pii.reason}")

    # 5. Write to tamper-evident audit log
    audit_dir = Path("./quickstart-audit")
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=audit_dir))
    event = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
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
    print(f"Audit chain: valid={result.valid}, events={result.event_count}")


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: Run the quickstart**

Run: `AGENTGUARD_AUDIT_KEY=demo-key-1234 python examples/quickstart.py`
Expected: Prints registered agent, permission results, and audit verification.

- [ ] **Step 3: Update CLAUDE.md repo layout for ADR-014**

In `CLAUDE.md`, replace the `domains/finance/` section of the repository layout to remove fraud references and use credit risk structure:

Replace:
```
│   ├── domains/                 # Layer 3: Domain Toolkits
│   │   └── finance/
│   │       ├── fraud/
│   │       │   ├── agent_templates.py   # Fraud investigation agent templates
│   │       │   ├── sar_pipeline.py      # SAR generation pipeline
│   │       │   └── red_team.py          # Adversarial eval suite
│   │       ├── synthetic/
│   │       │   ├── wgan_gp.py           # Wasserstein GAN-GP for tabular fraud data
│   │       │   └── generators.py        # High-level synthetic data API
│   │       └── pii.py                   # PII detection and masking
```

With:
```
│   ├── domains/                 # Layer 3: Domain Toolkits
│   │   └── finance/
│   │       ├── credit_risk/
│   │       │   ├── agent_templates.py   # Credit decisioning agent templates
│   │       │   ├── adverse_action.py    # ECOA/Reg B adverse action notice generation
│   │       │   ├── model_validation.py  # SR 11-7 model validation agent patterns
│   │       │   ├── fairness.py          # Disparate impact / equalized odds analysis
│   │       │   └── red_team.py          # Credit AI adversarial eval suite
│   │       ├── synthetic/
│   │       │   ├── wgan_gp.py           # Wasserstein GAN-GP for tabular credit data
│   │       │   └── generators.py        # High-level synthetic data API
│   │       └── pii.py                   # PII detection and masking
```

Also replace any remaining references to "fraud" in example paths:
- `examples/fraud_investigation/` → `examples/credit_decisioning/`
- `examples/sar_generation/` → `examples/adverse_action_generation/`

- [ ] **Step 4: Commit**

```bash
mkdir -p examples
git add examples/quickstart.py CLAUDE.md
git commit -m "feat: add quickstart example, update CLAUDE.md for ADR-014 credit risk pivot"
```

---

## Task 10: Coverage check and final M1 polish

**Files:**
- Modify: `agentguard/core/__init__.py` — re-export public API

- [ ] **Step 1: Update `agentguard/core/__init__.py` with re-exports**

```python
"""AgentGuard core security runtime.

Public API:
    from agentguard.core import AgentRegistry, RBACEngine, AppendOnlyAuditLog
"""

from agentguard.core.audit import AppendOnlyAuditLog, FileAuditBackend
from agentguard.core.identity import AgentRegistry
from agentguard.core.rbac import Permission, RBACEngine, Role

__all__ = [
    "AgentRegistry",
    "AppendOnlyAuditLog",
    "FileAuditBackend",
    "Permission",
    "RBACEngine",
    "Role",
]
```

- [ ] **Step 2: Run full test suite with coverage**

Run: `AGENTGUARD_AUDIT_KEY=test-key pytest tests/ -v --cov=agentguard --cov-report=term-missing`
Expected: All tests pass. Coverage ≥ 80% on `agentguard/core/`.

- [ ] **Step 3: Run linter and type checker**

Run: `ruff check . --fix && ruff format .`
Run: `mypy agentguard/`
Expected: No errors.

- [ ] **Step 4: Commit final polish**

```bash
git add agentguard/core/__init__.py
git commit -m "chore: re-export core public API, verify coverage and lint"
```

---

## Summary

| Task | What it builds | Key files | Tests |
|------|---------------|-----------|-------|
| 1 | Package skeleton + exceptions | `agentguard/__init__.py`, `exceptions.py` | — |
| 2 | Shared Pydantic models | `agentguard/models.py` | `test_models.py` |
| 3 | Logging + CI | `_logging.py`, `ci.yml` | — |
| 4 | Audit logger (HMAC chain) | `core/audit.py` | `test_audit.py` (7 tests) |
| 5 | Identity registry | `core/identity.py` | `test_identity.py` (7 tests) |
| 6 | RBAC engine (deny-override) | `core/rbac.py` | `test_rbac.py` (11 tests) |
| 7 | Integration test | `test_core_e2e.py` | 1 e2e test |
| 8 | CLI (audit show/verify) | `cli.py` | manual verification |
| 9 | Quickstart + CLAUDE.md fix | `examples/quickstart.py`, `CLAUDE.md` | manual verification |
| 10 | Coverage check + polish | `core/__init__.py` | full suite run |

**Total estimated tests:** ~30 unit tests + 1 integration test.
**Target coverage:** 80%+ on `agentguard/core/`.
**Commits:** 10 atomic commits following conventional commit format.
