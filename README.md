# AgentGuard

**Framework-agnostic governance and security runtime for AI agents in regulated industries.**

AgentGuard sits between your agent orchestration framework (LangGraph, CrewAI, Google ADK, or raw Python) and the tools/services your agents access. It enforces RBAC, immutable audit logging, sandboxed execution, circuit breakers, and policy-as-code compliance rules — so you can deploy AI agents in environments where security and regulatory compliance are non-negotiable.

Financial services / credit risk is the flagship domain, with built-in support for ECOA adverse action notices, SR 11-7 model validation, and fairness analysis under the Fair Housing Act.

## Current Status: v0.1.0 (Milestone 1)

The core security runtime is implemented and tested:

| Component | Status | Description |
|-----------|--------|-------------|
| Audit Logger | Done | HMAC-SHA256 chained, append-only, tamper-evident JSONL log |
| Agent Identity | Done | In-memory registry with register, resolve, list |
| RBAC Engine | Done | Deny-override semantics, role inheritance, wildcard matching |
| CLI | Done | `agentguard audit show` and `agentguard audit verify` |
| Shared Models | Done | Frozen Pydantic v2 contracts for all layers |
| CI | Done | GitHub Actions: lint, type check, test (Python 3.11 + 3.12) |

**52 tests, 90% coverage.**

## Quickstart

```bash
pip install -e "."
export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
```

```python
import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agentguard.core import AgentRegistry, AppendOnlyAuditLog, FileAuditBackend
from agentguard.core import RBACEngine, Role, Permission
from agentguard.models import AuditEvent


async def main():
    # 1. Register an agent
    registry = AgentRegistry()
    agent = await registry.register(name="Credit Bot", roles=["credit-analyst"])

    # 2. Define RBAC roles (deny-override: explicit deny always wins)
    engine = RBACEngine(roles=[
        Role(name="credit-analyst", permissions=[
            Permission(action="tool:credit_check", resource="bureau/*", effect="allow"),
            Permission(action="data:read:pii", resource="*", effect="deny"),
        ]),
    ])

    # 3. Check permissions
    allowed = await engine.check_permission(agent, "tool:credit_check", "bureau/experian")
    print(f"Credit check: granted={allowed.granted}")  # True

    denied = await engine.check_permission(agent, "data:read:pii", "customer_ssn")
    print(f"PII access:   granted={denied.granted}")    # False

    # 4. Write to tamper-evident audit log
    audit = AppendOnlyAuditLog(backend=FileAuditBackend(directory=Path("./audit-logs")))
    await audit.write(AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        agent_id=agent.agent_id,
        action="tool:credit_check",
        resource="bureau/experian",
        permission_context=allowed,
        result="allowed",
        duration_ms=5.0,
        trace_id=str(uuid.uuid4()),
    ))

    # 5. Verify chain integrity
    result = await audit.verify_chain()
    print(f"Audit chain: valid={result.valid}, events={result.event_count}")


asyncio.run(main())
```

## Architecture

```
Your Agent Application (LangGraph / CrewAI / ADK / Python)
                    |
                    v
        AgentGuard Runtime Middleware
        +----------------------------------+
        | Layer 1: Security Runtime        |  <-- v0.1.0 (current)
        |   RBAC, Identity, Audit          |
        +----------------------------------+
        | Layer 2: Compliance Engine       |  <-- v0.3.0
        |   Policy-as-Code, HITL, Z3      |
        +----------------------------------+
        | Layer 3: Domain Toolkit          |  <-- v0.4.0
        |   Credit Risk, Fairness, PII    |
        +----------------------------------+
        | Layer 4: Observability           |  <-- v1.0.0
        |   OTel Traces, Replay, Metrics  |
        +----------------------------------+
                    |
                    v
        Tools / Services / External APIs
```

### Design Principles

- **Zero-trust by default** — agents have no permissions unless explicitly granted
- **Log-first, act-second** — every action is audit-logged before execution; if logging fails, the action is blocked
- **Deny-override RBAC** — explicit deny always wins, like AWS IAM
- **Tamper-evident audit** — HMAC-SHA256 chain; modifying any past event breaks the chain
- **Framework-agnostic** — works with any agent framework; integrations are adapters, not requirements
- **Fail-safe over fail-open** — when governance errors, it blocks the action, not allows it

## CLI

```bash
# Show audit log events
agentguard audit show --log-dir ./audit-logs

# Verify audit chain integrity (detects tampering)
agentguard audit verify --log-dir ./audit-logs
```

## Roadmap

| Milestone | Version | Status | What |
|-----------|---------|--------|------|
| M0+M1 | v0.1.0 | **Done** | Audit logger, RBAC, identity, CLI |
| M2 | v0.2.0 | Planned | Circuit breaker, Docker sandbox, MCP middleware |
| M3 | v0.3.0 | Planned | Compliance engine, Z3 formal verifier, OWASP/FINOS/EU AI Act policies |
| M4 | v0.4.0 | Planned | Credit risk domain toolkit, WGAN-GP synthetic data, adverse action generator |
| M5 | v0.5.0 | Planned | LangGraph, CrewAI, Google ADK integrations |
| M6 | v1.0.0 | Planned | Observability (OTel), replay debugger, production-ready release |

See [PROJECT_PLAN.md](PROJECT_PLAN.md) for detailed milestone breakdowns.

## Development

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Lint + format
ruff check . --fix && ruff format .

# Type check
mypy agentguard/

# Test
AGENTGUARD_AUDIT_KEY=dev-key pytest tests/unit/ -v

# All tests with coverage
AGENTGUARD_AUDIT_KEY=dev-key pytest tests/ --cov=agentguard --cov-report=term-missing
```

## Project Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — full architecture reference (4 layers, threat model, deployment patterns)
- [DECISIONS.md](DECISIONS.md) — architectural decision records (14 ADRs)
- [PROJECT_PLAN.md](PROJECT_PLAN.md) — 12-month milestone roadmap
- [AGENTS.md](AGENTS.md) — agent role definitions for parallel development

## License

MIT
