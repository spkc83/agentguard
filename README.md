# AgentGuard

**Framework-agnostic governance and security runtime for AI agents in regulated industries.**

AgentGuard sits between your agent orchestration framework (LangGraph, CrewAI, Google ADK, or raw Python) and the tools/services your agents access. Today it enforces RBAC, HMAC-chained audit logging, and circuit breakers on every governed call; policy-as-code compliance checks, PII masking, human-in-the-loop escalation, and sandboxed execution exist as offline tools and are being moved onto the runtime path (see `docs/plans/guardrails-realignment.md`). The goal is a live guardrails engine for environments where security and regulatory compliance are non-negotiable.

Financial services / credit risk is the flagship domain, with built-in support for ECOA adverse action notices, SR 11-7 model validation, and fairness analysis under the Fair Housing Act.

## Current Status: v0.9.0 (Alpha)

AgentGuard is being realigned from a governance decorator into a live guardrails engine — see [docs/plans/guardrails-realignment.md](docs/plans/guardrails-realignment.md) for the gap analysis and phased plan.

### Enforced at runtime

Reachable from the governed call path today:

| Component | Description |
|-----------|-------------|
| Audit Logger | HMAC-SHA256 chained, append-only JSONL log (truncation detection and multi-writer safety are planned) |
| Agent Identity | In-memory and file-backed registries with atomic persistence |
| RBAC Engine | Deny-override semantics, role inheritance, wildcard matching |
| Circuit Breaker | CLOSED/OPEN/HALF_OPEN states + per-agent token bucket rate limiter |
| Shared governance pipeline | Identity → RBAC → circuit breaker → audit → call, used by every adapter |

### Offline analysis tools

Run by CLI / reports — not yet on the runtime call path:

| Component | Description |
|-----------|-------------|
| Policy Engine | YAML policy-as-code evaluator with 6 check types |
| Policy bundles | OWASP Top 10 for Agentic AI (10 rules), 15 controls informed by FINOS AIGF v2.0 (unofficial mapping), EU AI Act high-risk (10 rules) |
| Formal Verifier | Z3 SMT solver, RBAC model only — see ADR-013 caveat |
| HITL Escalation | Callback-based human-in-the-loop primitives (auto-approve/deny modes) |
| Compliance Reporter | JSON and Markdown compliance attestation reports |
| Replay Debugger | Audit log replay with filtering, timeline, and summarization |
| Metrics Dashboard | Denial rates, latency percentiles, agent activity, policy trends |
| OTel Tracer | One OpenTelemetry span per governed call, with NoOp fallback |
| Credit-risk toolkit | Decisioning template, adverse action notices, model validation, fairness analysis, PII masking, synthetic data generation |

### Wrappers awaiting framework validation

Duck-typed; import no framework code yet:

| Component | Description |
|-----------|-------------|
| LangGraph | `GovernedLangGraphToolNode` |
| CrewAI | `GovernedCrewAITool` |
| Google ADK | `GovernedAdkTool` |
| MCP | `GovernedMcpClient` |
| A2A | `GovernedA2AClient` |

Unit tests run with `pytest tests/unit/` (coverage gate: 80% in CI; current run is reported in the job log).

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
        | Layer 1: Security Runtime        |  Enforced at runtime
        |   RBAC, Identity, Audit,         |
        |   Circuit Breaker, Sandbox, MCP  |
        +----------------------------------+
        | Layer 2: Compliance Engine       |  Offline analysis tool
        |   Policy-as-Code, HITL, Z3,     |
        |   OWASP, FINOS, EU AI Act       |
        +----------------------------------+
        | Layer 3: Domain Toolkit          |  Offline analysis tool
        |   Credit Risk, Adverse Action,   |
        |   Fairness, PII, Synthetic Data  |
        +----------------------------------+
        | Layer 4: Integrations + Observe  |  Wrappers / offline analysis
        |   LangGraph, CrewAI, ADK, A2A,  |
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
# Audit log operations
agentguard audit show --log-dir ./audit-logs
agentguard audit verify --log-dir ./audit-logs
agentguard audit replay --log-dir ./audit-logs

# Policy management
agentguard policy validate                    # List all loaded policy rules
agentguard policy report --log-dir ./audit-logs  # Generate compliance report

# Formal verification
# The two `verify` commands need the Z3 extra: pip install 'agentguard[verify]'
agentguard verify policy                      # Check policy consistency via Z3
agentguard verify rbac --config rbac.yaml     # Verify RBAC escalation absence

# Observability
agentguard observe dashboard --log-dir ./audit-logs  # Aggregate metrics (JSON/Markdown)
agentguard observe replay    --log-dir ./audit-logs \
  --agent-id <uuid> --result denied           # Filtered replay with decision summaries
agentguard observe summary   --log-dir ./audit-logs  # Quick counts by result/agent/action
```

## Roadmap

Milestones below track code landing in `main`, not independent releases — only
`v0.2.0` has ever been tagged. The package version was `1.0.0` through M6 despite
this; see [CHANGELOG.md](CHANGELOG.md) for the `0.9.0` correction and
[docs/plans/guardrails-realignment.md](docs/plans/guardrails-realignment.md) for
what's next.

| Milestone | Code landed | Status | What |
|-----------|-------------|--------|------|
| M0+M1 | v0.1.0 | **Code complete** | Audit logger, RBAC, identity, CLI |
| M2 | v0.2.0 (tagged) | **Code complete** | Circuit breaker, Docker sandbox, MCP middleware, file-backed registry |
| M3 | — | **Code complete** | Compliance engine, Z3 formal verifier, OWASP/FINOS/EU AI Act policies |
| M4 | — | **Code complete** | Credit risk domain toolkit, synthetic data, adverse action, fairness |
| M5 | — | **Code complete** | LangGraph, CrewAI, Google ADK, A2A integrations |
| M6 | — | **Code complete** | Observability (OTel tracer, replay debugger, metrics dashboard) |

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
- [DECISIONS.md](DECISIONS.md) — architectural decision records (21 ADRs)
- [AGENTS.md](AGENTS.md) — agent role definitions for parallel development

## License

MIT
