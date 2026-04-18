# AgentGuard

**Framework-agnostic governance and security runtime for AI agents in regulated industries.**

AgentGuard sits between your agent orchestration framework (LangGraph, CrewAI, Google ADK, or raw Python) and the tools/services your agents access. It enforces RBAC, immutable audit logging, sandboxed execution, circuit breakers, and policy-as-code compliance rules — so you can deploy AI agents in environments where security and regulatory compliance are non-negotiable.

Financial services / credit risk is the flagship domain, with built-in support for ECOA adverse action notices, SR 11-7 model validation, and fairness analysis under the Fair Housing Act.

## Current Status: v1.0.0 (Production Release)

All 4 layers are implemented and tested:

| Component | Layer | Status | Description |
|-----------|-------|--------|-------------|
| Audit Logger | 1 | Done | HMAC-SHA256 chained, append-only, tamper-evident JSONL log |
| Agent Identity | 1 | Done | In-memory and file-backed registries with atomic persistence |
| RBAC Engine | 1 | Done | Deny-override semantics, role inheritance, wildcard matching |
| Circuit Breaker | 1 | Done | CLOSED/OPEN/HALF_OPEN states + per-agent token bucket rate limiter |
| Sandbox | 1 | Done | Docker container isolation + NoOp backend for dev/testing |
| MCP Middleware | 1 | Done | `GovernedMcpClient` — full governance pipeline for MCP tool calls |
| Policy Engine | 2 | Done | YAML policy-as-code evaluator with 6 check types |
| OWASP Policies | 2 | Done | 10 rules covering OWASP Top 10 for Agentic AI |
| FINOS Policies | 2 | Done | 15 rules from FINOS AI Governance Framework v2.0 |
| EU AI Act Policies | 2 | Done | 10 rules covering Articles 9, 10, 13, 14, 17 |
| Formal Verifier | 2 | Done | Z3 SMT solver — RBAC escalation, policy consistency, workflow safety |
| HITL Escalation | 2 | Done | Callback-based human-in-the-loop with auto-approve/deny modes |
| Compliance Reporter | 2 | Done | JSON and Markdown compliance attestation reports |
| Credit Decisioning | 3 | Done | Configurable PD-based agent template with auto/review/decline bands |
| Adverse Action | 3 | Done | ECOA/Reg B compliant notice generation with deterministic ordering |
| Model Validation | 3 | Done | SR 11-7 aligned validation workflow with structured findings |
| Fairness Analysis | 3 | Done | Disparate impact (4/5ths rule), equalized odds, calibration |
| PII Detection | 3 | Done | SSN, account numbers, email, phone masking |
| Synthetic Data | 3 | Done | Statistical generator + WGAN-GP (PyTorch) for credit data |
| LangGraph Integration | 4 | Done | `GovernedLangGraphToolNode` — governed tool execution |
| CrewAI Integration | 4 | Done | `GovernedCrewAITool` — governed CrewAI tool wrapper |
| Google ADK Integration | 4 | Done | `GovernedAdkTool` — governed ADK tool wrapper |
| A2A Middleware | 4 | Done | `GovernedA2AClient` — governed agent-to-agent messaging |
| OTel Tracer | 4 | Done | OpenTelemetry-native agent decision traces with NoOp fallback |
| Replay Debugger | 4 | Done | Audit log replay with filtering, timeline, and summarization |
| Metrics Dashboard | 4 | Done | Denial rates, latency percentiles, agent activity, policy trends |
| CLI | All | Done | `audit show/verify/replay`, `policy validate/report`, `verify rbac/policy` |
| CI | All | Done | GitHub Actions: lint, type check, test (Python 3.11 + 3.12) |

**278 tests, 92% coverage.**

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
        | Layer 1: Security Runtime        |  v0.2.0 Done
        |   RBAC, Identity, Audit,         |
        |   Circuit Breaker, Sandbox, MCP  |
        +----------------------------------+
        | Layer 2: Compliance Engine       |  v0.3.0 Done
        |   Policy-as-Code, HITL, Z3,     |
        |   OWASP, FINOS, EU AI Act       |
        +----------------------------------+
        | Layer 3: Domain Toolkit          |  v0.4.0 Done
        |   Credit Risk, Adverse Action,   |
        |   Fairness, PII, Synthetic Data  |
        +----------------------------------+
        | Layer 4: Integrations + Observe  |  v1.0.0 Done (current)
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
agentguard verify policy                      # Check policy consistency via Z3
agentguard verify rbac --config rbac.yaml     # Verify RBAC escalation absence

# Observability (v1.0)
agentguard observe dashboard --log-dir ./audit-logs  # Aggregate metrics (JSON/Markdown)
agentguard observe replay    --log-dir ./audit-logs \
  --agent-id <uuid> --result denied           # Filtered replay with decision summaries
agentguard observe summary   --log-dir ./audit-logs  # Quick counts by result/agent/action
```

## Roadmap

| Milestone | Version | Status | What |
|-----------|---------|--------|------|
| M0+M1 | v0.1.0 | **Done** | Audit logger, RBAC, identity, CLI |
| M2 | v0.2.0 | **Done** | Circuit breaker, Docker sandbox, MCP middleware, file-backed registry |
| M3 | v0.3.0 | **Done** | Compliance engine, Z3 formal verifier, OWASP/FINOS/EU AI Act policies |
| M4 | v0.4.0 | **Done** | Credit risk domain toolkit, synthetic data, adverse action, fairness |
| M5 | v0.5.0 | **Done** | LangGraph, CrewAI, Google ADK, A2A integrations |
| M6 | v1.0.0 | **Done** | Observability (OTel tracer, replay debugger, metrics dashboard) |

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
