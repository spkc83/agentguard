---
created: "2026-04-19"
last_edited: "2026-04-19"
---

# Cavekit Overview

## Project

**AgentGuard** — open-source, framework-agnostic agent governance and security runtime for AI agents in regulated industries. Sits between agent orchestration frameworks (LangGraph, CrewAI, Google ADK, MCP, A2A) and the tools/services they access, enforcing RBAC, sandboxed execution, immutable audit logging, circuit breakers, and policy-as-code compliance rules. Financial services / credit risk is the flagship domain.

This kit set was reverse-engineered (`/ck:sketch --from-code`) from the **v1.0.0 production codebase** in **strict-as-built** mode: every requirement reflects current behavior, and capabilities mentioned in `ARCHITECTURE.md` or `DECISIONS.md` that are not yet implemented are explicitly listed in each kit's "Out of Scope" section, marked `[GAP]`.

## Domain Index

| Domain | Kit File | Requirements | Complexity | Status | Description |
|--------|----------|--------------|------------|--------|-------------|
| Security Runtime (Layer 1) | cavekit-security-runtime.md | 10 | complex | DRAFT | Identity, RBAC (deny-override), HMAC-chained audit log, sandbox (Docker + NoOp), circuit breaker, per-agent rate limiter, log-first contract |
| Compliance Engine (Layer 2) | cavekit-compliance-engine.md | 10 | medium | DRAFT | YAML policy-as-code (35 built-in rules: OWASP/FINOS/EU AI Act), Z3 formal verifier (RBAC, consistency, workflow), HITL escalation, attestation reporter |
| Finance Credit Risk (Layer 3) | cavekit-finance-credit-risk.md | 7 | medium | DRAFT | Credit decisioning template, ECOA/Reg B adverse action, SR 11-7 model validation, fairness (4/5ths, equalized odds, calibration), PII masking, synthetic data (statistical + WGAN-GP) |
| Framework Integrations | cavekit-framework-integrations.md | 8 | quick | DRAFT | Shared `run_governed` pipeline, governed adapters for MCP, A2A, LangGraph, CrewAI, Google ADK |
| Observability (Layer 4) | cavekit-observability.md | 8 | quick | DRAFT | OTel-native tracer (NoOp fallback, library-mode safety), audit-log replay debugger, metrics dashboard with JSON/Markdown serialization |
| CLI Surface | cavekit-cli-surface.md | 12 | quick | DRAFT | Command groups: `audit` (show/verify/replay), `policy` (validate/report), `verify` (rbac/policy), `observe` (dashboard/replay/summary) |

**Totals:** 6 domains, 55 requirements, ~278 backing tests (92% coverage).

## Cross-Reference Map

| From Domain | Depends On | Interaction Type |
|-------------|-----------|------------------|
| compliance-engine | security-runtime | Consumes `AuditEvent` and `PermissionContext` for policy evaluation |
| finance-credit-risk | security-runtime | Credit-risk tools are invoked through governed pipeline (RBAC, audit, sandbox) |
| finance-credit-risk | compliance-engine | Fairness results and PII signals feed compliance evaluation and HITL escalation |
| framework-integrations | security-runtime | Shared pipeline composes RBAC, audit log, circuit breaker, identity registry |
| framework-integrations | observability | Adapters accept optional tracer for full-pipeline span wrapping |
| observability | security-runtime | Reads `AuditEvent` from file backend as single source of truth (no second store) |
| cli-surface | security-runtime | `audit show/verify/replay` commands |
| cli-surface | compliance-engine | `policy validate/report`, `verify rbac/policy` commands |
| cli-surface | observability | `observe dashboard/replay/summary` commands |
| cli-surface | finance-credit-risk | Credit-risk outputs surface through `policy report` (no direct subcommand) |
| cli-surface | framework-integrations | Adapter activity surfaces through `audit show` and `observe replay` |

No circular dependencies. Forms a layered DAG with `security-runtime` as the foundation (no incoming non-CLI deps) and `cli-surface` as the apex (depends on all other domains).

## Dependency Graph

Implement / specify in this order (later layers depend on earlier ones):

```
1. security-runtime          (foundation — no internal dependencies)
       │
       ├─► 2. compliance-engine        (consumes audit events)
       │       │
       │       ▼
       ├─► 3. finance-credit-risk      (uses runtime + compliance)
       │
       ├─► 4. observability            (reads audit events)
       │       ▲
       │       │
       └─► 5. framework-integrations   (uses runtime + optional tracer)
                  │
                  ▼
            6. cli-surface             (apex — surfaces all layers)
```

Tier ordering for `/ck:map`:
- **Tier 0:** security-runtime
- **Tier 1:** compliance-engine, observability (parallelizable)
- **Tier 2:** finance-credit-risk, framework-integrations (parallelizable)
- **Tier 3:** cli-surface

## Documented Gaps (from strict-as-built reverse-engineering)

The following capabilities appear in `ARCHITECTURE.md` or `DECISIONS.md` but are NOT in v1.0.0 code; they are marked `[GAP]` in their kits' Out of Scope sections rather than as requirements:

| Kit | Gap | Source |
|-----|-----|--------|
| compliance-engine | Z3 properties 4 (credit-model monotonicity) and 5 (adverse-action determinism) | ARCHITECTURE.md §Layer 2 |
| finance-credit-risk | Counterfactual fairness | ARCHITECTURE.md §Fairness Tools |
| finance-credit-risk | Same Z3 properties 4 & 5 | ARCHITECTURE.md §Layer 3 |
| observability | Cost/token attribution span attributes (`agentguard.cost.tokens`, `agentguard.cost.usd`) | ARCHITECTURE.md §Semantic Conventions |
| cli-surface | `verify model` and `verify workflow` subcommands | ARCHITECTURE.md §Layer 2 CLI examples |
| security-runtime | Wasm sandbox backend, S3/GCS and PostgreSQL audit backends, audit log rotation/compression, HMAC key rotation tooling | ARCHITECTURE.md §Sandbox Design + §Audit Log |
| framework-integrations | Adapters for Autogen, Swarm, Atomic Agents; TypeScript/JavaScript bindings | ADR-001, ADR-020 |
| finance-credit-risk | TabDDPM diffusion synthetic backend; loan-performance / vintage / cohort generators; healthcare/government/energy domain modules | ADR-008, ADR-011 |

Promote any of these to a requirement only after a separate sketch decision; this overview reflects v1.0.0 only.

## Changelog

- 2026-04-19: Initial draft, generated alongside the six domain kits via `/ck:sketch --from-code` against the v1.0.0 codebase.
