# AgentGuard — Claude Code Context

AgentGuard is an **open-source, framework-agnostic agent governance and security runtime** for AI agents in regulated industries. It provides security, compliance, and observability as a middleware layer — sitting between agent orchestration frameworks (LangGraph, CrewAI, Google ADK) and the tools/services they access, enforcing RBAC, sandboxed execution, immutable audit logging, circuit breakers, and policy-as-code compliance rules. Financial services / credit risk is the flagship domain.

---

## Repository Layout

```
agentguard/
├── agentguard/                  # Main Python package
│   ├── __init__.py
│   ├── core/                    # Layer 1: Security Runtime (v0.2.0 complete)
│   │   ├── rbac.py              # Role-based access control for agents
│   │   ├── audit.py             # Immutable audit logger (append-only)
│   │   ├── sandbox.py           # Sandboxed tool execution (Docker + NoOp)
│   │   ├── circuit_breaker.py   # Circuit breaker + token bucket rate limiter
│   │   └── identity.py          # Agent identity (in-memory + file-backed)
│   ├── compliance/              # Layer 2: Compliance Engine (v0.3.0 complete)
│   │   ├── engine.py            # Policy-as-code evaluator (6 check types)
│   │   ├── formal_verifier.py   # Z3 SMT verification (RBAC, policy, workflow)
│   │   ├── z3_models.py         # Z3 formula encodings for AgentGuard concepts
│   │   ├── policies/            # Built-in policy YAML files (35 rules)
│   │   │   ├── owasp_agentic.yaml   # OWASP Top 10 for Agentic AI (10 rules)
│   │   │   ├── finos_aigf_v2.yaml   # FINOS AIGF v2.0 (15 rules)
│   │   │   └── eu_ai_act.yaml       # EU AI Act high-risk (10 rules)
│   │   ├── hitl.py              # Human-in-the-loop escalation patterns
│   │   └── reporter.py          # Compliance attestation report generator (JSON/Markdown)
│   ├── domains/                 # Layer 3: Domain Toolkits (v0.4.0 complete)
│   │   └── finance/
│   │       ├── credit_risk/
│   │       │   ├── agent_templates.py   # Credit decisioning agent (auto/review/decline)
│   │       │   ├── adverse_action.py    # ECOA/Reg B adverse action notice generation
│   │       │   ├── model_validation.py  # SR 11-7 validation workflow + findings
│   │       │   └── fairness.py          # Disparate impact, equalized odds, calibration
│   │       ├── synthetic/
│   │       │   ├── wgan_gp.py           # WGAN-GP for tabular credit data (PyTorch)
│   │       │   └── generators.py        # Statistical synthetic data generator
│   │       └── pii.py                   # PII detection and masking (SSN, accounts, etc.)
│   ├── observability/           # Layer 4: Observability (v1.0.0 complete)
│   │   ├── tracer.py            # OTel-native agent decision traces (NoOp fallback)
│   │   ├── replay.py            # Audit log replay debugger (filter, timeline, summarize)
│   │   └── dashboard.py         # Aggregate metrics (denial rates, latency, policy trends)
│   ├── integrations/            # Framework adapters (v0.5.0 complete)
│   │   ├── _pipeline.py         # Shared governance pipeline (ADR-020) — used by all adapters
│   │   ├── mcp_middleware.py    # MCP governed client (identity→RBAC→breaker→audit→call)
│   │   ├── a2a_middleware.py    # A2A governed agent-to-agent messaging
│   │   ├── langgraph.py         # GovernedLangGraphToolNode — governed tool node
│   │   ├── crewai.py            # GovernedCrewAITool — governed CrewAI tool wrapper
│   │   └── google_adk.py        # GovernedAdkTool — governed ADK tool wrapper
│   └── cli.py                   # `agentguard` CLI entry point
├── tests/
│   ├── unit/                    # Fast unit tests (267 tests, 90% coverage)
│   ├── integration/             # Docker sandbox integration tests
│   └── red_team/                # Adversarial sandbox escape tests
├── examples/
│   ├── credit_decisioning/      # End-to-end credit decisioning agent demo
│   ├── adverse_action_generation/ # Adverse action notice pipeline demo
│   └── quickstart.py            # 5-minute getting started
├── docs/
│   ├── architecture.md          # Links to ARCHITECTURE.md
│   ├── compliance/
│   └── api/
├── datasets/                    # Synthetic benchmark datasets
├── CLAUDE.md                    # ← this file
├── AGENTS.md                    # Claude Code agent role definitions
├── ARCHITECTURE.md              # Full architecture reference
├── CONTRIBUTING.md              # Dev setup and contribution guide
├── DECISIONS.md                 # Architectural Decision Records (ADRs)
├── pyproject.toml
├── README.md
└── .github/
    ├── workflows/
    │   ├── ci.yml
    │   └── publish.yml
    └── ISSUE_TEMPLATE/
```

---

## Tech Stack and Conventions

### Language and Runtime
- **Python 3.11+** — use `match` statements, `tomllib`, `typing.Self` where appropriate
- **Type hints everywhere** — all public functions must be fully annotated
- **Pydantic v2** for all data models and policy schemas
- **Async-first** — core runtime functions should be `async def`; provide sync wrappers via `asyncio.run()` for simple cases

### Core Dependencies
```toml
python = "^3.11"
pydantic = "^2.0"
structlog = "*"          # Structured logging
opentelemetry-sdk = "*"  # Observability
httpx = "*"              # Async HTTP
docker = "*"             # Sandbox execution
pyyaml = "*"             # Policy files
rich = "*"               # CLI output
typer = "*"              # CLI framework
z3-solver = "*"          # Formal policy verification (SMT solver — no GPU, pure Python)
```

### Dev Dependencies
```toml
pytest = "*"
pytest-asyncio = "*"
pytest-cov = "*"
ruff = "*"               # Linter + formatter (replaces black/flake8/isort)
mypy = "*"
```

### Code Style
- **Formatter/linter:** `ruff` — run `ruff check . --fix && ruff format .` before every commit
- **Line length:** 100 characters
- **Imports:** stdlib → third-party → internal (ruff enforces this)
- **Docstrings:** Google-style for all public classes and functions
- **No print statements** in library code — use `structlog` logger
- **Error handling:** define custom exceptions in `agentguard/exceptions.py`; never swallow exceptions silently

### Testing
- **Target coverage:** 90%+ for `core/` and `compliance/`
- **Test file naming:** `test_<module>.py` mirrors source layout
- **Fixtures:** shared fixtures in `tests/conftest.py`
- **Integration tests** in `tests/integration/` use real Docker for sandbox tests; mark with `@pytest.mark.integration`
- Run unit tests only: `pytest tests/unit/`
- Run all: `pytest --cov=agentguard`

### Git Conventions
- **Branch naming:** `feat/rbac-engine`, `fix/sandbox-timeout`, `docs/mcp-guide`
- **Commit format:** Conventional Commits — `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`
- **Never commit** secrets, API keys, or real PII data
- **Every PR** must have tests; CI blocks merge without passing tests

---

## Common Development Commands

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Lint + format
ruff check . --fix && ruff format .

# Type check
mypy agentguard/

# Test (unit only, fast)
pytest tests/unit/ -v

# Test (all, including integration — requires Docker)
pytest --cov=agentguard --cov-report=html

# CLI
agentguard --help
agentguard audit show --agent-id <id>
agentguard policy validate --file policies/custom.yaml
agentguard sandbox run --tool <tool_name>

# Build distribution
python -m build

# Run quickstart example
python examples/quickstart.py
```

---

## Layer Build Order (Follow This Sequence)

Build in this exact order — later layers depend on earlier ones:

1. **`agentguard/core/audit.py`** — everything depends on audit logging; build this first
2. **`agentguard/core/identity.py`** — agent identity needed by RBAC
3. **`agentguard/core/rbac.py`** — needs identity; needed by sandbox and integrations
4. **`agentguard/core/circuit_breaker.py`** — standalone; add after RBAC
5. **`agentguard/core/sandbox.py`** — needs RBAC + audit; Docker-based
6. **`agentguard/integrations/mcp_middleware.py`** — wraps MCP calls with core layer
7. **`agentguard/compliance/engine.py`** — policy evaluator; needs audit
8. **`agentguard/compliance/formal_verifier.py`** — Z3-based formal policy verifier; needs engine
9. **`agentguard/compliance/policies/*.yaml`** — OWASP, FINOS, EU AI Act rules
10. **`agentguard/domains/finance/`** — credit risk templates, synthetic data, adverse action
11. **`agentguard/observability/`** — traces, replay, dashboard
12. **`agentguard/integrations/langgraph.py`** — framework adapters last

---

## Key Design Principles

1. **Framework-agnostic first** — the core runtime must work with any agent system, not just LangGraph or CrewAI. Integrations are adapters, not requirements.
2. **Zero-trust by default** — agents have no permissions unless explicitly granted. Deny-first, allow-explicit.
3. **Immutable audit trail** — every tool call, permission check, and policy evaluation is logged before execution, not after. Failure to log = failure to execute.
4. **Policy as code** — compliance rules are YAML files in version control, not database rows. They can be reviewed, diffed, and audited like code.
5. **Fail-safe over fail-open** — when the governance layer errors, it must block the action, not allow it. No silent pass-throughs.
6. **Domain depth beats breadth** — the financial services module should be production-quality and credible to banking practitioners, not a toy demo.

---

## Critical Domain Knowledge (Financial Services — Credit Risk)

The owner has 17 years of finance domain experience. Reference these correctly:

### Regulatory Framework
- **ECOA** = Equal Credit Opportunity Act — prohibits discrimination in credit decisions; requires adverse action notices
- **Fair Housing Act (FHA)** — prohibits discriminatory lending on housing-related credit
- **Adverse action notice** — required when credit is denied; must cite specific reasons (Regulation B)
- **SR 11-7** — Federal Reserve / OCC guidance on model risk management; requires independent model validation, ongoing monitoring, documentation
- **CECL** = Current Expected Credit Loss — FASB ASC 326; forward-looking loss reserve methodology replacing incurred-loss model
- **Basel III/IV** — international capital adequacy standards; PD/LGD/EAD models are regulatory capital models subject to validation
- **FINOS AIGF v2.0** — 46 AI risks mapped for financial services; the compliance engine should map to these risk IDs
- **EU AI Act** — credit scoring is explicitly High-Risk AI under Annex III, Article 6; requires conformity assessment, human oversight, accuracy and robustness metrics, bias audits

### Credit Risk Model Concepts
- **PD** = Probability of Default; **LGD** = Loss Given Default; **EAD** = Exposure at Default — the three Basel IRB model components
- **Scorecards** — logistic-regression-based credit scoring models; weight of evidence (WoE) and information value (IV) are key feature selection metrics
- **Through-the-cycle vs point-in-time PD** — regulatory distinction; TTC models smooth economic cycles, PIT models are sensitive to current conditions
- **Vintage analysis** — cohort-based performance tracking; essential for model monitoring
- **Disparate impact / disparate treatment** — the two legal theories of lending discrimination; 80% rule (4/5ths rule) for disparate impact testing
- **Demographic parity / equalized odds / calibration** — fairness metrics; regulators increasingly require documentation of which metric was optimized and why
- **Challenger model** — production model (champion) vs. experimental model (challenger) in A/B deployment; standard risk management pattern
- **ALLL/ACL** — Allowance for Loan and Lease Losses / Allowance for Credit Losses; the balance sheet reserve funded by CECL model output

### Synthetic Data (Credit Risk)
- Synthetic datasets simulate: loan applications (FICO score, DTI, LTV, income, employment), loan performance (payment history, delinquency, default), portfolio-level metrics
- Feature distributions must match real credit data statistical profiles without containing real customer data
- Must include protected class proxies (for fairness testing) that are themselves synthetic — never infer real demographics

### PII in Credit Context
- SSN, account numbers, routing numbers, DOB, full name + address combination — all Category 1 PII
- FCRA-regulated data (credit report contents) has additional handling requirements
- Must be masked in all logs: SSN → `XXX-XX-####`, account numbers → last 4 digits only

### Formal Verification in Credit Risk
- Regulatory models require **model documentation** proving properties like monotonicity (higher income → lower default probability)
- Z3 solver can formally verify these constraints hold across the RBAC and agent policy space
- Adverse action reason ordering must be deterministic and explainable — formal verification of decision tree properties is directly applicable

---

## What NOT to Build (Scope Boundaries)

- **Do not** build a new agent orchestration framework — AgentGuard wraps existing ones
- **Do not** build a model fine-tuning pipeline — out of scope; training is done externally
- **Do not** add a database dependency to the core layer — use file-based append-only logs + optional connectors
- **Do not** make the governance layer opinionated about which LLM provider to use
- **Do not** hard-code financial services into the core — it must be a pluggable domain module
- **Do not** add a UI to the core package — the observability dashboard is a separate optional install
- **Do not** build use cases outside the credit risk domain — the flagship domain is credit decisioning, adverse action, model validation, and fairness analysis
- **Do not** use employer's proprietary data, models, or methodologies as reference implementations

---

## Security Posture of the Project Itself

AgentGuard is a security tool — it must be secure:

- Dependency scanning in CI via `pip-audit`
- No `eval()`, `exec()`, or `subprocess.shell=True` in library code
- Sandbox escapes are the #1 threat model — test this explicitly in `tests/red_team/`
- Secrets must never appear in logs — use `structlog` processors to scrub known patterns
- SBOM generation in release workflow via `syft`
