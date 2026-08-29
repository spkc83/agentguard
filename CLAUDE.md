# AgentGuard — Claude Code Context

AgentGuard is an **open-source, framework-agnostic agent governance and security runtime** for AI agents in regulated industries. It sits between agent orchestration frameworks (LangGraph, CrewAI, Google ADK, MCP, A2A) and the tools/services they access. The governed call path is owned by `agentguard.guardrails.GovernanceKernel`: authentication (optional JWT verifier + authoritative signed registry) → derived-resource RBAC → staged policy-as-code on real tool payloads → content guardrails (PII masking, secret egress) → audit-first admission (HMAC-chained, checkpointed, rollback-witness-anchored) → rate limits/circuit breakers → execution (optional hardened Docker sandbox obligations) → post-stage guardrails → delivery terminals, with restart-safe HITL escalation/resume and shadow mode. Formal verification (Z3), fairness monitoring, and compliance reporting run as offline evidence tools. The realignment history and remaining follow-ups live in `docs/plans/guardrails-realignment.md` §9. Financial services / credit risk is the flagship domain.

---

## Repository Layout

```
agentguard/
├── agentguard/                  # Main Python package
│   ├── __init__.py
│   ├── guardrails/              # Governance kernel — owns the governed call path
│   │   ├── kernel.py            # GovernanceKernel: full lifecycle incl. HITL resume, sandbox obligations
│   │   ├── chain.py             # GuardrailChain: enforce / shadow / off modes
│   │   ├── contracts.py         # Guardrail protocol, payloads, stages, outcomes
│   │   ├── content.py           # PII input masking, PII/secret egress denial, schema checks
│   │   ├── config.py            # Declarative YAML guardrail composition
│   │   ├── executors.py         # Trusted registered-executor resolution (HITL resume)
│   │   ├── normalization.py     # Canonical JSON / payload freezing
│   │   └── reason_codes.py      # Machine-stable runtime reason-code registry
│   ├── core/                    # Layer 1: Security Runtime
│   │   ├── rbac.py              # RBAC engine (deny-override, fnmatchcase, role inheritance)
│   │   ├── audit.py             # HMAC-chained append-only log, checkpoints, key epochs, rollback witness
│   │   ├── audit_collector.py   # Out-of-process UDS signing collector + external witness anchoring
│   │   ├── authentication.py    # Mechanism-neutral agent / control-plane auth protocols
│   │   ├── jwt_authentication.py # Optional offline RS256 verifier (agentguard[auth])
│   │   ├── registry.py          # Authoritative in-memory agent registry (signed evidence)
│   │   ├── registry_state.py    # Immutable registry records + revisions
│   │   ├── registry_store.py    # Signed file-backed authoritative registry
│   │   ├── registry_control_plane.py # Authenticated mutation ledger (prepare→audit→commit)
│   │   ├── identity.py          # Legacy self-asserted registries (compatibility only)
│   │   ├── sandbox.py           # Hardened Docker sandbox backend (used for kernel obligations)
│   │   └── circuit_breaker.py   # Circuit breaker + token bucket rate limiter
│   ├── compliance/              # Layer 2: Compliance Engine
│   │   ├── engine.py            # Staged policy-as-code evaluator; content-addressed bundles, atomic reload
│   │   ├── formal_verifier.py   # Z3 verification (fnmatch-sound RBAC, policy consistency; BFS workflow)
│   │   ├── z3_models.py         # Z3 encodings (fnmatch → regex, role inheritance)
│   │   ├── policies/            # Built-in bundles (35 rules: 3 deny, 3 escalate, 29 warn)
│   │   │   ├── owasp_agentic.yaml   # OWASP Top 10 for Agentic AI (10 rules)
│   │   │   ├── finos_aigf_v2.yaml   # AG-FINOS-NNN local controls informed by FINOS AIGF (15 rules)
│   │   │   └── eu_ai_act.yaml       # EU AI Act high-risk (10 rules)
│   │   ├── escalation_store.py  # Durable HMAC-authenticated HITL escalation state + prune_terminal
│   │   ├── execution_journal.py # Opt-in signed journal for protected continuations + prune_terminal
│   │   ├── continuation.py      # AEAD-protected continuation envelopes (PRE/POST/journal)
│   │   ├── hitl.py              # Offline HITL escalation patterns (legacy helpers)
│   │   └── reporter.py          # Compliance attestation reports (JSON/Markdown)
│   ├── domains/                 # Layer 3: Domain Toolkits
│   │   └── finance/
│   │       ├── credit_risk/
│   │       │   ├── governed_agent.py    # GovernedCreditAgent — kernel-governed decision workflow
│   │       │   ├── agent_templates.py   # CreditDecisionCandidate / policy bands
│   │       │   ├── decision_guardrails.py # Reason/attribution/policy/review integrity guardrails
│   │       │   ├── decision_reasons.py  # CreditPolicyBundle + ReviewJudgment (non-model reasons)
│   │       │   ├── attribution.py       # Truthful adverse-contribution attribution
│   │       │   ├── reason_codes.py      # Versioned ECOA/FCRA reason registries (AG-RB-*)
│   │       │   ├── adverse_action.py    # ECOA/Reg B notice artifacts + principal-reason selection
│   │       │   ├── notice_governance.py # Governed notice preparation + completeness evidence
│   │       │   ├── notice_renderer.py   # Deterministic Reg B notice rendering (verified body digest)
│   │       │   ├── review_governance.py # HITL review lineage verification for overrides
│   │       │   ├── audit_correlation.py # Unresolved-decline detection from signed evidence
│   │       │   ├── model_validation.py  # Strict revisioned validation reports (signed envelope)
│   │       │   ├── model_governance.py  # ModelProvenanceGuardrail + signed-report provider
│   │       │   ├── fairness.py          # DI (4/5ths), equalized odds, calibration, exact tests
│   │       │   └── fairness_monitor.py  # Checkpoint-verified private-join fairness monitoring
│   │       ├── synthetic/               # Compatibility re-exports of agentguard.testing
│   │       └── pii.py                   # Finance PII API (delegates to guardrails content masking)
│   ├── testing/                 # Synthetic credit benchmarks (seeded, deterministic)
│   │   ├── synthetic.py         # Statistical generator with explicit bias controls
│   │   └── wgan_gp.py           # Optional WGAN-GP (torch; agentguard[finance])
│   ├── observability/           # Layer 4: Observability
│   │   ├── tracer.py            # OTel-native traces (NoOp fallback)
│   │   ├── replay.py            # Audit log replay debugger
│   │   └── dashboard.py         # Aggregate metrics incl. shadow/HITL views
│   ├── integrations/            # Framework adapters — all construct through the kernel
│   │   ├── _pipeline.py         # Deprecated run_governed shim + shared kernel construction
│   │   ├── mcp_middleware.py    # Governed MCP client (native CallToolResult denials)
│   │   ├── a2a_middleware.py    # Governed A2A messaging (canonicalise-once target)
│   │   ├── langgraph.py         # GovernedLangGraphToolNode (native messages-state node)
│   │   ├── crewai.py            # GovernedCrewAITool (native BaseTool when installed)
│   │   └── google_adk.py        # GovernedAdkTool (native FunctionTool export)
│   └── cli.py                   # `agentguard` CLI (audit incl. export-checkpoint, policy, verify, observe)
├── tests/
│   ├── unit/                    # Fast unit tests (count/coverage reported by CI; do not pin here)
│   ├── integration/             # Docker sandbox integration tests
│   └── red_team/                # Adversarial sandbox escape tests
├── examples/
│   ├── credit_decisioning/      # End-to-end credit decisioning agent demo (end_to_end_demo.py)
│   ├── adverse_action_generation/ # Adverse action notice pipeline demo (notice_pipeline.py)
│   ├── observability/           # Metrics + replay demo (monitoring_demo.py)
│   └── quickstart.py            # 5-minute getting started
├── docs/
│   ├── architecture.md          # Index into root ARCHITECTURE.md
│   ├── api/index.md             # Module-by-module API overview
│   └── compliance/index.md      # Policy frameworks reference
├── scripts/
│   └── generate_datasets.py     # Deterministic synthetic dataset generator
├── datasets/                    # On-demand synthetic datasets (README + generated output; no binaries committed)
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
agentguard policy validate --policy-dir policies/

# Build distribution
python -m build

# Run quickstart example
python examples/quickstart.py
```

---

## Dependency Order (for understanding and changing the stack)

All layers are built; change code with this dependency order in mind — lower
items must never import from higher ones:

1. **`agentguard/core/audit.py` + `audit_collector.py`** — the evidence root of trust; everything writes here
2. **`agentguard/core/{authentication,registry*,identity}.py`** — who the agent is (authoritative vs legacy)
3. **`agentguard/core/rbac.py`** — what the agent may do; consumes canonicalised action/resource only
4. **`agentguard/compliance/engine.py` + `policies/*.yaml`** — staged policy on real payloads
5. **`agentguard/guardrails/`** — the kernel composes 1–4 plus content guardrails, limits, sandbox obligations, and HITL (`compliance/{escalation_store,execution_journal,continuation}.py`)
6. **`agentguard/integrations/`** — adapters construct through the kernel; never bypass it
7. **`agentguard/domains/finance/`** — domain guardrails and evidence plug into the kernel's `ON_DECISION` stage
8. **`agentguard/observability/`** — reads signed evidence; never on the enforcement path
9. **`agentguard/compliance/{formal_verifier,reporter}.py`, `agentguard/testing/`** — offline tools over the same artifacts

Before adding any feature, check it is reachable from the governed path — the
requirements ledger and execution log in `docs/plans/guardrails-realignment.md`
are the definition of done.

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
- **SR 11-7 / SR 26-2** — Federal Reserve model risk management guidance. SR 11-7 (2011) required independent model validation, ongoing monitoring, documentation; SR 26-2 (April 17, 2026, interagency with OCC/FDIC) superseded it with a principles-based, risk-scaled framework. Cite SR 26-2 as current guidance; SR 11-7 only as historical context
- **CECL** = Current Expected Credit Loss — FASB ASC 326; forward-looking loss reserve methodology replacing incurred-loss model
- **Basel III/IV** — international capital adequacy standards; PD/LGD/EAD models are regulatory capital models subject to validation
- **FINOS AIGF v2.0** — FINOS AI Governance Framework for financial services. The shipped bundle is 15 AgentGuard-local controls informed by it, with `AG-FINOS-NNN` IDs. Do **not** invent official FINOS `AIR-*` risk IDs; a real crosswalk to the FINOS risk registry requires domain review.
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
- Z3 solver can formally verify these constraints hold across the RBAC and agent policy space (planned; not yet implemented — the shipped verifier covers RBAC reachability and policy consistency only)
- Adverse action reason ordering must be deterministic and explainable — formal verification of decision tree properties is directly applicable (planned; not yet implemented — ordering is currently enforced by a sort tie-break)

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
