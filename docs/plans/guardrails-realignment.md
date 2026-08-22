# Guardrails Realignment: Gap Analysis and Fix Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Every PR listed below is independently shippable and has an acceptance test.

**Date:** 2026-08-21
**Trigger:** External code review concluded AgentGuard is "essentially a thin wrapper" and that intent (live guardrails engine for agentic AI in regulated industries) does not match implementation (notably: unclear how reason codes would be used in production).
**Method:** Five parallel read-only reviews (core runtime + adapters, compliance layer, finance domain, observability/CLI/docs/packaging, target architecture), each with file:line evidence and runnable probes. Every headline finding below marked ✔ was independently re-executed by the coordinating session before inclusion.

---

## 1. Verdict

**The criticism is correct, and it is structural, not cosmetic.**

The only runtime enforcement path in the package is `agentguard/integrations/_pipeline.py:run_governed` (176 lines):

```
resolve identity → RBAC fnmatch on two caller-supplied strings → write audit event → circuit breaker → call
```

Everything the README stacks on top of that — policy-as-code, OWASP/FINOS/EU AI Act rules, PII masking, HITL escalation, rate limiting, sandboxing, formal verification — is **not reachable from that path**. `PolicyEngine` is called only by the CLI and the reporter. `HitlManager`, `PiiDetector`, `PiiMasker`, `TokenBucketRateLimiter`, and both sandbox backends have **zero call sites** outside `__init__.py` re-exports and their own tests.

The gap in one sentence: **the payload never reaches the policy layer, and the policy layer has no way to say "no."**

A second, independent problem: the flagship credit-risk domain produces **regulatory artifacts that are wrong**, not merely thin — adverse action notices citing factors with zero contribution, a fairness analyzer that fails provably fair data, and an audit trail that cannot reconstruct a single decision.

### Capability scorecard (from the target-architecture review)

| | Present | Partial | Absent |
|---|---|---|---|
| Interception points (8) | 0 | 3 | 5 |
| Guardrail types (15) | 2 | 6 | 7 |
| Decision actions (5) | 2 | 0 | 3 |
| Evidence (9) | 1 | 3 | 5 |
| Operations (9) | 1 | 3 | 5 |
| **Total (39)** | **6** | **12** | **21** |

All six "Present" items live in `core/`. Test suite: 287 passed, 92% coverage — but every test models a *cooperative* caller; there is no adversarial test anywhere.

---

## 2. What is genuinely solid (do not rebuild)

- **`_pipeline.py` is honest, fail-closed, log-first.** Identity/RBAC/pre-audit failures all propagate before `executor()`; an error-event write failure cannot mask the original exception (`:155-159`). ADR-020's single-path consolidation means every fix below lands in one file.
- **`core/rbac.py`** — deny-override, inheritance, cycle-safe. Correct given trustworthy inputs. The problem is the inputs.
- **`core/audit.py`** — HMAC chaining, restart-safe chain initialisation, pluggable `AuditBackend` Protocol. Good seam for a real WORM/signing backend.
- **`core/circuit_breaker.py`** — correct state machine, wired in.
- **Engineering hygiene** — mypy strict passes, ruff with `S`/`B`/`A`, frozen Pydantic models, structlog throughout, examples all run from a bare checkout, `z3` kept optional via a real AST test.
- **`DECISIONS.md` is more honest than the README.** ADR-013 and ADR-016 already concede the formal-verifier and workflow-safety caveats reproduced below.
- **`WganGpTrainer.fit`** is a textbook-correct WGAN-GP loop; the plumbing around it is what's missing.
- **Deterministic adverse-action tie-break** (`adverse_action.py:121-124`) is the right instinct for appeal reproducibility.

---

## 3. Gaps by layer

Severity: **C** critical, **H** high, **M** medium, **L** low. ✔ = reproduced by coordinator.

### 3.1 Core runtime and adapters

| Sev | Gap | Evidence |
|---|---|---|
| C ✔ | **RBAC resource is caller-asserted, default `"*"`.** With `allow tool:* on *` + `deny tool:* on admin/*`, calling `admin_delete` with `resource="public/report"` (or omitting it) executes. Deny fires only when the caller volunteers an incriminating label. | `langgraph.py:82`, `crewai.py:72`, `google_adk.py:81`, `mcp_middleware.py:74` |
| C | **Policy engine is not on the hot path.** Audit events written by the pipeline carry `policy_results: []`. | `_pipeline.py:99-176`; `PolicyEngine` only at `cli.py:178,219,344`, `reporter.py:110` |
| C ✔ | **No input or output inspection.** Tool args are captured in an adapter closure and never read by governance; results are returned verbatim. `"exfiltrated: SSN 123-45-6789"` passes through. `pii.py` (196 lines) is imported by nothing in `agentguard/`. | `_pipeline.py:137-141`; `langgraph.py:104-105` |
| C | **Prompt-injection rule can never fire.** `content_scan` reads `permission_context.context`, which no code populates; the `tool_args` target scans the literal string `"{}"`. | `engine.py:224-254`; `rbac.py:139-180` |
| H ✔ | **Trivially bypassable.** Adapters wrap a callable the caller still holds; raw `tool()` works outside governance. | `langgraph.py:74,102-105` and siblings |
| H | **No agent authentication.** `registry.resolve()` is a dict lookup on a self-asserted string; `register()` lets any code mint any roles. | `identity.py:31-79` |
| H ✔ | **Audit truncation is undetectable.** Deleting the last 3 of 5 events → `verify_chain()` returns `valid=True`. No sequence number, no signed head. | `audit.py:161-178` |
| H | **Audit chain breaks under two writers** (false `AuditTamperDetectedError`). `_prev_hash` is per-instance; no `flock`; blocking I/O inside `async def`. | `audit.py:63-68,103` |
| H | **Signing key held by the audited process** (`os.environ`). Any code in the agent process can forge the chain. No key ID, no rotation. | `audit.py:98` |
| H | **"Sandboxed execution" does not exist on the governed path.** `sandbox.py` runs a `list[str]` command; the pipeline runs an in-process callable. Disjoint APIs. Docker backend sets only `network_disabled` + `mem_limit` (no `read_only`, `user`, `cap_drop`, seccomp, pids/cpu limits); 0% coverage; red-team tests never run in CI. | `sandbox.py:101-171`; `ci.yml:48` |
| H ✔ | **Framework adapters import no framework.** Zero `langgraph`/`crewai`/`google.adk`/`mcp` imports repo-wide. `GovernedLangGraphToolNode.ainvoke(tool_name, tool_input, resource)` cannot sit in a `StateGraph` (real `ToolNode.ainvoke(state)`). CrewAI wrapper is async where CrewAI calls tools synchronously. All tested against `AsyncMock`. | `integrations/*.py`; `pyproject.toml:46-55` |
| M | Rate limiter is dead code; breaker is per-instance, in-memory, not keyed by (agent, tool). | `circuit_breaker.py:116-147` |
| M | Breaker rejection is logged as `allowed` then `error` (pre-event precedes breaker). | `_pipeline.py:133-139` |
| L | `fnmatch` is platform case-normalising; `*` crosses `/`; cyclic roles warn instead of fail; `FileBackedRegistry` temp-file race. | `rbac.py:41,71-89`; `identity.py:116-118` |

### 3.2 Compliance layer

| Sev | Gap | Evidence |
|---|---|---|
| C | **`PolicyResult` cannot deny.** Only `passed: bool` — no `effect`/`action` vocabulary. | `models.py:55-74` |
| C | **Attestation certifies a god-mode agent.** `*`/`*` allow-everything RBAC + metadata `{"model_version": "", "fairness_review_date": "never", "risk_category": "banana"}` → **100% pass, 0 critical failures, 35 rules**. | `reporter.py:87-193`; `engine.py:301` |
| C | **EU AI Act / FINOS "controls" are key-presence checks.** 10 of 35 rules check that a string key exists in caller-supplied identity metadata; values are never read. | `engine.py:297-312`; `eu_ai_act.yaml`, `finos_aigf_v2.yaml` |
| C ✔ | **Z3 RBAC verifier is unsound.** Encodes exact `(action, resource)` indices (`target_permission_index`), not `fnmatch` subsumption or `inherited_roles`. A `tool:*`/`*` grant that the runtime expands into `admin_delete` is invisible to it. Also incomplete (false alarms on wildcard denies). | `formal_verifier.py:61-97`; `z3_models.py:56-84` |
| C | **`verify policy` is a tautology.** `Contains(action, kw1) ∧ Contains(action, kw2)` over an unconstrained string is always satisfiable; CLI fabricates `effect` from `severity`. Reports **264/264 possible pairs** as contradictions on the shipped policies and exits 0. | `z3_models.py:130-137`; `cli.py:352-379` |
| H | `verify_workflow_safety` contains no Z3 (BFS); docs still advertise "Z3 Datalog/µZ". Claimed monotonicity / adverse-action-ordering verification: **zero hits** for `monotonic` in `agentguard/`. | `formal_verifier.py:231-262`; `ARCHITECTURE.md:232-247` |
| H | **Unknown check type → `passed=True`.** A YAML typo silently turns a critical control green. Contradicts design principle #5. | `engine.py:168-176` |
| H | **5 rules are structurally un-failable** (`permission_required` reduces to `granted == True` on every event the pipeline emits) — including "Audit Trail Completeness" and "Post-Market Monitoring". 6 more only detect `result == "error"` while labelled Explainability / Resilience / Override. | `engine.py:256-279` |
| H | **HITL: zero call sites; no pending state, timeout, persistence, or audit linkage.** Nothing ever writes `result="escalated"`; dashboard's escalation counter is permanently zero. `ARCHITECTURE.md:204` documents an `AgentGuard(hitl_handler=…)` class that does not exist. | `hitl.py:93-139` |
| H | **Reporter never calls `verify_chain()`** — a tampered log yields a clean attestation. | `reporter.py:109-110` |
| M | **FINOS IDs are fabricated.** Published framework uses `AIR-OP-*`/`AIR-SEC-*`/`AIR-RC-*` (23 risks); repo invents `FINOS-AIGF-001…040` and claims "46 risks mapped". EU AI Act article citations are accurate; implementations bear no relation to them. | `finos_aigf_v2.yaml:5`; `ARCHITECTURE.md:177` |
| M | Detection polarity punishes correct behaviour (masked PII access at `data/pii/masked` fails two critical rules); two critical "Human Oversight" rules are tool-name greps defeated by renaming `tool:credit_decision` → `tool:credit_eval`. | `engine.py:202-222`; `finos_aigf_v2.yaml:69-86`; `eu_ai_act.yaml:101-118` |
| M ✔ | HITL/notice/finding timestamps use `datetime.now(UTC)` as a class-level default → frozen at import. | `hitl.py:48,66`; `adverse_action.py:65`; `model_validation.py:88` |

**Rule classification (35 rules):** 9 machine-checkable against real action/resource strings (detect-only, inverted polarity); 10 honour-system metadata key-presence; 16 with no enforcement relation to their stated control. Not one shipped rule has a test.

### 3.3 Finance domain and reason codes

| Sev | Gap | Evidence |
|---|---|---|
| C ✔ | **Notice cites reasons with zero contribution.** FICO 810 / DTI 0.10 / PD 0.30 → declined → notice reasons `['Debt-to-income ratio too high', 'Credit score below threshold']`, both with importance `0.0`. No zero/sign filter; sorts by `abs()` so a *favourable* factor can outrank an adverse one. | `adverse_action.py:121-136` |
| C ✔ | **Real decision driver silently dropped.** `pd_score` (the only non-zero contributor) is absent from `DEFAULT_REASON_MAP`, so `if reason:` skips it with no warning. | `adverse_action.py:133-134` |
| C | **"Feature importances" are not model attributions.** Only producer is `max(0,(700-fico)/100)`, `max(0,(dti-0.35)/0.1)` — constants that don't even match the config thresholds (620, 0.43). No scorecard points-lost, no SHAP, no coefficients. | `agent_templates.py:127-134` |
| C | **No reason-code taxonomy.** Ten English strings keyed by Python variable names; no code IDs, no versioning, no Reg B Appendix C wording. "Credit score below threshold" is the one reason Reg B commentary explicitly disallows for scoring systems. | `adverse_action.py:25-36` |
| C | **Notice unlinkable to audit trail.** `AuditEvent` has no subject/payload field; demo's 200 events are identical except IDs — **zero applicant IDs, zero PDs, zero decisions**. Notice is generated *outside* `run_governed`. The chain proves `score_application` was called 200 times; it cannot say why anyone was declined. | `models.py:100-111`; `end_to_end_demo.py:167-173` |
| C | **Nothing enforces a notice on decline.** Best-effort example-loop code. Silent declines are the most common ECOA enforcement finding. | `end_to_end_demo.py:159-174` |
| C | **Fairness analyzer fails a provably fair model.** Demographic label is uniform random and independent of all features; DI ratio at n=200 = 0.62–0.75 (FAIL) across five seeds, 0.97 at n=20,000. No min cell size, no significance test, no CI, disadvantaged group not named. Demo headline: `Overall passed: False`. | `fairness.py:174-177` |
| H | Notice missing most required content: creditor identity/address, verbatim ECOA agency notice (§1002.9(b)(1)), FCRA §615(a) score disclosure, CRA identity, 60-day free-report right; `decision` is free text. `MAX_REASONS=4` mis-attributed to Reg B (it's FCRA §615(a); 5 allowed when inquiries is a factor). | `adverse_action.py:38-72` |
| H ✔ | `frozen=True` is shallow — `notice.reasons.append("injected")` succeeds; the "frozen" test never attempts mutation. | `adverse_action.py:57`; `test_adverse_action.py:90-98` |
| H | **PII:** `_SSN_NO_DASH` and `_ROUTING_PATTERN` defined and never used; no SSN validity rules (`000-`, `666-`, `9xx-` all "detected"); loan amounts masked as phone numbers; `mask_dict` skips ints and dicts nested in lists; no structlog scrubbing processor despite CLAUDE.md requirement; masker wired into nothing. | `pii.py:24-27,186-195`; `_logging.py:20-26` |
| H | **SR 11-7 "validation" is five `if`s** over caller-supplied metrics. Findings have no ID/owner/due date/status. Gini ≡ 2·AUC−1 never checked — every test fixture is internally impossible (`gini=0.50, auc=0.80`). "Calibration" is a single mean-diff, not binned; demo feeds *denial rate* as predicted default rate. | `model_validation.py:119-256`; `fairness.py:148-151`; `end_to_end_demo.py:196` |
| H | **Synthetic data has no dependence structure** (corr(income, loan) = −0.001; 42.8% of applications request >3× income). The "demographic proxy" is uniform random — by definition not a proxy — so bias detection cannot be tested. `generate_datasets.py` uses `hash(name)` → non-deterministic across processes (seeds 603/424/644 observed). | `generators.py:102-115`; `generate_datasets.py:108` |
| H | **WGAN-GP:** 0% coverage, no test file, `generate(1)` raises (never `.eval()`), outputs unbounded floats (FICO −1.6), no scaler, no seeding; docstring claims embeddings and imbalance handling that don't exist. | `wgan_gp.py` |
| M | `CreditDecisioningAgent` is not an agent — synchronous threshold function, holds no governance references; single `tool:score_application` permission covers score/decide/decline/notice; `or len(reasons) >= 2` banding is arbitrary and routes 52% of demo applications to review. | `agent_templates.py:81-152` |

### 3.4 Observability, CLI, docs, packaging

| Sev | Gap | Evidence |
|---|---|---|
| H ✔ | **Latency percentiles measure failures only.** Allowed events hard-code `duration_ms=0.0`; dashboard filters `> 0`. Demo prints `p50 latency: 0.00ms` over 200 calls. Policy trends permanently empty (`policy_results` never populated). | `_pipeline.py:130`; `dashboard.py:141` |
| H | **"OpenTelemetry-native" = one span, four attributes** per call. No child spans for RBAC/audit; 11 of 15 documented attributes never emitted; attribute naming differs from docs; `trace_rbac_check`/`trace_policy_evaluation`/`trace_tool_call` are dead code; `is_active` is true under a discarding `ProxyTracerProvider`. | `tracer.py:79-187`; `ARCHITECTURE.md:386-400` |
| H | **Docs reference APIs that don't exist:** `DockerSandbox`, `NoOpSandbox`, `HITLEscalation`, `HITLDecision`, `InMemoryAuditBackend`, `Agent`, `WGANGPCreditGenerator`, `agentguard verify workflow/model`, `agentguard sandbox run`, `policy validate --file`. ARCHITECTURE.md describes Wasm backend, S3/GCS/Postgres backends, sidecar/gateway, Vault, seccomp — none exist. | `docs/api/index.md`; `ARCHITECTURE.md:112-128,204,254-256,505-527`; `CLAUDE.md:161-162` |
| H | **"v1.0.0 Production Release"** with no `LICENSE` (MIT declared), no `py.typed`, no `CHANGELOG`, no `SECURITY.md`, `Development Status :: 3 - Alpha`, only git tag `v0.2.0`, no `pip-audit`/SBOM in CI despite CLAUDE.md. | `pyproject.toml:10,20`; `ci.yml`; `publish.yml` |
| M ✔ | **Declared deps never imported:** `presidio-analyzer`, `presidio-anonymizer`, `aif360`, `fairlearn`, `scikit-learn`, `numpy`, `pandas`, `wasmtime`, `httpx`, `anyio`. `z3-solver` (~50 MB) is a *core* dep used only offline. | `pyproject.toml:36-66` |
| M | Built-in policies fail out of the box (20 critical failures / 68% on the demo log) because they demand metadata no AgentGuard code sets. | `policy report` output |
| M | No real-time surface (`/metrics`, Prometheus, OTel instruments); replay is a filter/printer, not re-evaluation; `read_all()` loads full history into memory. | `observability/` |
| L | `python -m agentguard.cli` does nothing (no `__main__` guard); test count in README stale (278 vs 287). | `cli.py`; `README.md:44` |

---

## 4. Reason codes: current state vs. production flow

A production Reg B flow has seven stages. The repo implements roughly one and a half.

| # | Stage | Status | Today |
|---|---|---|---|
| 1 | Model emits per-applicant attributions (scorecard points-lost vs. reference profile; SHAP/coef×deviation for GBM/logit) | **Absent** | Two hard-coded formulas in `agent_templates.py:130-135` |
| 2 | Attributions signed and filtered to adverse-only | **Absent** | Sorts by `abs()`, no zero filter → fabricated reasons |
| 3 | Ranked by contribution magnitude, deterministic tie-break | **Present** (sorting) | Orders fabricated numbers; alphabetises fiction when all are 0.0 |
| 4 | Mapped to a versioned reason-code set (Appendix C wording; deployer-supplied bureau factor codes) | **Absent** | 10 English strings keyed by variable names; unmapped features dropped silently |
| 5 | Rendered into a compliant notice (creditor, ECOA agency text, FCRA §615(a) block, CRA identity, rights, 30-day clock) | **~10%** | One generic sentence |
| 6 | Linked to the decision in the audit trail (decision_id ↔ notice_id ↔ model+version ↔ features ↔ attributions) | **Impossible today** | `AuditEvent` has no payload; notice generated outside governance |
| 7 | Delivered and tracked (SLA, counteroffer, incomplete, withdrawn) | **Absent** | — |

**Target flow** (from the architecture review):

```
PD model → ModelAttributor.attribute() → ReasonCodeMapper.map() (versioned taxonomy)
  → DecisionPayload(domain="credit_risk", outcome, body={pd, band, model_version,
                     attributions, reason_codes})
  → kernel.guard("on_decision") chain:
       ProtectedAttributeGuardrail   deny   FAIR.PROTECTED_FEATURE_IN_INPUT
       ModelProvenanceGuardrail      deny   MRM.MODEL_UNVALIDATED / FAIR.DI_RATIO_BELOW_THRESHOLD
       DecisionBandGuardrail         escalate HITL.REVIEW_BAND
       ReasonCodeGuardrail           deny   AA.NO_REASON_CODES / AA.TOO_MANY / AA.UNKNOWN_CODE
       AttributionIntegrityGuardrail deny   AA.CODE_NOT_ATTRIBUTED / AA.ATTRIBUTION_MODEL_MISMATCH
       NoticeCompletenessGuardrail   deny   AA.NOTICE_INCOMPLETE / AA.NOTICE_WINDOW_EXCEEDED
       PiiGuardrail                  transform PII.REDACTED_IN_EVIDENCE
  → AdverseActionGenerator.generate() → GuardrailEvent(links={notice_id, model_version})  [HMAC-chained]
```

The invariant "a decline carries ≥1 and ≤4 valid reason codes" must be a **guardrail at the emission boundary**, not a check inside the generator — the generator can be bypassed by any caller; the `on_decision` chain is the only path by which a decision reaches the outside world.

---

## 5. Target architecture (summary)

New package `agentguard/guardrails/`. Framework-agnostic, async, Pydantic v2, no DB, fail-closed.

```python
Stage = Literal["pre_tool", "post_tool", "pre_llm", "post_llm", "pre_message",
                "post_message", "pre_retrieval", "post_retrieval",
                "pre_memory_write", "on_decision"]

Payload = ToolCallPayload | ToolResultPayload | PromptPayload | CompletionPayload
        | MessagePayload | RetrievalPayload | DecisionPayload     # discriminated on `kind`

class GuardrailContext(BaseModel):      # frozen
    trace_id: str; invocation_id: str; stage: Stage
    identity: AgentIdentity; action: str; resource: str
    payload: Payload; attributes: dict[str, Any]               # ABAC surface
    prior: tuple[Decision, ...]

class Reason(BaseModel):    code: str; message: str; severity; reference: str; evidence: dict
class Decision(BaseModel):  # frozen; validators: deny/escalate require ≥1 reason, transform requires payload
    action: Literal["allow", "deny", "transform", "escalate", "degrade"]
    guardrail_id: str; guardrail_version: str; reasons: tuple[Reason, ...]
    payload: Payload | None; escalation: EscalationRequest | None
    obligations: tuple[Obligation, ...]; duration_ms: float

class Guardrail(Protocol):
    id: str; version: str; stages: frozenset[Stage]
    fail_mode: Literal["closed", "open"]     # default "closed"
    timeout_ms: int
    async def evaluate(self, ctx: GuardrailContext) -> Decision: ...

class GuardrailChain:   # mode: ENFORCE | SHADOW | OFF; ordered phases:
    # IDENTITY → DETERMINISTIC (rbac, abac) → LIMITS (rate, budget, blast radius)
    # → CONTENT (pii, injection, secrets) → SCHEMA → SEMANTIC (judge) → DOMAIN
    async def run(self, ctx) -> ChainOutcome: ...
    # allow→continue; transform→replace payload, continue; degrade→record, continue
    # escalate→stop, persist resume token; deny→stop; raise/timeout→deny when fail_mode="closed"

class GovernanceKernel:  # replaces run_governed
    async def guard(self, stage, *, agent_id, action, resource, payload, attributes) -> ChainOutcome
    async def guarded_tool_call(self, *, agent_id, action, resource, payload, executor) -> Any
    #   pre_tool chain → execute transformed payload (honouring obligations, e.g. sandbox) → post_tool chain
```

**Migration map:** `RBACEngine` → `RbacGuardrail`; `TokenBucketRateLimiter` → `RateLimitGuardrail`; `PolicyEngine.evaluate(AuditEvent)` → `PolicyGuardrail.evaluate(ctx) -> Decision` with rule schema gaining `stage`, `applies_to`, `on_fail`; `PiiDetector/Masker` → `PiiGuardrail` (transform internally, deny on egress); `HitlManager` → `HitlGuardrail` + durable `EscalationStore`; `AppendOnlyAuditLog` → `EvidenceSink` (**not** a chain member — it records other guardrails' denials); `SandboxBackend` → obligation handler (**not** a chain member); `FormalVerifier` → bundle-build/CI gate; `FairnessAnalyzer`/`ModelValidator` → evidence producers feeding `ctx.attributes` so `ModelProvenanceGuardrail` can deny live decisions from a stale or biased model.

---

## 6. Fix plan

Ordered so each phase is shippable, the five public adapters stay green throughout, and the highest-risk gaps close first. Estimates are for a single engineer using subagents.

### Phase 0 — Truth and hygiene (1–2 days, zero behaviour risk)

| PR | Change | Acceptance |
|---|---|---|
| 0.1 | README: drop "Production Release"; version `0.9.0`; replace status table with three sections — *Enforced at runtime* / *Offline analysis tools* / *Wrappers awaiting framework validation* — or the §1 capability scorecard. Add `LICENSE`, `py.typed`, `CHANGELOG.md`, `SECURITY.md`. | README and `pyproject` classifiers agree; `pip install` ships license and types. |
| 0.2 | Remove unused deps (`presidio-*`, `aif360`, `fairlearn`, `sklearn`, `numpy`, `pandas`, `wasmtime`, `httpx`, `anyio`); move `z3-solver` to a `verify` extra. | `pip install agentguard` pulls no ML stack; `grep` proves every declared dep is imported. |
| 0.3 | Fix one-line correctness bugs: `Field(default_factory=...)` at `adverse_action.py:65`, `model_validation.py:88`, `hitl.py:48,66`; `tuple[str, ...]` for notice fields; `zlib.crc32` in `generate_datasets.py:108`; `__main__` guard in `cli.py`; unknown check type → load-time `PolicyLoadError`. | Regression test per bug (two notices 1s apart differ; `notice.reasons.append` raises; three processes produce identical datasets; typo'd YAML fails to load). |
| 0.4 | Docs: delete every reference to non-existent APIs/commands; move ARCHITECTURE.md's unbuilt items (Wasm, S3/GCS/Postgres, sidecar, Vault, seccomp, monotonicity proofs, `verify workflow/model`) into a labelled **Roadmap** section; correct FINOS to 15 rules and real `AIR-*` IDs or rename the bundle; fix CLAUDE.md CLI examples. | CI test imports every symbol named in `docs/api/index.md`. |
| 0.5 | CI: add `pip-audit` step; add Docker-service job running `-m "integration or red_team"`; add syft SBOM to `publish.yml`. | Red-team suite has a CI run in its history. |

### Phase 1 — Close the enforcement holes in `run_governed` (1 week)

| PR | Change | Acceptance |
|---|---|---|
| 1.1 | **Derive the resource; never accept it.** Remove `resource` from all adapter call signatures. Add a `ResourceResolver` protocol registered per tool at adapter construction (`{tool_name: callable(args) -> resource}`); unresolvable → deny. | Adversarial tests: omitted, falsified, and `"*"` resources are all denied where the honest label would be. |
| 1.2 | **Thread the payload.** Introduce `GuardrailContext` + `ToolCallPayload`/`ToolResultPayload` (from §5) and pass real `arguments` and the executor's result through `run_governed`. | A test guardrail asserts it received the actual args dict and result object through all five adapters. |
| 1.3 | **Policy engine on the hot path with an effect.** Add `effect: allow \| deny \| escalate \| warn` to `PolicyRule`/`PolicyResult`; evaluate after RBAC, before pre-event; raise on `deny`; stamp `policy_results` into the event. `content_scan` reads real args. Re-type all 35 rules with `stage` and `on_fail`. | A live MCP call carrying `"ignore previous instructions"` in args is **blocked** by OWASP-AGENT-01 with the reason code in the audit event. `test_pipeline.py` contains the word "policy". |
| 1.4 | **Post-execution stage.** Run the result through a `post_tool` chain; wire `PiiGuardrail` (transform internally, deny on egress), `SecretEgressGuardrail`, `OutputSchemaGuardrail`. Add a structlog scrubbing processor. Fix PII regexes (SSN validity, dead patterns, numeric-context guard, recursive `mask_dict`). | An SSN in tool args is redacted before the executor is called and before the evidence write; a schema-violating result is denied; `"exfiltrated: SSN …"` no longer passes through. |
| 1.5 | **Wire limits; fix event ordering.** Call `TokenBucketRateLimiter` keyed by `(agent_id, tool)`; move breaker/limiter checks before the pre-event; emit a distinct `rejected` result; emit a **completion** event with real `duration_ms`. | Dashboard p50/p95 are non-zero on successful calls; a breaker rejection produces no `allowed` event. |
| 1.6 | **Fail-closed contract test.** Any exception inside a guardrail → deny (unless explicitly `fail_mode="open"`). | Test: a guardrail that raises yields `PermissionDeniedError`, and the denial is audited. |

### Phase 2 — Evidence integrity (1 week)

| PR | Change | Acceptance |
|---|---|---|
| 2.1 | Monotonic `sequence` + `key_id` inside the HMAC payload; `flock` + `fsync` in `FileAuditBackend.append`; re-read tail hash under lock; `verify_chain` rejects sequence gaps and validates against a signed head checkpoint. | Truncating the tail fails verification; two concurrent writers produce a valid chain. |
| 2.2 | `SigningAuditBackend` forwarding to an out-of-process signer (UDS collector first; KMS behind an interface). Agent process never holds the signing key. | Documented threat-model boundary; integration test with the collector. |
| 2.3 | `AuditEvent` gains `subject_ref`, `payload_digest`, `payload_redacted`, `policy_bundle_version`, `chain_mode`, `links`. Reporter calls `verify_chain()` first and refuses (or stamps `CHAIN BROKEN`) otherwise. | Replay can answer "why was APP-000038 declined"; a tampered log cannot produce a clean attestation. |
| 2.4 | OTel: child spans `agentguard.rbac_check`, `agentguard.policy_eval`, `agentguard.audit_write`; attributes per `ARCHITECTURE.md:386-400`; span status on deny; delete dead tracer helpers; `is_active` reflects a configured provider. Add OTel counters/histograms (or Prometheus exporter) for allow/deny/escalate and latency. | `InMemorySpanExporter` test asserts the span tree; denial reason visible in the trace. |

### Phase 3 — Guardrail kernel, shadow mode, durable HITL (2 weeks)

| PR | Change | Acceptance |
|---|---|---|
| 3.1 | Land `agentguard/guardrails/` (§5): `Guardrail`, `Decision`, `GuardrailChain`, `GovernanceKernel`. Reimplement RBAC, policy, PII, rate-limit, breaker-precheck as guardrails. `run_governed` becomes a deprecated shim over `kernel.guarded_tool_call`. | All existing adapter tests pass unmodified; chain semantics table (§5) has a test per row. |
| 3.2 | `ChainMode.SHADOW`: every guardrail runs, decisions recorded `enforced=False`, nothing blocked. | A shadow run reports would-be denials while blocking nothing. *This is the bank on-ramp; nothing gets enabled in production without it.* |
| 3.3 | `PolicyBundle` (content-hashed, versioned), atomic hot-reload, bundle version stamped into evidence. | Editing a policy file changes enforcement without restart and bumps `policy_bundle_version`. |
| 3.4 | `EscalationStore` (file-backed), resume tokens, TTL → deny-on-timeout, `escalated` and approval events (with `approver_id`, reason) written into the chain. | Process restarts between escalation and approval; invocation resumes at the correct chain index. Dashboard escalation counter is non-zero. |
| 3.5 | Agent authentication: signed short-lived credentials (JWT/workload identity) verified per call; registration behind an authenticated control plane. | Self-asserted `agent_id` without a valid credential is denied. |

### Phase 4 — Credit-risk domain as real guardrails (2 weeks)

| PR | Change | Acceptance |
|---|---|---|
| 4.1 | **Reason codes that are true or nothing.** Filter to strictly positive adverse contributions; raise on unmapped features and on zero true factors; `ReasonCode(code, code_set_version, consumer_text, reg_b_ref)` registry seeded with Appendix C wording, explicit slot for deployer bureau factor codes; `ScorecardAttributor` (points-lost vs. reference) and `CoefficientAttributor` as honest producers. | The 810-FICO / 0.10-DTI case **raises** instead of fabricating; notices carry code IDs and taxonomy version. |
| 4.2 | `on_decision` stage + the seven guardrails in §4. `CreditDecisioningAgent` → `CreditDecisionPolicy` (threshold logic) plus `GovernedCreditAgent` that emits through the kernel with distinct actions `model:score`, `decision:approve`, `decision:decline`, `notice:issue`, `decision:override`. | A decline with zero valid reason codes is blocked and never emitted; notice id is linked in the HMAC chain; PD in review band escalates rather than auto-declining; unresolved declines surface as violations. |
| 4.3 | Notice completeness: full Reg B Form C-1/C-3 structure, FCRA §615(a)/(b) blocks, decision-type enum (denied / counteroffer / incomplete / withdrawn), 30-day window, correct `MAX_REASONS` citation and 5-when-inquiries rule. | Snapshot test against a reference notice. |
| 4.4 | Fairness made statistically honest: `min_group_size`, two-proportion z / Fisher with p-values, CI on DI ratio, named disadvantaged group, `INSUFFICIENT_DATA` verdict; decile-binned calibration + ECE; `FairnessMonitor` fed by audit events with rolling windows. Fix demo to pass mean PD. | Random independent groups → `INSUFFICIENT_DATA` at n=200, pass at n=20,000; golden-value tests for DI, TPR/FPR, ECE. |
| 4.5 | Model validation: finding lifecycle (id, owner, due date, status), Gini/AUC consistency check, challenger comparison, backtest evidence, versioned signed report; outputs populate `ctx.attributes` for `ModelProvenanceGuardrail`. | Contradictory metrics rejected; a stale validation denies live decisions. |
| 4.6 | Synthetic data: joint structure (income → loan → LTV given property value; DTI from obligations), tunable `bias` parameter producing a real proxy; WGAN-GP `.eval()`, seeding, scaler round-trip, test asserting FICO ∈ [300, 850]. Demote `synthetic/` to `agentguard.testing` or a separate package. | Tests assert DI ≈ 0.65 at bias=X and ≥ 0.95 at bias=0; `generate(1)` works. |

### Phase 5 — Real adapters, honest verifier, real sandbox (1–2 weeks)

| PR | Change | Acceptance |
|---|---|---|
| 5.1 | LangGraph: subclass/compose real `ToolNode` (`ainvoke(state) -> {"messages": [ToolMessage]}`); CrewAI: subclass `BaseTool` with sync `_run`; ADK: wrap `FunctionTool`; MCP: wrap the real `ClientSession`. Tests run against the real packages under their extras. | Each adapter is placed in a real graph/crew/agent in an integration test and a denial surfaces as the framework's native error/message. |
| 5.2 | Formal verifier: differential test against `RBACEngine.check_permission` over random role sets *with wildcards and inheritance*; encode fnmatch subsumption and inheritance; delete severity→effect fabrication; `verify policy` compares real check predicates or is removed. Move to `agentguard/assurance/` and run as a bundle gate (`agentguard policy build`). | Differential test passes; `verify policy` on shipped bundle reports 0 contradictions; CI fails on a bundle with a proven escalation path. |
| 5.3 | Sandbox as an obligation: `Decision.obligations=[sandbox]` routes execution through `DockerSandboxBackend`; harden (`read_only`, `user`, `cap_drop=ALL`, `no-new-privileges`, `pids_limit`, CPU quota); red-team assertions check the *reason* for failure, not `exit_code != 0`. | Sandbox obligation is honoured on the governed path; hardened flags verified by inspecting the container. |
| 5.4 | Declarative composition: `guardrails.yaml` chain config; adapters take a `GovernanceKernel` instead of seven positional dependencies; remove deprecated constructors. | A chain defined entirely in YAML round-trips; README status table rewritten against the capability model. |

---

## 7. What to cut or demote

| Item | Action | Why |
|---|---|---|
| `synthetic/wgan_gp.py` | Move to `agentguard-synth` or `examples/` | A GAN has no business in a guardrails runtime; drags `torch` into the product story. |
| `synthetic/generators.py` | Demote to `agentguard.testing` | Demo/test utility, not a governance capability. |
| Unused extras (`presidio`, `aif360`, `fairlearn`, `wasmtime`, …) | Remove (or use) | Supply-chain surface and credibility hit for a security tool. |
| README status table + "Production" | Replace with capability scorecard | The specific thing the external reviewer reacted to. |
| `formal_verifier.py`, `z3_models.py` | Move to `agentguard/assurance/`, bundle gate | Good work, wrong layer; unsound as shipped. |
| `FairnessAnalyzer`, `ModelValidator` | Move to `domains/finance/mrm/`; outputs become guardrail inputs | Converts two report generators into a runtime control — the product thesis. |
| `ComplianceReporter` | Rebase on emitted evidence | A report of which YAML files loaded is a table of contents, not an attestation. |
| `observability/replay.py` | Reposition as re-evaluation against a pinned bundle version | What a model validator will actually ask for. |

---

## 8. Requirements ledger (walk before declaring any phase done)

1. No governance check may accept its subject (resource, identity, metadata value) from the party being governed.
2. Every decision boundary (tool pre/post, decision emission) is a chain that can `deny`, `transform`, or `escalate`.
3. Any exception inside governance → deny, audited.
4. Every deny/escalate carries ≥1 machine-stable reason code and is written to the chain *before* the caller learns of it.
5. The chain detects truncation and survives concurrent writers.
6. A decline cannot be emitted without ≥1 valid, attributed, taxonomy-versioned reason code linked in evidence.
7. Shadow mode exists before any domain guardrail is enabled.
8. No dependency is declared that is not imported; no API is documented that does not exist; no claim is in the README that lacks a test.
