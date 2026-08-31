# Guardrails Realignment: Gap Analysis and Fix Plan

> **For implementers:** Follow the repository's current `AGENTS.md` orchestration contract. Every PR listed below is independently shippable and has an acceptance test.

**Date:** 2026-08-21
**Trigger:** External code review concluded AgentGuard is "essentially a thin wrapper" and that intent (live guardrails engine for agentic AI in regulated industries) does not match implementation (notably: unclear how reason codes would be used in production).
**Method:** Five parallel read-only reviews (core runtime + adapters, compliance layer, finance domain, observability/CLI/docs/packaging, target architecture), each with file:line evidence and runnable probes. Every headline finding below marked ✔ was independently re-executed by the coordinating session before inclusion.

### Planning baseline and source-of-truth order

Use the following order when this plan, an older review, and the working tree disagree:

1. Checked-in production code and tests at the named baseline commit establish what exists.
2. Accepted ADRs in `DECISIONS.md` establish contracts and compatibility decisions.
3. Sections 1–7 preserve the baseline analysis and acceptance criteria; §9 records implementation status.
4. `context/impl/impl-review-findings.md` and the original Claude review are historical inputs; an item remains open until code and fresh verification close it.

**Historical review baseline:** branch `fix/phase0-truth-and-hygiene` at `d35f436` had Phase 0 (0.1–0.5) and Phase 1.1 committed.

**Current status (2026-08-29):** Phases 0–5 are implemented, independently re-reviewed (five probe-backed security reviews with every confirmed finding fixed), and committed at `288115f`; the four known limitations recorded in that review are closed per the 2026-08-29 §9 entry, with the remaining follow-ups listed there. Live Docker execution remains a required CI-only gate; the integration job fails before collection unless both the Docker SDK and daemon are available. The branch has not been pushed or merged.

---

## 1. Verdict at the historical baseline

**At `d35f436`, the criticism was correct, and it was structural, not cosmetic.**

At that baseline, the only runtime enforcement path in the package was `agentguard/integrations/_pipeline.py:run_governed` (176 lines):

```
resolve identity → RBAC fnmatch on two caller-supplied strings → write audit event → circuit breaker → call
```

At that baseline, everything the README stacked on top of that — policy-as-code, OWASP/FINOS/EU AI Act rules, PII masking, HITL escalation, rate limiting, sandboxing, formal verification — was **not reachable from that path**. `PolicyEngine` was called only by the CLI and the reporter. `HitlManager`, `PiiDetector`, `PiiMasker`, `TokenBucketRateLimiter`, and both sandbox backends had **zero call sites** outside `__init__.py` re-exports and their own tests.

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
| H ✔ | **No concrete workload credential verifier.** Closed by optional `JwtAgentAuthenticator`: fixed RS256, exact issuer/audience/subject, required short-lived claims, operator-pinned local JWK snapshots, bounded compare-and-swap rotation overlap, atomic replay protection, emergency revocation, and no request-path key discovery. | `core/jwt_authentication.py`; `guardrails/kernel.py`; Phase 3.5e |
| H ✔ | **Audit truncation is undetectable.** Deleting the last 3 of 5 events → `verify_chain()` returns `valid=True`. No sequence number, no signed head. | `audit.py:161-178` |
| H | **Audit chain breaks under two writers** (false `AuditTamperDetectedError`). `_prev_hash` is per-instance; no `flock`; blocking I/O inside `async def`. | `audit.py:63-68,103` |
| H | **Signing key held by the audited process** (`os.environ`). Any code in the agent process can forge the chain. No key ID, no rotation. | `audit.py:98` |
| H | **"Sandboxed execution" does not exist on the governed path.** `sandbox.py` runs a `list[str]` command; the pipeline runs an in-process callable. Disjoint APIs. Docker backend sets only `network_disabled` + `mem_limit` (no `read_only`, `user`, `cap_drop`, seccomp, pids/cpu limits); 0% coverage; red-team tests never run in CI. | `sandbox.py:101-171`; `ci.yml:48` |
| H ✔ | **Framework adapters import no framework.** Zero `langgraph`/`crewai`/`google.adk`/`mcp` imports repo-wide. `GovernedLangGraphToolNode.ainvoke(tool_name, tool_input, resource)` cannot sit in a `StateGraph` (real `ToolNode.ainvoke(state)`). CrewAI wrapper is async where CrewAI calls tools synchronously. All tested against `AsyncMock`. | `integrations/*.py`; `pyproject.toml:46-55` |
| M | Rate limiter is dead code; breaker is per-instance, in-memory, not keyed by (agent, tool). | `circuit_breaker.py:116-147` |
| M | Breaker rejection is logged as `allowed` then `error` (pre-event precedes breaker). | `_pipeline.py:133-139` |
| L | `*` still crosses `/`; the legacy compatibility-only `FileBackedRegistry` uses a predictable temporary path and unsigned JSON. | `rbac.py`; `identity.py` |

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
       ModelProvenanceGuardrail      deny   MRM.MODEL_UNVALIDATED / FAIR.CHECK_FAILED
       DecisionBandGuardrail         escalate HITL.REVIEW_BAND
       ReasonCodeGuardrail           deny   AA.NO_REASON_CODES / AA.UNKNOWN_CODE
       AttributionIntegrityGuardrail deny   AA.CODE_NOT_ATTRIBUTED / AA.ATTRIBUTION_MODEL_MISMATCH
       NoticeCompletenessGuardrail   deny   AA.NOTICE_INCOMPLETE / AA.NOTICE_WINDOW_EXCEEDED
       DecisionEvidenceGuardrail     deny   PII.UNSAFE_DECISION_EVIDENCE
  → typed notice artifact → NoticeRenderer.render()
  → governed notice:issue evidence links={notice_id, template_version, body_sha256,
                                          model_version}  [HMAC-chained; no body/PII]
```

The invariant "a decline carries at least one valid ECOA principal reason" must be a
**guardrail at the emission boundary**, not only a check inside an artifact constructor — any
library object can be bypassed by a caller; the `on_decision` chain is the only path by which a decision reaches
the outside world. Regulation B does not impose a hard four-reason maximum. An institution may
configure a principal-reason presentation limit, but that is policy rather than a statutory cap.
FCRA credit-score key factors are a separate disclosure with a four-factor limit and a fifth only
when inquiries are themselves a key factor.

### Phase 4.1 locked contract

- Replace the ambiguous `feature_importances` input; do not silently reinterpret it. This is an
  announced pre-1.0 break, and every repository caller, example, API document, and serialization
  test must migrate.
- `ScorecardAttributor` takes exact applicant and reference point maps plus an explicit
  `higher_is_better` / `lower_is_better` direction. It emits `reference - applicant` for the former
  and the reverse for the latter.
- `CoefficientAttributor` takes exact values, reference values, coefficients, and an explicit
  modeled-output direction. It computes `coefficient * (value - reference)` and negates that delta
  only when lower model output is more adverse. Inputs are the fitted model's actual transformed
  feature space; booleans, missing/extra keys, intercept pseudo-features, NaN, and infinities fail.
- Both attributors emit only finite, strictly positive contributions in deterministic
  `(-contribution, feature)` order. Their immutable attribution envelope also carries `model_id`,
  `model_version`, `reference_id`, method, and the complete transformed-feature schema evaluated,
  including zero and favorable factors. Empty positive attribution evidence is valid, but notice
  generation from it fails `AA.NO_TRUE_FACTORS`.
- The versioned code vocabulary and each model's feature-to-code binding are separate. Appendix C
  wording is seeded under AgentGuard-local IDs; no generic feature name automatically selects a
  reason. Deployers must bind every scored feature or bin explicitly.
- Every positive contribution is resolved before selection or presentation limiting. Any unmapped
  contribution fails `AA.UNMAPPED_FEATURES`, including a lower-ranked contribution that would not
  be displayed.
- The registry binding must exactly cover the attribution envelope's complete transformed-feature
  schema before applicant-specific positive filtering. A feature cannot remain silently unbound
  merely because it is favorable for one applicant; missing and extra model bindings fail closed.
- `ReasonCodeSelection` and every notice preserve the attribution envelope's model, version,
  reference, and method fields so Phase 4.2 can validate provenance without reconstructing it.
- Multiple source features mapped to one principal reason are consolidated by summing their
  contributions and sorting their canonical feature names. Consolidated reasons are ranked by
  `(-sum, code)`.
- ECOA principal reasons and FCRA bureau score factors occupy distinct registry purposes. Bureau
  factors cannot satisfy the ECOA principal-reason invariant. Custom ECOA reasons and bureau
  factors require explicit code, version, consumer text, and legal/source reference.
- Stable failures are locked now: `AA.NO_TRUE_FACTORS`, `AA.UNMAPPED_FEATURES`,
  `AA.INVALID_ATTRIBUTION`, and `AA.TAXONOMY_MISMATCH`. Phase 4.2 maps them directly to guardrail
  outcomes without parsing exception text.
- The test matrix covers both scorecard directions, every coefficient sign/direction quadrant,
  exact-key and finite-number failures, favorable/zero omission, the 810-FICO/0.10-DTI empty case,
  unmapped lower-ranked factors, duplicate-code aggregation, deterministic ties, namespace and
  taxonomy collisions, deep immutability, and serialized taxonomy/model/reference/code IDs.

Rejected alternatives: patching `abs(feature_importance)` in place would leave model direction and
reference undefined; accepting a compatibility shim would keep the unsafe ambiguity callable;
inferring codes from generic feature names could emit a reason the deployed model did not actually
use. The selected design therefore uses explicit attribution and per-model binding boundaries.

---

## 5. Target architecture (summary)

New package `agentguard/guardrails/`. Framework-agnostic, async, Pydantic v2, no DB, fail-closed.

```python
Stage = Literal["input_transform", "pre_tool", "post_tool", "pre_llm", "post_llm",
                "pre_message", "post_message", "pre_retrieval", "post_retrieval",
                "pre_memory_write", "on_decision", "attestation"]

# Every model is frozen and every nested JSON value is recursively immutable.
# Tool calls and agent messages remain different contracts; neither can be
# smuggled through the other's discriminator.
RuntimePayload = ToolCallPayload | ToolResultPayload | PromptPayload | CompletionPayload \
               | MessagePayload | RetrievalPayload | DecisionPayload
EvidencePayload = RedactedToolCallEvidence | RedactedToolResultEvidence \
                | RedactedMessageEvidence | RedactedDecisionEvidence

class GuardrailContext(BaseModel):      # frozen, including nested values
    trace_id: str; invocation_id: str; stage: Stage
    identity: AgentIdentity
    action: str | None; resource: str | None  # absent during input_transform
    payload: RuntimePayload; attributes: FrozenJsonObject
    prior: tuple[Decision, ...]

class Reason(BaseModel):    # code is registry-backed and machine-stable
    code: str; message: str; severity; reference: str; evidence: FrozenJsonObject

class Decision(BaseModel):  # deeply frozen
    # deny/escalate require >=1 reason; transform requires a same-kind payload
    action: Literal["allow", "deny", "transform", "escalate", "warn"]
    guardrail_id: str; guardrail_version: str; reasons: tuple[Reason, ...]
    payload: RuntimePayload | None; escalation: EscalationRequest | None
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
    # allow→continue; transform→replace payload, continue; warn→record, continue
    # escalate→stop, persist resume token; deny→stop; raise/timeout→deny when fail_mode="closed"

class GovernanceKernel:  # replaces run_governed
    async def guard(self, stage, *, agent_id, action, resource, payload, attributes) -> ChainOutcome
    async def guarded_tool_call(self, *, agent_id, action, resource, payload, executor) -> Any
    #   pre_tool chain → execute transformed payload (honouring obligations, e.g. sandbox) → post_tool chain
```

**Phase 1 call order is contractual:** construct a typed raw payload → run fail-closed `input_transform` guardrails → derive `action` and `resource` from the transformed payload → authorize and evaluate pre-stage policy → atomically reserve limiter/breaker capacity and write `admission` → execute only the transformed runtime payload → evaluate output → write exactly one delivery terminal. A resolver and the executor therefore see the same payload. Sync resolvers run in a dedicated bounded executor with a bounded queue and timeout; saturation, timeout, cancellation, invalid output, or resolver failure yields an audited denial.

**Evidence separation is contractual:** runtime payloads may contain secrets and are never serialized into audit events. The evidence sink receives only a policy-produced, redacted `EvidencePayload` plus a digest of the canonical runtime payload. Redaction failure denies delivery. The runtime and evidence types are deliberately not interchangeable.

**Stable reason codes:** every deny or escalation carries at least one code from a registry. Runtime codes use stable namespaces such as `RESOURCE.UNRESOLVED`, `RBAC.PERMISSION_DENIED`, `GUARDRAIL.TIMEOUT`, `GUARDRAIL.INTERNAL_ERROR`, `RATE_LIMIT.EXCEEDED`, and `CIRCUIT_BREAKER.OPEN`; policy violations use the stable shipped rule ID (for example `OWASP-AGENT-01`). Human text and evidence may evolve without changing the code.

**Lifecycle evidence:** Phase 1 emits `admission`, `execution_completed`, and exactly one of `delivery_completed`, `delivery_denied`, or `delivery_escalated` for an admitted invocation. A pre-admission rejection emits `delivery_denied` without an `admission`. Dashboard aggregation groups by `invocation_id`; if malformed history contains more than one delivery terminal, precedence is `delivery_denied` → `delivery_escalated` → `delivery_completed`. Without a delivery terminal, `execution_completed` means executed but not delivered, and `admission` means admitted but not known to have executed; neither is counted as allowed.

**Migration map:** `RBACEngine` → `RbacGuardrail` with a typed `PermissionContext` artifact; `TokenBucketRateLimiter` → `RateLimitGuardrail`; `PolicyEngine.evaluate(AuditEvent)` → `PolicyGuardrail.evaluate(ctx) -> Decision` with typed `PolicyResult` artifacts and rule schema gaining `stage`, `applies_to`, `on_fail`; `PiiDetector/Masker` → `PiiGuardrail` (transform internally, deny on egress); `HitlManager` → `HitlGuardrail` + durable `EscalationStore`; `AppendOnlyAuditLog` → `EvidenceSink` (**not** a chain member — it records other guardrails' denials); `CircuitBreaker` remains a kernel-owned atomic admission/execution boundary (**not** a precheck guardrail, which would introduce a reservation race); `SandboxBackend` → obligation handler (**not** a chain member); `FormalVerifier` → bundle-build/CI gate; `FairnessAnalyzer`/`ModelValidator` → evidence producers feeding `ctx.attributes` so `ModelProvenanceGuardrail` can deny live decisions from a stale or biased model.

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
| 1.2 | **Lock payload and transform ordering.** Add deeply immutable, discriminated runtime payloads. `ToolCallPayload`/`ToolResultPayload` and `MessagePayload` are distinct contracts. Run `input_transform` before deriving action/resource, and execute exactly the transformed payload. Split runtime payloads from redacted evidence payloads. Run sync resolvers in a dedicated bounded executor with bounded queue and timeout; apply the same timeout to async resolvers. | Mutation of nested args/parts fails; a tool payload cannot validate as a message; all five adapters expose their real input and output through the correct payload type. A resolver and executor both observe the transformed value. Resolver saturation, timeout, cancellation, exception, non-string output, or invalid resource is denied and audited; the event loop remains responsive. No raw runtime payload appears in serialized evidence. |
| 1.3 | **Move evidence and lifecycle prerequisites into Phase 1.** Add `invocation_id`, stable `reason_codes`, `payload_digest`, typed redacted evidence, and lifecycle event type to `AuditEvent`. New writes use HMAC schema v2; historical unversioned/v1 bytes verify under the exact v1 serializer and are never rewritten. Emit `admission` before execution, `execution_completed` after every admitted executor attempt, then one delivery terminal. Update replay/dashboard to aggregate by invocation with terminal precedence from §5. | Golden v1 fixture verifies unchanged; new v2 and mixed v1→v2 chains verify; changing a v2 lifecycle/evidence field breaks verification. Admission write failure prevents execution. Success, executor error, post-stage denial, escalation, breaker rejection, and rate rejection have exact lifecycle sequences. Dashboard does not count admission as allow and resolves duplicate terminals deny → escalate → complete. |
| 1.4 | **Put policy on the hot path with safe effects.** Add schema-versioned `stage`, `applies_to`, and `effect: allow \| deny \| escalate \| warn`. A v2 rule missing or carrying an unknown stage/effect/check type fails bundle load; exceptions and timeouts deny. Legacy v1 bundles remain detect-only `warn` for compatibility. Migrate the shipped 35 rules exactly per the table below; `content_scan` reads typed runtime content, while attestation rules never authorize a call. | Totals are exactly 14 `pre_tool`, 1 `post_tool`, 20 `attestation`; effects are exactly 3 `deny`, 3 `escalate`, 29 `warn`. A live MCP prompt-injection call is blocked with `OWASP-AGENT-01`; RBAC defense-in-depth failure is blocked with `OWASP-AGENT-06`; insecure output is withheld with `OWASP-AGENT-09`. An invalid or throwing policy cannot silently become allow. |
| 1.5 | **Add post-execution delivery guardrails.** Run results through `post_tool`; wire generic `PiiGuardrail`, `SecretEgressGuardrail`, and `OutputSchemaGuardrail`. Move generic detection/redaction to `agentguard/guardrails/` while keeping `agentguard.domains.finance.pii` as the finance preset and compatibility import boundary. Add a structlog scrubbing processor; fix SSN validity, dead patterns, numeric-context guard, and recursive container handling. | An SSN in tool args is transformed before resource derivation and execution; an SSN or secret in output is redacted or denied before delivery; schema-invalid output is not returned. Audit/log capture contains redacted evidence only. Existing finance PII imports continue to work and generic guardrails do not import the finance domain. |
| 1.6 | **Wire limits through an atomic breaker admission callback.** Key rate limits by `(agent_id, action)`. Breaker state admission and single HALF_OPEN probe reservation stay under its lock; its `before_execute` callback writes `admission` after reservation and before the executor. Callback failure releases the probe and never calls the executor. | Concurrent recovery admits exactly one probe; concurrent threshold failures emit one OPEN transition; a breaker rejection has no admission event; admission failure cannot execute; successful terminal latency is non-zero. |
| 1.7 | **Prove the fail-closed matrix.** Exercise transform, derivation, RBAC, policy, limiter, breaker callback, executor, post-stage, redaction, evidence, and terminal-write failures. Only an explicitly configured `warn` rule continues; there is no generic fail-open runtime mode in Phase 1. | Table-driven tests prove the executor is not called before admission; no result is delivered without `delivery_completed`; every deny/escalate has a stable reason code; audit-write failure is never replaced by an allow. |

#### Shipped policy migration table (Phase 1.4)

This is a compatibility migration, not a claim that all 35 controls become enforcement. The 20 `attestation` rules remain `warn` until a trusted evidence producer exists. The pre/post rules that remain `warn` are detection signals whose current string checks are too broad to block safely.

| Bundle | Rule ID | Stage | Effect |
|---|---|---|---|
| OWASP | `OWASP-AGENT-01` | `pre_tool` | `deny` |
| OWASP | `OWASP-AGENT-02` | `pre_tool` | `warn` |
| OWASP | `OWASP-AGENT-03` | `pre_tool` | `warn` |
| OWASP | `OWASP-AGENT-04` | `pre_tool` | `warn` |
| OWASP | `OWASP-AGENT-05` | `pre_tool` | `warn` |
| OWASP | `OWASP-AGENT-06` | `pre_tool` | `deny` |
| OWASP | `OWASP-AGENT-07` | `pre_tool` | `warn` |
| OWASP | `OWASP-AGENT-08` | `pre_tool` | `warn` |
| OWASP | `OWASP-AGENT-09` | `post_tool` | `deny` |
| OWASP | `OWASP-AGENT-10` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-001` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-002` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-003` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-004` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-005` | `pre_tool` | `escalate` |
| FINOS-aligned | `AG-FINOS-008` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-010` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-012` | `pre_tool` | `warn` |
| FINOS-aligned | `AG-FINOS-015` | `pre_tool` | `warn` |
| FINOS-aligned | `AG-FINOS-018` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-022` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-025` | `pre_tool` | `escalate` |
| FINOS-aligned | `AG-FINOS-030` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-035` | `attestation` | `warn` |
| FINOS-aligned | `AG-FINOS-040` | `pre_tool` | `warn` |
| EU AI Act | `EU-AI-ACT-ART9-01` | `attestation` | `warn` |
| EU AI Act | `EU-AI-ACT-ART9-02` | `attestation` | `warn` |
| EU AI Act | `EU-AI-ACT-ART10-01` | `attestation` | `warn` |
| EU AI Act | `EU-AI-ACT-ART10-02` | `attestation` | `warn` |
| EU AI Act | `EU-AI-ACT-ART13-01` | `attestation` | `warn` |
| EU AI Act | `EU-AI-ACT-ART13-02` | `attestation` | `warn` |
| EU AI Act | `EU-AI-ACT-ART14-01` | `pre_tool` | `escalate` |
| EU AI Act | `EU-AI-ACT-ART14-02` | `attestation` | `warn` |
| EU AI Act | `EU-AI-ACT-ART17-01` | `attestation` | `warn` |
| EU AI Act | `EU-AI-ACT-ART17-02` | `attestation` | `warn` |

Totals: OWASP 10 + FINOS-aligned 15 + EU AI Act 10 = **35 rules**; stages = **14 pre-tool + 1 post-tool + 20 attestation**; effects = **3 deny + 3 escalate + 29 warn**.

### Phase 2 — Evidence integrity (1 week)

| PR | Change | Acceptance |
|---|---|---|
| 2.1 | Build sequence and checkpoint integrity on the Phase 1 v2 envelope: monotonic `sequence` + `key_id` inside signed bytes; `flock` + `fsync` in `FileAuditBackend.append`; re-read tail hash under lock; reject sequence gaps; validate a signed head checkpoint. | Truncating the tail fails verification; two concurrent writers produce a valid chain; the v1 compatibility fixture still verifies and the first v2 sequence starts without rewriting v1 history. |
| 2.2 | `SigningAuditBackend` forwarding to an out-of-process signer (UDS collector first; KMS behind an interface). Agent process never holds the signing key. | Documented threat-model boundary; integration test with the collector. |
| 2.3 | Add `subject_ref`, `policy_bundle_version`, `chain_mode`, and typed `links` to the Phase 1 evidence envelope. Reporter validates chain, sequence, and signed checkpoint first and refuses (or stamps `CHAIN BROKEN`) otherwise. | Replay can answer "why was APP-000038 declined" without exposing the runtime payload; a tampered or truncated log cannot produce a clean attestation. |
| 2.4 | OTel: child spans `agentguard.rbac_check`, `agentguard.policy_eval`, `agentguard.audit_write`; attributes per `ARCHITECTURE.md:386-400`; span status on deny; delete dead tracer helpers; `is_active` reflects a configured provider. Add OTel counters/histograms (or Prometheus exporter) for allow/deny/escalate and latency. | `InMemorySpanExporter` test asserts the span tree; denial reason visible in the trace. |

### Phase 3 — Guardrail kernel, shadow mode, durable HITL (2 weeks)

| PR | Change | Acceptance |
|---|---|---|
| 3.1a | Land the pure chain boundary first: preserve the public `GuardrailOutcome` contract, add chain-owned evaluated-decision records (`guardrail_id`, version, duration, enforced), and add `GuardrailChain`. The chain accumulates prior decisions, propagates external cancellation, rejects cross-kind transforms, converts ordinary failures/timeouts to stable fail-closed outcomes, and validates duplicate IDs/stages/timeouts at construction. | Tests cover stage skip, allow/warn continuation, transform propagation, exact payload-kind safety, deny/escalate short-circuit, exception, timeout, cancellation, prior accumulation, invalid construction, and terminal non-execution. No adapter or signed lifecycle behavior changes in this slice. |
| 3.1b | Add `GovernanceKernel` and migrate RBAC, policy, PII, and rate limiting behind it while retaining typed `PermissionContext`/`PolicyResult` artifacts. Keep circuit-breaker admission and its `before_execute` audit callback kernel-owned so HALF_OPEN reservation remains atomic. Preserve the exact admission → execution-completed → delivery-terminal evidence order. `run_governed` becomes a deprecated behavior-preserving shim over `kernel.guarded_tool_call`; adapters may accept a kernel without breaking legacy constructors. | All existing adapter/pipeline tests pass unmodified; new tests prove typed artifacts survive into evidence, one HALF_OPEN probe remains atomic, lifecycle ordering is byte-for-byte compatible, and every adapter can use the kernel path. |
| 3.2 | Wire the pure-chain `ChainMode.SHADOW` semantics from 3.1a into the kernel, adapters, evidence, configuration, and reporting. Every guardrail runs, decisions are recorded `enforced=False`, transforms do not alter the runtime payload, and nothing is blocked. | A configured adapter shadow run reports durable would-be denials while blocking and transforming nothing. *This is the bank on-ramp; nothing gets enabled in production without it.* |
| 3.3 | `PolicyBundle` (content-hashed, versioned), atomic hot-reload, bundle version stamped into evidence. | Editing a policy file changes enforcement without restart and bumps `policy_bundle_version`. |
| 3.4a | Durable request-state foundation first: file-backed `EscalationStore`, opaque token verifiers, exact TTL expiry, schema-v5 request evidence, idempotent request event IDs, and dashboard support for future lifecycle evidence. The store exposes no decision/claim method, and existing non-resumable kernel behavior remains compatible until the authenticated continuation boundary exists. | Pending state and TTL survive restart; tokens are never persisted or audited; tampered state fails closed; a token escapes only after durable state and signed request evidence exist; post-execution cancellation still commits one delivery terminal. |
| 3.4b | Authenticated decisions plus protected pre-execution resume: mandatory authenticated approver, signed/idempotent granted/denied/expired events, trusted executor registry, injected AEAD continuation protector, exact policy/complete-chain fingerprint, multi-approval cursor, pinned policy execution, stable claim metadata, and RBAC recheck. `resume_tool_call` accepts neither a caller payload nor arbitrary executor. | Process restarts after one or more pre-execution escalations; authenticated approval evidence is signed before it becomes effective; each approval resumes after its triggering guardrail; one live/concurrent claimant can invoke the executor at most once; revoked, denied, expired, and ordinary pre-admission-cancelled requests write one delivery terminal. A process crash after claim is never replayed automatically and remains Phase 3.4d reconciliation. |
| 3.4c | Protected post-execution delivery: seal the completed result and authenticated post-stage cursor before exposing the approval token; approval resumes only post-processing and never resolves or invokes an executor. Use distinct delivery-claim/handoff/terminal store states and stable terminal evidence. Guardrail-triggered POST_TOOL/POST_MESSAGE requests are the first safe slice; policy-only post cursors remain non-resumable until explicitly modeled. | Restart after a post-stage guardrail escalation delivers the sealed result without another executor call; denial/expiry/cancellation writes one `delivery_denied`; concurrent delivery has one claimant; a downstream post escalation creates a protected child request without executor replay. |
| 3.4d | Execution journal and authenticated `IN_DOUBT` reconciliation: add stable admission/execution event IDs and a protected outcome journal; classify claimed-without-terminal, admission-without-completion, and completion-without-protected-result windows from verified evidence. Reconciliation requires authenticated `hitl:reconcile` authority and the only generic resolution is deny delivery. | No arbitrary executor is automatically replayed after admission. A protected known result can continue without execution; an unknown side-effect window becomes `IN_DOUBT`; append-then-raise audit/store windows converge idempotently; no API accepts a caller-supplied replacement result or executor. |
| 3.5a | Mechanism-neutral agent-authentication contracts plus schema-v7 signed `AuthenticationEvidence`. Credentials yield a trusted principal without roles; invalid credentials audit under a reserved unauthenticated actor without persisting claims, raw errors, or secrets. | Contract tests prove principals contain no authorization claims; rejected lifecycle envelopes cannot persist a claimed actor, request data, raw errors, or credentials; all authentication failure classes share canonical `AUTH.*` codes; and frozen v1-v6 audit bytes still verify. Live authenticate-before-lookup enforcement remains 3.5c. |
| 3.5b | Registry authority and authenticated library control plane: active/revoked records, monotonic revision and credential epoch, defensive snapshots, constrained role grants, prepare → audit → commit idempotency, and hardened signed POSIX persistence (or an explicitly legacy-only file registry). | Runtime token claims cannot grant roles; registration/role/revocation mutation requires a distinct administrator authority and survives concurrency/tamper/restart tests. |
| 3.5c | Sticky authenticated kernel mode and protected-continuation authentication binding. Authenticate before identity/executor lookup; never fall back to self-asserted IDs. Resume rechecks current active identity, registry epoch, and RBAC without requiring the original short-lived credential. | A configured secure kernel rejects ID-only calls and legacy continuations; expiry during HITL wait does not replay execution, while explicit agent/credential revocation denies PRE execution and POST delivery. |
| 3.5d | Per-call credential providers for every adapter; providers are invoked for each call and never cached. Isolate the deprecated `run_governed` shim as legacy-only and remove adapter-side use/logging of claimed actor identity before authentication. | Each adapter rotates credentials between calls, provider failures are audited in the kernel, and registered executor IDs cannot be probed before authentication. |
| 3.5e | Concrete signed short-lived verifier after the trust model and dependency are explicitly selected. JWT/OIDC or workload identity must define issuer/audience/subject, fixed algorithms, key rotation, expiry/skew, replay protection, and emergency revocation; registration uses a distinct trust domain. | Adversarial signature/algorithm/key/claim/replay tests pass; self-asserted `agent_id` without a valid per-call credential is denied. |

### Phase 4 — Credit-risk domain as real guardrails (2 weeks)

| PR | Change | Acceptance |
|---|---|---|
| 4.1 | **Reason codes that are true or nothing.** Filter to strictly positive adverse contributions; raise on unmapped features and on zero true factors; `ReasonCode(code, code_set_version, consumer_text, reg_b_ref)` registry seeded with Appendix C wording, explicit slot for deployer bureau factor codes; `ScorecardAttributor` (points-lost vs. reference) and `CoefficientAttributor` as honest producers. | The 810-FICO / 0.10-DTI case **raises** instead of fabricating; notices carry code IDs and taxonomy version. |
| 4.2 | `on_decision` stage + the seven controls in §4. `CreditDecisioningAgent` → `CreditDecisionPolicy` (threshold logic) plus `GovernedCreditAgent` that emits through the kernel with distinct actions `model:score`, `decision:approve`, `decision:review`, `decision:decline`, `decision:override`, and `notice:issue`. | A decline with zero valid reason codes is blocked and never emitted; notice id is linked in the HMAC chain; PD in review band escalates rather than auto-declining; unresolved declines surface as violations. |
| 4.3 | Notice completeness: full Reg B Form C-1/C-3 structure, FCRA §615(a)/(b) blocks, decision-type enum (denied / counteroffer / incomplete / withdrawn), 30-day window, correct `MAX_REASONS` citation and 5-when-inquiries rule. | Snapshot test against a reference notice. |
| 4.4 | Fairness made statistically honest: typed per-decision observations, `min_group_size`, two-proportion z / Fisher with p-values, CI on the named DI ratio, `INSUFFICIENT_DATA`, decile-binned calibration + ECE, and a rolling `FairnessMonitor` that joins verified decision evidence to a trusted private observation provider. | Small deterministic fixtures are insufficient, a fixed large balanced fixture passes, golden DI/CI/p-value/TPR/FPR/ECE values match, and no protected label, PD, or outcome row enters audit evidence. |
| 4.5 | Model validation: finding lifecycle (id, owner, due date, status), definition-aware Gini/AUC consistency, same-sample challenger comparison, backtest and private-monitor fairness evidence, and a versioned signed report. A verified exact-model report source populates the trusted `ModelGovernanceEvidenceProvider`; caller `ctx.attributes` remain non-authorizing. | Contradictory metrics and tampered/future/stale reports are rejected; exact signed current evidence allows while stale validation denies live decisions. |
| 4.6 | Synthetic data: joint structure (income → loan → LTV given property value; DTI from obligations), tunable `bias` parameter producing a real proxy; WGAN-GP `.eval()`, seeding, scaler round-trip, test asserting FICO ∈ [300, 850]. Demote `synthetic/` to `agentguard.testing` or a separate package. | Tests assert DI ≈ 0.65 at bias=X and ≥ 0.95 at bias=0; `generate(1)` works. |

#### Phase 4.2 locked contract

- Add immutable `DecisionPayload(kind="decision", domain, decision_id, outcome, body)` and
  `GuardrailStage.ON_DECISION` to the generic guardrail boundary. A decision payload is preserved
  as the executor result and uses the kernel's existing authentication, RBAC, policy, limiter,
  breaker, audit-first admission, signed execution, shadow-mode, protected POST continuation, and
  delivery-terminal lifecycle. No domain code may call `GuardrailChain` directly or duplicate that
  governance path.
- `model:score` remains an ordinary governed tool call. A pure, synchronous, side-effect-free
  `CreditDecisionPolicy` validates a finite PD in `[0, 1]` and returns only `approve`, `review`, or
  `decline` from explicit versioned thresholds. Remove applicant logging, mutable reason strings,
  hard cutoff diagnostics masquerading as model reasons, and the arbitrary
  `len(reasons) >= 2` decline branch from the legacy template.
- `GovernedCreditAgent` emits fixed actions with independently authorizable resources:
  `model:score`, `decision:approve`, `decision:review`, `decision:decline`,
  `decision:override`, and `notice:issue`. A review outcome is never rewritten as a decline.
  `ON_DECISION` is a terminal validation boundary and does not permit transformations; changing a
  final outcome requires a new independently authorized emission.
  `DecisionBandGuardrail` escalates `HITL.REVIEW_BAND` at `ON_DECISION`; protected POST resume
  continues from the sealed decision without scoring or policy execution again.
- Generic HITL approval authorizes delivery of the sealed `review` result only; it is not a credit
  approval or decline. An underwriter's final result is a separate authenticated
  `decision:override` emission checked by its own RBAC action. Its executor validates a
  checkpoint-attested, ordered review lifecycle for the supplied parent escalation and requires
  exact decision/application/model/policy lineage; a caller-provided parent string is never
  authorizing evidence.
- The seven `ON_DECISION` controls are: configured protected-feature schema denial; trusted exact
  model/version validation and fairness provenance; review-band escalation; decline reason-code
  presence/taxonomy validation; exact attribution-to-reason integrity; notice artifact/timing and
  rerendered digest validation for `notice:issue`; and a deny-by-default allowlist for redacted
  decision evidence. Caller-supplied context cannot satisfy trusted model provenance. Phase 4.5
  supplies production model-validation evidence; missing evidence fails closed in this phase.
- A decline candidate may carry a typed attribution/reason failure so the emission boundary can
  sign the exact stable denial instead of losing it before governance. Stable runtime identifiers
  are explicit constants, including `FAIR.PROTECTED_FEATURE_IN_INPUT`,
  `MRM.MODEL_UNVALIDATED`, `FAIR.CHECK_FAILED`, `HITL.REVIEW_BAND`,
  `AA.NO_REASON_CODES`, `AA.UNKNOWN_CODE`, `AA.CODE_NOT_ATTRIBUTED`,
  `AA.ATTRIBUTION_MODEL_MISMATCH`, `AA.UNRESOLVED_DECLINE`, and
  `PII.UNSAFE_DECISION_EVIDENCE`; existing Phase 4.1/4.3 failures remain exact.
- `notice:issue` records an already-completed Phase 4.3 written-notification event; it does not
  claim that rendering performed delivery. The notice body and the notice/applicant artifact never
  enter a guardrail payload or audit event. Only an allowlisted evidence envelope may be governed:
  domain-separated hashes of decision/application/notice/model identifiers, profile/template
  version, body SHA-256, actual notification timestamp, and legal deadline. Future notification
  timestamps fail closed, and the private prepared-notice provider is mutated only inside the
  admitted executor.
- Thread the existing signed `subject_ref` and typed `AuditLink` fields through decision lifecycle
  events and protected continuations without changing frozen audit wire versions. Link namespaces
  and relations are allowlisted; raw applicant IDs, names, addresses, reason text, feature names or
  values, contributions, PD, and notice bodies are forbidden.
- A verified-audit correlation validator reports a delivered decline without one matching,
  successfully delivered, timely `notice:issue` link as `AA.UNRESOLVED_DECLINE`. It refuses a clean
  classification when chain/checkpoint verification fails; malformed decision/application links,
  final decline overrides, and missing trusted notice-control evidence are classified explicitly.
  Denied, mismatched, unvalidated, or late notice attempts do not resolve the decline.
- Implement in eight reviewable slices: generic contracts; kernel decision-result routing and
  protected resume; pure decision policy/candidate models; reason/attribution/protected-feature/
  review controls; trusted model-governance evidence; notice metadata/link plumbing; governed
  agent orchestration; correlation validator plus examples/docs. Each slice locks behavior with
  focused regression tests before the next begins.

#### Phase 4.3 locked contract

- Replace the Phase 4.1 reason-evidence wrapper with immutable, `extra="forbid"` regulatory
  artifacts for denied applications, standalone counteroffers, combined counteroffer/adverse
  action, counteroffer nonacceptance, incomplete applications, and withdrawal records.
- Denial timing supports both completed-application and action-taken triggers; C-6 keeps its
  distinct incomplete-application receipt trigger. Combined C-4 artifacts require written
  acceptance instructions, a response address, and a deployer-defined acceptance deadline.
- Only `WrittenNotificationEvent` (`mailed` or `delivered`) satisfies denied, combined,
  nonacceptance, and incomplete written-notice timing. The initial standalone counteroffer may
  use a distinct `CounterofferNotificationEvent` that also permits `oral`. Thirty-day and
  ninety-day windows are calculated from the applicable actual communication event, never from
  render or preparation time.
- Principal reasons use one normalized, ranked set with either model attribution provenance or a
  versioned policy/HITL decision-component origin. `ReasonCodeSelection` converts losslessly into
  the model-origin form; notice artifacts cannot imply model attribution for non-model reasons.
- Information-source applicability is explicit and discriminated: no FCRA source, consumer-report
  source, non-CRA third-party source under 15 USC 1681m(b)(1), affiliate source under
  1681m(b)(2), or a validated combination. Consumer-report sources require unique CRA contacts
  and an explicit `score_used` assertion; a score disclosure is present if and only if the score
  was used. Non-CRA written requests use the 60-day request rule and reasonable response;
  affiliate written requests use the 60-day request rule and the 30-day response window after a
  timely request.
- Bureau score-factor codes, model bindings, and selections form an independent immutable registry
  and namespace. Score disclosures carry provider, score, range, creation date, and ranked factors.
  The registry validates the complete model schema and ranks every adverse factor before selecting
  four for display; one unambiguous inquiry factor is appended as a fifth when it was not already
  selected in the four.
- Rendering uses explicit versioned profiles: current Appendix C C-1 (general adverse action), C-3
  (credit-scoring adverse action), C-4 (combined counteroffer/adverse action), C-6 (incomplete
  application), and an AgentGuard standalone-counteroffer profile. Canonical output is UTF-8 text
  with LF line endings and one terminal newline; its SHA-256 digest covers those exact bytes.
- `AA.NOTICE_INCOMPLETE` and `AA.NOTICE_WINDOW_EXCEEDED` are stable failures. Withdrawal is a record,
  not a renderable notice. Rendering does not write audit evidence; Phase 4.2 owns redacted notice
  references and must never persist notice bodies or applicant PII in the audit chain.
- This is a source-grounded artifact and rendering boundary, not a claim that one template is
  universally sufficient. Deployers remain responsible for product, jurisdiction, delivery, and
  legal-review requirements.

#### Phase 4.4 locked contract

- The primary analyzer input is an immutable per-decision observation with an explicit protected
  group name, final binary outcome (`approve` or `decline`), finite predicted PD in `[0, 1]`, and
  an optional matured default label. `review` is not final and is excluded until a delivered
  override exists. The library never infers protected-group membership.
- Every analysis names one disadvantaged group and one reference group. Disparate impact is the
  favorable approval-rate ratio `disadvantaged / reference`; it is not inverted or selected from
  sample minima/maxima and may exceed one. The point estimate controls the inclusive four-fifths
  verdict (`>= 0.8`); p-values and confidence intervals are descriptive, not substitutes for that
  rule.
- `min_group_size` applies separately to every denominator: completed decisions for DI, actual
  defaults for TPR, actual non-defaults for FPR, and matured scored outcomes for calibration.
  Missing or undersized denominators produce `INSUFFICIENT_DATA`, never a fabricated zero-rate
  pass. Report fields are deeply immutable and use explicit `PASS`, `FAIL`, or
  `INSUFFICIENT_DATA` verdicts.
- Equality of approval rates uses a two-sided pooled two-proportion z-test only when all expected
  2x2 cells are at least five; otherwise use an exact two-sided Fisher test from the standard
  library. Report a Katz log-risk-ratio interval at the configured confidence level, applying
  Haldane-Anscombe `+0.5` to all observed cells for the interval only when any cell is zero.
  Undefined reference approval rates remain non-finite-free insufficient results.
- Equalized-odds positive prediction means `decline`, actual positive means matured default, TPR is
  declined/defaulted over all defaulted, and FPR is declined/non-defaulted over all non-defaulted.
  Threshold boundaries are inclusive.
- Calibration uses stable fixed-width PD bins `[0.0, 0.1)`, ..., `[0.9, 1.0]`; `1.0` belongs to
  bin nine. Each nonempty bin reports mean PD, observed default rate, and absolute gap. Group ECE
  is the count-weighted gap, and the calibration verdict uses the maximum ECE of the two named
  groups. Aggregate mean PD is not a calibration substitute.
- Audit events remain PII-free lifecycle evidence and cannot supply protected group, PD, or
  matured outcomes. `FairnessMonitor` first requires a checkpoint-attestable audit snapshot, then
  selects final delivered approve/decline/override events in `(as_of - window, as_of]` and joins
  their exact opaque application/decision/model references to an injected trusted private
  observation provider. Private rows are never logged, audited, or returned.
- Missing joins, malformed final events, duplicate decision references, invalid links, or an
  invalid/unattestable audit snapshot prevent a clean pass. Monitor output contains only aggregate
  metrics, window/provider identity, and audit-head provenance, and maps clean aggregate outcomes
  to `ModelFairnessStatus.PASSED`, `FAILED`, or `INSUFFICIENT_DATA` for Phase 4.5.
- Acceptance uses fixed deterministic fixtures. No finite random sample is claimed to prove
  fairness or to pass universally at a particular sample size; a non-significant equality test
  does not erase a four-fifths point-estimate failure.

#### Phase 4.5 locked contract

- Preserve the Phase 4.2 provider-only trust boundary. Model-validation output never authorizes a
  decision through caller-controlled `GuardrailContext.attributes`. The handoff is typed validation
  inputs → immutable report → domain-separated signed envelope → exact-model signed-report source
  → verifying `ModelGovernanceEvidenceProvider` → `ModelProvenanceGuardrail`.
- The report follows the conceptual-soundness, ongoing-monitoring, and outcomes-analysis structure
  associated with historical SR 11-7 and records independent effective challenge, evidence, and
  remediation lifecycle. It is not a legal attestation. SR 26-2 superseded SR 11-7 in April 2026;
  both are principles-based and prescribe neither this schema nor fixed Gini/AUC thresholds.
- All inputs are strict, finite, deeply immutable, `extra="forbid"`, and canonically identified.
  A `ValidationPolicy` carries versioned thresholds and freshness bounds. `PerformanceMetrics`
  explicitly names ROC-derived Gini before enforcing `Gini = 2*AUC - 1` within the configured
  absolute tolerance; that identity is an implementation convention, not a regulatory rule.
- Backtest evidence binds the exact model/version, opaque dataset/evidence references, observation
  window, evaluated time, sample/default counts, discrimination metrics, predicted and observed
  default rates, and Brier score. Its counts and time order must be internally possible, and the
  configured minimum sample and maximum age are evaluated at validation time.
- Challenger evidence binds a different exact challenger to the same dataset, window, and sample
  counts as the champion backtest. Metric deltas are derived rather than caller asserted. Missing
  or non-comparable evidence cannot be represented by fabricated zero metrics.
- Fairness validation evidence is derived only from an exact-model `FairnessMonitoringReport` and
  binds its canonical digest, aggregate `ModelFairnessStatus`, window/provider identity, integrity
  counts, and audit-head provenance. It never embeds protected labels, row PD/default data, event
  IDs, or opaque application/decision/model references. Monitor status is derived from the
  aggregate analysis and is forced to `INSUFFICIENT_DATA` by any integrity error; contradictory
  caller-constructed status cannot be promoted into validation evidence.
- Findings have unique IDs, exact section, severity, owner, opened/due timestamps, lifecycle
  status, and closure evidence. They are revised through new immutable report revisions rather than
  mutated in place. Open or in-remediation critical/high findings make validation unvalidated; one
  high finding is never conditionally approved. Finding open/closure times cannot postdate the
  report, and unresolved findings cannot disappear or regress across revisions; they must be
  explicitly closed with evidence. Later revisions bind the exact superseded report.
- Signed envelopes separate signature schema version from report revision, use canonical JSON and
  a dedicated model-validation HMAC-SHA256 domain, bind the key ID/algorithm/report reference/full
  report, require keys of at least 32 bytes, and compare signatures in constant time. HMAC proves
  integrity inside one trust domain, not public non-repudiation. The source is responsible for
  latest-revision/rollback guarantees; the bundled in-memory source is explicitly process-local.
- The verifying provider fetches only the exact requested model/version, verifies source identity,
  report reference, signature, version, revision lineage, internal status, freshness, and fairness
  binding, then projects the existing `ModelGovernanceEvidence` fields. Any mismatch or verifier/
  source failure yields no evidence and the live guardrail denies. Evidence is invalid before
  `validated_at` and at or after `expires_at`. Expiry is derived exactly from report validity,
  backtest/fairness freshness, and unresolved-finding due dates, then recomputed by the provider;
  a signer cannot extend it through a caller-supplied timestamp.
- Acceptance uses fixed timestamps, keys, and canonical golden bytes. Tests cover impossible metric
  pairs, finding lifecycle and supersession, backtest/challenger comparability, aggregate-only
  fairness binding, field/signature/digest/key/version tampering, exact model isolation, future and
  stale evidence, and a governed decision denial that caller attributes cannot override.

#### Phase 4.6 locked contract

- Synthetic generation is testing/benchmark support, not a production credit model or a source of
  real demographic data. The canonical public namespace becomes `agentguard.testing`; the existing
  `agentguard.domains.finance.synthetic` modules remain compatibility re-exports during the
  pre-1.0 transition. No new dependency is added.
- `SyntheticCreditGenerator` accepts finite `default_rate` in `(0, 1)` and finite `bias` in
  `[0, 1]`, rejects non-positive sample counts, and uses only its seeded private RNG. Equal
  constructor inputs and call sequence produce byte-identical records across processes.
- Each row is generated in dependency order in one O(n) pass: a synthetic group and latent credit
  quality influence income/obligations only through the explicitly configured benchmark `bias`;
  property value depends on income; requested loan depends on income and property value; LTV is
  exactly loan/property value; and DTI is exactly annual existing plus proposed obligations divided
  by annual income, subject only to documented output bounds. Default probability is derived from
  the generated risk factors and the configured portfolio base rate.
- At `bias=0`, the synthetic group is independent of the latent credit-quality distribution. A
  positive bias deliberately shifts only the named synthetic disadvantaged group so the label is a
  measurable proxy for generated underwriting factors. This is an artificial evaluation control,
  never a demographic inference. Acceptance computes approval from a fixed documented underwriting
  predicate over generated FICO/DTI/LTV—not from `is_default`—and uses a fixed large seed/sample:
  unbiased DI is at least 0.95; the locked biased fixture is approximately 0.65 within an explicit
  tolerance.
- WGAN input is a non-empty rectangular finite numeric matrix with unique feature names. A frozen
  standard scaler stores one mean/positive scale per feature, maps constant columns with scale 1,
  standardizes before training, and inverse-transforms every generated row. Scaler state and feature
  order are exposed as defensive immutable values for exact round-trip tests.
- `WganGpConfig` is strict and deeply immutable, validates positive dimensions/training parameters,
  and owns a deterministic seed. Fit and generation use explicit seeded PyTorch generators; equal
  data/config produce equal first output without relying on ambient Python or PyTorch RNG state.
  `generate(n)` rejects `n < 1`, requires a trained model, switches the generator to evaluation mode
  so `generate(1)` works with BatchNorm, uses `no_grad`, inverse-scales output, and clamps only named
  domain-bounded features (including FICO to `[300, 850]`). PyTorch remains a lazy optional import.
- Acceptance covers joint-structure invariants, deterministic regeneration, unbiased/biased DI,
  invalid inputs, scaler round-trip/constant columns, WGAN single-row generation, output finiteness
  and feature bounds, equal-seed reproducibility, lazy import, and legacy namespace compatibility.

### Phase 5 — Real adapters, honest verifier, real sandbox (1–2 weeks)

| PR | Change | Acceptance |
|---|---|---|
| 5.1 | LangGraph: subclass/compose real `ToolNode` (`ainvoke(state) -> {"messages": [ToolMessage]}`); CrewAI: subclass `BaseTool` with sync `_run`; ADK: wrap `FunctionTool`; MCP: wrap the real `ClientSession`. Tests run against the real packages under their extras. | Each adapter is placed in a real graph/crew/agent in an integration test and a denial surfaces as the framework's native error/message. |
| 5.2 | Formal verifier: differential test against `RBACEngine.check_permission` over random role sets *with wildcards and inheritance*; encode fnmatch subsumption and inheritance; delete severity→effect fabrication. Workflow safety is a dependency-free BFS; declarative policy contradiction analysis is explicitly unsupported until a sound predicate encoding exists, and `verify policy` exits non-success rather than certifying. | Differential test passes; unsupported policy analysis cannot pass an automated gate; CI fails on a bundle with a proven escalation path. |
| 5.3 | Sandbox as an obligation: `Decision.obligations=[sandbox]` routes execution through `DockerSandboxBackend`; harden (`read_only`, `user`, `cap_drop=ALL`, `no-new-privileges`, `pids_limit`, CPU quota); red-team assertions check the *reason* for failure, not `exit_code != 0`. | Sandbox obligation is honoured on the governed path; hardened flags verified by inspecting the container. |
| 5.4 | Declarative composition: strict `guardrails.yaml` chain config and explicit built-in registry; adapters accept a preconfigured `GovernanceKernel` while retaining legacy constructors as compatibility-only until a major release. | A chain defined entirely in YAML round-trips; README status table rewritten against the capability model; mixed kernel/legacy ownership is rejected. |

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
9. Runtime payloads are deeply immutable and never serialized as evidence; only typed redacted evidence and a canonical digest enter the audit chain.
10. Lifecycle state is computed per invocation, and no executor result is returned without `delivery_completed`.

---

## 9. Execution log

| Date | Scope | Branch / commits | Evidence |
|---|---|---|---|
| 2026-08-22 | Phase 0 (PRs 0.1–0.5) + PR 1.1 | `fix/phase0-truth-and-hygiene` | 468 unit tests green, 93.9% coverage (core 92.7%, compliance 98.3%); ruff/mypy clean; all four examples run; bypass probes closed (omit → denied, supply → `TypeError`, `Admin/users` → denied, `*`/`..` → `<unresolved>` denied, A2A `../peer` and `Treasury-Agent` → denied). Approach and completion gates passed by fresh-context critics; blocking findings (traversal checked before normalisation, A2A action-axis canonicalisation, `pip-audit --strict`, SBOM `path:`, README/CLAUDE.md headline claims) fixed. Not verified locally: the new CI `integration` job (no Docker daemon here). |
| 2026-08-26 | Phase 1 (PRs 1.2–1.7) + review findings F-001–F-004 | Shared working tree | 535 unit tests green with 93.15% coverage; Ruff clean; strict mypy clean across 43 source files. Targeted adversarial evidence covers transformed-resource authorization, A2A retargeting, resolver timeout/capacity, v1/v2 HMAC compatibility, lifecycle terminals, policy/guardrail failures, PII/secret redaction, rate/breaker rejection, one HALF_OPEN probe, and exactly one OPEN transition. F-001/F-004 formal-verifier boundary: 11 tests green; F-002/F-003 logging isolation: 42 tests green in both file orders. Not verified locally: Docker integration/red-team jobs. |
| 2026-08-26 | Phase 2 local evidence integrity (2.1 + partial 2.3) and completion-review fixes | Shared working tree | 578 unit tests green with 93.18% coverage; Ruff, strict mypy across 44 source files, and `git diff --check` clean; independent completion review approved with zero remaining findings. Golden v1/v2 bytes and mixed legacy→v3 history verify, while unsigned newer fields on legacy records are rejected. Twenty concurrent writers allocate one contiguous chain; steady-state append reads only checkpoint/tail. Sequence gaps, truncation, checkpoint/reference tampering, and paired rollback against a trusted external head are detected. Reporter requires a lock-consistent anchored snapshot and exact policy/rule provenance, and deduplicates lifecycle policy results. Policy/guardrail handlers are bounded/timed, executor cancellation emits completion evidence, stable reason codes match ADR-024, and dashboard terminal precedence is deny → escalate → complete. The full repository run failed only the six Docker integration/red-team cases because this environment cannot access the Docker socket. Remaining before Phase 2 completion: UDS collector/key rotation (2.2), richer crash/process/rotation fault injection, and OTel (2.4). |
| 2026-08-26 | Phase 2 completion (2.2 + 2.4 and final hardening) | Shared working tree | 623 unit tests green with 91.85% coverage; Ruff clean; strict mypy clean across 45 source files; `git diff --check` clean. The keyless application-facing UDS client and stateful collector own sequence allocation, signing, checkpoints, immutable key epochs, signed external state, idempotent retries, bounded snapshots/transport/operations, peer-UID checks, singleton locks, and deterministic interrupted-append recovery. Separate-process, concurrent-client, rotation rollback, malformed-frame, collision, timeout-capacity, stale/corrupt-state, and snapshot-integrity tests pass. OTel now emits the root tool-call span plus RBAC, policy, audit, and narrowly scoped execution children, records terminal outcome/latency instruments, reports configured-provider activity accurately, and treats all telemetry failures as best-effort. Real SDK exporter tests cover allowed and denied calls, denial reasons, status, hierarchy, and metrics. Two independent final reviewers returned APPROVE with no remaining high/medium findings. The most recent full-repository run remains green except for the six Docker integration/red-team cases blocked by local Docker-socket permission. Phase 2 is locally complete; Phase 3+ remains open. |
| 2026-08-26 | Phase 3.1a guardrail-chain boundary and plan repair | Shared working tree | 653 unit tests green with 91.97% coverage; full repository run: 654 passed and only the six Docker integration/red-team cases failed because the local Docker socket returns `PermissionError`; Ruff clean; strict mypy clean across 46 source files; `git diff --check` clean; independent re-review approved with no remaining high/medium findings. The original 3.1 plan was split because treating the circuit breaker as an ordinary precheck guardrail would race HALF_OPEN reservation, and a reason-code-only decision would discard signed `PermissionContext`/`PolicyResult` artifacts. The new pure `GuardrailChain` preserves `GuardrailOutcome`, stamps chain-owned guardrail/version/duration/enforcement metadata, accumulates prior decisions, rejects cross-kind transforms and invalid construction, snapshots validated descriptors, propagates cancellation, and fails closed on ordinary exceptions/cooperative timeouts. ENFORCE, SHADOW, and OFF semantics have direct tests. Guardrails must yield control or isolate blocking work because Python async cannot hard-preempt a non-yielding coroutine; eventual overruns are classified as timeouts after return. Kernel migration remains in 3.1b with breaker admission and lifecycle ordering explicitly retained as kernel-owned contracts. |
| 2026-08-26 | Phase 3.1b public governance-kernel migration | Shared working tree | 670 unit tests green with 91.89% coverage; full repository run: 671 passed and only the six Docker integration/red-team cases failed because the local Docker socket returns `PermissionError`; Ruff clean; strict mypy clean across 47 source files; documentation symbol checks and `git diff --check` clean; independent completion re-review approved with no remaining critical/high/medium findings. `GovernanceKernel` now owns the root OTel context and full framework-independent runtime; all five adapters support either the legacy constructor or a single preconfigured kernel and reject mixed ownership. The deprecated `run_governed` shim only constructs and delegates. The live path uses one reusable `GuardrailChain`, preserves typed `PermissionContext`/`PolicyResult` evidence, propagates guardrail cancellation, retains the breaker-owned atomic `before_execute` admission callback, and proves one HALF_OPEN executor. Admitted success, failure, and cancellation now commit the exact `admission` → `execution_completed` → delivery-terminal lifecycle, with stable `EXECUTION.FAILED`/`EXECUTION.CANCELLED` codes on failed delivery. Kernel policy/guardrail configuration is explicit, and parity tests prove the legacy secure defaults and an explicitly configured kernel both block prompt injection and mask PII. ADR-027 and current-state architecture/API documentation record the boundary. Phase 3.2 shadow-mode persistence/reporting remains open. |
| 2026-08-26 | Phase 3.2 signed shadow mode and reporting | Shared working tree | 729 unit tests green with 92.08% coverage; full repository run: 730 passed and only the six Docker integration/red-team cases failed because the local Docker socket returns `PermissionError`; Ruff clean; strict mypy clean across 47 source files; `git diff --check` clean; independent adversarial re-review approved with no remaining critical/high/medium findings. `ChainMode.SHADOW` now runs the complete content-guardrail chain without blocking or applying input/output transforms, while RBAC, staged policy, rate limiting, circuit breaking, audit, and native execution remain enforced. Schema v4 signs immutable guardrail ID/version/stage/effect/reason/duration/enforcement evidence, preserves exact v1-v3 verification and mixed v3→v4 append, rejects unknown unsigned top-level/nested fields as tampering, and has field-by-field tamper coverage. Input/pre evidence is committed once on admission or the pre-admission terminal, post evidence once on the delivery terminal, and execution completion carries none. Post-policy/guardrail cancellation, including repeated cancellation during a delayed sink write, commits `delivery_denied` with `DELIVERY.CANCELLED` before propagation. All five adapters and the deprecated shim propagate shadow mode and reject mixed kernel ownership. Replay exposes exact would-be decisions; dashboard and compliance output group by guardrail/version/stage, retain every conflicting effect/reason (including allow-only conflicts), count would-effects per unique invocation, and keep shadow observations isolated from actual outcome and policy metrics. ADR-028 records the signed observation boundary. Phase 3.3+ remains open. |
| 2026-08-26 | Phase 3.3 atomic policy-bundle reload | Shared working tree | 749 unit tests green with 92.13% coverage; full repository run: 750 passed and only the same six Docker integration/red-team cases failed because the local Docker socket returns `PermissionError`; Ruff clean; strict mypy clean across 47 source files; `git diff --check` clean; independent adversarial review approved with no remaining critical/high/medium findings. `PolicyEngine` now publishes recursively immutable, path-independent content-addressed `PolicyBundle` generations and provides explicit serialized copy-on-write reload with last-known-good rollback. Duplicate IDs, non-JSON mutable check values, invalid candidates, and overlapping older reload publication are rejected or contained. `GovernanceKernel` pins one snapshot before its first await, uses it for pre/post evaluation and OTel, and stamps its digest across the full signed lifecycle. The reporter resolves each event against retained historical generations, rejects unknown/mixed/contradictory provenance, separates same rule IDs by bundle version, and preserves legacy `RuleSummary` construction. ADR-029 records the contract. Phase 3.4+ remains open. |
| 2026-08-26 | Phase 3.4a durable HITL request-state foundation | Shared working tree | 803 unit tests green with 92.09% coverage; full repository run: 804 passed and only the same six Docker integration/red-team cases failed because the local Docker socket returns `PermissionError`; Ruff clean; strict mypy clean across 48 source files; documentation/packaging symbol tests and `git diff --check` clean; final independent re-review approved with zero critical/high/medium findings. The original monolithic HITL plan was split because safe restart resumption requires authenticated approval, protected continuations, trusted executor resolution, exact chain/policy identity, and ambiguous-crash handling. `EscalationStore` now persists only HMAC-authenticated pending/expired metadata on a local POSIX filesystem with 0700/0600 permissions, symlink-safe reads, `flock`, atomic fsync/replace, exact TTL, and a SHA-256 verifier for a 256-bit opaque token; it exposes no decision or claim API and stores no payload/result/reason/approver. Configured kernels commit durable state then schema-v5 `escalation_requested` evidence before returning the token, retain legacy behavior without a store, use nonterminal post-tool request semantics, and reconcile cancellation/store failure after execution to `delivery_denied`. Schema v5 preserves exact v1-v4 verification, collector round-trips HITL evidence, local/collector `write_once` deduplicates stable IDs and rejects conflicts, and dashboard HITL counters deduplicate by escalation identity. ADR-030 records the boundary. Authenticated decisions/protected pre-execution resume remain Phase 3.4b; protected post delivery remains Phase 3.4c; ambiguous crash reconciliation remains Phase 3.4d. |
| 2026-08-26 | Phase 3.4b authenticated protected PRE-stage resume | Shared working tree | 860 unit tests green with 91.64% coverage; full repository run: 861 passed and only the same six Docker integration/red-team cases failed because the local Docker socket returns `PermissionError`; Ruff clean; strict mypy clean across 50 source files; documentation/packaging symbol tests and `git diff --check` clean; final independent adversarial re-review approved with no critical/high/medium findings. Registered PRE_TOOL/PRE_MESSAGE calls now bind an authenticated approver, injected continuation protector, immutable payload/evidence, exact policy snapshot, complete restart-resumable chain, authenticated multi-approval cursor, and trusted executor ID/version/fingerprint. Decisions and expiry use prepare → stable `write_once` evidence → effective commit; denial/expiry also close delivery. Resume validates policy/chain/cursor/executor/current identity/RBAC/evidence before a stable atomic claim, pins the exact restored policy across reload races, skips only authenticated approved escalations, and supports sequential approvals. Concurrency, replay, forged credentials, tampering, revoked RBAC, expiry before/inside claim, maximum-length decision IDs, admission audit failure, and repeated cancellation all fail closed with at most one live executor invocation and one delivery terminal. Protected post-execution result delivery remains Phase 3.4c; process crashes after claim remain Phase 3.4d. ADR-031 records the boundary. |
| 2026-08-26 | Phase 3.4c protected POST-stage result delivery | Shared working tree | 885 unit tests green with 90.92% coverage; full repository run: 886 passed and only the same six Docker integration/red-team cases failed because the sandbox extra is absent from the local `uv` environment; 73 focused continuation/store/PRE/POST tests green; Ruff clean; strict mypy clean across 50 source files and the changed test contracts; documentation/packaging symbol tests 42/42 and `git diff --check` clean; final independent re-review approved with no critical/high/medium findings. Enforced guardrail-triggered POST_TOOL/POST_MESSAGE requests now seal the completed `ToolResultPayload`, exact post cursor, full chain fingerprint, pinned policy snapshot, permission/evidence state, timing, and TTL in a discriminator-bound continuation that contains no executor reference. Resume validates protected state, active policy, chain/cursor, current identity, RBAC, and result evidence before a distinct atomic delivery claim, then runs only the remaining post chain. Completion and denial share one stable audit ID and precede mutually exclusive store terminals; repeated cancellation drains every post-claim terminal. Sequential approvals create a sealed child request with signed parent linkage before the parent becomes `HANDED_OFF`; cancellation after child creation completes the transaction and returns the usable child token. Concurrency, wrong keys, changed policy/chain, revoked RBAC, denial, expiry, repeated cancellation, POST_MESSAGE, and chained approvals never replay the executor. Policy-only post escalation remains metadata-only. ADR-032 records the boundary; execution-journal and authenticated `IN_DOUBT` reconciliation remain Phase 3.4d. |
| 2026-08-27 | Phase 3.4d protected execution journal and authenticated reconciliation | Shared working tree | Full repository run: 966 passed, 5 skipped, and only the six Docker integration/red-team cases failed because the optional `docker` SDK is absent; 90.79% coverage; 26 focused reconciliation tests green; Ruff, scoped formatting, strict mypy across 53 source/test files, packaging/schema/replay contracts, and `git diff --check` clean; final independent adversarial re-review approved with no critical/high/medium findings. Opt-in journaled protected PRE resumptions now commit stable admission, execution-completion, post-processing-claim, and delivery evidence; seal exact successful outcomes before POST; and never resolve or replay an executor. Authenticated `hitl:reconcile` assessment uses checkpoint-attested absence for unknown windows, resumes only a sealed known result, and permits only denial for `IN_DOUBT`. Executor failure, cancellation, and invalid output converge to one stable `DELIVERY_DENIED`; repeated cancellation cannot release the caller before audit and journal terminalization. Verified delivery/claim markers detect replay of older valid signed journal revisions before any POST callback, while downstream guardrail escalation creates a protected child handoff. Schema v6 signs typed redacted reconciliation evidence without changing frozen v1-v5 bytes. ADR-033 records the boundary. |
| 2026-08-27 | Phase 3.5a mechanism-neutral authentication contracts and signed evidence | Shared working tree | 275 focused authentication/model/audit/collector/packaging tests green; Ruff, scoped formatting, strict mypy, and `git diff --check` clean; independent re-review approved with no critical/high/medium findings. Frozen agent and control-plane principals separate credential-derived identity from registry-controlled authorization; async provider/authenticator protocols select no credential mechanism; and `AuthenticationFailure` is the canonical source for nine reserved `AUTH.*` codes without a raw diagnostic channel. Schema v7 signs secret-free verified/rejected `AuthenticationEvidence`, reserves `__unauthenticated__` for rejected-event producers, rejects claimed identity and request/credential/provider details across the complete lifecycle envelope, round-trips through the collector, and preserves fixed v5-v7 hash vectors plus exact v1-v6 verification branches. This slice did not enforce authentication in the kernel or adapters; at its completion, registry authority, sticky runtime enforcement, per-call credential providers, and a concrete verifier were assigned to Phase 3.5b-e. ADR-034 records the boundary. |
| 2026-08-27 | Phase 3.5b authoritative registry, authenticated control plane, and signed persistence | Shared working tree | 72 focused registry contract/state/control-plane/store and packaging tests and 374 expanded audit/auth/registry/model/packaging tests green; Ruff, formatting, strict mypy, public imports, and diff checks clean. Deeply immutable active/revoked records make roles registry-owned and advance global revision, record revision, and credential epoch monotonically. A distinct authenticated control plane requires exact action and per-role capabilities, then drives an idempotent `PREPARED` → `AUDITED` → `COMMITTED`/`CONFLICTED` ledger so authorized audit evidence precedes state. Both registry implementations independently re-read their configured audit sink before commit or rejection-head anchoring. Schema v8 signs typed `RegistryMutationEvidence` while preserving exact v1-v7 serializers. `SignedFileAuthoritativeAgentRegistry` uses a separate canonical HMAC domain, checkpoint-capable audit history, owner-only no-follow POSIX files, worker-thread `flock`/fsync transactions, a chained local crash checkpoint, and a required trusted checkpoint outside the registry directory. Tests cover mismatched audit sinks, paired local-state rollback, missing/stale checkpoints, one-step interrupted writes, symlink/hard-link/mode violations, concurrency, and event-loop responsiveness. `AgentRegistry`/`FileBackedRegistry` remain unsigned, self-asserted compatibility surfaces. The kernel still uses that legacy boundary; sticky workload authentication, adapter credential providers, and a concrete verifier remain Phase 3.5c-e. ADR-035 records the boundary. |
| 2026-08-27 | Phase 3.5c sticky authenticated kernel and protected continuation binding | Shared working tree | 170 focused authentication/continuation/journal/resume/reconciliation tests and 1209 full unit tests green with 5 optional skips; Ruff, formatting, strict mypy, docs-symbol checks, and `git diff --check` clean. Secure kernel construction requires the authoritative registry and authenticator together, rejects ID-only/mixed modes, authenticates and signs secret-free evidence before request, tracer, registry, resolver, RBAC, or executor observation, and derives roles from one atomic registry snapshot. Schema-v2 PRE/POST/journal continuations bind the exact signed authentication event, registry identity/revision, record revision, and credential epoch; legacy v1 JSON/AAD bytes remain exact. Resume ignores original credential expiry but revalidates the signed event, current active record, monotonic revisions, exact epoch, and current RBAC before executor or POST callbacks. Revocation/rotation/role denial and cancellation after durable claims converge to signed non-replayable denial terminals. Independent review and verification approved after reproducing and fixing the reconciliation cancellation window and v1 wire regression. Adapter credential providers and a concrete verifier remain Phase 3.5d-e. ADR-036 records the boundary. |
| 2026-08-27 | Phase 3.5d fresh per-call adapter credential providers | Shared working tree | 102 focused adapter-authentication cases, 257 integration tests with 2 optional skips, and 1312 full unit tests with 5 optional skips green; Ruff, formatting, strict mypy across 56 source files, packaging/docs symbols, and `git diff --check` clean. `GovernanceKernel.bind_adapter` returns a mode-neutral caller bound once to either a legacy ID or secure `AgentCredentialProvider`. Every secure attempt invokes the provider exactly once and keeps its credential coroutine-local; provider exception or missing output becomes one signed reserved-actor `AUTH.PROVIDER_FAILURE` event with a fixed no-credential sentinel and no raw exception chain. The common authentication writer rejects unchanged/unsigned or pre-v7 success and rejection envelopes before returning a canonical failure; 15 pass-through unsigned-sink regressions cover provider and ordinary authentication rejection. Frozen deferred commands ensure provider and workload authentication complete before adapters construct payloads, actions, resources, tool lookups, executor closures, or tracer input. All five adapters store only the bound caller, rotate credentials across sequential/concurrent calls, and never call the deprecated shim. LangGraph no longer probes/logs the claimed actor pre-authentication. `run_governed` is documented and warned as legacy-only. A concrete signed verifier remains Phase 3.5e. ADR-037 records the boundary. |
| 2026-08-27 | Phase 3.5e concrete signed short-lived workload verifier | Shared working tree | 82 focused JWT adversarial tests, 268 expanded authentication/kernel/adapter/packaging tests, and 1396 full unit tests with 5 optional skips green; Ruff, formatting, strict mypy across 57 source files plus the changed test, lock/docs/packaging checks, public lazy imports, build, and `git diff --check` clean; independent security review and verification approved with no critical/high/medium findings. Optional `agentguard[auth]` selects patched `PyJWT[crypto]>=2.13,<3` for offline RS256 verification only. `JwtAgentAuthenticator` enforces exact issuer/audience, canonical signed subject/token ID, required bounded integer time claims, strict headers, operator-pinned public RSA JWKs, and no discovery, network refresh, or token-supplied key source. Immutable snapshots use strictly increasing integer revisions, compare-and-swap rotation, monotonic bounded overlap, and reject unmanaged initial overlap. `CredentialUseStore` consumes `(issuer,jti)` atomically through effective expiry, supports issuer/key/subject/token/digest revocation, owns nondecreasing trusted time, and fails closed on rollback or capacity. Review reproduced and closed cancellation-driven crypto concurrency escape, replay resurrection after wall-clock rollback, key-revision ABA, wall-clock-prolonged overlap, and immortal initial overlap. The bundled stores are bounded and process-local; shared deployments must inject atomic backends, and JWT revocation must accompany registry epoch rotation/revocation to invalidate protected continuations. ADR-038 records the trust boundary. |
| 2026-08-27 | Phase 4.1 truthful credit attribution and versioned reason evidence | Shared working tree | 66 focused attribution/reason/generator/decision tests and 1449 full unit tests green with 90.89% coverage; repository-wide Ruff/format clean, strict mypy clean across 59 source files, finance packaging/public imports, both migrated examples, bounded governed demo smoke, and `git diff --check` clean. Scorecard and coefficient attributors require explicit direction, exact finite transformed-feature schemas, and immutable model/version/reference provenance; only positive adverse contributions survive. The complete feature schema, including favorable and zero factors, must exactly match an explicit per-model ECOA binding before filtering. The versioned registry seeds current Appendix C wording under AgentGuard-local IDs, keeps bureau score factors in a separate runtime-enforced type/namespace, consolidates same-reason features, and exposes stable `AA.*` failures. There is no default claimed ECOA four-reason cap. Ambiguous `feature_importances`/`reason_map` inputs and fabricated decision-template importances were removed as a pre-1.0 correction. Independent approach and completion reviews approved after fixing hidden favorable-feature bindings, provenance carriers, intercept pseudo-features, runtime namespace substitution, and deserialized selection integrity. ADR-039 records the boundary; complete notice artifacts and governed emission remain Phase 4.3/4.2. |
| 2026-08-27 | Phase 4.3 typed credit notice artifacts and deterministic rendering | Shared working tree | 1487 full unit tests with 5 optional skips passed at 90.69% coverage before the final localized renderer correction; the post-correction finance/packaging suite passed 155 tests and the renderer suite passed 13 tests. Ruff and scoped formatting are clean across 148 source/test/example/script files; strict mypy is clean across 60 production files and all modified Phase 4.3 tests/examples; the notice pipeline example renders successfully; `git diff --check` is clean. Immutable extra-forbid artifacts now model denial, standalone/combined counteroffers, nonacceptance, incomplete applications, and withdrawal with actual communication timing, normalized principal-reason provenance, discriminated FCRA source regimes, typed written requests, and independent bureau-factor selection. Versioned C-1/C-3/C-4/C-6 and standalone render profiles produce canonical UTF-8/LF output with a verified exact-body SHA-256; C-3 is deliberately limited to completed-application denials so counteroffer-nonacceptance lifecycle links and terms cannot be dropped. Audit evidence remains outside this rendering boundary and may carry only redacted identifiers/digests in Phase 4.2. Two independent verification reviews and the final completion re-review approved with no remaining findings. ADR-040 records the contract. |
| 2026-08-27 | Phase 4.2 governed credit decisions and PII-free notice evidence | Shared working tree | 172 focused remediation/kernel/domain tests and 1616 full unit tests with 5 optional skips passed at 90.78% coverage; Ruff check and scoped formatting are clean across 161 source/test/example/script files; strict mypy is clean across 66 production files; public packaging imports and `git diff --check` pass. Immutable terminal `DecisionPayload` results use the full kernel lifecycle; `ON_DECISION` cannot transform an already-authorized result; unsafe caller projections remain digest-only until every post/resumed control allows. `GovernedCreditAgent` uses fixed actions, checkpoint-verifies exact delivered review lineage inside override execution, records only already-completed notices after admission/RBAC, and rejects future notification times. Correlation treats malformed direct/override declines as unresolved and accepts only notices with signed enforced completeness evidence. Two adversarial completion passes reproduced and closed eight high/medium trust-boundary findings; the final re-review approved with no remaining critical/high/medium findings. ADR-041 records the contract. |
| 2026-08-27 | Phase 4.4 statistically honest fairness analysis and private monitoring | Shared working tree | 45 focused fairness/monitor regressions and 1655 full unit tests with 5 optional skips passed at 90.79% coverage; repository-wide Ruff and formatting are clean across 162 source/test/example/script files; strict mypy is clean across 67 production files; packaging imports, the 1,200-event governed credit demo, and `git diff --check` pass. Immutable final-decision observations require explicit disadvantaged/reference groups, strict finite PD, denominator-specific tri-state results, exact z/Fisher selection, stable extreme-tail Fisher summation, Katz intervals, decline/default equalized odds, and fixed-decile ECE. `FairnessMonitor` checkpoint-verifies signed history, scopes one exact model/version, rejects naive timestamps and malformed/duplicate evidence, joins protected/PD/outcome rows only through a trusted private provider, and returns aggregate-only status/provenance. The adversarial completion review found and verified closure of two high and three medium model-scope, timestamp, aggregate-integrity, numerical, and private-group findings; final re-review approved with no remaining critical/high/medium findings. ADR-042 records the contract. |
| 2026-08-27 | Phase 4.5 signed exact-model validation evidence and live provider handoff | Shared working tree | 81 focused adversarial model-validation/signing/fairness-monitor tests and 1715 full unit tests with 5 optional skips passed at 90.55% coverage; repository-wide Ruff and formatting are clean across 165 source/test/example/script files; strict mypy is clean across 67 production files; packaging imports and `git diff --check` pass. Strict immutable policies, backtests, same-sample challengers, aggregate-only fairness bindings, owned finding lifecycles, exact derived expiry, and revisioned reports feed a domain-separated HMAC envelope and fail-closed exact-model provider; caller attributes remain non-authorizing. The completion review reproduced and closed caller-extended expiry, unresolved-finding deletion, future closures, contradictory fairness promotion, and malicious skipped-revision source responses. Final re-review approved with no remaining critical/high/medium findings. SR 26-2's April 2026 supersession of historical SR 11-7 and the non-attestation boundary are documented. ADR-043 records the contract. |
| 2026-08-27 | Phase 4.6 structured synthetic benchmarks and hardened optional WGAN-GP | Shared working tree | 46 focused statistical/WGAN tests passed with 2 optional Torch skips; 1752 full unit tests with 7 optional skips passed at 90.53% coverage; Ruff/formatting, strict mypy across 70 source files, packaging imports, and `git diff --check` pass. Canonical `agentguard.testing` helpers now generate deterministic dependency-ordered income/property/loan/LTV and obligations/DTI records with explicit artificial bias controls and fixed non-label approval DI fixtures; `CreditApplicationSchema` is strict, finite, bounded, and extra-forbid. Optional WGAN-GP validates numeric matrices, persists an immutable scaler, isolates seeded PyTorch RNGs, supports evaluation-mode `generate(1)`, inverse-scales results, and bounds named credit features. Legacy finance-synthetic imports are identity-preserving re-exports. Adversarial review reproduced and closed subnormal-sigmoid overflow and permissive-schema findings; final re-review approved with no remaining critical/high/medium findings. ADR-044 records the testing namespace boundary. |
| 2026-08-27 | Phase 5 real adapters, sound formal verification, sandbox obligations, and declarative composition | Shared working tree | 45 focused final-review checks and 1817 full unit tests with 12 optional skips passed at 90.25% coverage; Ruff/formatting, strict mypy across 71 source files, packaging imports, `uv lock --check`, and `git diff --check` pass. LangGraph executes the governed node inside a compiled `StateGraph`; CrewAI exposes a conditional native `BaseTool` with synchronous `.run()` plus async `.arun()` compatibility; ADK executes a real `FunctionTool`; MCP uses a real in-memory `ClientSession` and returns native `CallToolResult(isError=True)` on denial; and A2A crosses the native `message_send` boundary. Declarative YAML uses strict duplicate-key-safe schemas and an explicit built-in registry. Formal verification models wildcard/inherited RBAC, emits replayable witnesses, returns unknown for unsupported Unicode, and no longer fabricates policy effects; the CLI exits nonzero for uncertainty. Workflow safety is dependency-free BFS. Sandbox obligations route only through the exact hardened Docker backend with bounded daemon/client logs, stable failure reasons, and preserved frozen v1 continuation bytes; host subprocess and subclass backends are rejected. Final adversarial rechecks found no remaining critical/high/medium findings. Live Docker execution and optional framework jobs require CI extras/daemon; local base runs skip only those optional packages. ADR-045 records the Phase 5 boundaries. |
| 2026-08-27 | Continuation verification and Docker-test hardening | Shared working tree | The complete local repository suite passes with 1819 tests, 14 optional skips, and 90.24% coverage; Ruff, formatting, strict mypy across 71 source files, lock consistency, and `git diff --check` pass. Docker-only modules skip when the optional SDK is absent locally, while the CI integration lane now explicitly imports the SDK and pings the daemon before collection so missing infrastructure cannot produce a false-green skip. Live red-team checks use deterministic network-namespace evidence, filesystem-specific stderr evidence, and Docker's authoritative `State.OOMKilled` signal mapped to `SANDBOX.MEMORY_LIMIT`. Live Docker execution remains pending the CI daemon. |

| 2026-08-28 | Independent five-lane security re-review of the Phase 0–5 working tree | Shared working tree | Five parallel read-only reviews (guardrail kernel, evidence-integrity/crypto, adapters, credit-risk domain, docs/packaging), each probe-backed, then coordinator fixes. 1830 full unit tests with 12 optional skips passed; Ruff/format, strict mypy, and `uv lock --check` clean. **Fixed:** (kernel HIGH) `redacted_evidence`/`subject_ref`/`links` now forwarded across the HITL resume boundary so the minimisation contract holds on the human-approved path; (kernel HIGH) `canonicalize_action`/`canonicalize_resource` reject C1/format/combining characters (`Cc`/`Cf`/`Mn`/`Me`), closing an invisible-character deny-override bypass and audit-spoof; (kernel/domain HIGH) the PII `_SSN` boundary is token-level, so 9-digit runs inside SHA-256 hex digests and UUIDs are no longer masked (10.39%→0.00%), preserving fairness-monitor join keys; (kernel MEDIUM) a POST-stage `BaseException` now writes a delivery terminal instead of leaving an in-doubt window; (kernel MEDIUM) JWT base64url decoding rejects non-canonical encodings, so one credential yields one digest and digest revocation holds; (evidence HIGH) `AGENTGUARD_AUDIT_KEY` now enforces the same ≥32-byte floor as the sibling signed stores (`AuditKeyWeakError`); (evidence LOW) execution-journal and escalation-store HMACs are domain-separated, audit-chain digest comparisons are constant-time, both store locks close their fd on a failed acquire, and audit filenames use the UTC date; (A2A HIGH×2) the target is canonicalised once and both axes are built from it, so path-shape variants and empty targets are audited `<unresolved>` denials; (adapter LOW) a LangGraph `resources` entry with no registered tool is denied, not admitted then `KeyError`; (domain MEDIUM) a non-DI fairness failure now emits `FAIR.CHECK_FAILED`, not a disparate-impact-specific code; (docs) the ARCHITECTURE roadmap no longer understates shipped sandbox/Docker-hardening/Z3-RBAC work, adapter descriptions and the ADR count match code, and SR 11-7 framing is corrected to SR 26-2. CI gains `finance-extra` (WGAN-GP determinism) alongside the adapter-extras matrix. **Known limitations recorded, not yet closed:** signed audit/journal/escalation state has no off-host rollback anchor (restoring a consistent earlier copy of the whole evidence set is undetectable); collector `rotate_key` persists no new key material, so it is unusable across restart as shipped; there is no governed path for a policy-rule or human-judgment adverse-action reason (declines can only cite model reasons); `_event_index`/`_bundle_history` and the journal/escalation directories are unbounded. |

| 2026-08-29 | Closure of the four 2026-08-28 known limitations | Shared working tree | Two parallel implementers with disjoint ownership, then coordinator gates: 1934 full unit tests with 12 optional skips passed; Ruff/format and strict mypy clean. **(1) Rollback anchor operational:** `agentguard audit export-checkpoint` (refuses to overwrite a newer witness), `audit verify --trusted-checkpoint` (fails closed when the head is behind the witness, cross-checking the anchored event hash), and `AuditCollectorServer(trusted_checkpoint_path=…)` outside the state directory — refused inside it — which the collector refuses to start behind and atomically re-exports (0600, fsync+replace) after each checkpoint. Detection now extends exactly as far as the witness is replicated off-host; the boundary is documented in ARCHITECTURE.md. **(2) Rotation continuity:** `AGENTGUARD_AUDIT_KEYS` declares additional epochs (same ≥32-byte floor, structural-only errors, no key material in messages); `rotate_key` on an environment-sourced keyring refuses up front (`AuditKeyRotationRefusedError`) unless the epoch is already declared and fingerprint-confirmed via `compare_digest`. **(3) Bounded caches:** collector event index bounded without weakening `write_once` conflict detection; `PolicyEngine(max_retained_generations=…)` with dropped generations still failing provenance resolution explicitly; operator-invoked `prune_terminal(older_than)` on the escalation store and execution journal deleting only terminal records under the store lock. **(4) Non-model adverse-action reasons:** `CreditPolicyBundle` evaluation + `PolicyReasonIntegrityGuardrail` recomputation for policy_rule reasons (`AA.POLICY_REASON_UNBOUND`), review-lineage-bound `ReviewJudgment` + `ReviewReasonIntegrityGuardrail` for human_review reasons (`AA.REVIEW_REASON_UNBOUND`), decision-chronology ordering (policy → model → human), fail-closed composition in `prepare_notice_record`, ~35 fabrication/ordering tests plus real-kernel end-to-end tests for a post-review underwriter decline and a hard policy overlay decline, both resolved by their notices in `find_unresolved_declines`. **Remaining follow-ups, recorded not closed:** a pre-scoring decline (no model score) is still unrepresentable because signed evidence shapes require a model reference; the new reason-integrity guardrails are opt-in like every other content guardrail; there is still no distinct governed `policy:evaluate` audit lifecycle (binding is by recomputation + scoped digest); ~~`AGENTGUARD_AUDIT_KEYS` is an unauthenticated declaration~~ — **closed 2026-08-30**: every declared epoch now requires a predecessor-keyed `activation_certificate` (sequential chain from the primary key, fingerprint-bound, minted via `mint_activation_certificate` / `agentguard audit mint-epoch-certificate`); the `adopt_declared_epochs` gate is retained as defense in depth, and custody of the primary `AGENTGUARD_AUDIT_KEY` itself remains an environment-protection responsibility; reconciling a pruned journal invocation reports CLAIMED rather than its true terminal outcome (cannot cause re-execution; the fix is a tombstone or `create_claim` refusal in kernel-owned code — set prune cutoffs beyond any reconciliation window); the collector's evicted-event reload path calls `read_all()` under the operation lock, so a trusted local peer replaying many aged-out event IDs can stall appends; the signed escalation schema has no `delivered_at`, so `prune_terminal`'s last-touch measure is the documented approximation. |

Historical Phase 0/1.1 follow-ups are closed or explicitly bounded by later contracts: secure unknown-identity failures enter the signed authentication/registry evidence path; policy loading wraps YAML and validation failures and accepts both `*.yaml` and `*.yml`; resolvers are bounded and transforms precede authorization; the kernel owns action/resource canonicalization and applies NFKC normalization. `FileAuditBackend` accepting `Path` and direct `RBACEngine.check_permission` operating on already-canonical values are intentional low-level API boundaries; production calls go through `GovernanceKernel`.
