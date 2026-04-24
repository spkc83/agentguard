---
created: "2026-04-19"
last_edited: "2026-04-19"
complexity: medium
---

# Cavekit: Compliance Engine (Layer 2)

## Scope
The compliance engine is AgentGuard's regulatory layer: it evaluates governance events against versioned, file-based policy rule sets, escalates approvals to humans when required, formally verifies safety properties of RBAC and policy configurations, and produces auditor-grade attestation reports. It builds on Layer 1's audit events but does not itself sit in the runtime hot path — verification and reporting are post-hoc or pre-deployment activities.

## Requirements

### R1: Policy-As-Code Rule Loading
**Description:** Compliance rules are versioned text files (per ADR-005), not database rows or hard-coded checks. Rule sets are loaded from one or more directories at engine construction time and exposed to evaluators with their source-of-truth identifiers preserved.
**Acceptance Criteria:**
- [ ] When given no policy directory, the engine loads the built-in shipped rule sets.
- [ ] When given one or more directories, the engine loads every rule file found in each directory.
- [ ] Each loaded rule has a unique identifier, a human-readable name, a severity, a check configuration, a remediation string, and an enabled flag.
- [ ] Rules whose enabled flag is false are excluded from evaluation but still listed in the loaded inventory.
- [ ] Loading an empty or malformed file logs a warning and does not crash the engine.
- [ ] A nonexistent policy directory logs a warning and is skipped.

### R2: Built-In Regulatory Policy Sets
**Description:** AgentGuard ships with three built-in rule sets covering the named industry standards: OWASP Top 10 for Agentic AI, FINOS AI Governance Framework v2.0, and EU AI Act high-risk obligations. Every shipped rule must declare its severity, its check configuration, and at least one external reference link to the standard it implements.
**Acceptance Criteria:**
- [ ] The built-in OWASP Agentic rule set provides exactly 10 rules, one per OWASP Top-10-for-Agentic-AI category.
- [ ] The built-in FINOS AIGF rule set provides 15 rules mapped to FINOS AIGF v2.0 risk identifiers.
- [ ] The built-in EU AI Act rule set provides 10 rules covering Articles 9, 10, 13, 14, and 17.
- [ ] Every shipped rule declares one of {critical, high, medium, low} as its severity.
- [ ] Every shipped rule includes at least one reference URL pointing to the standard it implements.

### R3: Typed Policy Check Dispatch
**Description:** Each rule selects a check strategy by a typed identifier; the engine dispatches to a registered handler for that strategy and produces a structured result (per ADR-015). Unknown check types must fail safely (non-blocking) so the engine never crashes on a misconfigured rule.
**Acceptance Criteria:**
- [ ] The engine supports the six check strategies it ships with: action blocklist, resource pattern, content scan, permission required, result required, metadata required.
- [ ] Each check strategy returns a structured policy result containing rule identifier, rule name, pass/fail, severity, evidence, and remediation text.
- [ ] A rule referencing an unknown check type produces a passing result with explanatory evidence and does not raise an exception.
- [ ] Action-blocklist and resource-pattern checks evaluate regex patterns from the rule's configuration against the corresponding fields on the audit event.
- [ ] Content-scan checks evaluate substring patterns case-insensitively against the configured target fields (action, resource, and/or tool arguments).
- [ ] Metadata-required checks pass only when every field listed in the rule configuration is present on the agent identity carried by the audit event.

### R4: Audit Event Evaluation
**Description:** The engine evaluates every loaded enabled rule against an audit event in a single call and returns an ordered list of structured results with no side effects on the event or rule store. Evaluation must be deterministic for a given event and rule set.
**Acceptance Criteria:**
- [ ] Evaluating an audit event returns one policy result per enabled rule.
- [ ] Re-evaluating the same event with the same rule set yields identical results in identical order.
- [ ] Evaluation does not modify the audit event nor the rule set.
- [ ] Evaluation completes for events whose result field is any of {allowed, denied, escalated, error}.

### R5: Human-in-the-Loop Escalation
**Description:** Some policies, role configurations, or actions require explicit human approval before execution. The engine produces an escalation request, routes it to a configurable handler, and records the resulting decision. Escalation must support callback, auto-approve (development), auto-deny, and a documented default behavior when no handler is configured.
**Acceptance Criteria:**
- [ ] An escalation request carries a unique identifier, the agent identifier, the action, the resource, a reason, an optional rule identifier, additional context, and a creation timestamp.
- [ ] An approval decision carries an approved flag, an approver identifier, an optional reason, and a decision timestamp.
- [ ] In auto-approve mode, escalation returns an approved decision attributed to the system without invoking any user handler.
- [ ] In auto-deny mode, escalation returns a denied decision attributed to the system.
- [ ] In block mode with a configured handler, escalation awaits the handler's returned decision and records it.
- [ ] In block mode with no configured handler, escalation returns a denied decision (fail-safe default per the project's deny-first principle).
- [ ] All escalations and their decisions are retained in an in-process history accessible for audit.

### R6: Formal Verifier Surface
**Description:** The compliance layer exposes a static verification facility that answers questions runtime checks cannot: properties about the entire space of possible agent behavior given a configuration. Verification is bounded by a timeout, runs out of the hot path, and is invoked explicitly (per ADR-013).
**Acceptance Criteria:**
- [ ] Verification jobs have a configurable timeout and report a status of one of {sat, unsat, timeout, unknown}.
- [ ] Every verification result identifies the property that was checked and includes a human-readable counterexample whenever the property is violated.
- [ ] The Z3 SMT solver dependency is imported lazily; the rest of the compliance engine functions when it is not installed.
- [ ] If the SMT solver is not installed, attempting to use formal verification raises an import error directing the user to install the optional dependency.

### R7: RBAC Privilege Escalation Verification
**Description:** Given a role configuration and a target permission, the verifier proves whether any combination of role assignments — excluding any explicitly forbidden roles — could grant that permission. Deny-override semantics from the runtime RBAC model must be preserved in the encoding.
**Acceptance Criteria:**
- [ ] When no allowed role combination grants the target permission, the verifier returns an unsatisfiable status (property holds).
- [ ] When some role combination does grant the target permission, the verifier returns a satisfiable status with a counterexample naming the offending role combination.
- [ ] The verifier honors deny-override: a role granting an allow plus a role granting a deny for the same permission yields no effective access (matching cavekit-security-runtime.md R2).

### R8: Policy Set Consistency Verification
**Description:** Given a set of rules, the verifier identifies pairs of rules that could simultaneously match the same (action, resource) but produce opposing effects (allow vs deny). It is a static contradiction detector for use during rule authoring and pre-deployment review.
**Acceptance Criteria:**
- [ ] A rule set with no contradictions returns an unsatisfiable status and reports the number of rules checked.
- [ ] A rule set containing at least one contradicting pair returns a satisfiable status, identifies each contradicting pair by rule identifier, and reports the count of pairs found.

### R9: Workflow Safety Verification
**Description:** Given a directed workflow graph and a designated set of human-in-the-loop checkpoints, the verifier proves whether a target node is reachable from a source node without passing through any HITL checkpoint. Implementation uses graph reachability over the HITL-pruned graph (per ADR-016).
**Acceptance Criteria:**
- [ ] When the target is unreachable from the source after removing HITL checkpoints, the verifier returns an unsatisfiable status (property holds).
- [ ] When a HITL-bypassing path exists, the verifier returns a satisfiable status with a counterexample identifying the source, target, and HITL set.
- [ ] If either source or target is missing from the supplied node list, the verifier returns an unknown status with an explanatory note instead of raising.

### R10: Compliance Attestation Reports
**Description:** The compliance reporter consumes audit events and policy evaluations to produce a structured attestation report covering: per-rule pass/fail counts, overall pass rate, count of critical-severity failures, the time range covered, and the names of the policy sets evaluated. Reports must be serializable in both a machine format and a reviewer-readable text format.
**Acceptance Criteria:**
- [ ] A generated report includes a unique report identifier and a generated-at timestamp.
- [ ] A generated report includes the earliest and latest timestamps from the input events (or null if no events).
- [ ] A generated report includes one summary entry per evaluated rule with total evaluations, passed, failed, and pass rate.
- [ ] A generated report counts the number of failed evaluations whose severity is critical.
- [ ] A generated report lists the names of every policy set whose rules contributed to the evaluation.
- [ ] A generated report lists every audit event that produced at least one failure with its identifier, action, resource, and the failed rule identifiers and severities.
- [ ] Reports are serializable to JSON and to Markdown; both formats contain the same underlying counts and identifiers.

## Out of Scope
- Audit event production, identity, RBAC, sandbox, circuit breaker, and rate limiting (see cavekit-security-runtime.md).
- Domain-specific compliance rules and reasoning (e.g., ECOA adverse action ordering, SR 11-7 model validation findings) — see cavekit-finance-credit-risk.md.
- Live (subscription) policy distribution; reload requires reinitializing the engine.
- Cross-event temporal correlation (no rule type today reasons over event sequences).
- Rego/OPA integration (mentioned in ADR-005 as a possible future direction but not implemented).
- Credit model monotonicity and adverse action determinism verifiers (mentioned in ARCHITECTURE.md as Z3 properties 4 and 5; only properties 1 (RBAC), 2 (consistency), and 3 (workflow) are implemented in the verifier surface). [GAP — see notes.]
- Any UI for writing or browsing rules.

## Cross-References
- See also: cavekit-security-runtime.md (audit events consumed for evaluation; permission contexts referenced by some checks)

## Source Traceability
- R1 satisfied by: agentguard/compliance/engine.py (PolicyEngine, PolicyRule, PolicySet) + tests/unit/compliance/test_engine.py
- R2 satisfied by: agentguard/compliance/policies/owasp_agentic.yaml + agentguard/compliance/policies/finos_aigf_v2.yaml + agentguard/compliance/policies/eu_ai_act.yaml + tests/unit/compliance/test_engine.py
- R3 satisfied by: agentguard/compliance/engine.py (_check_handlers dispatch table and six handlers) + tests/unit/compliance/test_engine.py
- R4 satisfied by: agentguard/compliance/engine.py (PolicyEngine.evaluate) + tests/unit/compliance/test_engine.py
- R5 satisfied by: agentguard/compliance/hitl.py (HitlEscalation, ApprovalDecision, HitlManager) + tests/unit/compliance/test_hitl.py
- R6 satisfied by: agentguard/compliance/formal_verifier.py (FormalVerifier, VerificationResult) + agentguard/compliance/z3_models.py (lazy import) + tests/unit/compliance/test_formal_verifier.py
- R7 satisfied by: agentguard/compliance/formal_verifier.py (verify_rbac_escalation) + agentguard/compliance/z3_models.py (encode_rbac_permissions) + tests/unit/compliance/test_formal_verifier.py
- R8 satisfied by: agentguard/compliance/formal_verifier.py (verify_policy_consistency) + agentguard/compliance/z3_models.py (encode_policy_consistency) + tests/unit/compliance/test_formal_verifier.py
- R9 satisfied by: agentguard/compliance/formal_verifier.py (verify_workflow_safety) + agentguard/compliance/z3_models.py (encode_workflow_reachability) + tests/unit/compliance/test_formal_verifier.py
- R10 satisfied by: agentguard/compliance/reporter.py (ComplianceReporter, ComplianceReport, RuleSummary) + tests/unit/compliance/test_reporter.py

## Changelog
- 2026-04-19: Initial draft, reverse-engineered from v1.0.0 codebase.
