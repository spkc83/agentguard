# Compliance Frameworks Reference

AgentGuard ships three built-in policy bundles under
[`agentguard/compliance/policies/`](../../agentguard/compliance/policies/).
Each is a YAML file consumed by `PolicyEngine`. Policies are code: they are
versioned, reviewable, and diffable alongside the runtime.

## How these rules run (read this before trusting a report)

`PolicyEngine` evaluates rules **against `AuditEvent` records that have already been
written** — it is not on the governed call path. Nothing here can block a tool call;
`PolicyResult` carries only `passed: bool`, with no deny/escalate vocabulary. The
engine is driven by `agentguard policy validate`, `agentguard policy report`, the
`verify` commands, and `ComplianceReporter`. Moving policy evaluation in front of
execution with a real effect is Phase 1.3 of
[`docs/plans/guardrails-realignment.md`](../plans/guardrails-realignment.md).

What a rule can inspect is limited by what an `AuditEvent` carries. Across all 35
shipped rules:

| Kind | Count | What it actually checks |
|---|---|---|
| Action / resource pattern rules (`action_blocklist`, `resource_pattern`) | 9 | Substring and glob matches against the `action` and `resource` strings on the event. Both strings are supplied by the caller, so these are detect-only and defeated by renaming a tool. |
| Metadata key-presence rules (`metadata_required`) | 10 | That a named key exists in the acting agent's identity metadata. **Values are never read** — `{"model_version": ""}` passes. These are honour-system attestations, not controls. |
| Result / permission field rules (`permission_required`, `result_required`, `content_scan`) | 16 | The event's `granted` flag, its `result` field, or a pattern scan of `permission_context.context` / `tool_args`. Note that no code currently populates the context or argument fields, so the `content_scan` rules cannot fire today (Phase 1.3). |

A passing report therefore means "no rule found a counter-signal in the log", not
"these controls are enforced". A separate known gap: `ComplianceReporter` does not call
`verify_chain()` before attesting, so a tampered log can still yield a clean report
(Phase 2.3).

## OWASP Top 10 for Agentic AI

File: `owasp_agentic.yaml` · 10 rules.

Covers prompt injection, tool misuse, supply chain compromise, agent memory
poisoning, excessive agency, and the other OWASP-Agentic categories. Rule IDs follow
`OWASP-AGENT-NN`, matching the published category numbering, and the same ID is
carried into the emitted `PolicyResult` so reporting lines up with OWASP's catalogue.

## FINOS AIGF v2.0-aligned controls

File: `finos_aigf_v2.yaml` · 15 rules.

15 controls **informed by** the FINOS AI Governance Framework v2.0, covering
segregation of duties on agent roles, explainability checkpoints on credit
decisioning, and SR 11-7 style documentation gates on model-serving tools.

Rule IDs are AgentGuard-local: `AG-FINOS-NNN`. **This is not an official mapping to
the FINOS risk registry.** The published framework uses `AIR-*` identifiers
(`AIR-OP-*`, `AIR-SEC-*`, `AIR-RC-*`); AgentGuard's numbering is its own and the
gaps in the sequence are historical, not references to FINOS risks. Producing a real
`AIR-*` crosswalk requires domain review and is a Phase 4/5 item. Ten of these fifteen
rules are metadata key-presence checks per the table above.

## EU AI Act (high-risk systems)

File: `eu_ai_act.yaml` · 10 rules.

Covers the High-Risk AI obligations most relevant to agentic credit scoring:
Article 9 (risk management), Article 10 (data governance), Article 13
(transparency / logging), Article 14 (human oversight), Article 17 (quality
management). Credit scoring is explicitly listed as High-Risk AI under Annex
III, so these rules are relevant whenever the domain toolkit is in the loop. The
article citations are accurate; the checks behind them are the key-presence and
result-field kinds described above, so they evidence intent rather than conformity.

## Formal verification

`agentguard.compliance.formal_verifier.FormalVerifier` offers three checks. Only the
first two involve Z3:

- **RBAC non-escalation** (Z3) — searches for a role combination that grants a
  forbidden action/resource pair. The encoding indexes exact `(action, resource)`
  pairs and does not yet model `fnmatch` subsumption or `inherited_roles`, so a
  `tool:*` grant that the runtime expands into a specific tool is invisible to it.
  Treat results as lint-grade until Phase 5.2.
- **Policy consistency** (Z3) — looks for pairs of rules with contradictory effects.
  Rule conditions are currently encoded as unconstrained strings, which makes most
  pairs trivially satisfiable; the check over-reports.
- **Workflow safety** (**not Z3**) — `verify_workflow_safety` is a breadth-first
  search over the agent graph checking that every path from a start node to a
  guarded node passes through a HITL node. ADR-016 records this decision; there is no
  Datalog/µZ encoding.

Available from the CLI as `agentguard verify rbac --config <file>` and
`agentguard verify policy --policy-dir <dir>`. Workflow safety is Python-API only.
See ADR-005 and ADR-016 in [`DECISIONS.md`](../../DECISIONS.md) for the encoding model
and the known caveats.

## Reporting

`agentguard.compliance.reporter.ComplianceReporter` walks the audit log and
produces a JSON or Markdown attestation covering rule hits/misses, denial
rates, and policy-rule trends over time. It is wired into the CLI:

```bash
agentguard policy validate --policy-dir agentguard/compliance/policies
agentguard policy report --log-dir ./audit-logs --output-format markdown
```
