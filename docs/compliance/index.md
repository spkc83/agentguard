# Compliance Frameworks Reference

AgentGuard ships three built-in policy bundles under
[`agentguard/compliance/policies/`](../../agentguard/compliance/policies/).
Each is a YAML file consumed by `PolicyEngine`. Policies are code: they are
versioned, reviewable, and diffable alongside the runtime.

## OWASP Top 10 for Agentic AI

File: `owasp_agentic.yaml` · 10 rules.

Covers prompt injection, tool misuse, supply chain compromise, agent memory
poisoning, excessive agency, and the other OWASP-Agentic categories. Each
rule maps to an OWASP rule ID and emits an event tagged with the same ID so
that downstream reporting aligns with OWASP's published catalogue.

## FINOS AI Governance Framework v2.0

File: `finos_aigf_v2.yaml` · 15 rules.

Maps to the FINOS AIGF 46-risk catalogue for financial services. Rules
enforce segregation of duties on agent roles, explainability checkpoints on
credit decisioning, and SR 11-7 style documentation gates on model-serving
tools. The rule IDs follow the `FINOS-AIGF-*` convention so compliance reports
can be reconciled directly with the framework's risk registry.

## EU AI Act (high-risk systems)

File: `eu_ai_act.yaml` · 10 rules.

Covers the High-Risk AI obligations most relevant to agentic credit scoring:
Article 9 (risk management), Article 10 (data governance), Article 13
(transparency / logging), Article 14 (human oversight), Article 17 (quality
management). Credit scoring is explicitly listed as High-Risk AI under Annex
III, so these rules are required whenever the domain toolkit is in the loop.

## Formal verification

`agentguard.compliance.formal_verifier.FormalVerifier` encodes policies into
Z3 SMT constraints and proves:

- **RBAC non-escalation** — no role combination grants a forbidden
  action/resource pair.
- **Policy consistency** — no two rules can be satisfied simultaneously with
  contradictory effects.
- **Workflow safety** — required sequence of pre/post conditions always holds
  along every agent path.

See ADR-005 in [`DECISIONS.md`](../../DECISIONS.md) for the encoding model and
why Z3 was chosen over custom property checkers.

## Reporting

`agentguard.compliance.reporter.ComplianceReporter` walks the audit log and
produces a JSON or Markdown attestation covering rule hits/misses, denial
rates, and policy-rule trends over time. It is wired into the CLI:

```bash
agentguard policy report --log-dir ./audit-logs --output markdown
```
