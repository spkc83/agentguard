---
created: "2026-04-19"
last_edited: "2026-04-19"
complexity: medium
---

# Cavekit: Finance — Credit Risk Domain Toolkit (Layer 3)

## Scope
This kit covers the flagship financial-services domain toolkit (per ADR-008 and ADR-014): credit decisioning workflows, ECOA/Regulation B adverse action notice generation, SR 11-7 model validation, fairness analysis under ECOA and the Fair Housing Act, PII detection and masking for credit data, and synthetic credit data generation for benchmarks and red-team testing. The kit specifies what the credit-risk module produces; the security and compliance layers govern *how* those tools are invoked.

## Requirements

### R1: Configurable Credit Decisioning Agent Template
**Description:** The toolkit provides a credit decisioning template that maps a model-predicted probability of default (PD) and an application's hard cutoffs to one of three decisions: approved, declined, or referred for review (HITL). Thresholds, FICO floor, debt-to-income ceiling, and loan amount ceiling are configurable.
**Acceptance Criteria:**
- [ ] Decision thresholds (auto-approve PD, decline PD), FICO floor, DTI ceiling, and loan amount ceiling are configurable per template instance.
- [ ] An applicant with a PD below the auto-approve threshold and no hard-cutoff violations is approved.
- [ ] An applicant with a PD at or above the decline threshold is declined regardless of other factors.
- [ ] An applicant with a PD between the two thresholds is routed to review.
- [ ] An applicant violating two or more hard cutoffs is declined.
- [ ] Every decision returns the applicant identifier, the decision, the PD score, an ordered list of human-readable reasons, a flag indicating whether HITL review is required, and a per-feature importance map.

### R2: ECOA/Regulation B Adverse Action Notice Generation
**Description:** When credit is denied, the toolkit produces an adverse action notice meeting ECOA and Regulation B obligations: a bounded list of specific principal reasons, deterministically ordered by impact, mapped from model features to consumer-readable reason codes (per ADR-014).
**Acceptance Criteria:**
- [ ] A generated notice contains an ordered list of reasons, with the most impactful feature first.
- [ ] The number of reasons in a notice does not exceed the configured maximum (default four, consistent with Regulation B practice).
- [ ] Given identical feature importances, regenerating the notice produces identical reasons in identical order (deterministic ordering, breaking ties by feature name).
- [ ] Each reason in the notice has a corresponding consumer-readable string (no raw feature names in the reason list).
- [ ] A custom feature-to-reason mapping can be supplied, overriding the default mapping.
- [ ] A generated notice carries a unique notice identifier, the applicant identifier, the decision string, the PD score, the creditor name, a decision timestamp, and a regulatory disclosure text referencing ECOA and Regulation B.

### R3: SR 11-7 Model Validation Workflow
**Description:** The toolkit provides a structured validation workflow producing a Federal Reserve / OCC SR 11-7-aligned report: discrimination metrics (Gini, KS, AUC-ROC), drift (PSI), accuracy, optional data-quality and fairness inputs, optional documentation completeness, and a per-section finding log mapped to SR 11-7 sections.
**Acceptance Criteria:**
- [ ] A validation report carries a unique report identifier, the model name and version, validation date, validator identifier, performance metrics, findings, an overall rating, an approval flag, and the SR 11-7 sections reviewed.
- [ ] Performance metrics below configured thresholds (Gini, AUC-ROC) produce findings of severity high or higher mapped to the outcomes-analysis section.
- [ ] PSI above its configured threshold produces a finding of severity critical mapped to the ongoing-monitoring section.
- [ ] A failing fairness result produces a finding of severity critical mapped to the outcomes-analysis section.
- [ ] Missing required documentation produces a finding mapped to the conceptual-soundness section.
- [ ] Any critical finding sets the overall rating to unsatisfactory and the approval flag to false; multiple high findings set the rating to needs-improvement and the approval flag to false.

### R4: Fairness Analysis for Credit Models
**Description:** The toolkit computes the fairness metrics most commonly required for credit-risk models: disparate impact under the 4/5ths rule, equalized odds (TPR and FPR differentials), calibration, and demographic parity. All fairness inputs use synthetic demographic proxies — never inferred real demographics.
**Acceptance Criteria:**
- [ ] Disparate impact ratio is computed as the smallest group approval rate divided by the largest, and the test passes only when the ratio meets or exceeds the configured threshold (default 0.8 — the 4/5ths rule).
- [ ] Equalized odds passes only when both the maximum across-group TPR difference and the maximum across-group FPR difference are strictly below the configured threshold.
- [ ] Calibration passes only when the maximum |predicted minus observed| default-rate difference across groups is strictly below the configured threshold.
- [ ] The per-group output reports total, approved, denied, approval rate, TPR, FPR, predicted default rate, and observed default rate.
- [ ] An overall pass flag is true only when all of disparate impact, equalized odds, and calibration pass.
- [ ] Demographic parity difference (max minus min approval rate across groups) is reported alongside the boolean test outcomes.

### R5: PII Detection and Masking for Credit Data
**Description:** The toolkit detects and masks PII categories relevant to consumer credit: SSN, financial account numbers, routing numbers, dates of birth, email addresses, and phone numbers. Masking preserves last-4 digits for account numbers and SSNs (consistent with FCRA log-handling conventions) and fully obscures DOB.
**Acceptance Criteria:**
- [ ] Detection returns a list of structured matches each carrying the PII type, character-offset range, original text, and masked replacement.
- [ ] SSNs in the canonical XXX-XX-#### format are detected and masked to XXX-XX- followed by the last four digits.
- [ ] Account numbers (8 to 17 digit sequences) are masked so only the last four digits remain.
- [ ] Email addresses are masked so the local part is reduced to the first character followed by an obfuscation suffix while preserving the domain for deliverability triage.
- [ ] Phone numbers are masked so only the last four digits remain.
- [ ] Date-of-birth patterns in common date formats are masked to a placeholder pattern that preserves no original digits.
- [ ] Masking applied to a string with multiple overlapping or sequential PII matches produces a result where every detected occurrence is replaced.
- [ ] Masking applied to a nested dictionary recursively masks every string value at any depth.

### R6: Synthetic Credit Application Dataset Generation
**Description:** The toolkit generates synthetic credit application records with realistic statistical profiles for use in benchmarks, fairness testing, and red-team scenarios. Generation is reproducible and includes a synthetic demographic proxy column for fairness work — never real demographics.
**Acceptance Criteria:**
- [ ] Generation given the same seed and configuration produces identical records in identical order.
- [ ] Each generated record has the documented schema fields: application identifier, FICO score, DTI ratio, LTV ratio, annual income, employment status, loan purpose, loan amount, term in months, 24-month delinquency count, credit utilization, number of open accounts, months employed, synthetic demographic proxy, and a default label.
- [ ] FICO scores fall within the regulatory range (300-850); DTI is bounded to the unit interval; LTV is bounded to the documented range.
- [ ] The synthetic demographic proxy column draws from a fixed labeled set (no real demographic categories or inferences).
- [ ] The realized default rate of a generated dataset is approximately within the configured target default rate (correlated with risk factors so high-FICO records default less frequently than low-FICO records).

### R7: WGAN-GP Synthetic Data Backend
**Description:** When PyTorch is available, a WGAN-GP-based generator (per ADR-011) provides higher-fidelity tabular synthesis as an alternative backend to the statistical generator. The backend trains a generator against a critic with gradient penalty and exposes a sample-from-trained-model API.
**Acceptance Criteria:**
- [ ] The trainer reports a not-trained state until training has been run and a trained state afterward.
- [ ] Calling the sample API before training raises a runtime error indicating the model must be trained first.
- [ ] The trainer surfaces the gradient-penalty weight, the critic-step ratio (critic updates per generator update), and the latent dimension as configurable hyperparameters.
- [ ] The trainer runs an Adam-based optimization loop using the documented WGAN-GP loss (critic loss includes the gradient-penalty term; generator loss is the negative critic mean over fakes).
- [ ] Generation returns the requested number of synthetic samples each having the same dimensionality as the training data.
- [ ] If the optional deep-learning dependency is not installed, attempting to use the WGAN-GP backend raises an import error directing the user to the optional install.

## Out of Scope
- Identity, RBAC, audit logging, sandbox, circuit breaker, rate limiting (see cavekit-security-runtime.md).
- Generic policy evaluation, formal verification, and HITL infrastructure (this kit uses their outputs but does not implement them — see cavekit-compliance-engine.md).
- Framework adapters that wrap the credit-risk tools (see cavekit-framework-integrations.md).
- Replay, dashboards, OpenTelemetry tracing (see cavekit-observability.md).
- Domain modules outside credit risk (healthcare, government, energy mentioned as future work in ADR-008 are not implemented).
- Loan performance / vintage / cohort dataset generation (the synthetic generator targets credit applications only).
- TabDDPM diffusion synthetic backend (mentioned in ADR-011 as a possible future option but not implemented).
- Counterfactual fairness (mentioned in ARCHITECTURE.md but not implemented in the fairness analyzer). [GAP]
- Z3-based credit model monotonicity and adverse action determinism verifiers (mentioned in ARCHITECTURE.md as Z3 properties 4 and 5; not implemented in v1.0.0). [GAP]
- Real-time bureau integration; the credit decisioning agent template consumes a PD score it does not itself compute.

## Cross-References
- See also: cavekit-security-runtime.md (audit, RBAC, and sandbox govern how credit-risk tools are invoked)
- See also: cavekit-compliance-engine.md (fairness results and PII signals feed into compliance evaluation and HITL escalation)

## Source Traceability
- R1 satisfied by: agentguard/domains/finance/credit_risk/agent_templates.py + tests/unit/domains/finance/test_agent_templates.py
- R2 satisfied by: agentguard/domains/finance/credit_risk/adverse_action.py + tests/unit/domains/finance/test_adverse_action.py
- R3 satisfied by: agentguard/domains/finance/credit_risk/model_validation.py + tests/unit/domains/finance/test_model_validation.py
- R4 satisfied by: agentguard/domains/finance/credit_risk/fairness.py + tests/unit/domains/finance/test_fairness.py
- R5 satisfied by: agentguard/domains/finance/pii.py + tests/unit/domains/finance/test_pii.py
- R6 satisfied by: agentguard/domains/finance/synthetic/generators.py + tests/unit/domains/finance/test_generators.py
- R7 satisfied by: agentguard/domains/finance/synthetic/wgan_gp.py + tests/unit/domains/finance/test_generators.py

## Changelog
- 2026-04-19: Initial draft, reverse-engineered from v1.0.0 codebase.
