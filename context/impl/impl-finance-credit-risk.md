---
created: "2026-04-22"
last_edited: "2026-04-22"
---

# Implementation Tracking: Finance — Credit Risk (Layer 3)

Build site: context/plans/build-site.md

Brownfield strict-as-built verification.

## Tier 2 Finance — Tasks T-079..T-101

| Task | Status | Notes |
|------|--------|-------|
| T-079 | DONE | R1 C1 thresholds configurable (agent_templates.py:25-42 CreditDecisionConfig frozen model + test_agent_templates.py). |
| T-080 | DONE | R1 C2-5 decision routing: PD auto-approve / decline / review / 2+ cutoffs (agent_templates.py:117-126 branch logic + test_agent_templates.py). |
| T-081 | DONE | R1 C6 decision return shape (agent_templates.py:45-64 CreditDecision + test_agent_templates.py asserts all six fields). |
| T-082 | DONE | R2 C1-2 ordered reasons + Reg-B 4-max (adverse_action.py:121-124 sorted desc, 131 break at max, MAX_REASONS=4 + test_adverse_action.py). |
| T-083 | DONE | R2 C3-4 deterministic feature-name tie-break + consumer-readable (adverse_action.py:123 key `(-abs(x[1]), x[0])` ties broken by feature name; DEFAULT_REASON_MAP maps features to readable strings + test_adverse_action.py asserts reasons don't contain raw feature names). |
| T-084 | DONE | R2 C5-6 custom map override + full schema (adverse_action.py:88-93 accepts reason_map; AdverseActionNotice carries ECOA/Reg-B disclosure_text default + test_adverse_action.py). |
| T-085 | DONE | R3 C1 SR 11-7 report schema (model_validation.py ModelValidationReport with all required fields + test_model_validation.py). |
| T-086 | DONE | R3 C2-5 finding generation per signal (model_validation.py validate() checks Gini/AUC/PSI/fairness/docs + maps to SR 11-7 sections + test_model_validation.py). |
| T-087 | DONE | R3 C6 rating/approval rules (model_validation.py aggregation: any critical→unsatisfactory+block; multi-high→needs-improvement+block + test_model_validation.py). |
| T-088 | DONE | R4 C1 disparate impact 4/5ths (fairness.py:174-177 min/max approval ratio vs 0.8 threshold + test_fairness.py). |
| T-089 | DONE | R4 C2 equalized odds (fairness.py:180-182 max TPR/FPR diffs < threshold + test_fairness.py). |
| T-090 | DONE | R4 C3 calibration (fairness.py:184-186 max |pred-obs| < threshold + test_fairness.py). |
| T-091 | DONE | R4 C4-6 per-group fields + overall AND + demographic parity (fairness.py:153-164 GroupMetrics, 192 overall = di AND eo AND cal, 189 dp_diff + test_fairness.py). |
| T-092 | DONE | R5 C1-3,5 PII match list + SSN/account/phone last-4 (pii.py detect/mask patterns + test_pii.py). |
| T-093 | DONE | R5 C4,6 email local-char + domain preserved; DOB placeholder (pii.py email/date patterns + test_pii.py). |
| T-094 | DONE | R5 C7-8 overlapping matches + recursive dict (pii.py mask_text + mask_dict recursive + test_pii.py). |
| T-095 | DONE | R6 C1 reproducibility (generators.py:76 seeded random.Random + test_reproducible). |
| T-096 | DONE | R6 C2-3 schema + bounded ranges (generators.py:23-60 CreditApplicationSchema; _clamp bounds FICO 300-850, DTI [0,1], LTV [0.1,1.5] + test_fico_in_range, test_dti_in_range, test_record_schema). |
| T-097 | DONE | R6 C4 demographic proxy from fixed labeled set (generators.py:97 ["group_a",...,"group_d"] hard-coded, no real-demo inference + test_demographic_proxies_present). |
| T-098 | DONE | R6 C5 realized default rate + FICO correlation (generators.py:117-121 pd_adj scales with FICO and DTI + existing test_default_rate_roughly_matches + NEW test_fico_correlates_with_default). |
| T-099 | DONE | R7 C1-2 trainer state transitions (wgan_gp.py is_trained flag; sample pre-train raises RuntimeError). Not covered in unit tests (torch optional dependency); verified by source inspection. |
| T-100 | DONE | R7 C3-4 WGAN-GP hyperparameters + Adam loop (wgan_gp.py exposes gp_weight, critic_steps, latent_dim; train() uses Adam + gradient penalty per Gulrajani 2017). Verified by source inspection; running requires torch + GPU/CPU time. |
| T-101 | DONE | R7 C5-6 sample dimensionality + missing-torch raise (wgan_gp.py imports torch at module level — importing module raises ImportError if not installed, directive is Python's default). Verified by source inspection. |

## Summary

23/23 finance tasks DONE. 1 new test (FICO/default correlation). WGAN-GP tasks T-099-T-101 verified structurally; unit tests are not present because torch is an optional install (see ADR-011, ADR-012).
