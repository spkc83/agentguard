# Credit Decisioning Demo

End-to-end demonstration of AgentGuard applied to a credit decisioning workflow.

`end_to_end_demo.py` exercises:

- **Synthetic data** — `SyntheticCreditGenerator` produces 200 applications with
  demographic proxies suitable for fairness testing (no real PII).
- **Governance pipeline** — every decision runs through `run_governed`, which
  enforces identity → RBAC → audit (pre-event) → execute → audit (error) per
  [ADR-004](../../DECISIONS.md) and [ADR-020](../../DECISIONS.md).
- **Credit decision bands** — the `CreditDecisioningAgent` template maps PD
  scores and hard cutoffs (FICO, DTI, loan amount) onto
  auto-approve / review / decline outcomes.
- **Adverse action notices** — declined applications trigger an ECOA /
  Regulation B compliant notice with deterministic reason ordering.
- **Fairness report** — disparate impact (4/5ths rule), equalized odds, and
  calibration are evaluated across synthetic demographic groups.
- **Tamper-evident audit** — the HMAC chain is verified at the end.

## Running

```bash
pip install -e "."
export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python examples/credit_decisioning/end_to_end_demo.py
```

Output includes a per-group fairness summary, a governance dashboard
(p50/p95 latency, denial rate), and a chain-integrity check. Audit logs are
written to `./credit-decisioning-audit/`.

## Extending

- Swap `_score_pd` for a real PD model (scorecard, GBM, etc.).
- Increase `N_APPLICATIONS` to stress-test the governance pipeline.
- Add extra RBAC denials (`data:read:pii`) to see deny-override in action.
- Pipe the produced audit log into `agentguard observe dashboard` or
  `agentguard observe replay` from the CLI.
