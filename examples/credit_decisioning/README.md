# Credit Decisioning Demo

End-to-end demonstration of AgentGuard's Phase 4.2 governed credit API using
synthetic applications and a bounded stub PD model. No LLM or real customer
data is used.

`end_to_end_demo.py` exercises:

- **Governed scoring** — `GovernedCreditAgent.score()` authorizes the fixed
  `model:score` action while retaining only opaque application and model
  references, not model inputs, PD values, or attribution details.
- **Action-scoped decisions** — approve, review, and decline results use the
  independent `decision:approve`, `decision:review`, and `decision:decline`
  RBAC actions. The demo also configures the separate `decision:override` and
  `notice:issue` permissions without exercising them.
- **Full decision controls** — the kernel applies typed decision-evidence,
  protected-feature, trusted model-provenance, decision-band, reason-code,
  attribution-integrity, and notice-completeness guardrails.
- **HITL review** — review-band decisions raise `EscalationRequiredError` and
  are counted as reviews. They are never relabeled as declines or approvals.
- **Truthful decline reasons** — every decline carries a versioned selection
  produced by `ReasonCodeMapper` from the stub model's exact attribution. The
  example does not fabricate reason text or infer reasons from raw cutoffs.
- **Fairness and audit evidence** — typed final observations for explicitly
  named synthetic groups feed disparate impact, equalized-odds, and fixed-bin
  calibration metrics before the signed audit chain is verified. Review-band
  results are excluded, and this intentionally small demo normally reports
  `INSUFFICIENT_DATA` rather than treating sparse denominators as a pass.

## Running

```bash
pip install -e "."
export AGENTGUARD_AUDIT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python examples/credit_decisioning/end_to_end_demo.py
```

Output includes decision counts, mapped reason selections, a named-group
fairness summary, a governance dashboard, and a chain-integrity check. Audit
and pending HITL control-plane records are written beneath
`./credit-decisioning-audit/`; delete that demo directory when it is no longer
needed.

## Notice issuance

`notice:issue` records evidence that a written notification has already been
completed. It is not a renderer, delivery transport, or claim that a notice
was sent. See the [adverse-action example](../adverse_action_generation/) for
typed notice construction and rendering before a completed notification is
recorded.

## Extending

- Replace the local `_score_pd` callback with a validated model while keeping
  its exact version and feature schema aligned with trusted
  `ModelGovernanceEvidence`.
- Increase `N_APPLICATIONS` to exercise a larger synthetic workload.
- Split RBAC roles to demonstrate that scoring, final decisions, overrides,
  and notice recording are independently authorized.
- Inspect the produced log with `agentguard observe dashboard` or
  `agentguard observe replay`.
