# Adverse Action Notice Artifacts

Demo of truthful attribution, typed notice construction, and deterministic rendering. The sample is
source-grounded in Regulation B Appendix C but still requires deployer-specific legal review; it
does not perform delivery or write applicant data to an audit log.

`notice_pipeline.py` covers four concerns:

1. **Truthful attribution** — declared scorecard direction and a reference profile produce only
   strictly positive points lost; arbitrary signed feature importance is not accepted.
2. **Versioned mapping and determinism** — every transformed feature has an explicit deployer
   binding, and identical attribution produces the same ranked local reason codes.
3. **Complete typed artifact and canonical renderer** — applicant, creditor, requested terms,
   actual notification timing, principal-reason provenance, ECOA disclosure, and explicit FCRA
   applicability are validated before a C-3 profile is rendered and SHA-256 digested.
4. **PII masking** — `PiiMasker` scrubs SSN / phone / account numbers out of
   text before it ever enters the audit log (see [CLAUDE.md](../../CLAUDE.md)
   PII rules).

## Running

```bash
pip install -e "."
python examples/adverse_action_generation/notice_pipeline.py
```

No audit log is written — Phase 4.2 owns redacted notice references on the governed path. For a
full flow including governance and audit, see
[`examples/credit_decisioning/end_to_end_demo.py`](../credit_decisioning/end_to_end_demo.py).
