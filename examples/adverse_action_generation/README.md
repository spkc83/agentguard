# Adverse Action Notice Generation

Narrow demo that focuses on the ECOA / Regulation B adverse action pipeline.

`notice_pipeline.py` covers four concerns:

1. **Standard denial notice** — feature importances from a PD model become an
   ordered, human-readable list of reasons.
2. **Determinism** — identical inputs produce identical notices; this is a
   regulatory requirement so that appeals can be reproduced exactly.
3. **Custom reason map** — institutions often want their own wording or a
   shorter cap (the default is four reasons per Regulation B).
4. **PII masking** — `PiiMasker` scrubs SSN / phone / account numbers out of
   text before it ever enters the audit log (see [CLAUDE.md](../../CLAUDE.md)
   PII rules).

## Running

```bash
pip install -e "."
python examples/adverse_action_generation/notice_pipeline.py
```

No audit log is written — this demo focuses on the notice object itself. For a
full flow including governance and audit, see
[`examples/credit_decisioning/end_to_end_demo.py`](../credit_decisioning/end_to_end_demo.py).
