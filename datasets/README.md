# AgentGuard Datasets

Benchmark datasets for governance, compliance, and credit risk evaluation.
All data is fully synthetic — no real PII, no proprietary data, no real
protected-class attributes. Demographic proxies (`group_a`..`group_d`) exist
solely to exercise fairness analysis.

## Generate on demand

The repository deliberately does **not** commit large binary datasets. They
are regenerated deterministically with the packaged generator:

```bash
python scripts/generate_datasets.py                  # all datasets, 10K rows each
python scripts/generate_datasets.py --size 50000     # larger
python scripts/generate_datasets.py --dataset applications --seed 1
```

Each run writes:

- `datasets/<name>/data.jsonl` — always written.
- `datasets/<name>/data.parquet` — written if `pandas` + `pyarrow` are installed.
- `datasets/<name>/metadata.json` — size, seed, target default rate.

Available datasets:

| Name | Directory | Purpose |
|------|-----------|---------|
| `applications` | `synthetic_credit_applications_v1/` | Consumer loan applications with demographic proxies |
| `performance` | `synthetic_loan_performance_v1/` | Loan performance with higher default rate for vintage analysis |
| `compliance_eval` | `credit_agent_compliance_eval_v1/` | Edge-case scenarios for compliance / red-team testing |

## Usage

```python
import json

with open("datasets/synthetic_credit_applications_v1/data.jsonl") as f:
    rows = [json.loads(line) for line in f]
```

Or via pandas if parquet was written:

```python
import pandas as pd

df = pd.read_parquet("datasets/synthetic_credit_applications_v1/data.parquet")
```

The canonical testing API is
[`agentguard.testing.synthetic`](../agentguard/testing/synthetic.py):

```python
from agentguard.testing import SyntheticCreditGenerator, is_synthetic_approval

rows = SyntheticCreditGenerator(seed=4600, default_rate=0.08, bias=0.0).generate(1000)
approval_rate = sum(map(is_synthetic_approval, rows)) / len(rows)
```

The pre-1.0 `agentguard.domains.finance.synthetic.generators` namespace remains
an identity-preserving compatibility re-export.

## Statistical generator contract

`default_rate` must be finite and strictly between zero and one. `bias` must be
finite and between zero and one inclusive, and sample counts must be positive.
The generator uses only its private seeded random-number generator; equal
constructor inputs and call sequences produce byte-identical ordered records.

Rows are produced in one dependency-ordered pass. Income is generated from
latent credit quality; property value is generated from income; requested loan
amount is generated from income and property value; and the reported LTV is
exactly requested loan divided by the internal property value. DTI is exactly
annual existing obligations plus the proposed annual principal obligation,
divided by annual income, then bounded to `[0, 1]`. The internal property and
obligation intermediates are intentionally omitted to preserve the published
record schema. Default probability is computed separately from FICO, DTI, LTV,
delinquencies, and utilization around the configured portfolio base rate.

The fixed benchmark approval predicate does not use `is_default`: approval
requires FICO at least 660, DTI at most 0.43, and LTV at most 0.90. With seed
4600 and 40,000 rows, `bias=0` yields DI 0.998, while the deliberately biased
`bias=0.75` fixture yields DI 0.642 (the locked acceptance target is
approximately 0.65 with absolute tolerance 0.03). DI compares artificial
`group_a` with the pooled `group_b`–`group_d` reference rows.

## Data ethics

- No real customer records are ever included.
- Group labels are assigned uniformly at random and are **not** inferences from
  any real demographic data. At `bias=0`, labels are independent of latent
  credit quality. Positive `bias` deliberately shifts only artificial
  `group_a` so fairness tooling has a measurable evaluation control.
- Biased fixtures are tests of disparity detection, not production credit
  models, underwriting recommendations, or representative population data.
- Do not commit generated parquet/jsonl files to the repository — the script
  is the source of truth, not its output.
