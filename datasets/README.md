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

The schema is defined by
[`agentguard.domains.finance.synthetic.generators.CreditApplicationSchema`](../agentguard/domains/finance/synthetic/generators.py).

## Data ethics

- No real customer records are ever included.
- Protected-class proxies are synthetic labels assigned uniformly at random;
  they are **not** inferences from any real demographic data.
- Do not commit generated parquet/jsonl files to the repository — the script
  is the source of truth, not its output.
