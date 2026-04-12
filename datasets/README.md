# AgentGuard Datasets

Synthetic benchmark datasets for agent governance and credit risk evaluation.

Datasets will be published to [HuggingFace Hub](https://huggingface.co/agentguard) as they become available.

## Planned Datasets

| Dataset | Description | Milestone |
|---------|-------------|-----------|
| `synthetic-credit-applications-v1` | Synthetic credit application data (SMOTE, then WGAN-GP) | M1 / M4 |
| `credit-agent-compliance-eval-v1` | Agent decision scenarios with expected policy results | M3 |
| `agent-security-red-team-suite` | Adversarial scenarios for agent security evaluation | M5 |

## Usage

```python
from datasets import load_dataset

ds = load_dataset("agentguard/synthetic-credit-applications-v1")
```

## Data Ethics

All datasets are fully synthetic. No real customer data, PII, or proprietary information is included. Protected class proxies are themselves synthetic and intended solely for fairness testing.
