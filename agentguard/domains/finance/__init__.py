"""Financial services domain toolkit.

Credit risk is the flagship domain: credit decisioning agent templates,
ECOA-compliant adverse action generation, SR 11-7 model validation,
fairness analysis, PII masking, and synthetic data generation.

Public API:
    from agentguard.domains.finance import PiiDetector, PiiMasker
    from agentguard.domains.finance.credit_risk import (
        AdverseActionGenerator, FairnessAnalyzer, CreditDecisionConfig,
    )
"""
