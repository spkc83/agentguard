"""Financial services domain toolkit.

Credit risk is the flagship domain: credit decisioning agent templates,
versioned adverse-reason attribution evidence, signed model-validation evidence,
fairness analysis, PII masking, and synthetic data generation.

Public API:
    from agentguard.domains.finance import PiiDetector, PiiMasker
    from agentguard.domains.finance.credit_risk import (
        CoefficientAttributor, DeniedApplicationNotice, NoticeRenderer,
    )
"""
