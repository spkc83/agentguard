"""PII detection and masking for financial data.

Detects and masks Category 1 PII and FCRA-regulated data:
- SSN: XXX-XX-#### (last 4 digits preserved)
- Account numbers: last 4 digits only
- Routing numbers: fully masked
- DOB: fully masked
- Full name + address combinations

All masking is applied BEFORE data enters the audit log.
"""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict

from agentguard.guardrails import detect_pii, mask_pii, mask_pii_match, thaw_payload

logger = structlog.get_logger()


class PiiMatch(BaseModel):
    """A detected PII occurrence.

    Args:
        pii_type: Type of PII detected.
        start: Start position in the text.
        end: End position in the text.
        original: The original text (for masking).
        masked: The masked replacement.
    """

    model_config = ConfigDict(frozen=True)

    pii_type: str
    start: int
    end: int
    original: str
    masked: str


class PiiDetector:
    """Detects PII in text using pattern matching.

    Covers SSN, account numbers, routing numbers, DOB, email, phone.
    FCRA-regulated data (credit report contents) is treated as Category 1
    PII regardless of format.
    """

    def detect(self, text: str) -> list[PiiMatch]:
        """Scan text for PII patterns.

        Args:
            text: The text to scan.

        Returns:
            List of PiiMatch objects for each detected PII.
        """
        return [
            PiiMatch(
                pii_type=match.pii_type,
                start=match.start,
                end=match.end,
                original=text[match.start : match.end],
                masked=mask_pii_match(text, match),
            )
            for match in detect_pii(text)
        ]


class PiiMasker:
    """Masks PII in text and structured data.

    Uses PiiDetector to find PII, then replaces all occurrences
    with masked versions.
    """

    def __init__(self) -> None:
        self._detector = PiiDetector()

    def mask_text(self, text: str) -> str:
        """Mask all detected PII in a text string.

        Args:
            text: Input text potentially containing PII.

        Returns:
            Text with all PII replaced by masked versions.
        """
        matches = self._detector.detect(text)
        result = thaw_payload(mask_pii(text))
        assert isinstance(result, str)
        if matches:
            logger.debug("pii_masked", count=len(matches))
        return result

    def mask_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively mask PII in a dictionary.

        Args:
            data: Dictionary potentially containing PII in string values.

        Returns:
            New dictionary with PII masked in all string values.
        """
        result = thaw_payload(mask_pii(data))
        assert isinstance(result, dict)
        return result
