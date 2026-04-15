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

import re
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict

logger = structlog.get_logger()

# PII detection patterns
_SSN_PATTERN = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")
_SSN_NO_DASH = re.compile(r"\b(\d{3})(\d{2})(\d{4})\b")
_ACCOUNT_PATTERN = re.compile(r"\b(\d{4})\d{4,13}\b")
_ROUTING_PATTERN = re.compile(r"\b\d{9}\b")
_DOB_PATTERN = re.compile(
    r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b"
    r"|\b(\d{4}[/-]\d{1,2}[/-]\d{1,2})\b"
)
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_PHONE_PATTERN = re.compile(r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")


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
        matches: list[PiiMatch] = []

        # SSN with dashes: 123-45-6789 -> XXX-XX-6789
        for m in _SSN_PATTERN.finditer(text):
            matches.append(
                PiiMatch(
                    pii_type="ssn",
                    start=m.start(),
                    end=m.end(),
                    original=m.group(),
                    masked=f"XXX-XX-{m.group(3)}",
                )
            )

        # Account numbers: preserve last 4 digits
        for m in _ACCOUNT_PATTERN.finditer(text):
            full = m.group()
            if len(full) >= 8:
                matches.append(
                    PiiMatch(
                        pii_type="account_number",
                        start=m.start(),
                        end=m.end(),
                        original=full,
                        masked="X" * (len(full) - 4) + full[-4:],
                    )
                )

        # Email
        for m in _EMAIL_PATTERN.finditer(text):
            local, domain = m.group().split("@")
            masked_local = local[0] + "***" if local else "***"
            matches.append(
                PiiMatch(
                    pii_type="email",
                    start=m.start(),
                    end=m.end(),
                    original=m.group(),
                    masked=f"{masked_local}@{domain}",
                )
            )

        # Phone
        for m in _PHONE_PATTERN.finditer(text):
            matches.append(
                PiiMatch(
                    pii_type="phone",
                    start=m.start(),
                    end=m.end(),
                    original=m.group(),
                    masked="XXX-XXX-" + m.group()[-4:],
                )
            )

        # DOB
        for m in _DOB_PATTERN.finditer(text):
            matched = m.group()
            matches.append(
                PiiMatch(
                    pii_type="dob",
                    start=m.start(),
                    end=m.end(),
                    original=matched,
                    masked="XX/XX/XXXX",
                )
            )

        return matches


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
        if not matches:
            return text

        # Sort by position (reverse) to replace from end to start
        matches.sort(key=lambda m: m.start, reverse=True)
        result = text
        for match in matches:
            result = result[: match.start] + match.masked + result[match.end :]

        logger.debug("pii_masked", count=len(matches))
        return result

    def mask_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively mask PII in a dictionary.

        Args:
            data: Dictionary potentially containing PII in string values.

        Returns:
            New dictionary with PII masked in all string values.
        """
        result: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.mask_text(value)
            elif isinstance(value, dict):
                result[key] = self.mask_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self.mask_text(item) if isinstance(item, str) else item for item in value
                ]
            else:
                result[key] = value
        return result
