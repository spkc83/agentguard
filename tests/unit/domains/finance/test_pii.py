"""Tests for agentguard.domains.finance.pii — PII detection and masking."""

from __future__ import annotations

from agentguard.domains.finance.pii import PiiDetector, PiiMasker


class TestPiiDetector:
    def test_detect_ssn(self) -> None:
        detector = PiiDetector()
        matches = detector.detect("SSN: 123-45-6789")
        ssn_matches = [m for m in matches if m.pii_type == "ssn"]
        assert len(ssn_matches) == 1
        assert ssn_matches[0].masked == "XXX-XX-6789"

    def test_detect_email(self) -> None:
        detector = PiiDetector()
        matches = detector.detect("Contact: john.doe@example.com")
        email_matches = [m for m in matches if m.pii_type == "email"]
        assert len(email_matches) == 1
        assert "@example.com" in email_matches[0].masked
        assert "john.doe" not in email_matches[0].masked

    def test_detect_phone(self) -> None:
        detector = PiiDetector()
        matches = detector.detect("Call 555-123-4567 for info")
        phone_matches = [m for m in matches if m.pii_type == "phone"]
        assert len(phone_matches) == 1
        assert phone_matches[0].masked.endswith("4567")

    def test_no_pii(self) -> None:
        detector = PiiDetector()
        matches = detector.detect("This is a clean sentence.")
        assert len(matches) == 0


class TestPiiMasker:
    def test_mask_text(self) -> None:
        masker = PiiMasker()
        result = masker.mask_text("SSN is 123-45-6789")
        assert "123-45" not in result
        assert "6789" in result

    def test_mask_dict(self) -> None:
        masker = PiiMasker()
        data = {
            "name": "John Doe",
            "ssn": "123-45-6789",
            "nested": {"email": "john@example.com"},
        }
        result = masker.mask_dict(data)
        assert "123-45" not in result["ssn"]
        assert "john@" not in result["nested"]["email"]

    def test_mask_dict_preserves_non_strings(self) -> None:
        masker = PiiMasker()
        data = {"score": 750, "approved": True, "name": "test"}
        result = masker.mask_dict(data)
        assert result["score"] == 750
        assert result["approved"] is True

    def test_mask_no_pii(self) -> None:
        masker = PiiMasker()
        text = "No sensitive data here"
        assert masker.mask_text(text) == text

    def test_mask_list_values(self) -> None:
        masker = PiiMasker()
        data = {"items": ["123-45-6789", "clean text"]}
        result = masker.mask_dict(data)
        assert "123-45" not in result["items"][0]
        assert result["items"][1] == "clean text"
