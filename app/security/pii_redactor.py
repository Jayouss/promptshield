"""High-Speed PII (Personally Identifiable Information) Redaction Engine"""

import re
from typing import Dict, Any, Tuple, List


class PIIRedactor:
    def __init__(self):
        # Pre-compiled high-performance regular expressions
        self.patterns = {
            "EMAIL": (
                re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE),
                "[REDACTED_EMAIL]"
            ),
            "CREDIT_CARD": (
                re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b'),
                "[REDACTED_CREDIT_CARD]"
            ),
            "API_SECRET": (
                re.compile(r'\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|whsec_[A-Za-z0-9]{20,}|[A-Za-z0-9_\-]{32,64})\b'),
                "[REDACTED_SECRET]"
            ),
            "PHONE_NUMBER": (
                re.compile(r'(?:\+?62|08)[0-9]{8,12}\b|\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
                "[REDACTED_PHONE]"
            ),
            "NATIONAL_ID": (
                re.compile(r'\b\d{16}\b|\b\d{3}-\d{2}-\d{4}\b'),  # 16-digit NIK or SSN
                "[REDACTED_NATIONAL_ID]"
            ),
            "IPV4_ADDRESS": (
                re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
                "[REDACTED_IP]"
            )
        }

    def redact(self, text: str) -> Tuple[str, Dict[str, Any]]:
        """Scan text and redact sensitive entities with placeholder tokens."""
        if not text:
            return "", {"total_redactions": 0, "entities": {}}

        redacted_text = text
        entity_counts: Dict[str, int] = {}
        total_redactions = 0

        for entity_type, (regex, placeholder) in self.patterns.items():
            matches = regex.findall(redacted_text)
            if matches:
                count = len(matches)
                entity_counts[entity_type] = count
                total_redactions += count
                redacted_text = regex.sub(placeholder, redacted_text)

        summary = {
            "total_redactions": total_redactions,
            "has_pii": total_redactions > 0,
            "entities": entity_counts
        }

        return redacted_text, summary


pii_redactor = PIIRedactor()
