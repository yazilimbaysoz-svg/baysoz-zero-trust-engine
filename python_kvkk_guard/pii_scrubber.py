"""
BAYSOZ YAZILIM - KVKK (Law No. 6698) & GDPR Automated PII Scrubbing Middleware
Department: 09-LEGAL-COMP
Standard: 2026-2027 Enterprise Production Grade
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

TCKN_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[1-9][0-9]{10}\b")
EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
TR_PHONE_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:\+90|0)?5[0-9]{9}\b")
API_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:sk-|ghp_|AIza)[A-Za-z0-9_-]{16,}\b")


@dataclass(frozen=True, slots=True)
class ScrubReport:
    sanitized_text: str
    redacted_count: int


def scrub_sensitive_data(raw_text: str) -> ScrubReport:
    count = 0
    text = raw_text

    for pattern, token in (
        (TCKN_PATTERN, "[REDACTED_TCKN]"),
        (EMAIL_PATTERN, "[REDACTED_EMAIL]"),
        (TR_PHONE_PATTERN, "[REDACTED_PHONE]"),
        (API_KEY_PATTERN, "[REDACTED_SECRET]"),
    ):
        text, n = pattern.subn(token, text)
        count += n

    return ScrubReport(sanitized_text=text, redacted_count=count)
