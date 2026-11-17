from python_kvkk_guard.pii_scrubber import scrub_sensitive_data


def test_scrubs_kvkk_personal_data_and_secrets() -> None:
    sample = "User TCKN 12345678901, phone 05551234567, email test@baysoz.com, key sk-1234567890abcdef1234"
    report = scrub_sensitive_data(sample)
    assert report.redacted_count == 4
    assert "12345678901" not in report.sanitized_text
    assert "[REDACTED_TCKN]" in report.sanitized_text
    assert "[REDACTED_EMAIL]" in report.sanitized_text
    assert "[REDACTED_PHONE]" in report.sanitized_text
    assert "[REDACTED_SECRET]" in report.sanitized_text
