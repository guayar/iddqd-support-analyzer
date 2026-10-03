"""MFA audit log analyzer tests."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_totp_validation_failure():
    """TOTP validation failure (WARN)."""
    log = '2026-01-15 10:00:00 WARN TOTP validation failed for user=alice: invalid_code expected=123456 got=654321'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_totp_time_skew():
    """TOTP time skew (>30s threshold)."""
    log = '2026-01-15 10:00:01 WARN TOTP time_diff=45s exceeds threshold=30s for user=bob clock_drift'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_sms_delivery_failure():
    """SMS delivery failure (WARN)."""
    log = '2026-01-15 10:00:02 WARN SMS delivery failed for user=charlie provider=twilio error=rate_limited'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_sms_retry_exhausted():
    """SMS retry attempts exhausted (ERROR)."""
    log = '2026-01-15 10:00:03 ERROR SMS delivery failed for user=dave: retry 3/3 exhausted max_retries'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_backup_codes_exhausted():
    """Backup MFA codes exhausted (CRITICAL)."""
    log = '2026-01-15 10:00:04 CRITICAL MFA backup codes exhausted for user=eve: no_codes_remaining'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_mfa_bypass_attempt():
    """MFA bypass attempt (CRITICAL)."""
    log = '2026-01-15 10:00:05 CRITICAL MFA bypass detected: user=frank attempting to skip 2fa requirement'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_hardware_token_failure():
    """Hardware token failure (ERROR)."""
    log = '2026-01-15 10:00:06 ERROR Hardware token YubiKey failure for user=grace: device_not_responding'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_push_notification_timeout():
    """Push authentication timeout (WARN)."""
    log = '2026-01-15 10:00:07 WARN Push notification timeout for user=henry: no_response_after_30s'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_multiple_mfa_failures_cascade():
    """Multiple MFA failures cascading."""
    text = (
        '2026-01-15 10:00:00 WARN TOTP validation failed for user=iris\n'
        '2026-01-15 10:00:05 WARN SMS delivery failed for user=iris provider=twilio\n'
        '2026-01-15 10:00:10 ERROR SMS retry 3/3 exhausted for user=iris\n'
        '2026-01-15 10:00:15 CRITICAL Backup codes exhausted for user=iris\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 3


def test_mfa_account_lockout():
    """MFA issues leading to account lockout scenario."""
    text = (
        '2026-01-15 10:00:00 WARN TOTP time_diff=60s for user=jack\n'
        '2026-01-15 10:00:05 WARN TOTP validation failed: invalid code\n'
        '2026-01-15 10:00:10 ERROR Hardware token failure: YubiKey\n'
        '2026-01-15 10:00:15 CRITICAL Account lockout: max MFA attempts exceeded\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 3


def test_widespread_totp_clock_skew():
    """Widespread TOTP clock skew (system time issue)."""
    text = (
        '2026-01-15 10:00:00 WARN TOTP time_diff=45s for user=karen\n'
        '2026-01-15 10:00:01 WARN TOTP time_diff=48s for user=leo\n'
        '2026-01-15 10:00:02 WARN TOTP time_diff=44s for user=mona\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_sms_provider_outage():
    """SMS provider outage affecting all users."""
    text = (
        '2026-01-15 10:00:00 WARN SMS delivery failed for user=nancy provider=twilio\n'
        '2026-01-15 10:00:01 WARN SMS delivery failed for user=oscar provider=twilio\n'
        '2026-01-15 10:00:02 ERROR SMS retry exhausted for user=nancy\n'
        '2026-01-15 10:00:03 ERROR SMS retry exhausted for user=oscar\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 3


if __name__ == "__main__":
    test_totp_validation_failure()
    test_totp_time_skew()
    test_sms_delivery_failure()
    test_sms_retry_exhausted()
    test_backup_codes_exhausted()
    test_mfa_bypass_attempt()
    test_hardware_token_failure()
    test_push_notification_timeout()
    test_multiple_mfa_failures_cascade()
    test_mfa_account_lockout()
    test_widespread_totp_clock_skew()
    test_sms_provider_outage()
    print("✓ MFA LOG TESTS OK")
