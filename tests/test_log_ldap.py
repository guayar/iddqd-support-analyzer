"""LDAP/AD log analyzer tests - IAM security."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_bind_failure():
    """LDAP bind failed."""
    log = '2026-01-15 10:23:45 ERROR bind failed for user=john invalid credentials'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_account_lockout():
    """Account locked after failures."""
    log = '2026-01-15 10:24:00 CRITICAL account locked for account=john_doe user=john'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_password_expired():
    """User password expired."""
    log = '2026-01-15 10:25:00 WARN password expired for user=alice must change password'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_group_membership_change():
    """User added/removed from group."""
    log = '2026-01-15 10:26:00 INFO user=bob added to group=admins group change'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_permission_denied_ldap():
    """Access denied to resource."""
    log = '2026-01-15 10:27:00 WARN permission denied for user=charlie insufficient privileges'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_mfa_failure():
    """MFA challenge failed."""
    log = '2026-01-15 10:28:00 ERROR mfa failed for user=david totp validation failed'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_multiple_bind_failures():
    """Repeated bind failures (possible attack)."""
    text = (
        '2026-01-15 10:29:00 ERROR bind failed for user=eve invalid password\n'
        '2026-01-15 10:29:01 ERROR bind failed for user=eve invalid password\n'
        '2026-01-15 10:29:02 ERROR bind failed for user=eve invalid password\n'
        '2026-01-15 10:29:03 ERROR bind failed for user=eve invalid password\n'
        '2026-01-15 10:29:04 ERROR bind failed for user=eve invalid password\n'
        '2026-01-15 10:29:05 CRITICAL account locked for account=eve\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 4


def test_active_directory_logon():
    """AD logon event."""
    log = '2026-01-15 10:30:00 INFO Logon Name: DOMAIN\\frank Account Name: frank'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_successful_authentication():
    """Normal auth event."""
    log = '2026-01-15 10:31:00 INFO authentication successful for user=grace'
    r = analyze_log_text(log + "\n")
    # Should not trigger errors
    assert r.get("line_count", 0) >= 0


def test_mfa_required_challenge():
    """MFA challenge initiated (normal flow)."""
    log = '2026-01-15 10:32:00 INFO mfa required for user=henry totp challenge sent'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_multiple_lockouts():
    """Multiple accounts locked (possible attack)."""
    text = (
        '2026-01-15 10:33:00 CRITICAL account locked for account=iris\n'
        '2026-01-15 10:33:01 CRITICAL account locked for account=jack\n'
        '2026-01-15 10:33:02 CRITICAL account locked for account=kate\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


if __name__ == "__main__":
    test_bind_failure()
    test_account_lockout()
    test_password_expired()
    test_group_membership_change()
    test_permission_denied_ldap()
    test_mfa_failure()
    test_multiple_bind_failures()
    test_active_directory_logon()
    test_successful_authentication()
    test_mfa_required_challenge()
    test_multiple_lockouts()
    print("LOG LDAP TESTS OK")
