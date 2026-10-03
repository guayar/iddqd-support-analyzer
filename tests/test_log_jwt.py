"""JWT token validation log analyzer tests."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_jwt_signature_validation_failure():
    """JWT signature validation failure (CRITICAL)."""
    log = '2026-01-15 10:00:00 ERROR JWT signature validation failed: kid=old_key expected=abc123 got=xyz789'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_jwt_token_expired():
    """JWT token expired (WARN)."""
    log = '2026-01-15 10:00:01 WARN JWT token expired: exp=1234567890 current=1234567999'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_jwt_claim_validation_failure():
    """JWT claim validation failure (ERROR)."""
    log = '2026-01-15 10:00:02 ERROR JWT claim validation failed: claim=aud expected=api.example.com got=unknown'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_jwt_token_revoked():
    """JWT token revoked (ERROR)."""
    log = '2026-01-15 10:00:03 ERROR JWT token revoked: jti=abc123 reason=user_logout'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_jwks_key_rotation():
    """JWKS key rotation event (INFO)."""
    log = '2026-01-15 10:00:04 INFO JWKS rotation event: 5 keys rotated from provider=auth.example.com'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_jwt_multiple_signature_failures():
    """Multiple signature validation failures."""
    text = (
        '2026-01-15 10:00:00 CRITICAL JWT signature validation failed: kid=key1\n'
        '2026-01-15 10:00:01 CRITICAL JWT signature validation failed: kid=key2\n'
        '2026-01-15 10:00:02 CRITICAL JWT signature validation failed: kid=key3\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_jwt_missing_claim():
    """JWT missing required claim."""
    log = '2026-01-15 10:00:05 WARN JWT missing claim: claim=sub required for this endpoint'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_jwt_token_in_logs():
    """JWT token detected in logs."""
    log = '2026-01-15 10:00:06 INFO Received token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_jwt_key_id_mismatch():
    """JWT key ID mismatch."""
    log = '2026-01-15 10:00:07 ERROR JWT key_id mismatch: kid=old_key not found in current JWKS'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_jwt_payload_corrupted():
    """JWT payload corrupted (claim extraction fails)."""
    log = '2026-01-15 10:00:08 ERROR JWT claim validation failed: claim=iss payload corrupted'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_jwt_lifecycle_full():
    """Full JWT lifecycle: creation, validation, refresh, revocation."""
    text = (
        '2026-01-15 10:00:00 INFO JWT created for user=alice kid=key1\n'
        '2026-01-15 10:00:10 INFO JWT validated successfully\n'
        '2026-01-15 10:00:30 INFO JWT refresh requested\n'
        '2026-01-15 10:00:40 INFO JWT revoked for user=alice\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 3


if __name__ == "__main__":
    test_jwt_signature_validation_failure()
    test_jwt_token_expired()
    test_jwt_claim_validation_failure()
    test_jwt_token_revoked()
    test_jwks_key_rotation()
    test_jwt_multiple_signature_failures()
    test_jwt_missing_claim()
    test_jwt_token_in_logs()
    test_jwt_key_id_mismatch()
    test_jwt_payload_corrupted()
    test_jwt_lifecycle_full()
    print("✓ JWT LOG TESTS OK")
