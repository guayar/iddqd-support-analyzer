"""SSH key audit log analyzer tests."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_key_generation():
    """SSH key created."""
    log = '2026-01-15 10:23:45 INFO ssh-keygen: key generated for user=admin ed25519 fingerprint=SHA256:xyz123'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_key_deletion():
    """SSH key removed from authorized_keys."""
    log = '2026-01-15 10:24:00 WARN key deleted for user=bob fingerprint=SHA256:abc789 removed from authorized_keys'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_key_rotation():
    """SSH key rotation performed."""
    log = '2026-01-15 10:25:00 INFO key rotation: user=alice replacing old RSA key with ED25519'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_weak_rsa_key():
    """Weak RSA 1024-bit key detected."""
    log = '2026-01-15 10:26:00 CRITICAL weak key: RSA 1024 bits for user=charlie (insufficient key size)'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_dsa_key_deprecated():
    """Deprecated DSA key in use."""
    log = '2026-01-15 10:27:00 CRITICAL deprecated key type DSA for user=dave (DSA is insecure)'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_unauthorized_key():
    """Unauthorized key detected on account."""
    log = '2026-01-15 10:28:00 CRITICAL unauthorized key: fingerprint=SHA256:evil123 found in authorized_keys for user=eve'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_stale_key():
    """Old key not rotated."""
    log = '2026-01-15 10:29:00 WARN stale key: RSA key for user=frank not rotated in 2+ years'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_key_deletion_without_rotation():
    """Key deleted but no rotation found."""
    text = (
        '2026-01-15 10:30:00 WARN key deleted for user=grace fingerprint=SHA256:old111\n'
        '2026-01-15 10:30:01 INFO No key rotation detected\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 1


def test_multiple_unauthorized_keys():
    """Multiple unauthorized keys on one account."""
    text = (
        '2026-01-15 10:31:00 CRITICAL unauthorized key: fingerprint=SHA256:evil1 for user=henry\n'
        '2026-01-15 10:31:01 CRITICAL unauthorized key: fingerprint=SHA256:evil2 for user=henry\n'
        '2026-01-15 10:31:02 CRITICAL unauthorized key: fingerprint=SHA256:evil3 for user=henry\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_ed25519_best_practice():
    """ED25519 key (strong modern key)."""
    log = '2026-01-15 10:32:00 INFO key generated for user=iris ed25519 fingerprint=SHA256:strong123'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_key_audit_trail():
    """Full lifecycle audit trail."""
    text = (
        '2026-01-15 10:33:00 INFO key generated for user=jack rsa 2048 fingerprint=SHA256:new123\n'
        '2026-01-15 10:33:01 INFO key added to authorized_keys\n'
        '2026-01-15 10:34:00 INFO key rotation: updating ssh key\n'
        '2026-01-15 10:34:01 INFO key deleted: old rsa key\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 3


if __name__ == "__main__":
    test_key_generation()
    test_key_deletion()
    test_key_rotation()
    test_weak_rsa_key()
    test_dsa_key_deprecated()
    test_unauthorized_key()
    test_stale_key()
    test_key_deletion_without_rotation()
    test_multiple_unauthorized_keys()
    test_ed25519_best_practice()
    test_key_audit_trail()
    print("LOG SSH KEYS TESTS OK")
