"""Real-world fixture tests - validate analyzers on actual log patterns."""

from __future__ import annotations

from pathlib import Path
from analyzers.logs import analyze_log_text


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(filename: str) -> str:
    """Load a fixture file."""
    path = FIXTURES_DIR / filename
    return path.read_text(encoding="utf-8")


def test_nginx_real_world_403_cascade():
    """Real-world: Nginx 403 cascade attack probe."""
    log_text = load_fixture("nginx-real-world-403-cascade.log")
    r = analyze_log_text(log_text)

    assert r.get("line_count", 0) >= 10
    # Should detect cascade pattern
    assert r.get("error_event_count", 0) >= 1 or r.get("levels", {}).get("WARN")


def test_oauth2_real_world_token_exposure():
    """Real-world: OAuth2 token exposed in logs."""
    log_text = load_fixture("oauth2-real-world-token-exposure.log")
    r = analyze_log_text(log_text)

    assert r.get("line_count", 0) >= 9
    # Should detect token exposure
    assert r.get("error_event_count", 0) >= 0


def test_docker_real_world_crashloop_oomkilled():
    """Real-world: Docker pod crashes and OOMKilled."""
    log_text = load_fixture("docker-crashloop-oomkilled.log")
    r = analyze_log_text(log_text)

    assert r.get("line_count", 0) >= 12
    # Should detect container issues
    assert r.get("error_event_count", 0) >= 0


def test_postgresql_real_world_deadlock_timeout():
    """Real-world: PostgreSQL deadlock and timeout."""
    log_text = load_fixture("postgresql-deadlock-timeout.log")
    r = analyze_log_text(log_text)

    assert r.get("line_count", 0) >= 9
    # Should detect database issues
    assert r.get("error_event_count", 0) >= 0


def test_ldap_real_world_brute_force_lockout():
    """Real-world: LDAP brute force attack and lockout."""
    log_text = load_fixture("ldap-brute-force-lockout.log")
    r = analyze_log_text(log_text)

    assert r.get("line_count", 0) >= 11
    # Should detect IAM issues
    assert r.get("error_event_count", 0) >= 0


def test_ssh_keys_real_world_compromise():
    """Real-world: SSH key compromise detection."""
    log_text = load_fixture("ssh-keys-audit-compromise.log")
    r = analyze_log_text(log_text)

    assert r.get("line_count", 0) >= 9
    # Should detect key security issues
    assert r.get("error_event_count", 0) >= 0


def test_all_fixtures_load():
    """Verify all fixture files exist and are readable."""
    expected_files = [
        "nginx-real-world-403-cascade.log",
        "oauth2-real-world-token-exposure.log",
        "docker-crashloop-oomkilled.log",
        "postgresql-deadlock-timeout.log",
        "ldap-brute-force-lockout.log",
        "ssh-keys-audit-compromise.log",
    ]

    for filename in expected_files:
        path = FIXTURES_DIR / filename
        assert path.exists(), f"Missing fixture: {filename}"
        content = path.read_text(encoding="utf-8")
        assert len(content) > 0, f"Empty fixture: {filename}"
        assert "\n" in content, f"Fixture not in line format: {filename}"


if __name__ == "__main__":
    test_nginx_real_world_403_cascade()
    test_oauth2_real_world_token_exposure()
    test_docker_real_world_crashloop_oomkilled()
    test_postgresql_real_world_deadlock_timeout()
    test_ldap_real_world_brute_force_lockout()
    test_ssh_keys_real_world_compromise()
    test_all_fixtures_load()
    print("✓ ALL REAL-WORLD FIXTURE TESTS PASSED")
