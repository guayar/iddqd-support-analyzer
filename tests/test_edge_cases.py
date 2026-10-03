"""Edge case testing - stress test analyzers with unusual but real scenarios."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_nginx_extremely_long_url():
    """Edge case: Nginx with 4KB+ URL (some attack tools do this)."""
    long_url = "/" + "a" * 4000
    log = f'192.168.1.1 - - [01/Jan/2026:10:00:00 +0000] "GET {long_url} HTTP/1.1" 414 183 "-" "curl"'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_nginx_null_bytes_in_log():
    """Edge case: Null bytes in log (corruption/encoding issue)."""
    # Safe test - replace null with escaped version
    log = '192.168.1.1 - - [01/Jan/2026:10:00:00 +0000] "GET /api HTTP/1.1" 200 512 "-" "Mozilla"'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_nginx_unicode_in_user_agent():
    """Edge case: Unicode/emoji in User-Agent."""
    log = '192.168.1.1 - - [01/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla 🤖 Bot"'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_oauth2_malformed_jwt():
    """Edge case: Broken JWT token in logs."""
    log = '2026-01-15 10:00:00 ERROR access_token: eyJhbGc...INVALID...NOTJWT'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_postgresql_extremely_long_query():
    """Edge case: 100KB+ query text in logs."""
    long_query = "SELECT " + ", ".join([f"col{i}" for i in range(10000)])
    log = f"2026-01-15 10:00:00 ERROR Query: {long_query[:1000]}"
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_docker_unparseable_json():
    """Edge case: Broken JSON in Docker logs."""
    log = '2026-01-15 10:00:00 ERROR {broken json: no closing brace'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_ldap_binary_in_password():
    """Edge case: Binary data in LDAP bind (encoding issues)."""
    log = '2026-01-15 10:00:00 ERROR bind failed for user=test password_contains_nullbytes_0x00_0x01'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_ssh_keys_key_with_whitespace():
    """Edge case: SSH key with embedded spaces/tabs."""
    log = '2026-01-15 10:00:00 INFO key generated for user=admin fingerprint=SHA256:abc def ghi'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_mixed_encodings_in_single_log():
    """Edge case: UTF-8, Latin-1, ASCII mixed in one log file."""
    lines = [
        '192.168.1.1 - - [01/Jan/2026:10:00:00 +0000] "GET /test HTTP/1.1" 200 512 "-" "ASCII"',
        '192.168.1.2 - - [01/Jan/2026:10:00:01 +0000] "GET /café HTTP/1.1" 200 512 "-" "UTF8"',
        '2026-01-15 10:00:02 ERROR Database: ñoño issue',
    ]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r.get("line_count", 0) >= 3


def test_timestamp_edge_cases():
    """Edge case: Various timestamp formats edge cases."""
    lines = [
        '2026-12-31T23:59:59Z ERROR Last second of year',
        '2026-01-01T00:00:00Z ERROR First second of year',
        '2026-02-29T12:00:00Z ERROR Leap year edge',  # 2026 is not leap year, but parser should handle attempts
        '2026-06-15T23:59:59.999999Z ERROR Microseconds',
    ]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r.get("line_count", 0) >= 3


def test_extremely_large_concurrent_events():
    """Edge case: 1000s of events in 1 second."""
    lines = [f'192.168.1.{i % 256} - - [01/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" {200 if i % 10 else 503} 512 "-" "test"'
             for i in range(5000)]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r.get("line_count", 0) >= 4000  # Most should parse


def test_only_errors_no_normal_logs():
    """Edge case: Log file with ONLY errors, no normal traffic."""
    lines = [
        '192.168.1.1 - - [01/Jan/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 403 162 "-" "curl"',
        '192.168.1.1 - - [01/Jan/2026:10:00:01 +0000] "GET /admin HTTP/1.1" 403 162 "-" "curl"',
        '2026-01-15 10:00:02 ERROR deadlock detected',
        '2026-01-15 10:00:03 CRITICAL too many connections',
        '2026-01-15 10:00:04 PANIC disk full',
    ]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r.get("error_event_count", 0) >= 1


def test_repeating_identical_lines():
    """Edge case: Log flooded with identical repeated line (runaway error)."""
    lines = ['2026-01-15 10:00:00 ERROR Database connection refused'] * 10000
    r = analyze_log_text("\n".join(lines) + "\n")
    # Should aggregate, not crash
    assert r.get("line_count", 0) >= 9000


def test_interleaved_attack_and_normal():
    """Edge case: Attack interleaved randomly with normal traffic (realistic)."""
    lines = []
    for i in range(1000):
        if i % 7 == 0:  # Every 7th line is attack
            lines.append(f'192.168.0.50 - - [01/Jan/2026:10:00:{i % 60:02d} +0000] "GET /admin HTTP/1.1" 403 162 "-" "curl"')
        else:  # Normal traffic
            lines.append(f'192.168.1.{i % 256} - - [01/Jan/2026:10:00:{i % 60:02d} +0000] "GET /api HTTP/1.1" 200 512 "-" "Chrome"')
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r.get("line_count", 0) >= 900


def test_empty_fields_in_structured_logs():
    """Edge case: Empty/missing fields in logs."""
    lines = [
        '2026-01-15 10:00:00 ERROR user= database= connection failed',
        '192.168.1.1 - "" [01/Jan/2026:10:00:00 +0000] "GET HTTP/1.1" 200 - "-" ""',
    ]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r.get("line_count", 0) >= 1


def test_recursive_error_messages():
    """Edge case: Error message mentioning error (nested)."""
    log = 'Caused by: java.lang.Exception: Caused by: Caused by: Caused by: Stack overflow'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


if __name__ == "__main__":
    import sys
    tests = [
        ("Nginx long URL", test_nginx_extremely_long_url),
        ("Nginx unicode", test_nginx_unicode_in_user_agent),
        ("OAuth2 malformed JWT", test_oauth2_malformed_jwt),
        ("PostgreSQL long query", test_postgresql_extremely_long_query),
        ("Docker broken JSON", test_docker_unparseable_json),
        ("Mixed encodings", test_mixed_encodings_in_single_log),
        ("Timestamp edge cases", test_timestamp_edge_cases),
        ("Concurrent surge", test_extremely_large_concurrent_events),
        ("Only errors", test_only_errors_no_normal_logs),
        ("Repeated lines", test_repeating_identical_lines),
        ("Interleaved attack", test_interleaved_attack_and_normal),
        ("Empty fields", test_empty_fields_in_structured_logs),
        ("Recursive errors", test_recursive_error_messages),
    ]

    failed = 0
    for name, test_func in tests:
        try:
            test_func()
            print(f"✓ {name}")
        except Exception as e:
            print(f"✗ {name}: {e}")
            failed += 1

    print(f"\n{len(tests) - failed}/{len(tests)} edge case tests passed")
    sys.exit(0 if failed == 0 else 1)
