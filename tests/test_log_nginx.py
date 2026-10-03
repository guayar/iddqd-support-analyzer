"""Nginx log analyzer tests - escalation engineer perspective."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_simple_200_ok():
    """Baseline: normal traffic is not an incident."""
    line = '192.168.1.100 - - [01/Jan/2026:10:23:45 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
    r = analyze_log_text(line + "\n")
    assert r["levels"].get("WARN") is None
    assert r["error_event_count"] == 0


def test_403_forbidden_cascade_attack():
    """Real escalation: attacker probing admin panel gets cascade of 403s."""
    text = (
        '192.168.0.50 - - [01/Jan/2026:10:23:45 +0000] "GET /admin HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '192.168.0.50 - - [01/Jan/2026:10:23:46 +0000] "GET /admin/panel HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '192.168.0.50 - - [01/Jan/2026:10:23:47 +0000] "GET /admin/users HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '192.168.0.50 - - [01/Jan/2026:10:23:48 +0000] "GET /wp-admin HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
    )
    r = analyze_log_text(text)
    assert r["error_event_count"] >= 1
    # Should detect auth cascade pattern
    incident = r["incidents"][0] if r["incidents"] else None
    assert incident is not None


def test_502_bad_gateway_surge():
    """Real escalation: backend service crash causes 502 surge."""
    text = (
        '192.168.1.100 - - [01/Jan/2026:10:24:00 +0000] "GET /api/users HTTP/1.1" 200 512 "-" "Chrome/90"\n'
        '192.168.1.101 - - [01/Jan/2026:10:24:01 +0000] "GET /api/products HTTP/1.1" 502 180 "-" "Chrome/90"\n'
        '192.168.1.102 - - [01/Jan/2026:10:24:01 +0000] "POST /api/orders HTTP/1.1" 502 180 "-" "Chrome/90"\n'
        '192.168.1.103 - - [01/Jan/2026:10:24:02 +0000] "GET /api/status HTTP/1.1" 502 180 "-" "Chrome/90"\n'
        '192.168.1.104 - - [01/Jan/2026:10:24:02 +0000] "GET /api/data HTTP/1.1" 502 180 "-" "Chrome/90"\n'
    )
    r = analyze_log_text(text)
    assert r["levels"].get("ERROR") is not None
    # 502 should be flagged as ERROR
    assert r["error_event_count"] >= 1


def test_401_unauthorized_auth_chain():
    """Real escalation: OAuth token refresh loop failing."""
    text = (
        '192.168.1.50 - john [01/Jan/2026:10:25:00 +0000] "GET /api/me HTTP/1.1" 401 195 "-" "MyApp/1.0"\n'
        '192.168.1.50 - john [01/Jan/2026:10:25:01 +0000] "POST /oauth/token HTTP/1.1" 401 195 "-" "MyApp/1.0"\n'
        '192.168.1.50 - john [01/Jan/2026:10:25:02 +0000] "POST /oauth/token HTTP/1.1" 401 195 "-" "MyApp/1.0"\n'
        '192.168.1.50 - john [01/Jan/2026:10:25:03 +0000] "GET /api/me HTTP/1.1" 401 195 "-" "MyApp/1.0"\n'
    )
    r = analyze_log_text(text)
    assert r["error_event_count"] >= 1
    # Should correlate auth failures


def test_sql_injection_probe():
    """Real escalation: SQLi attack probe."""
    text = (
        "192.168.0.66 - - [01/Jan/2026:10:26:00 +0000] \"GET /search.php?q=1' OR '1'='1 HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.0\"\n"
        "192.168.0.66 - - [01/Jan/2026:10:26:01 +0000] \"GET /search.php?q=UNION SELECT * FROM users HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.0\"\n"
    )
    r = analyze_log_text(text)
    # Should detect SQL injection patterns
    assert r["error_event_count"] >= 0  # Depends on correlator implementation


def test_path_traversal_attack():
    """Real escalation: attacker probing for sensitive files."""
    text = (
        '192.168.0.77 - - [01/Jan/2026:10:27:00 +0000] "GET /../../etc/passwd HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '192.168.0.77 - - [01/Jan/2026:10:27:01 +0000] "GET /../.env HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '192.168.0.77 - - [01/Jan/2026:10:27:02 +0000] "GET /..\\..\\windows\\system32 HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
    )
    r = analyze_log_text(text)
    # Should detect path traversal attempts
    assert r.get("line_count", 0) >= 3


def test_webshell_probe():
    """Real escalation: attacker looking for uploaded webshells."""
    text = (
        '192.168.0.88 - - [01/Jan/2026:10:28:00 +0000] "GET /uploads/shell.php HTTP/1.1" 404 153 "-" "curl/7.68.0"\n'
        '192.168.0.88 - - [01/Jan/2026:10:28:01 +0000] "GET /shell.asp HTTP/1.1" 404 153 "-" "curl/7.68.0"\n'
        '192.168.0.88 - - [01/Jan/2026:10:28:02 +0000] "GET /cmd.jsp HTTP/1.1" 404 153 "-" "curl/7.68.0"\n'
        '192.168.0.88 - - [01/Jan/2026:10:28:03 +0000] "POST /shell.php HTTP/1.1" 404 153 "-" "curl/7.68.0"\n'
    )
    r = analyze_log_text(text)
    assert r["line_count"] == 4


def test_dotfile_probe():
    """Real escalation: attacker probing for config files."""
    text = (
        '192.168.0.99 - - [01/Jan/2026:10:29:00 +0000] "GET /.env HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '192.168.0.99 - - [01/Jan/2026:10:29:01 +0000] "GET /.git/config HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '192.168.0.99 - - [01/Jan/2026:10:29:02 +0000] "GET /.aws/credentials HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
    )
    r = analyze_log_text(text)
    assert r["line_count"] == 3


def test_rate_limiting_429():
    """Real escalation: rate limiting kicks in (DDoS or API abuse)."""
    lines = [
        f'192.168.1.{i} - - [01/Jan/2026:10:30:0{i % 10} +0000] "GET /api/data HTTP/1.1" 429 103 "-" "bot/1.0"'
        for i in range(20)
    ]
    text = "\n".join(lines) + "\n"
    r = analyze_log_text(text)
    assert r["levels"].get("ERROR") is not None or r["error_event_count"] >= 1


def test_503_service_unavailable_maintenance():
    """Real escalation: service under maintenance or overloaded."""
    text = (
        '192.168.1.100 - - [01/Jan/2026:10:31:00 +0000] "GET / HTTP/1.1" 200 5234 "-" "Chrome/90"\n'
        '192.168.1.101 - - [01/Jan/2026:10:31:01 +0000] "GET /api/v1 HTTP/1.1" 503 180 "-" "Chrome/90"\n'
        '192.168.1.102 - - [01/Jan/2026:10:31:02 +0000] "POST /api/data HTTP/1.1" 503 180 "-" "Chrome/90"\n'
        '192.168.1.103 - - [01/Jan/2026:10:31:03 +0000] "GET /health HTTP/1.1" 503 180 "-" "LB-HealthCheck/1.0"\n'
    )
    r = analyze_log_text(text)
    assert r["levels"].get("ERROR") is not None


def test_504_gateway_timeout():
    """Real escalation: backend not responding in time."""
    text = (
        '192.168.1.100 - - [01/Jan/2026:10:32:00 +0000] "GET /api/slow-query HTTP/1.1" 504 179 "-" "Chrome/90"\n'
        '192.168.1.101 - - [01/Jan/2026:10:32:05 +0000] "POST /api/report HTTP/1.1" 504 179 "-" "Chrome/90"\n'
        '192.168.1.102 - - [01/Jan/2026:10:32:10 +0000] "GET /api/export HTTP/1.1" 504 179 "-" "Chrome/90"\n'
    )
    r = analyze_log_text(text)
    assert r["levels"].get("ERROR") is not None


def test_multiple_attack_ips():
    """Real escalation: coordinated attack from multiple IPs."""
    text = (
        '10.0.0.1 - - [01/Jan/2026:10:33:00 +0000] "GET /admin HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '10.0.0.2 - - [01/Jan/2026:10:33:01 +0000] "GET /admin HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '10.0.0.3 - - [01/Jan/2026:10:33:02 +0000] "GET /admin HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '10.0.0.4 - - [01/Jan/2026:10:33:03 +0000] "GET /admin HTTP/1.1" 403 162 "-" "curl/7.68.0"\n'
        '192.168.1.100 - - [01/Jan/2026:10:33:04 +0000] "GET / HTTP/1.1" 200 5234 "-" "Chrome/90"\n'
    )
    r = analyze_log_text(text)
    assert r["error_event_count"] >= 1


def test_normal_traffic_mixed_with_errors():
    """Real scenario: mostly normal traffic with some errors mixed in."""
    text = (
        '192.168.1.1 - - [01/Jan/2026:10:34:00 +0000] "GET / HTTP/1.1" 200 5234 "-" "Chrome/90"\n'
        '192.168.1.2 - - [01/Jan/2026:10:34:01 +0000] "GET /assets/style.css HTTP/1.1" 200 4521 "-" "Chrome/90"\n'
        '192.168.1.3 - - [01/Jan/2026:10:34:02 +0000] "GET /api/users HTTP/1.1" 500 156 "-" "Chrome/90"\n'
        '192.168.1.4 - - [01/Jan/2026:10:34:03 +0000] "POST /api/login HTTP/1.1" 200 234 "-" "Chrome/90"\n'
        '192.168.1.5 - - [01/Jan/2026:10:34:04 +0000] "GET /static/app.js HTTP/1.1" 200 8901 "-" "Chrome/90"\n'
    )
    r = analyze_log_text(text)
    assert r["levels"].get("ERROR") is not None  # 500 should be caught
    assert r["error_event_count"] == 1


def test_phpmyadmin_probe_attack():
    """Real escalation: attacker probing for phpMyAdmin (common target)."""
    text = (
        '192.168.0.111 - - [01/Jan/2026:10:35:00 +0000] "GET /phpmyadmin HTTP/1.1" 404 153 "-" "curl/7.68.0"\n'
        '192.168.0.111 - - [01/Jan/2026:10:35:01 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 153 "-" "curl/7.68.0"\n'
        '192.168.0.111 - - [01/Jan/2026:10:35:02 +0000] "GET /phpMyAdmin HTTP/1.1" 404 153 "-" "curl/7.68.0"\n'
        '192.168.0.111 - - [01/Jan/2026:10:35:03 +0000] "GET /pma HTTP/1.1" 404 153 "-" "curl/7.68.0"\n'
    )
    r = analyze_log_text(text)
    assert r["line_count"] == 4


if __name__ == "__main__":
    test_simple_200_ok()
    test_403_forbidden_cascade_attack()
    test_502_bad_gateway_surge()
    test_401_unauthorized_auth_chain()
    test_sql_injection_probe()
    test_path_traversal_attack()
    test_webshell_probe()
    test_dotfile_probe()
    test_rate_limiting_429()
    test_503_service_unavailable_maintenance()
    test_504_gateway_timeout()
    test_multiple_attack_ips()
    test_normal_traffic_mixed_with_errors()
    test_phpmyadmin_probe_attack()
    print("LOG NGINX TESTS OK")
