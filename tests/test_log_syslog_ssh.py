from __future__ import annotations

from analyzers.log_ssh import (
    BRUTE_FORCE_GAP_SECONDS,
    BRUTE_FORCE_RAPID_WINDOW_SECONDS,
    ssh_rule,
)
from analyzers.logs import (
    INCIDENT_RESULT_CAP,
    _parse_ts,
    analyze_log_text,
    colon_severity,
    syslog_stamp,
)
from reporting import INCIDENT_REPORT_DETAIL_CAP, _severity_icon, render_log_report


def _failed_password(pid: int, ip: str, stamp: str) -> str:
    return f"{stamp} box sshd[{pid}]: Failed password for root from {ip} port 22 ssh2"


def test_rfc3164_two_digit_day():
    line = "Dec 24 06:55:46 box sshd[100]: Failed password for root from 10.1.2.3 port 22 ssh2"
    assert syslog_stamp(line) == "Dec 24 06:55:46"
    assert _parse_ts(line) is None


def test_rfc3164_one_digit_day_extra_whitespace():
    line = "Dec  4 06:55:46 box sshd[100]: Failed password for root from 10.1.2.3 port 22 ssh2"
    assert syslog_stamp(line) == "Dec  4 06:55:46"
    assert _parse_ts(line) is None


def test_timestamp_range_extraction():
    text = (
        "Dec  4 06:55:46 box sshd[10]: Failed password for root from 10.1.2.3 port 1 ssh2\n"
        "Dec 24 11:04:45 box sshd[11]: Failed password for root from 10.1.2.3 port 2 ssh2\n"
    )
    r = analyze_log_text(text)
    assert r["time_range"]["from"] == "Dec  4 06:55:46"
    assert r["time_range"]["to"] == "Dec 24 11:04:45"
    assert r["time_range"]["year_present"] is False


def test_lowercase_error_colon():
    line = "Dec 24 07:51:15 box sshd[20]: error: Received disconnect from 10.9.8.7: 3: Auth fail [preauth]"
    assert colon_severity(line) == "ERROR"
    r = analyze_log_text(line + "\n")
    assert r["levels"].get("ERROR", 0) >= 1


def test_lowercase_fatal_colon_does_not_create_critical_incident():
    line = "Dec 24 11:03:53 box sshd[21]: fatal: Write failed: Connection reset by peer [preauth]"
    assert colon_severity(line) == "FATAL"
    r = analyze_log_text(line + "\n")
    assert r["levels"].get("FATAL", 0) == 1
    assert r["levels"].get("CRITICAL", 0) == 0
    sessions = [g for g in r["incidents"] if g.get("kind") == "ssh_session"]
    assert sessions
    assert all(g["level"] != "CRITICAL" for g in r["incidents"])
    assert sessions[0]["level"] == "ERROR"
    findings = [f for f in r["line_findings"] if f["source_level"] == "FATAL"]
    assert len(findings) == 1
    assert findings[0]["line"] == 1
    assert findings[0]["kind"] == "explicit_source_marker"
    assert findings[0]["component"] == "sshd[21]"
    md = render_log_report(r)
    assert "🛑 **FATAL:** 1" in md
    assert "❌ **FATAL:**" not in md
    assert "## Notable line findings" in md
    assert md.index("## Notable line findings") < md.index("## Correlated incidents")
    assert "- **Line:** 1" in md
    assert "<summary>Relevant log</summary>" in md
    assert "fatal: Write failed: Connection reset by peer [preauth]" in md
    assert _severity_icon("FATAL") != _severity_icon("ERROR")
    assert _severity_icon("FATAL") == "🛑"
    assert _severity_icon("ERROR") == "❌"


def test_failed_password_semantic():
    line = "Dec 24 06:55:48 box sshd[30]: Failed password for invalid user webmaster from 10.4.5.6 port 38926 ssh2"
    rule = ssh_rule(line)
    assert rule is not None and rule[2] == "failed_password"
    r = analyze_log_text(line + "\n")
    assert r["levels"].get("WARN", 0) >= 1
    assert r["error_event_count"] >= 1
    assert not any(f["source_level"] == "WARN" for f in r.get("line_findings") or [])
    md = render_log_report(r)
    assert "Explicit WARN source marker" not in md
    assert "## Notable line findings" not in md


def test_authentication_failure_semantic():
    line = (
        "Dec 24 06:55:46 box sshd[31]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=10.4.5.6"
    )
    rule = ssh_rule(line)
    assert rule is not None and rule[2] == "auth_failure"
    r = analyze_log_text(line + "\n")
    assert any("authentication" in (g["signature"] or "").lower() for g in r["incidents"])


def test_reverse_dns_mismatch_alone_is_warn():
    line = (
        "Dec 24 06:55:46 box sshd[32]: reverse mapping checking getaddrinfo for ns.example.com "
        "[10.4.5.6] failed - POSSIBLE BREAK-IN ATTEMPT!"
    )
    rule = ssh_rule(line)
    assert rule is not None and rule[2] == "reverse_dns_mismatch" and rule[0] == "WARN"
    r = analyze_log_text(line + "\n")
    assert r["levels"].get("WARN", 0) >= 1
    assert r["levels"].get("CRITICAL", 0) == 0
    sessions = [g for g in r["incidents"] if g.get("kind") == "ssh_session"]
    assert len(sessions) == 1
    assert sessions[0]["level"] == "WARN"
    assert "POSSIBLE BREAK-IN ATTEMPT" in sessions[0]["sample"]


def test_too_many_authentication_failures():
    line = "Dec 24 07:13:56 box sshd[33]: Disconnecting: Too many authentication failures for root [preauth]"
    rule = ssh_rule(line)
    assert rule is not None and rule[2] == "too_many_failures"
    r = analyze_log_text(line + "\n")
    assert any(g["level"] == "ERROR" for g in r["incidents"])


def test_connection_closed_alone_is_not_an_incident():
    line = "Dec 24 07:02:47 box sshd[34]: Connection closed by 10.8.8.8 [preauth]"
    assert ssh_rule(line) is None
    r = analyze_log_text(line + "\n")
    assert r["error_event_count"] == 0
    assert r["incidents"] == []
    assert r["incident_unique_count"] == 0
    assert "ERROR" not in r["levels"]
    assert "WARN" not in r["levels"]


def test_year_not_fabricated_when_absent():
    text = "Dec 24 06:55:46 box sshd[40]: Failed password for root from 10.0.0.9 port 1 ssh2\n"
    r = analyze_log_text(text)
    assert r["time_range"]["year_present"] is False
    blob = (r["time_range"]["from"] or "") + (r["time_range"]["to"] or "")
    assert "202" not in blob
    assert "2000" not in blob
    md_from_iso = r["time_range"]["from"]
    assert not md_from_iso.startswith("20")


def test_iso_formats_still_fill_calendar_range():
    text = "2026-09-01 14:04:46 ERROR boom\n"
    r = analyze_log_text(text)
    assert r["time_range"]["from"].startswith("2026-09-01T14:04:46")
    assert r["time_range"]["year_present"] is True
    assert r["error_event_count"] == 1
    assert r["levels"]["ERROR"] == 1


def test_pid_reverse_dns_plus_failed_auth_is_error_session():
    text = """Dec 24 06:55:46 box sshd[24200]: reverse mapping checking getaddrinfo for ns.example.net [203.0.113.10] failed - POSSIBLE BREAK-IN ATTEMPT!
Dec 24 06:55:46 box sshd[24200]: Invalid user webmaster from 203.0.113.10
Dec 24 06:55:46 box sshd[24200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10
Dec 24 06:55:48 box sshd[24200]: Failed password for invalid user webmaster from 203.0.113.10 port 38926 ssh2
Dec 24 06:55:48 box sshd[24200]: Connection closed by 203.0.113.10 [preauth]
"""
    r = analyze_log_text(text)
    sessions = [g for g in r["incidents"] if g.get("kind") == "ssh_session"]
    assert len(sessions) == 1
    assert sessions[0]["level"] == "ERROR"
    assert all(g["level"] != "CRITICAL" for g in r["incidents"])
    assert r["levels"].get("CRITICAL", 0) == 0
    assert "203.0.113.10" in sessions[0]["signature"]
    assert "webmaster" in sessions[0]["sample"]
    assert r["error_event_count"] == 1


def test_five_slow_attempts_are_suspected_warn():
    ip = "198.51.100.7"
    stamps = [
        "Dec 24 07:00:00",
        "Dec 24 07:03:00",
        "Dec 24 07:06:00",
        "Dec 24 07:09:00",
        "Dec 24 07:12:00",
    ]
    lines = [_failed_password(50 + i, ip, stamp) for i, stamp in enumerate(stamps)]
    r = analyze_log_text("\n".join(lines) + "\n")
    brute = [g for g in r["incidents"] if g.get("kind") == "brute_force"]
    assert len(brute) == 1
    assert brute[0]["count"] == 5
    assert brute[0]["level"] == "WARN"
    assert brute[0]["signature"].startswith("Suspected SSH brute-force")


def test_five_rapid_attempts_are_brute_force_error():
    ip = "198.51.100.8"
    lines = [_failed_password(60 + i, ip, f"Dec 24 07:28:0{i}") for i in range(5)]
    r = analyze_log_text("\n".join(lines) + "\n")
    brute = [g for g in r["incidents"] if g.get("kind") == "brute_force"]
    assert len(brute) == 1
    assert brute[0]["count"] == 5
    assert brute[0]["level"] == "ERROR"
    assert brute[0]["signature"].startswith("SSH brute-force")


def test_rapid_window_boundary():
    ip = "198.51.100.9"
    at_window = [
        "Dec 24 07:28:00",
        "Dec 24 07:28:15",
        "Dec 24 07:28:30",
        "Dec 24 07:28:45",
        "Dec 24 07:29:00",
    ]
    past_window = at_window[:-1] + ["Dec 24 07:29:01"]
    assert BRUTE_FORCE_RAPID_WINDOW_SECONDS == 60
    r_eq = analyze_log_text("\n".join(_failed_password(70 + i, ip, s) for i, s in enumerate(at_window)) + "\n")
    brute_eq = [g for g in r_eq["incidents"] if g.get("kind") == "brute_force"]
    assert brute_eq[0]["level"] == "ERROR"
    r_over = analyze_log_text(
        "\n".join(_failed_password(80 + i, ip, s) for i, s in enumerate(past_window)) + "\n"
    )
    brute_over = [g for g in r_over["incidents"] if g.get("kind") == "brute_force"]
    assert brute_over[0]["level"] == "WARN"
    assert brute_over[0]["signature"].startswith("Suspected SSH brute-force")


def test_ten_or_more_attempts_are_brute_force_error_even_when_slow():
    ip = "198.51.100.10"
    lines = []
    for i in range(10):
        minute = 0 + i * 2
        lines.append(_failed_password(90 + i, ip, f"Dec 24 07:{minute:02d}:00"))
    r = analyze_log_text("\n".join(lines) + "\n")
    brute = [g for g in r["incidents"] if g.get("kind") == "brute_force"]
    assert len(brute) == 1
    assert brute[0]["count"] == 10
    assert brute[0]["level"] == "ERROR"
    assert brute[0]["signature"].startswith("SSH brute-force")


def test_same_ip_split_by_gap_stays_two_clusters():
    ip = "198.51.100.11"
    first = [_failed_password(100 + i, ip, f"Dec 24 07:00:0{i}") for i in range(5)]
    # 07:00:04 → 07:16:00 is 15 min 56 s > BRUTE_FORCE_GAP_SECONDS
    second = [_failed_password(200 + i, ip, f"Dec 24 07:16:0{i}") for i in range(5)]
    assert BRUTE_FORCE_GAP_SECONDS == 15 * 60
    r = analyze_log_text("\n".join(first + second) + "\n")
    brute = [g for g in r["incidents"] if g.get("kind") == "brute_force"]
    assert len(brute) == 2
    assert all(g["count"] == 5 for g in brute)


def test_warn_auth_lines_can_aggregate_to_error_brute_force():
    ip = "198.51.100.12"
    lines = [_failed_password(110 + i, ip, f"Dec 24 07:28:0{i}") for i in range(5)]
    r = analyze_log_text("\n".join(lines) + "\n")
    sessions = [g for g in r["incidents"] if g.get("kind") == "ssh_session"]
    brute = [g for g in r["incidents"] if g.get("kind") == "brute_force"]
    assert all(g["level"] == "WARN" for g in sessions)
    assert brute[0]["level"] == "ERROR"


def test_display_cap_does_not_change_unique_count():
    lines = [
        _failed_password(i, f"203.0.{i // 256}.{i % 256}", "Dec 24 06:55:46")
        for i in range(INCIDENT_RESULT_CAP + 1)
    ]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r["incident_unique_count"] == INCIDENT_RESULT_CAP + 1
    assert len(r["incidents"]) == INCIDENT_RESULT_CAP
    assert len(r["error_groups"]) == INCIDENT_RESULT_CAP
    md = render_log_report(r)
    assert f"Correlated incidents ({INCIDENT_RESULT_CAP + 1} unique;" in md
    assert f"Showing first {INCIDENT_RESULT_CAP} incidents" in md
    assert "## Detected line severities" in md
    assert "## Severity counts" not in md


def test_brute_force_from_repeated_source_ip():
    lines = [_failed_password(50 + i, "198.51.100.7", f"Dec 24 07:28:0{i}") for i in range(6)]
    r = analyze_log_text("\n".join(lines) + "\n")
    brute = [g for g in r["incidents"] if g.get("kind") == "brute_force"]
    assert brute
    assert "198.51.100.7" in brute[0]["signature"]
    assert brute[0]["count"] >= 5
    assert brute[0]["level"] == "ERROR"


def test_fatal_finding_pid_context_excludes_other_pids():
    text = (
        "Dec 24 11:03:51 box sshd[25457]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=183.62.140.253  user=root\n"
        "Dec 24 11:03:53 box sshd[25457]: Failed password for root from 183.62.140.253 port 53245 ssh2\n"
        "Dec 24 11:03:53 box sshd[25457]: fatal: Write failed: Connection reset by peer [preauth]\n"
        "Dec 24 11:03:53 box sshd[25463]: Failed password for root from 183.62.140.253 port 55138 ssh2\n"
    )
    r = analyze_log_text(text)
    assert r["levels"].get("FATAL", 0) == 1
    f = r["line_findings"][0]
    assert f["line"] == 3
    assert f["source_level"] == "FATAL"
    assert f["component"] == "sshd[25457]"
    ctx = "\n".join(f["context"])
    assert "Failed password for root from 183.62.140.253 port 53245 ssh2" in ctx
    assert "fatal: Write failed: Connection reset by peer [preauth]" in ctx
    assert "sshd[25463]" not in ctx
    md = render_log_report(r)
    assert "sshd[25463]" not in md.split("## Correlated incidents")[0]


def test_fatal_finding_visible_past_incident_detail_cap():
    lines = [
        _failed_password(100 + i, f"10.0.0.{i + 1}", "Dec 24 06:55:46")
        for i in range(40)
    ]
    lines.append(
        "Dec 24 11:03:53 box sshd[99999]: Failed password for root from 10.9.9.9 port 53245 ssh2"
    )
    lines.append(
        "Dec 24 11:03:53 box sshd[99999]: fatal: Write failed: Connection reset by peer [preauth]"
    )
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r["levels"]["FATAL"] == 1
    assert r["levels"]["WARN"] == 41
    assert r["incident_unique_count"] > INCIDENT_REPORT_DETAIL_CAP
    findings = [f for f in r["line_findings"] if f["source_level"] == "FATAL"]
    assert findings[0]["line"] == 42
    md = render_log_report(r)
    assert f"Showing first {INCIDENT_REPORT_DETAIL_CAP} incident details" in md
    notable, _, _ = md.partition("## Correlated incidents")
    assert "## Notable line findings" in notable
    assert "- **Line:** 42" in notable
    assert "fatal: Write failed: Connection reset by peer [preauth]" in notable
    assert "<summary>Relevant log</summary>" in notable
    assert "Failed password for root from 10.9.9.9 port 53245 ssh2" in notable
    assert "🛑 **FATAL:** 1" in md


def test_explicit_critical_source_marker_is_notable():
    line = "2026-09-09 10:00:00 CRITICAL datastore unavailable"
    r = analyze_log_text(line + "\n")
    assert r["levels"].get("CRITICAL", 0) == 1
    assert r["line_findings"][0]["source_level"] == "CRITICAL"
    assert r["line_findings"][0]["line"] == 1
    assert r["line_findings"][0]["kind"] == "explicit_source_marker"
    md = render_log_report(r)
    assert "🔴 **CRITICAL:** 1" in md
    assert "Explicit CRITICAL source marker" in md
    assert _severity_icon("CRITICAL") == "🔴"


if __name__ == "__main__":
    test_rfc3164_two_digit_day()
    test_rfc3164_one_digit_day_extra_whitespace()
    test_timestamp_range_extraction()
    test_lowercase_error_colon()
    test_lowercase_fatal_colon_does_not_create_critical_incident()
    test_failed_password_semantic()
    test_authentication_failure_semantic()
    test_reverse_dns_mismatch_alone_is_warn()
    test_too_many_authentication_failures()
    test_connection_closed_alone_is_not_an_incident()
    test_year_not_fabricated_when_absent()
    test_iso_formats_still_fill_calendar_range()
    test_pid_reverse_dns_plus_failed_auth_is_error_session()
    test_five_slow_attempts_are_suspected_warn()
    test_five_rapid_attempts_are_brute_force_error()
    test_rapid_window_boundary()
    test_ten_or_more_attempts_are_brute_force_error_even_when_slow()
    test_same_ip_split_by_gap_stays_two_clusters()
    test_warn_auth_lines_can_aggregate_to_error_brute_force()
    test_display_cap_does_not_change_unique_count()
    test_brute_force_from_repeated_source_ip()
    test_fatal_finding_pid_context_excludes_other_pids()
    test_fatal_finding_visible_past_incident_detail_cap()
    test_explicit_critical_source_marker_is_notable()
    print("LOG SYSLOG/SSH TESTS OK")
