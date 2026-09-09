from __future__ import annotations

from analyzers.logs import (
    _parse_ts,
    analyze_log_text,
    colon_severity,
    ssh_rule,
    syslog_stamp,
)


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


def test_lowercase_fatal_colon():
    line = "Dec 24 11:03:53 box sshd[21]: fatal: Write failed: Connection reset by peer [preauth]"
    assert colon_severity(line) == "FATAL"
    rule = ssh_rule(line)
    assert rule is not None and rule[0] == "CRITICAL" and rule[2] == "fatal"
    r = analyze_log_text(line + "\n")
    assert r["levels"].get("FATAL", 0) >= 1
    assert any(g["level"] == "CRITICAL" for g in r["incidents"])


def test_failed_password_semantic():
    line = "Dec 24 06:55:48 box sshd[30]: Failed password for invalid user webmaster from 10.4.5.6 port 38926 ssh2"
    rule = ssh_rule(line)
    assert rule is not None and rule[2] == "failed_password"
    r = analyze_log_text(line + "\n")
    assert r["levels"].get("WARN", 0) >= 1
    assert r["error_event_count"] >= 1


def test_authentication_failure_semantic():
    line = (
        "Dec 24 06:55:46 box sshd[31]: pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=10.4.5.6"
    )
    rule = ssh_rule(line)
    assert rule is not None and rule[2] == "auth_failure"
    r = analyze_log_text(line + "\n")
    assert any("authentication" in (g["signature"] or "").lower() for g in r["incidents"])


def test_possible_break_in():
    line = (
        "Dec 24 06:55:46 box sshd[32]: reverse mapping checking getaddrinfo for ns.example.com "
        "[10.4.5.6] failed - POSSIBLE BREAK-IN ATTEMPT!"
    )
    rule = ssh_rule(line)
    assert rule is not None and rule[2] == "break_in" and rule[0] == "CRITICAL"
    r = analyze_log_text(line + "\n")
    assert r["levels"].get("CRITICAL", 0) >= 1


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


def test_pid_correlates_one_authentication_attempt():
    text = """Dec 24 06:55:46 box sshd[24200]: reverse mapping checking getaddrinfo for ns.example.net [203.0.113.10] failed - POSSIBLE BREAK-IN ATTEMPT!
Dec 24 06:55:46 box sshd[24200]: Invalid user webmaster from 203.0.113.10
Dec 24 06:55:46 box sshd[24200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10
Dec 24 06:55:48 box sshd[24200]: Failed password for invalid user webmaster from 203.0.113.10 port 38926 ssh2
Dec 24 06:55:48 box sshd[24200]: Connection closed by 203.0.113.10 [preauth]
"""
    r = analyze_log_text(text)
    sessions = [g for g in r["incidents"] if g.get("kind") == "ssh_session"]
    assert len(sessions) == 1
    assert sessions[0]["level"] == "CRITICAL"
    assert "203.0.113.10" in sessions[0]["signature"]
    assert "webmaster" in sessions[0]["sample"]
    assert r["error_event_count"] == 1


def test_brute_force_from_repeated_source_ip():
    lines = []
    for i, pid in enumerate(range(50, 56)):
        lines.append(
            f"Dec 24 07:28:0{i} box sshd[{pid}]: Failed password for root from 198.51.100.7 port {4000+i} ssh2"
        )
    r = analyze_log_text("\n".join(lines) + "\n")
    brute = [g for g in r["incidents"] if g.get("kind") == "brute_force"]
    assert brute
    assert "198.51.100.7" in brute[0]["signature"]
    assert brute[0]["count"] >= 5


if __name__ == "__main__":
    test_rfc3164_two_digit_day()
    test_rfc3164_one_digit_day_extra_whitespace()
    test_timestamp_range_extraction()
    test_lowercase_error_colon()
    test_lowercase_fatal_colon()
    test_failed_password_semantic()
    test_authentication_failure_semantic()
    test_possible_break_in()
    test_too_many_authentication_failures()
    test_connection_closed_alone_is_not_an_incident()
    test_year_not_fabricated_when_absent()
    test_iso_formats_still_fill_calendar_range()
    test_pid_correlates_one_authentication_attempt()
    test_brute_force_from_repeated_source_ip()
    print("LOG SYSLOG/SSH TESTS OK")
