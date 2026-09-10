from __future__ import annotations

import time

from analyzers.log_ssh import SSH_SESSION_STORE_CAP, SshCorrelator, ssh_line_hint
from analyzers.logs import (
    GROUP_STORE_CAP,
    LogScanTimeout,
    _looks_like_java_event,
    _split_record,
    analyze_log_text,
)


def test_ssh_hint_skips_non_sshd():
    assert ssh_line_hint("Dec 24 06:55:46 box sshd[1]: Failed password") is True
    assert ssh_line_hint("[Sun Dec 04 04:47:44 2005] [error] Directory index forbidden") is False
    c = SshCorrelator()
    c.on_line(1, "[error] not ssh", None)
    incidents, n = c.flush()
    assert incidents == []
    assert n == 0


def test_prefix_parsed_once_shape():
    line = "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6"
    rec, new_rec = _split_record(line)
    assert new_rec is True
    assert rec["style"] == "timestamp_bracket"
    assert rec["level"] == "ERROR"


def test_apache_one_liner_is_not_a_java_event():
    ev = {
        "lines": ["[Sun Dec 04 04:47:44 2005] [error] Directory index forbidden by rule: /var/www/html/"],
        "style": "timestamp_bracket",
        "level": "ERROR",
        "start_line": 1,
    }
    assert _looks_like_java_event(ev) is False


def test_unique_incident_count_survives_store_cap():
    n = GROUP_STORE_CAP + 5
    lines = [
        f"[Sun Dec 04 04:47:44 2005] [error] unique message number {i} for grouping"
        for i in range(n)
    ]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r["error_event_count"] == n
    assert r["incident_unique_count"] == n
    assert len(r["incidents"]) <= n


def test_ssh_session_store_cap_counts_overflow_without_storing():
    extra = 40
    c = SshCorrelator()
    n = SSH_SESSION_STORE_CAP + extra
    for i in range(n):
        line = (
            f"Dec 24 06:55:46 box sshd[{1000 + i}]: Failed password for root "
            f"from 10.0.{i // 256}.{i % 256} port 22 ssh2"
        )
        c.on_line(i + 1, line, "Dec 24 06:55:46")
    incidents, events = c.flush()
    stored = [g for g in incidents if g.get("kind") == "ssh_session"]
    assert len(c.sessions) == SSH_SESSION_STORE_CAP
    assert len(stored) == SSH_SESSION_STORE_CAP
    assert events == n
    assert len(c.overflow_auth_pids) == extra


def test_scan_time_budget_aborts():
    text = "[Sun Dec 04 04:47:44 2005] [error] boom\n" * 80_000
    try:
        analyze_log_text(text, max_seconds=1e-9)
    except LogScanTimeout as e:
        assert "time budget" in str(e)
        return
    raise AssertionError("expected LogScanTimeout")


def test_scan_100k_repeated_apache_stays_under_budget():
    text = "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6\n" * 100_000
    t0 = time.perf_counter()
    r = analyze_log_text(text, max_seconds=0)
    elapsed = time.perf_counter() - t0
    assert r["error_event_count"] == 100_000
    assert r["incident_unique_count"] == 1
    assert elapsed < 30, f"100k-line scan took {elapsed:.1f}s"


if __name__ == "__main__":
    test_ssh_hint_skips_non_sshd()
    test_prefix_parsed_once_shape()
    test_apache_one_liner_is_not_a_java_event()
    test_unique_incident_count_survives_store_cap()
    test_ssh_session_store_cap_counts_overflow_without_storing()
    test_scan_time_budget_aborts()
    test_scan_100k_repeated_apache_stays_under_budget()
    print("LOG ENGINE TESTS OK")
