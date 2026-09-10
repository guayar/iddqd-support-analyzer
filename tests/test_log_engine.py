from __future__ import annotations

from analyzers.log_ssh import SshCorrelator, ssh_line_hint
from analyzers.logs import (
    GROUP_STORE_CAP,
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


if __name__ == "__main__":
    test_ssh_hint_skips_non_sshd()
    test_prefix_parsed_once_shape()
    test_apache_one_liner_is_not_a_java_event()
    test_unique_incident_count_survives_store_cap()
    print("LOG ENGINE TESTS OK")
