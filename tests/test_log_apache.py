from __future__ import annotations

from analyzers.logs import (
    _grouping_key,
    _header_message,
    _normalize_for_group,
    analyze_log_text,
    log_record_prefix,
)
from reporting import render_log_report


def test_bracket_level_after_timestamp():
    line = "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6"
    rec = log_record_prefix(line)
    assert rec is not None
    assert rec["level"] == "ERROR"
    assert rec["style"] == "timestamp_bracket"
    assert rec["rest"].strip().startswith("mod_jk")
    assert _header_message(line) == "mod_jk child workerEnv in error state 6"
    r = analyze_log_text(line + "\n")
    assert r["levels"]["ERROR"] == 1
    assert r["error_event_count"] == 1
    assert r["incident_unique_count"] == 1
    assert "04:47:44" not in r["incidents"][0]["signature"]


def test_notice_is_info_not_an_incident():
    line = "[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties"
    rec = log_record_prefix(line)
    assert rec["level"] == "INFO"
    r = analyze_log_text(line + "\n")
    assert r["levels"]["INFO"] == 1
    assert "ERROR" not in r["levels"]
    assert r["error_event_count"] == 0


def test_repeated_apache_errors_group_without_timestamp():
    text = (
        "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6\n"
        "[Sun Dec 04 04:51:18 2005] [error] mod_jk child workerEnv in error state 6\n"
        "[Sun Dec 04 04:52:15 2005] [error] mod_jk child workerEnv in error state 7\n"
    )
    r = analyze_log_text(text)
    assert r["levels"]["ERROR"] == 3
    assert r["error_event_count"] == 3
    by_sig = {g["signature"]: g["count"] for g in r["incidents"]}
    assert by_sig["mod_jk child workerEnv in error state 6"] == 2
    assert by_sig["mod_jk child workerEnv in error state 7"] == 1


def test_client_ip_is_context_not_identity():
    text = (
        "[Sun Dec 04 05:15:09 2005] [error] [client 222.166.160.184] Directory index forbidden by rule: /var/www/html/\n"
        "[Sun Dec 04 07:45:45 2005] [error] [client 63.13.186.196] Directory index forbidden by rule: /var/www/html/\n"
    )
    r = analyze_log_text(text)
    assert r["error_event_count"] == 2
    assert r["incident_unique_count"] == 1
    assert r["incidents"][0]["count"] == 2
    assert "[client <ip>]" in _normalize_for_group(_header_message(text.splitlines()[0]))


def test_child_id_is_context_not_identity():
    text = (
        "[Sun Dec 04 17:43:08 2005] [error] jk2_init() Can't find child 1566 in scoreboard\n"
        "[Sun Dec 04 17:43:08 2005] [error] jk2_init() Can't find child 1567 in scoreboard\n"
    )
    r = analyze_log_text(text)
    assert r["incident_unique_count"] == 1
    assert r["incidents"][0]["count"] == 2
    ev = {"lines": [text.splitlines()[0]], "level": "ERROR", "style": "timestamp_bracket"}
    chain = {"root_cause": None, "top_exception": None, "causes": [], "exception_chain": []}
    _, key = _grouping_key(ev, chain)
    assert "1566" not in key
    assert "child <id>" in key


def test_java_and_maven_prefixes_unchanged():
    java = "2026-09-07 10:00:00 ERROR boom\n    at foo.Bar(Bar.java:1)\n"
    r = analyze_log_text(java)
    assert r["error_event_count"] == 1
    assert r["incidents"][0]["level"] == "ERROR"
    maven = "[ERROR] Failed to execute goal\n"
    m = analyze_log_text(maven)
    assert m["error_event_count"] == 1
    rec = log_record_prefix("[ERROR] Failed to execute goal")
    assert rec["style"] == "bracket"


def test_many_apache_errors_stay_grouped():
    lines = [
        "[Sun Dec 04 04:47:44 2005] [error] mod_jk child workerEnv in error state 6"
        for _ in range(300)
    ]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r["levels"]["ERROR"] == 300
    assert r["error_event_count"] == 300
    assert r["incident_unique_count"] == 1
    assert len(r["incidents"]) == 1
    md = render_log_report(r)
    assert "## Correlated incidents" in md
    assert "mod_jk child workerEnv in error state 6" in md


if __name__ == "__main__":
    test_bracket_level_after_timestamp()
    test_notice_is_info_not_an_incident()
    test_repeated_apache_errors_group_without_timestamp()
    test_client_ip_is_context_not_identity()
    test_child_id_is_context_not_identity()
    test_java_and_maven_prefixes_unchanged()
    test_many_apache_errors_stay_grouped()
    print("LOG APACHE TESTS OK")
