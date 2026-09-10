from __future__ import annotations

from datetime import datetime

from analyzers.logs import (
    _first_vendor_code,
    _parse_ts,
    analyze_log_text,
    colon_severity,
    syslog_stamp,
)
from reporting import render_log_report


def test_oracle_alert_stamp_is_calendar_time():
    line = "Wed Jul 01 15:00:00 2026"
    assert _parse_ts(line) == datetime(2026, 7, 1, 15, 0, 0)
    assert syslog_stamp(line) is None
    r = analyze_log_text(line + "\nORA-01555: snapshot too old\n")
    assert r["time_range"]["from"].startswith("2026-07-01T15:00:00")
    assert r["time_range"]["to"].startswith("2026-07-01T15:00:00")
    assert r["time_range"]["year_present"] is True
    assert r["error_codes"]["ORA-01555"] == 1
    assert r["vendor_code_families"]["ORA"] == 1
    assert r["error_event_count"] == 0


def test_rfc3164_without_year_is_unchanged():
    line = "Dec 24 06:55:46 LabSZ sshd[1]: Connection closed"
    assert _parse_ts(line) is None
    assert syslog_stamp(line) == "Dec 24 06:55:46"
    r = analyze_log_text(line + "\n")
    assert r["time_range"]["from"] == "Dec 24 06:55:46"
    assert r["time_range"]["year_present"] is False


def test_embedded_sp2_is_not_a_vendor_code():
    line = (
        "RMAN-08500: channel CDR_STAGING : SID= user_sessions device type= SP2-0552"
    )
    assert _first_vendor_code(line) == "RMAN-08500"
    r = analyze_log_text(line + "\n")
    assert r["error_codes"]["RMAN-08500"] == 1
    assert "SP2-0552" not in r["error_codes"]


def test_internal_error_after_oracle_code_is_not_source_error():
    line = "KUP-04057: internal error: OCIEnvCreate"
    assert colon_severity(line) is None
    r = analyze_log_text(
        "Wed Jul 01 15:00:00 2026\n"
        f"{line}\n"
        "RMAN-03015: WARNING: stacked message\n"
    )
    assert "ERROR" not in r["levels"]
    assert r["levels"].get("WARN") is None
    assert r["error_codes"]["KUP-04057"] == 1
    assert r["error_codes"]["RMAN-03015"] == 1
    assert r["error_event_count"] == 0
    md = render_log_report(r)
    assert "## Vendor codes" in md
    assert "KUP-04057" in md
    assert "Example:" in md
    assert "## Correlated incidents" in md
    assert "Vendor codes above are reported separately" in md
    assert "not importance" in md


def test_java_ora_after_error_level_still_counts():
    text = (
        "2026-09-07 10:02:00 ERROR Database failed ORA-12514\n"
        "Caused by: java.sql.SQLException: ORA-12514 listener\n"
    )
    r = analyze_log_text(text)
    assert r["error_codes"]["ORA-12514"] >= 1
    assert r["error_event_count"] == 1
    assert r["levels"]["ERROR"] == 1


def test_oracle_scan_stays_bounded():
    chunks = []
    for i in range(4000):
        chunks.append("Wed Jul 01 15:00:00 2026")
        chunks.append("ORA-01555: snapshot too old")
        chunks.append("RMAN-08500: channel x device type= SP2-0552")
    text = "\n".join(chunks) + "\n"
    r = analyze_log_text(text, "alert.log")
    assert r["line_count"] == 12000
    assert r["error_codes"]["ORA-01555"] == 4000
    assert r["error_codes"]["RMAN-08500"] == 4000
    assert "SP2-0552" not in r["error_codes"]
    assert r["error_event_count"] == 0
    assert "ERROR" not in r["levels"]


def test_http_status_is_aux_not_vendor():
    r = analyze_log_text("2026-09-07 10:01:00 ERROR Request failed HTTP 500\n")
    assert "HTTP 500" not in r["error_codes"]
    assert r["aux_codes"]["HTTP 500"] == 1
    assert r["vendor_code_unique"] == 0


def test_many_distinct_codes_keep_exact_unique():
    lines = [f"ORA-{10000 + i}: msg {i}" for i in range(2100)]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r["vendor_code_unique"] == 2100
    assert r["vendor_code_occurrences"] == 2100
    assert r["vendor_code_families"]["ORA"] == 2100
    assert len(r["error_codes"]) == 500
    assert r["vendor_code_list_truncated"] is True
    assert r["vendor_code_json_truncated"] is True
    md = render_log_report(r)
    assert "Showing 40 of 2100 unique" in md


def test_late_repeat_is_counted_after_detail_cap():
    lines = [f"ORA-{10000 + i}: once" for i in range(2000)]
    lines.extend(["ORA-00600: internal error"] * 50)
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r["vendor_code_unique"] == 2001
    assert r["vendor_code_occurrences"] == 2050
    assert r["error_codes"]["ORA-00600"] == 50


if __name__ == "__main__":
    test_oracle_alert_stamp_is_calendar_time()
    test_rfc3164_without_year_is_unchanged()
    test_embedded_sp2_is_not_a_vendor_code()
    test_internal_error_after_oracle_code_is_not_source_error()
    test_java_ora_after_error_level_still_counts()
    test_oracle_scan_stays_bounded()
    test_http_status_is_aux_not_vendor()
    test_many_distinct_codes_keep_exact_unique()
    test_late_repeat_is_counted_after_detail_cap()
    print("LOG ORACLE TESTS OK")
