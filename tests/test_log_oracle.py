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


if __name__ == "__main__":
    test_oracle_alert_stamp_is_calendar_time()
    test_rfc3164_without_year_is_unchanged()
    test_embedded_sp2_is_not_a_vendor_code()
    test_internal_error_after_oracle_code_is_not_source_error()
    test_java_ora_after_error_level_still_counts()
    test_oracle_scan_stays_bounded()
    print("LOG ORACLE TESTS OK")
