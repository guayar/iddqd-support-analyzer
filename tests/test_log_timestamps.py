from __future__ import annotations

from datetime import datetime

from analyzers.logs import (
    _parse_ts,
    _split_events,
    _timestamp_at_start,
    analyze_log_text,
    is_new_log_record,
    log_record_prefix,
)


def test_unambiguous_formats_parse():
    assert _parse_ts("2026-09-01 14:04:46") == datetime(2026, 9, 1, 14, 4, 46)
    assert _parse_ts("2026-09-01T14:04:46.123Z") == datetime(2026, 9, 1, 14, 4, 46, 123000)
    assert _parse_ts("2026/09/01 14:04:46") == datetime(2026, 9, 1, 14, 4, 46)
    assert _parse_ts("01-Sep-2026 14:04:46") == datetime(2026, 9, 1, 14, 4, 46)
    assert _parse_ts("[2026-09-01 14:04:46]") == datetime(2026, 9, 1, 14, 4, 46)


def test_ambiguous_slash_is_not_invented_on_a_single_line():
    assert _parse_ts("09/01/26 14:04:46") is None
    assert _parse_ts("01/09/2026 14:04:46") is None
    assert _parse_ts("[09/01/26 14:04:46 healthCheck]") is None


def test_slash_day_over_12_is_dmy():
    assert _parse_ts("13/01/26 14:04:46") == datetime(2026, 1, 13, 14, 4, 46)
    assert _parse_ts("01/13/2026 14:04:46") == datetime(2026, 1, 13, 14, 4, 46)


def test_syslog_is_a_boundary_but_not_a_calendar_time():
    line = "Sep 01 14:04:46 host app: fail"
    assert _parse_ts(line) is None
    assert _timestamp_at_start(line) is not None
    assert is_new_log_record(line)


def test_bracketed_two_digit_year_is_a_record_boundary():
    line = "[09/01/26 14:04:46 healthCheck] ERROR failed"
    assert _timestamp_at_start(line) is not None
    assert is_new_log_record(line)
    rec = log_record_prefix(line)
    assert rec is not None
    assert rec["level"] == "ERROR"
    assert rec["style"] == "timestamped"


def test_bracketed_iso_is_a_record_boundary():
    line = "[2026-09-01 14:04:46] INFO ok"
    assert _timestamp_at_start(line) is not None
    rec = log_record_prefix(line)
    assert rec is not None
    assert rec["level"] == "INFO"


def test_file_with_iso_disambiguates_slash_mdy():
    text = (
        "2026-09-01 14:04:46 INFO start\n"
        "[09/01/26 14:04:46 healthCheck] ERROR failed\n"
        "    at foo.Bar(Bar.java:1)\n"
    )
    r = analyze_log_text(text)
    assert r["timestamped_lines"] == 2
    assert r["time_range"]["from"].startswith("2026-09-01T14:04:46")
    assert r["time_range"]["to"].startswith("2026-09-01T14:04:46")
    assert r["error_event_count"] == 1
    assert r["levels"]["ERROR"] == 1
    assert "at foo.Bar" in r["incidents"][0]["sample"]


def test_file_with_day_over_12_disambiguates_as_dmy():
    text = (
        "13/01/26 10:00:00 INFO start\n"
        "09/01/26 14:04:46 ERROR failed\n"
    )
    r = analyze_log_text(text)
    assert r["time_range"]["from"].startswith("2026-01-09T14:04:46")
    assert r["time_range"]["to"].startswith("2026-01-13T10:00:00")


def test_only_ambiguous_slash_does_not_fill_time_range():
    text = "[09/01/26 14:04:46 healthCheck] ERROR failed\n"
    r = analyze_log_text(text)
    assert r["time_range"] == {"from": None, "to": None}
    assert r["error_event_count"] == 1
    assert r["timestamped_lines"] == 0


def test_timestamped_info_still_closes_an_error_block():
    text = (
        "2026-09-01 14:04:46 ERROR boom\n"
        "    at foo.Bar(Bar.java:1)\n"
        "[09/01/26 14:04:47 healthCheck] INFO recovered\n"
        "    at should.NotAttach(X.java:2)\n"
    )
    events = _split_events(text.splitlines())
    assert len(events) == 1
    sample = "\n".join(events[0]["lines"])
    assert "at foo.Bar" in sample
    assert "NotAttach" not in sample


if __name__ == "__main__":
    test_unambiguous_formats_parse()
    test_ambiguous_slash_is_not_invented_on_a_single_line()
    test_slash_day_over_12_is_dmy()
    test_syslog_is_a_boundary_but_not_a_calendar_time()
    test_bracketed_two_digit_year_is_a_record_boundary()
    test_bracketed_iso_is_a_record_boundary()
    test_file_with_iso_disambiguates_slash_mdy()
    test_file_with_day_over_12_disambiguates_as_dmy()
    test_only_ambiguous_slash_does_not_fill_time_range()
    test_timestamped_info_still_closes_an_error_block()
    print("LOG TIMESTAMP TESTS OK")
