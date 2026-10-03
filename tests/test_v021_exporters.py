"""Tests for v0.21.0 export formats."""

import json
import csv
import io

from analyzers.exporters import (
    JsonExporter,
    CsvExporter,
    SplunkExporter,
    ElkExporter,
    GraylogExporter,
    SlackExporter,
)


def test_json_exporter():
    """Test JSON export format."""
    findings = [
        {
            "signature": "Test error (5)",
            "count": 5,
            "level": "ERROR",
            "category": "test",
            "kind": "test_error",
            "first_line": 0,
            "codes": {},
        }
    ]

    exporter = JsonExporter()
    output = exporter.export(findings)

    assert isinstance(output, str)
    data = json.loads(output)
    assert data["count"] == 1
    assert len(data["findings"]) == 1
    assert data["findings"][0]["signature"] == "Test error (5)"


def test_csv_exporter():
    """Test CSV export format."""
    findings = [
        {
            "signature": "Test 1",
            "count": 5,
            "level": "ERROR",
            "category": "test",
            "kind": "test1",
            "first_line": 0,
            "codes": {},
        },
        {
            "signature": "Test 2",
            "count": 3,
            "level": "WARN",
            "category": "test",
            "kind": "test2",
            "first_line": 10,
            "codes": {},
        },
    ]

    exporter = CsvExporter()
    output = exporter.export(findings)

    assert isinstance(output, str)
    assert "signature" in output
    assert "Test 1" in output
    assert "Test 2" in output

    # Parse and verify CSV structure
    reader = csv.DictReader(io.StringIO(output))
    rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["signature"] == "Test 1"
    assert rows[1]["count"] == "3"


def test_splunk_exporter():
    """Test Splunk HEC export format."""
    findings = [
        {
            "signature": "Database error",
            "count": 10,
            "level": "CRITICAL",
            "category": "performance",
            "kind": "deadlock",
            "first_line": 0,
            "codes": {"ORA": ["ORA-60"]},
        }
    ]

    exporter = SplunkExporter(
        endpoint="https://splunk.example.com:8088",
        hec_token="test-token-123",
    )
    output = exporter.export(findings)

    assert isinstance(output, str)
    # Parse HEC format
    lines = output.strip().split("\n")
    assert len(lines) > 0

    hec_event = json.loads(lines[0])
    assert "time" in hec_event
    assert "source" in hec_event
    assert "event" in hec_event
    assert hec_event["event"]["signature"] == "Database error"


def test_elk_exporter():
    """Test Elasticsearch bulk format."""
    findings = [
        {
            "signature": "API timeout",
            "count": 5,
            "level": "ERROR",
            "category": "performance",
            "kind": "timeout",
            "first_line": 0,
            "codes": {},
        }
    ]

    exporter = ElkExporter(
        endpoint="http://localhost:9200",
        index="iddqd-findings",
    )
    output = exporter.export(findings)

    assert isinstance(output, str)
    # Parse bulk format (alternating metadata + data)
    lines = output.strip().split("\n")
    assert len(lines) >= 2

    # First line is metadata
    metadata = json.loads(lines[0])
    assert "index" in metadata
    assert metadata["index"]["_index"] == "iddqd-findings"

    # Second line is data
    data = json.loads(lines[1])
    assert data["signature"] == "API timeout"
    assert "@timestamp" in data


def test_graylog_exporter():
    """Test Graylog GELF export format."""
    findings = [
        {
            "signature": "Authentication failure",
            "count": 15,
            "level": "ERROR",
            "category": "security",
            "kind": "auth_failure",
            "first_line": 0,
            "codes": {},
            "root_cause": "invalid_credentials",
        }
    ]

    exporter = GraylogExporter(
        endpoint="graylog.example.com",
        port=12201,
        facility="iddqd",
    )
    output = exporter.export(findings)

    assert isinstance(output, str)
    lines = output.strip().split("\n")
    assert len(lines) > 0

    gelf_msg = json.loads(lines[0])
    assert gelf_msg["version"] == "1.1"
    assert "timestamp" in gelf_msg
    assert gelf_msg["short_message"] == "Authentication failure"
    assert gelf_msg["level"] == 3  # ERROR maps to syslog level 3
    assert "_finding_kind" in gelf_msg


def test_slack_exporter():
    """Test Slack message format."""
    findings = [
        {
            "signature": "Database down (234)",
            "count": 234,
            "level": "CRITICAL",
            "category": "reliability",
            "kind": "db_unavailable",
            "first_line": 0,
            "codes": {},
        },
        {
            "signature": "API timeout (100)",
            "count": 100,
            "level": "ERROR",
            "category": "performance",
            "kind": "timeout",
            "first_line": 50,
            "codes": {},
        },
    ]

    exporter = SlackExporter(webhook_url="https://hooks.slack.com/services/TEST")
    output = exporter.export(findings)

    assert isinstance(output, str)
    payload = json.loads(output)

    assert "blocks" in payload
    blocks = payload["blocks"]
    assert len(blocks) > 0

    # Should have header
    assert blocks[0]["type"] == "header"
    assert "2 Findings" in blocks[0]["text"]["text"]


def test_exporters_batch_export():
    """Test batch export functionality."""
    findings = [make_test_finding(i) for i in range(250)]

    exporter = JsonExporter()
    batches = exporter.batch_export(findings, batch_size=100)

    assert len(batches) == 3  # 250 findings / 100 = 3 batches
    assert all(isinstance(b, str) for b in batches)


def make_test_finding(i: int) -> dict:
    """Create a test finding."""
    return {
        "signature": f"Test finding {i}",
        "count": i + 1,
        "level": "ERROR",
        "category": "test",
        "kind": f"test_{i}",
        "first_line": i * 10,
        "codes": {},
    }


if __name__ == "__main__":
    test_json_exporter()
    test_csv_exporter()
    test_splunk_exporter()
    test_elk_exporter()
    test_graylog_exporter()
    test_slack_exporter()
    test_exporters_batch_export()
    print("✓ All exporter tests passed!")
