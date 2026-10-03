"""Tests for v0.21.0 finding deduplication."""

from analyzers.deduplication import (
    deduplicate_findings,
    deduplicate_by_signature,
    group_by_root_cause,
    make_test_finding,
)


def test_single_finding_no_dedup():
    """Single finding should pass through unchanged."""
    findings = [make_test_finding(kind="test", count=10)]
    result = deduplicate_findings(findings)

    assert len(result) == 1
    assert result[0]["count"] == 10
    assert "deduped" not in result[0] or result[0].get("deduped") is False


def test_multiple_related_findings_deduplicated():
    """Multiple related findings should be merged."""
    findings = [
        make_test_finding(kind="timeout", count=100, level="ERROR", first_line=0),
        make_test_finding(kind="timeout", count=50, level="ERROR", first_line=10),
    ]
    result = deduplicate_findings(findings, sequence_distance=300)

    # Should be merged into one
    assert len(result) == 1
    assert result[0]["count"] == 150  # 100 + 50
    assert result[0]["deduped"] is True
    assert "variations" in result[0]


def test_deduplication_preserves_highest_severity():
    """Deduplication should keep highest severity level."""
    findings = [
        make_test_finding(kind="error1", count=5, level="WARN"),
        make_test_finding(kind="error2", count=3, level="CRITICAL"),
        make_test_finding(kind="error3", count=7, level="ERROR"),
    ]
    result = deduplicate_findings(findings)

    # Should have CRITICAL as highest
    assert any(f["level"] == "CRITICAL" for f in result)


def test_deduplicate_by_signature():
    """Test signature-based deduplication."""
    findings = [
        {
            "signature": "Database timeout (5)",
            "count": 5,
            "level": "ERROR",
            "category": "performance",
            "kind": "timeout",
            "first_line": 0,
            "codes": {},
        },
        {
            "signature": "Database timeout (5)",
            "count": 3,
            "level": "ERROR",
            "category": "performance",
            "kind": "timeout",
            "first_line": 10,
            "codes": {},
        },
    ]
    result = deduplicate_by_signature(findings)

    assert len(result) == 1
    assert result["Database timeout (5)"]["count"] == 8


def test_group_by_root_cause():
    """Test grouping by root_cause."""
    findings = [
        {"root_cause": "db_deadlock", "kind": "timeout", "count": 5},
        {"root_cause": "db_deadlock", "kind": "connection_error", "count": 3},
        {"root_cause": "network_latency", "kind": "timeout", "count": 2},
    ]
    result = group_by_root_cause(findings)

    assert len(result) == 2
    assert len(result["db_deadlock"]) == 2
    assert len(result["network_latency"]) == 1


def test_variations_included_in_deduped():
    """Deduped finding should list variations."""
    findings = [
        make_test_finding(kind="connection_timeout", count=100, level="ERROR"),
        make_test_finding(kind="query_timeout", count=50, level="ERROR"),
        make_test_finding(kind="pool_exhausted", count=10, level="CRITICAL"),
    ]
    result = deduplicate_findings(findings)

    assert len(result) == 1
    assert "variations" in result[0]
    assert len(result[0]["variations"]) == 3
    assert result[0]["variations"][0]["count"] == 100


def test_make_test_finding():
    """Test helper function for creating test findings."""
    finding = make_test_finding(kind="test", count=42, level="WARN", first_line=100)

    assert finding["kind"] == "test"
    assert finding["count"] == 42
    assert finding["level"] == "WARN"
    assert finding["first_line"] == 100
    assert "signature" in finding
    assert "category" in finding


if __name__ == "__main__":
    test_single_finding_no_dedup()
    test_multiple_related_findings_deduplicated()
    test_deduplication_preserves_highest_severity()
    test_deduplicate_by_signature()
    test_group_by_root_cause()
    test_variations_included_in_deduped()
    test_make_test_finding()
    print("✓ All deduplication tests passed!")
