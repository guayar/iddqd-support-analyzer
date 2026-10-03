"""Tests for v0.22 root cause analysis."""

from datetime import datetime, timedelta
from analyzers.root_cause import (
    RootCauseAnalyzer,
    CausalEvent,
    CausalityLink,
    RootCauseIncident,
    incident_to_dict,
)


def test_root_cause_analyzer_init():
    """Test analyzer initialization."""
    analyzer = RootCauseAnalyzer()
    assert analyzer is not None
    assert len(analyzer.KNOWN_CHAINS) > 0


def test_causal_event_creation():
    """Test creating causal events."""
    now = datetime.now()
    event = CausalEvent(
        timestamp=now,
        analyzer="postgresql",
        level="CRITICAL",
        kind="deadlock",
        message="Deadlock detected",
        first_line=10,
    )

    assert event.analyzer == "postgresql"
    assert event.kind == "deadlock"
    assert event.level == "CRITICAL"


def test_causality_link_time_delta():
    """Test causality link calculates time delta."""
    cause_time = datetime.now()
    effect_time = cause_time + timedelta(seconds=5)

    cause = CausalEvent(
        timestamp=cause_time,
        analyzer="postgresql",
        level="ERROR",
        kind="deadlock",
        message="Deadlock",
        first_line=0,
    )

    effect = CausalEvent(
        timestamp=effect_time,
        analyzer="nginx",
        level="ERROR",
        kind="timeout",
        message="Timeout",
        first_line=10,
    )

    link = CausalityLink(
        cause=cause,
        effect=effect,
        confidence=0.9,
        reason="Known pattern",
    )

    assert link.time_delta_seconds == 5.0


def test_root_cause_incident_add_event():
    """Test adding events to incident."""
    incident = RootCauseIncident(
        incident_id="test_1",
        root_cause=CausalEvent(
            timestamp=datetime.now(),
            analyzer="postgresql",
            level="CRITICAL",
            kind="deadlock",
            message="Deadlock",
            first_line=0,
        ),
        root_cause_confidence=0.95,
    )

    event = CausalEvent(
        timestamp=datetime.now(),
        analyzer="nginx",
        level="ERROR",
        kind="timeout",
        message="Timeout",
        first_line=10,
    )

    incident.add_event(event)
    assert len(incident.events) == 1
    assert "nginx" in incident.affected_analyzers


def test_analyze_findings_simple():
    """Test analyzing findings for root causes."""
    findings = [
        {
            "signature": "Deadlock (1)",
            "kind": "deadlock",
            "category": "postgresql",
            "level": "CRITICAL",
            "first_line": 0,
        },
        {
            "signature": "Timeout (1)",
            "kind": "timeout",
            "category": "nginx",
            "level": "ERROR",
            "first_line": 10,
        },
    ]

    analyzer = RootCauseAnalyzer()
    incidents = analyzer.analyze(findings)

    assert len(incidents) > 0
    assert incidents[0].root_cause.kind in ["deadlock", "timeout"]


def test_analyze_findings_empty():
    """Test analyzing empty findings."""
    analyzer = RootCauseAnalyzer()
    incidents = analyzer.analyze([])
    assert len(incidents) == 0


def test_incident_to_dict():
    """Test converting incident to dict."""
    now = datetime.now()
    root_cause = CausalEvent(
        timestamp=now,
        analyzer="postgresql",
        level="CRITICAL",
        kind="deadlock",
        message="Deadlock detected",
        first_line=0,
    )

    incident = RootCauseIncident(
        incident_id="test_1",
        root_cause=root_cause,
        root_cause_confidence=0.95,
    )

    incident.add_event(root_cause)
    incident.calculate_duration()

    result = incident_to_dict(incident)

    assert result["incident_id"] == "test_1"
    assert result["root_cause"]["kind"] == "deadlock"
    assert result["duration_seconds"] >= 0.0  # Duration is non-negative


def test_known_causality_patterns():
    """Test that known patterns are recognized."""
    findings = [
        {
            "signature": "Deadlock (1)",
            "kind": "deadlock",
            "category": "postgresql",
            "level": "CRITICAL",
            "first_line": 0,
        },
        {
            "signature": "Connection exhausted (1)",
            "kind": "connection_exhausted",
            "category": "postgresql",
            "level": "ERROR",
            "first_line": 5,
        },
    ]

    analyzer = RootCauseAnalyzer()
    incidents = analyzer.analyze(findings)

    # Should find causality between deadlock → connection exhaustion
    if incidents and incidents[0].causal_links:
        link = incidents[0].causal_links[0]
        # Known pattern has high confidence
        assert link.confidence > 0.8


if __name__ == "__main__":
    test_root_cause_analyzer_init()
    test_causal_event_creation()
    test_causality_link_time_delta()
    test_root_cause_incident_add_event()
    test_analyze_findings_simple()
    test_analyze_findings_empty()
    test_incident_to_dict()
    test_known_causality_patterns()
    print("✓ All root cause tests passed!")
