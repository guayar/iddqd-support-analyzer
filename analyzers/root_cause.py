"""Root cause analysis engine for v0.22 (EXPERIMENTAL).

⚠️  EXPERIMENTAL FEATURE - NOT PROVEN DIAGNOSTICS

This module provides HEURISTIC suggestions about possible causality chains.
It is NOT root-cause analysis, NOT deterministic validation, NOT probabilistic.

Confidence scores are pattern-match weights, NOT statistical probabilities.
Correlation ≠ causation. Temporal proximity ≠ causality.

Use for investigation hints only. Manual review required.
"""

from __future__ import annotations

from typing import Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import re


@dataclass
class CausalEvent:
    """Single event in causality chain."""

    timestamp: datetime
    analyzer: str  # postgresql, nginx, docker, etc
    level: str  # CRITICAL, ERROR, WARN
    kind: str  # deadlock, timeout, connection_error, etc
    message: str
    first_line: int
    duration_seconds: float = 0.0
    line_idx: int = 0

    def __lt__(self, other: CausalEvent) -> bool:
        """Sort by timestamp."""
        return self.timestamp < other.timestamp


@dataclass
class CausalityLink:
    """Link between two events (possible cause → effect relationship).

    ⚠️  IMPORTANT: pattern_match_strength is NOT a probability.
    It indicates how familiar this pattern is, not how likely causation is.
    """

    cause: CausalEvent
    effect: CausalEvent
    pattern_match_strength: float  # 0.0-1.0 heuristic weight, NOT probability
    reason: str  # Why we think they're connected
    time_delta_seconds: float = 0.0

    def __post_init__(self):
        """Calculate time delta."""
        self.time_delta_seconds = (self.effect.timestamp - self.cause.timestamp).total_seconds()


@dataclass
class RootCauseIncident:
    """Possible incident chain (EXPERIMENTAL - not proven causality)."""

    incident_id: str
    root_cause: CausalEvent
    pattern_match_strength: float  # NOT a probability, heuristic weight
    events: list[CausalEvent] = field(default_factory=list)
    causal_links: list[CausalityLink] = field(default_factory=list)
    start_time: datetime | None = None  # No synthetic timestamps
    end_time: datetime | None = None  # No synthetic timestamps
    duration_seconds: float = 0.0
    affected_analyzers: set[str] = field(default_factory=set)
    total_impact: int = 0
    pattern_strength_chain: list[float] = field(default_factory=list)
    causality_status: str = "NOT_ESTABLISHED"  # NOT_ESTABLISHED, POSSIBLE, CORRELATED

    def add_event(self, event: CausalEvent) -> None:
        """Add event to chain."""
        self.events.append(event)
        self.affected_analyzers.add(event.analyzer)
        self.total_impact += 1
        if not self.start_time or event.timestamp < self.start_time:
            self.start_time = event.timestamp
        if not self.end_time or event.timestamp > self.end_time:
            self.end_time = event.timestamp

    def add_causal_link(self, link: CausalityLink) -> None:
        """Add possible causal relationship."""
        self.causal_links.append(link)
        self.pattern_strength_chain.append(link.pattern_match_strength)

    def calculate_duration(self) -> None:
        """Calculate incident duration."""
        if self.start_time and self.end_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()

    def chain_confidence(self) -> float:
        """Average pattern-match strength across chain (NOT probability)."""
        if not self.pattern_strength_chain:
            return 0.0
        return sum(self.pattern_strength_chain) / len(self.pattern_strength_chain)


class RootCauseAnalyzer:
    """Analyze root causes across findings."""

    # Time thresholds for causality detection
    IMMEDIATE_THRESHOLD_SECONDS = 5  # Events within 5s are likely connected
    SHORT_TERM_THRESHOLD_SECONDS = 30  # Events within 30s might be connected
    MEDIUM_TERM_THRESHOLD_SECONDS = 300  # Events within 5min could be connected

    # Known patterns: (cause_kind, effect_kind) → pattern_match_strength
    # ⚠️  These are NOT probabilities. They indicate pattern familiarity only.
    KNOWN_PATTERNS = {
        ("deadlock", "connection_exhausted"): 0.95,
        ("connection_exhausted", "timeout"): 0.90,
        ("timeout", "service_restart"): 0.85,
        ("connection_exhausted", "http_error"): 0.88,
        ("query_slow", "connection_timeout"): 0.80,
        ("memory_spike", "oom_killed"): 0.92,
        ("cpu_spike", "timeout"): 0.75,
        ("network_latency", "timeout"): 0.80,
        ("circuit_breaker_open", "error_cascade"): 0.90,
        ("service_unavailable", "http_503"): 0.95,
    }

    def __init__(self):
        """Initialize root cause analyzer."""
        self.incidents: dict[str, RootCauseIncident] = {}

    def analyze(self, findings: list[dict[str, Any]]) -> list[RootCauseIncident]:
        """Analyze findings for root causes.

        Args:
            findings: List of finding dicts with timestamps

        Returns:
            List of RootCauseIncident with chains
        """
        if not findings:
            return []

        # Convert findings to causal events
        events = self._extract_events(findings)

        # Find root causes
        root_causes = self._identify_root_causes(events)

        # Build incident chains
        incidents = self._build_incident_chains(events, root_causes)

        return incidents

    def _extract_events(self, findings: list[dict[str, Any]]) -> list[CausalEvent]:
        """Convert findings to events (skip findings without valid timestamps)."""
        events = []

        for finding in findings:
            # Only include findings with valid timestamps
            timestamp = None
            if "timestamp" in finding:
                try:
                    timestamp = datetime.fromisoformat(finding["timestamp"])
                except (ValueError, TypeError):
                    pass

            # Skip events without timestamps - no synthetic timestamps
            if not timestamp:
                continue

            event = CausalEvent(
                timestamp=timestamp,
                analyzer=finding.get("category", "unknown"),
                level=finding.get("level", "INFO"),
                kind=finding.get("kind", "unknown"),
                message=finding.get("signature", "Unknown"),
                first_line=finding.get("first_line", 0),
                line_idx=finding.get("first_line", 0),
            )
            events.append(event)

        # Sort by timestamp
        events.sort()
        return events

    def _identify_root_causes(self, events: list[CausalEvent]) -> list[CausalEvent]:
        """Identify events that are likely root causes.

        Root causes are events that:
        - Come first temporally
        - Have high severity
        - Match known root cause patterns
        """
        if not events:
            return []

        root_causes = []

        for event in events:
            is_root = True

            # Check if this event is caused by another
            for other in events:
                if other.timestamp >= event.timestamp:
                    continue  # Only look at earlier events

                if self._is_causal(other, event):
                    is_root = False
                    break

            if is_root and event.level in ("CRITICAL", "ERROR"):
                root_causes.append(event)

        return root_causes if root_causes else [events[0]]  # Fallback to first

    def _is_causal(self, cause: CausalEvent, effect: CausalEvent) -> bool:
        """Check if events might be related (NOT proven causality)."""
        time_delta = (effect.timestamp - cause.timestamp).total_seconds()

        # Must be within reasonable time window
        if time_delta < 0 or time_delta > self.MEDIUM_TERM_THRESHOLD_SECONDS:
            return False

        # Check known patterns
        pattern_key = (cause.kind, effect.kind)
        if pattern_key in self.KNOWN_PATTERNS:
            return True

        # Check analyzer sequence (db → api → nginx is common)
        analyzer_seq = (cause.analyzer, effect.analyzer)
        common_sequences = [
            ("postgresql", "api_performance"),
            ("postgresql", "nginx"),
            ("docker", "nginx"),
            ("docker", "api_performance"),
        ]

        if analyzer_seq in common_sequences:
            return time_delta <= self.SHORT_TERM_THRESHOLD_SECONDS

        return False

    def _calculate_pattern_strength(self, cause: CausalEvent, effect: CausalEvent) -> float:
        """Calculate pattern-match strength (NOT causal probability)."""
        pattern_key = (cause.kind, effect.kind)
        base_strength = self.KNOWN_PATTERNS.get(pattern_key, 0.5)

        time_delta = (effect.timestamp - cause.timestamp).total_seconds()

        # Adjust for temporal proximity (closer = stronger pattern match)
        if time_delta <= self.IMMEDIATE_THRESHOLD_SECONDS:
            base_strength *= 1.1
        elif time_delta > self.SHORT_TERM_THRESHOLD_SECONDS:
            base_strength *= 0.8

        # Adjust if same analyzer
        if cause.analyzer == effect.analyzer:
            base_strength *= 1.05

        return min(1.0, base_strength)

    def _build_incident_chains(
        self,
        events: list[CausalEvent],
        root_causes: list[CausalEvent],
    ) -> list[RootCauseIncident]:
        """Build possible incident chains (EXPERIMENTAL - not proven)."""
        incidents = []

        for root_cause in root_causes:
            incident = RootCauseIncident(
                incident_id=f"incident_{root_cause.analyzer}_{int(root_cause.timestamp.timestamp())}",
                root_cause=root_cause,
                pattern_match_strength=0.90,
                start_time=root_cause.timestamp,
                end_time=root_cause.timestamp,
                causality_status="POSSIBLE",
            )

            incident.add_event(root_cause)

            # Find all events that follow this root cause
            for event in events:
                if event.timestamp <= root_cause.timestamp:
                    continue

                # Check temporal proximity
                time_delta = (event.timestamp - root_cause.timestamp).total_seconds()
                if time_delta > self.MEDIUM_TERM_THRESHOLD_SECONDS:
                    continue

                # Try to build possible causal chain
                previous_event = incident.events[-1] if incident.events else root_cause

                if self._is_causal(previous_event, event):
                    strength = self._calculate_pattern_strength(previous_event, event)
                    link = CausalityLink(
                        cause=previous_event,
                        effect=event,
                        pattern_match_strength=strength,
                        reason=self._explain_causality(previous_event, event),
                    )
                    incident.add_causal_link(link)
                    incident.add_event(event)

            incident.calculate_duration()
            incidents.append(incident)

        return incidents

    def _explain_causality(self, cause: CausalEvent, effect: CausalEvent) -> str:
        """Generate human-readable explanation of causality."""
        time_delta = (effect.timestamp - cause.timestamp).total_seconds()

        pattern_key = (cause.kind, effect.kind)
        if pattern_key in self.KNOWN_PATTERNS:
            return f"{cause.kind} → {effect.kind} (known pattern)"

        if cause.analyzer == effect.analyzer:
            return f"{cause.analyzer}: {cause.kind} cascades to {effect.kind}"

        if time_delta <= self.IMMEDIATE_THRESHOLD_SECONDS:
            return f"{cause.kind} (rapid cascade) → {effect.kind} ({time_delta:.1f}s)"

        return f"{cause.kind} → {effect.kind} ({time_delta:.1f}s later)"


def incident_to_dict(incident: RootCauseIncident) -> dict[str, Any]:
    """Convert possible incident chain to dict (EXPERIMENTAL - not proven).

    ⚠️  pattern_match_strength is NOT a probability of causation.
    causality_status indicates level of evidence, not proof.
    """
    return {
        "incident_id": incident.incident_id,
        "causality_status": incident.causality_status,
        "warning": "This is EXPERIMENTAL - temporal proximity does NOT prove causation",
        "root_cause": {
            "analyzer": incident.root_cause.analyzer,
            "kind": incident.root_cause.kind,
            "level": incident.root_cause.level,
            "message": incident.root_cause.message,
            "timestamp": incident.root_cause.timestamp.isoformat(),
            "pattern_match_strength": incident.pattern_match_strength,
        },
        "chain": [
            {
                "cause": link.cause.kind,
                "effect": link.effect.kind,
                "pattern_match_strength": link.pattern_match_strength,
                "note": "pattern_match_strength is NOT a causal probability",
                "reason": link.reason,
                "time_delta_seconds": link.time_delta_seconds,
                "cause_analyzer": link.cause.analyzer,
                "effect_analyzer": link.effect.analyzer,
            }
            for link in incident.causal_links
        ],
        "events": [
            {
                "analyzer": e.analyzer,
                "kind": e.kind,
                "level": e.level,
                "message": e.message,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in incident.events
        ],
        "duration_seconds": incident.duration_seconds,
        "affected_analyzers": list(incident.affected_analyzers),
        "total_impact": incident.total_impact,
        "chain_pattern_strength": incident.chain_confidence(),
        "start_time": incident.start_time.isoformat() if incident.start_time else None,
        "end_time": incident.end_time.isoformat() if incident.end_time else None,
    }
