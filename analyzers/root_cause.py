"""Root cause analysis engine for v0.22.

Detects causality chains across incidents:
  - Temporal proximity (event A → event B within N seconds?)
  - State correlation (error A + error B = root cause C?)
  - Resource correlation (CPU spike → memory spike → timeout?)
  - Service correlation (Service A down → Service B fails?)

Builds incident chains with confidence scores and exception tracking.
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
    """Link between two events (cause → effect)."""

    cause: CausalEvent
    effect: CausalEvent
    confidence: float  # 0.0-1.0
    reason: str  # Why we think they're connected
    time_delta_seconds: float = 0.0

    def __post_init__(self):
        """Calculate time delta."""
        self.time_delta_seconds = (self.effect.timestamp - self.cause.timestamp).total_seconds()


@dataclass
class RootCauseIncident:
    """Complete incident with root cause chain."""

    incident_id: str
    root_cause: CausalEvent
    root_cause_confidence: float
    events: list[CausalEvent] = field(default_factory=list)
    causal_links: list[CausalityLink] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    affected_analyzers: set[str] = field(default_factory=set)
    total_impact: int = 0  # Total events/errors
    confidence_chain: list[float] = field(default_factory=list)
    exception_chain: list[str] = field(default_factory=list)

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
        """Add causal relationship."""
        self.causal_links.append(link)
        self.confidence_chain.append(link.confidence)

    def calculate_duration(self) -> None:
        """Calculate incident duration."""
        if self.start_time and self.end_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()

    def chain_confidence(self) -> float:
        """Average confidence across all links."""
        if not self.confidence_chain:
            return 0.0
        return sum(self.confidence_chain) / len(self.confidence_chain)


class RootCauseAnalyzer:
    """Analyze root causes across findings."""

    # Time thresholds for causality detection
    IMMEDIATE_THRESHOLD_SECONDS = 5  # Events within 5s are likely connected
    SHORT_TERM_THRESHOLD_SECONDS = 30  # Events within 30s might be connected
    MEDIUM_TERM_THRESHOLD_SECONDS = 300  # Events within 5min could be connected

    # Causality patterns
    KNOWN_CHAINS = {
        # (cause_kind, effect_kind) → base_confidence
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
        """Convert findings to events."""
        events = []

        for finding in findings:
            # Parse timestamp if available
            timestamp = datetime.now()
            if "timestamp" in finding:
                try:
                    timestamp = datetime.fromisoformat(finding["timestamp"])
                except (ValueError, TypeError):
                    pass

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
        """Check if cause event likely caused effect event."""
        time_delta = (effect.timestamp - cause.timestamp).total_seconds()

        # Must be within reasonable time window
        if time_delta < 0 or time_delta > self.MEDIUM_TERM_THRESHOLD_SECONDS:
            return False

        # Check known patterns
        pattern_key = (cause.kind, effect.kind)
        if pattern_key in self.KNOWN_CHAINS:
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

    def _calculate_confidence(self, cause: CausalEvent, effect: CausalEvent) -> float:
        """Calculate confidence that cause → effect."""
        pattern_key = (cause.kind, effect.kind)
        base_confidence = self.KNOWN_CHAINS.get(pattern_key, 0.5)

        time_delta = (effect.timestamp - cause.timestamp).total_seconds()

        # Boost confidence if events are very close
        if time_delta <= self.IMMEDIATE_THRESHOLD_SECONDS:
            base_confidence *= 1.1
        # Reduce confidence if far apart
        elif time_delta > self.SHORT_TERM_THRESHOLD_SECONDS:
            base_confidence *= 0.8

        # Boost if same analyzer or related analyzers
        if cause.analyzer == effect.analyzer:
            base_confidence *= 1.05

        return min(1.0, base_confidence)

    def _build_incident_chains(
        self,
        events: list[CausalEvent],
        root_causes: list[CausalEvent],
    ) -> list[RootCauseIncident]:
        """Build complete incident chains from root causes."""
        incidents = []

        for root_cause in root_causes:
            incident = RootCauseIncident(
                incident_id=f"incident_{root_cause.analyzer}_{int(root_cause.timestamp.timestamp())}",
                root_cause=root_cause,
                root_cause_confidence=0.90,  # Root causes are high confidence
                start_time=root_cause.timestamp,
                end_time=root_cause.timestamp,
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

                # Try to build causal chain
                previous_event = incident.events[-1] if incident.events else root_cause

                if self._is_causal(previous_event, event):
                    confidence = self._calculate_confidence(previous_event, event)
                    link = CausalityLink(
                        cause=previous_event,
                        effect=event,
                        confidence=confidence,
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
        if pattern_key in self.KNOWN_CHAINS:
            return f"{cause.kind} → {effect.kind} (known pattern)"

        if cause.analyzer == effect.analyzer:
            return f"{cause.analyzer}: {cause.kind} cascades to {effect.kind}"

        if time_delta <= self.IMMEDIATE_THRESHOLD_SECONDS:
            return f"{cause.kind} (rapid cascade) → {effect.kind} ({time_delta:.1f}s)"

        return f"{cause.kind} → {effect.kind} ({time_delta:.1f}s later)"


def incident_to_dict(incident: RootCauseIncident) -> dict[str, Any]:
    """Convert incident to dict for JSON serialization."""
    return {
        "incident_id": incident.incident_id,
        "root_cause": {
            "analyzer": incident.root_cause.analyzer,
            "kind": incident.root_cause.kind,
            "level": incident.root_cause.level,
            "message": incident.root_cause.message,
            "timestamp": incident.root_cause.timestamp.isoformat(),
            "confidence": incident.root_cause_confidence,
        },
        "chain": [
            {
                "cause": link.cause.kind,
                "effect": link.effect.kind,
                "confidence": link.confidence,
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
        "chain_confidence": incident.chain_confidence(),
        "start_time": incident.start_time.isoformat(),
        "end_time": incident.end_time.isoformat(),
    }
