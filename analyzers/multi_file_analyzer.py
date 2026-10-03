"""Multi-file log analysis for v0.22 (EXPERIMENTAL).

⚠️  EXPERIMENTAL FEATURE - NOT PROVEN MULTI-FILE ANALYSIS

Cross-file correlation requires REAL TIMESTAMPS to establish chronological order.
Line numbers from different files have NO temporal relationship.
Cross-file causality requires matching timestamps - otherwise marked UNKNOWN.

Temporal proximity within a file is valid; across files requires timestamps.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime, timezone
import json

from .root_cause import RootCauseAnalyzer, incident_to_dict
from .deduplication import deduplicate_findings


class MultiFileAnalyzer:
    """Analyze multiple log files together."""

    def __init__(self):
        """Initialize multi-file analyzer."""
        self.root_cause_analyzer = RootCauseAnalyzer()

    def analyze_files(
        self,
        file_contents: dict[str, str],
    ) -> dict[str, Any]:
        """Analyze multiple log files together.

        Args:
            file_contents: Dict mapping filename → file content

        Returns:
            Analysis result with cross-file incidents
        """
        # Import here to avoid circular dependency
        from .logs import analyze_log_text

        all_findings = []
        file_analyses = {}

        # Analyze each file individually
        for filename, content in file_contents.items():
            result = analyze_log_text(content)
            file_analyses[filename] = result
            findings = result.get("incidents", [])

            # Tag findings with source file
            for finding in findings:
                finding["_source_file"] = filename
            all_findings.extend(findings)

        # Deduplicate findings
        deduped_findings = deduplicate_findings(all_findings, sequence_distance=300)

        # Perform root cause analysis
        root_cause_incidents = self.root_cause_analyzer.analyze(deduped_findings)

        # Build cross-file summary
        summary = self._build_summary(file_analyses, deduped_findings, root_cause_incidents)

        return summary

    def _build_summary(
        self,
        file_analyses: dict[str, Any],
        findings: list[dict[str, Any]],
        root_cause_incidents: list,
    ) -> dict[str, Any]:
        """Build comprehensive cross-file analysis summary."""
        # Calculate metrics
        total_findings = sum(len(a.get("incidents", [])) for a in file_analyses.values())
        total_lines = sum(a.get("line_count", 0) for a in file_analyses.values())

        # Group findings by analyzer
        by_analyzer = {}
        for finding in findings:
            analyzer = finding.get("category", "unknown")
            if analyzer not in by_analyzer:
                by_analyzer[analyzer] = []
            by_analyzer[analyzer].append(finding)

        # Build timeline
        timeline_events = self._build_timeline(findings)

        return {
            "summary": {
                "total_files": len(file_analyses),
                "total_findings": total_findings,
                "deduped_findings": len(findings),
                "total_lines_analyzed": total_lines,
                "root_cause_incidents": len(root_cause_incidents),
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "files": {
                name: {
                    "incident_count": len(a.get("incidents", [])),
                    "line_count": a.get("line_count", 0),
                    "analyzers_active": list(
                        set(f.get("category") for f in a.get("incidents", []))
                    ),
                }
                for name, a in file_analyses.items()
            },
            "by_analyzer": {
                analyzer: {
                    "finding_count": len(f),
                    "top_kinds": self._top_kinds(f),
                    "severity_distribution": self._severity_dist(f),
                }
                for analyzer, f in by_analyzer.items()
            },
            "root_cause_incidents": [
                incident_to_dict(incident) for incident in root_cause_incidents
            ],
            "timeline": timeline_events,
            "findings": findings,
            "cross_file_insights": self._extract_cross_file_insights(
                findings, root_cause_incidents
            ),
        }

    def _build_timeline(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build timeline - only cross-file ordering if timestamps exist.

        ⚠️  WARNING: Without real timestamps, cross-file order is UNKNOWN.
        Line numbers from different files have no temporal relationship.
        """
        timeline = []
        has_timestamps = any("timestamp" in f for f in findings)

        for finding in findings:
            source_file = finding.get("_source_file", "unknown")
            timestamp = finding.get("timestamp", "UNKNOWN")

            # For cross-file ordering, only use real timestamps
            if not has_timestamps and finding.get("_source_file"):
                # Multiple files without timestamps - order within files only
                sequence = finding.get("first_line", 0)
                sort_key = (source_file, sequence)
            elif timestamp != "UNKNOWN":
                sort_key = (0, timestamp)  # Timestamp available
            else:
                sort_key = (1, 0)  # No timestamp

            event = {
                "sequence": finding.get("first_line", 0),
                "analyzer": finding.get("category", "unknown"),
                "kind": finding.get("kind", "unknown"),
                "level": finding.get("level", "INFO"),
                "signature": finding.get("signature", "Unknown"),
                "count": finding.get("count", 0),
                "source": source_file,
                "timestamp": timestamp,
                "cross_file_order": "UNKNOWN" if not has_timestamps and len(set(f.get("_source_file") for f in findings)) > 1 else "WITHIN_FILE",
            }
            timeline.append((sort_key, event))

        # Sort by key, then extract event
        timeline.sort(key=lambda x: (isinstance(x[0][1], str), x[0]))
        return [event for _, event in timeline]

    def _top_kinds(self, findings: list[dict[str, Any]]) -> list[str]:
        """Get top incident kinds by frequency."""
        kinds = {}
        for finding in findings:
            kind = finding.get("kind", "unknown")
            kinds[kind] = kinds.get(kind, 0) + 1

        # Sort by count
        sorted_kinds = sorted(kinds.items(), key=lambda x: x[1], reverse=True)
        return [k for k, _ in sorted_kinds[:5]]

    def _severity_dist(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        """Get severity level distribution."""
        dist = {"CRITICAL": 0, "ERROR": 0, "WARN": 0, "INFO": 0}
        for finding in findings:
            level = finding.get("level", "INFO")
            dist[level] = dist.get(level, 0) + 1
        return dist

    def _extract_cross_file_insights(
        self,
        findings: list[dict[str, Any]],
        root_cause_incidents: list,
    ) -> dict[str, Any]:
        """Extract insights from cross-file analysis (EXPERIMENTAL).

        ⚠️  WARNING: Correlation strength is based on pattern-match heuristics,
        NOT statistical probabilities. Causality is NOT proven by correlation.
        """
        # Collect affected sources
        sources = set()
        for finding in findings:
            if "_source_file" in finding:
                sources.add(finding["_source_file"])

        # Identify possible cascading failures
        cascades = []
        if len(root_cause_incidents) > 0:
            for incident in root_cause_incidents:
                if len(incident.causal_links) > 1:
                    cascades.append(
                        {
                            "root": incident.root_cause.kind,
                            "depth": len(incident.causal_links),
                            "pattern_match_level": "EXPERIMENTAL",
                            "analyzers_involved": list(incident.affected_analyzers),
                            "note": "Possible pattern - not proven causality",
                        }
                    )

        # Calculate pattern-match strength (NOT correlation probability)
        pattern_strength = "WEAK"
        if len(sources) > 1 and len(root_cause_incidents) > 0:
            avg_strength = sum(
                incident.chain_confidence() for incident in root_cause_incidents
            ) / len(root_cause_incidents)
            if avg_strength > 0.85:
                pattern_strength = "STRONG_PATTERN_MATCH"
            elif avg_strength > 0.70:
                pattern_strength = "MODERATE_PATTERN_MATCH"

        return {
            "affected_sources": list(sources),
            "possible_cascades": cascades,
            "pattern_match_strength": pattern_strength,
            "warning": "Pattern matches are NOT proof of causation",
            "cross_analyzer_incidents": len(
                [i for i in root_cause_incidents if len(i.affected_analyzers) > 1]
            ),
            "key_finding": self._summarize_key_finding(root_cause_incidents),
        }

    def _summarize_key_finding(self, incidents: list) -> str:
        """Generate summary of strongest pattern match (EXPERIMENTAL).

        ⚠️  NOTE: This is pattern-match strength, not proof of causation.
        """
        if not incidents:
            return "No patterns detected"

        # Find incident with strongest pattern match
        best = max(incidents, key=lambda i: i.chain_confidence())

        if best.chain_confidence() > 0.85:
            return f"STRONG pattern match: {best.root_cause.kind} followed by events across {len(best.affected_analyzers)} components (not proven causal)"
        elif best.chain_confidence() > 0.70:
            return f"MODERATE pattern match: {best.root_cause.kind} correlated with {len(best.affected_analyzers)} components (investigate further)"
        else:
            return f"WEAK pattern match: {best.root_cause.kind} may be related (requires manual verification)"


def merge_log_files(
    *file_contents: str,
    filenames: list[str] | None = None,
) -> dict[str, Any]:
    """Convenient function to analyze multiple log files.

    Args:
        *file_contents: Log file contents (strings)
        filenames: Optional filenames for labeling (defaults to file_0, file_1, ...)

    Returns:
        Cross-file analysis result
    """
    if not filenames:
        filenames = [f"file_{i}" for i in range(len(file_contents))]

    file_dict = dict(zip(filenames, file_contents))

    analyzer = MultiFileAnalyzer()
    return analyzer.analyze_files(file_dict)
