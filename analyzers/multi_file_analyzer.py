"""Multi-file log analysis for v0.22.

Merges findings from multiple log files (PostgreSQL + Nginx + Docker):
  - Correlates incidents across files
  - Deduplicates by root cause
  - Reconstructs complete timeline
  - Calculates impact metrics
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
        deduped_findings = deduplicate_findings(all_findings, window_seconds=300)

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
        """Reconstruct chronological timeline of incidents."""
        timeline = []

        for finding in findings:
            first_line = finding.get("first_line", 0)
            # Approximate timestamp from line number (rough estimation)
            # In real usage, findings would have actual timestamps
            event = {
                "sequence": first_line,
                "analyzer": finding.get("category", "unknown"),
                "kind": finding.get("kind", "unknown"),
                "level": finding.get("level", "INFO"),
                "signature": finding.get("signature", "Unknown"),
                "count": finding.get("count", 0),
                "source": finding.get("_source_file", "unknown"),
            }
            timeline.append(event)

        # Sort by sequence
        timeline.sort(key=lambda x: x["sequence"])
        return timeline

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
        """Extract high-level insights from cross-file analysis."""
        # Collect affected sources
        sources = set()
        for finding in findings:
            if "_source_file" in finding:
                sources.add(finding["_source_file"])

        # Identify cascading failures
        cascades = []
        if len(root_cause_incidents) > 0:
            for incident in root_cause_incidents:
                if len(incident.causal_links) > 1:
                    cascades.append(
                        {
                            "root": incident.root_cause.kind,
                            "depth": len(incident.causal_links),
                            "analyzers_involved": list(incident.affected_analyzers),
                        }
                    )

        # Calculate correlation strength
        correlation_strength = "WEAK"
        if len(sources) > 1 and len(root_cause_incidents) > 0:
            avg_confidence = sum(
                incident.chain_confidence() for incident in root_cause_incidents
            ) / len(root_cause_incidents)
            if avg_confidence > 0.85:
                correlation_strength = "STRONG"
            elif avg_confidence > 0.70:
                correlation_strength = "MODERATE"

        return {
            "affected_sources": list(sources),
            "cascading_failures": cascades,
            "correlation_strength": correlation_strength,
            "cross_analyzer_incidents": len(
                [i for i in root_cause_incidents if len(i.affected_analyzers) > 1]
            ),
            "key_finding": self._summarize_key_finding(root_cause_incidents),
        }

    def _summarize_key_finding(self, incidents: list) -> str:
        """Generate summary of most critical finding."""
        if not incidents:
            return "No critical incidents detected"

        # Find incident with highest confidence
        best = max(incidents, key=lambda i: i.chain_confidence())

        if best.chain_confidence() > 0.85:
            return f"High-confidence root cause chain: {best.root_cause.kind} → {best.duration_seconds:.1f}s impact across {len(best.affected_analyzers)} services"
        elif best.chain_confidence() > 0.70:
            return f"Moderate-confidence incident: {best.root_cause.kind} affected {len(best.affected_analyzers)} services"
        else:
            return f"Low-confidence correlation: {best.root_cause.kind} may be related to cascading failures"


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
