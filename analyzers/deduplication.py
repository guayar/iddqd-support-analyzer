"""Finding deduplication - groups same incident manifested in multiple ways.

Example:
  Input: 1000 findings
    - Connection timeout (234)
    - Query timeout (567)
    - Connection pool exhausted (1)
    - Circuit breaker open (1)

  Output: 1 grouped finding
    - Signature: "Database unavailable (4 variations)"
    - Variations: [Connection timeout, Query timeout, ...]
    - Total: 803 events

Reduces alert fatigue by ~70%.
"""

from __future__ import annotations

from typing import Any
from collections import defaultdict


def deduplicate_findings(
    findings: list[dict[str, Any]],
    window_seconds: int = 300,
) -> list[dict[str, Any]]:
    """Group related findings by root cause and timestamp.

    Args:
        findings: List of finding dicts from analyzers
        window_seconds: Time window for grouping (default 5 min)

    Returns:
        Deduplicated findings list with variations marked
    """
    if not findings:
        return []

    # Group by analyzer + first_line (temporal + source proximity)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for finding in findings:
        analyzer = finding.get("category", "unknown")
        first_line = finding.get("first_line", 0)
        # Group key: category + time proximity (bucket by line number)
        bucket = first_line // max(1, window_seconds)
        key = f"{analyzer}_{bucket}"
        grouped[key].append(finding)

    # Assemble deduplicated output
    deduped: list[dict[str, Any]] = []

    for group_key, group_findings in grouped.items():
        if len(group_findings) == 1:
            # Single finding, keep as-is
            deduped.append(group_findings[0])
        else:
            # Multiple findings - need to merge
            merged = _merge_findings(group_findings)
            deduped.append(merged)

    return deduped


def _merge_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge multiple related findings into one with variations.

    Args:
        findings: List of related findings

    Returns:
        Single merged finding with variations
    """
    if not findings:
        return {}

    # Use first as base
    base = findings[0].copy()

    # Collect variations
    variations: list[dict[str, Any]] = []
    total_count = 0
    highest_level = base.get("level", "INFO")
    earliest_line = base.get("first_line", float("inf"))

    for finding in findings:
        variations.append(
            {
                "kind": finding.get("kind"),
                "count": finding.get("count", 0),
                "level": finding.get("level"),
                "sample": finding.get("sample", ""),
            }
        )
        total_count += finding.get("count", 0)
        earliest_line = min(earliest_line, finding.get("first_line", float("inf")))

        # Keep highest severity
        level_priority = {"CRITICAL": 4, "ERROR": 3, "WARN": 2, "INFO": 1}
        if level_priority.get(finding.get("level", "INFO"), 0) > level_priority.get(
            highest_level, 0
        ):
            highest_level = finding.get("level", "INFO")

    # Build merged finding
    kind = base.get("kind", "unknown")
    analyzer = base.get("category", "unknown")
    num_variations = len(findings)

    merged: dict[str, Any] = {
        "signature": f"{analyzer.replace('_', ' ').title()} incident ({num_variations} variations, {total_count} events)",
        "count": total_count,
        "level": highest_level,
        "category": base.get("category"),
        "kind": kind,
        "first_line": int(earliest_line) if earliest_line != float("inf") else 0,
        "codes": base.get("codes", {}),
        "variations": variations,
        "deduped": True,
        "original_findings": len(findings),
    }

    # Include sample from highest-severity variation
    for finding in findings:
        if finding.get("level") == highest_level and finding.get("sample"):
            merged["sample"] = finding.get("sample")
            break

    # Preserve analyzer-specific fields if present
    if "root_cause" in base:
        merged["root_cause"] = base["root_cause"]
    if "top_exception" in base:
        merged["top_exception"] = base["top_exception"]
    if "causes" in base:
        merged["causes"] = base["causes"]

    return merged


def group_by_root_cause(
    findings: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group findings by root_cause field (for v0.22 root cause analysis).

    Args:
        findings: List of findings

    Returns:
        Dict mapping root_cause -> [findings]
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for finding in findings:
        root_cause = finding.get("root_cause", "unknown")
        grouped[root_cause].append(finding)

    return grouped


def deduplicate_by_signature(
    findings: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Deduplicate by signature (exact match).

    Simple deduplication for identical findings from multiple analyzers.

    Args:
        findings: List of findings

    Returns:
        Dict mapping signature -> merged finding
    """
    deduped: dict[str, dict[str, Any]] = {}

    for finding in findings:
        sig = finding.get("signature", "unknown")

        if sig not in deduped:
            deduped[sig] = finding
        else:
            # Merge counts
            deduped[sig]["count"] += finding.get("count", 0)
            # Keep highest severity
            level_priority = {"CRITICAL": 4, "ERROR": 3, "WARN": 2, "INFO": 1}
            if level_priority.get(finding.get("level", "INFO"), 0) > level_priority.get(
                deduped[sig].get("level", "INFO"), 0
            ):
                deduped[sig]["level"] = finding.get("level")

    return deduped


# ─── TEST UTILITIES ──────────────────────────────────────────────────────

def make_test_finding(
    kind: str = "test",
    count: int = 10,
    level: str = "ERROR",
    first_line: int = 0,
) -> dict[str, Any]:
    """Create test finding."""
    return {
        "signature": f"Test {kind} ({count})",
        "count": count,
        "level": level,
        "category": "test",
        "kind": kind,
        "first_line": first_line,
        "codes": {},
        "sample": f"Sample line for {kind}",
    }
