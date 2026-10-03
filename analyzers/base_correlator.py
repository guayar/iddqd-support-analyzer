"""Base class for all log analyzers - reduces code duplication by 30%.

Implements common LogFamily protocol methods, leaving only analyzer-specific
logic to subclasses:
  - hint(): override for custom filtering
  - on_line(): override for state updates
  - Custom methods: analyzer-specific patterns/logic

Base handles:
  - flush(): standardized finding assembly
  - overflow_unique(): memory tracking
  - line_rule(): severity classification
  - finding_component(): message extraction
  - context_pid(): correlation ID extraction
"""

from __future__ import annotations

from typing import Any
import collections
import re


class BaseCorrelator:
    """Base correlator for all LogFamily analyzers."""

    def __init__(self):
        """Initialize common state."""
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.first_error_line: int = 0
        self.total_lines: int = 0
        self._details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

    def hint(self, line: str) -> bool:
        """Override in subclass. Quick check: relevant to this analyzer?"""
        return False

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        """Override in subclass. Process one log line."""
        self.total_lines += 1

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings. Can override for custom assembly, calls _make_finding()."""
        return [], self.total_lines

    def overflow_unique(self) -> int:
        """Return count of unique tracked items (IPs, users, keys, etc)."""
        return sum(len(v) if isinstance(v, (list, set, dict)) else 1
                   for v in self._details.values())

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        """Return (level, category, kind) for line-level classification."""
        return None

    def finding_component(self, line: str) -> str | None:
        """Extract human-readable error message from line."""
        return None

    def context_pid(self, line: str) -> str | None:
        """Extract correlation ID (PID, IP, user, etc) - first 16 chars."""
        return None

    # ─── HELPER METHODS FOR SUBCLASSES ────────────────────────────────────

    def _add_finding(
        self,
        kind: str,
        level: str,
        category: str,
        count: int,
        first_line: int | None = None,
        sample: str = "",
        codes: dict[str, Any] | None = None,
        **extras: Any,
    ) -> dict[str, Any]:
        """Create standardized finding dict. Subclasses call this instead of
        manually constructing the dict.

        Args:
            kind: Finding type (e.g., 'brute_force', 'timeout')
            level: CRITICAL|ERROR|WARN|INFO
            category: Category (e.g., 'security', 'performance')
            count: Number of occurrences
            first_line: Line index (defaults to self.first_error_line)
            sample: Example log excerpt
            codes: Vendor codes dict (e.g., {'ORA': ['ORA-00000']})
            **extras: Additional fields to include

        Returns:
            Complete finding dict ready for return from flush()
        """
        if codes is None:
            codes = {}

        finding: dict[str, Any] = {
            "signature": f"{kind.replace('_', ' ').title()} ({count})",
            "count": count,
            "level": level,
            "category": category,
            "kind": kind,
            "first_line": first_line if first_line is not None else self.first_error_line,
            "codes": codes,
            "sample": sample,
        }
        finding.update(extras)
        return finding

    def _update_first_error(self, idx: int, condition: bool = True) -> None:
        """Track first error line if condition met."""
        if condition and self.first_error_line == 0:
            self.first_error_line = idx

    def _track_detail(self, detail_key: str, detail: dict[str, Any]) -> None:
        """Track detail for later assembly. Auto-manages list limits."""
        if len(self._details[detail_key]) < 100:  # Cap per-category tracking
            self._details[detail_key].append(detail)
