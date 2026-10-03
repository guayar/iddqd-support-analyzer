"""Visual regression: Screenshot diffs, CSS changes, layout shifts."""
from __future__ import annotations
import collections, re
from typing import Any

VISUAL_DIFF_RE = re.compile(r'(?:visual|diff|difference)[:\s=]*(\d+)(?:\.\d+)?%', re.IGNORECASE)
REGRESSION_RE = re.compile(r'(?:regression|changed|differs)', re.IGNORECASE)

class VisualCorrelator:
    def __init__(self):
        self.visual_diffs: list[dict] = []
        self.regressions: int = 0
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.first_error_line: int = 0
        self.total_lines = 0

    def hint(self, line: str) -> bool:
        return any(kw in line.lower() for kw in ['visual', 'screenshot', 'regression', 'diff', 'pixel'])

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if not self.hint(line): return
        if any(kw in line.lower() for kw in ['differ', 'regress']): self.first_error_line = idx
        
        if m := VISUAL_DIFF_RE.search(line):
            self.findings['visual_diff'] += 1
            self.visual_diffs.append({'diff_pct': float(m.group(1))})
        if REGRESSION_RE.search(line):
            self.findings['regression'] += 1
            self.regressions += 1

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        findings = []
        first_line = self.first_error_line if self.first_error_line > 0 else 0
        
        if self.findings['visual_diff'] > 0:
            avg_diff = sum(d['diff_pct'] for d in self.visual_diffs) / len(self.visual_diffs)
            findings.append({'signature': f"Visual diffs (avg {avg_diff:.1f}%)", 'count': len(self.visual_diffs), 'level': 'WARN', 'category': 'visual', 'kind': 'visual_diff', 'first_line': first_line, 'codes': {}})
        if self.findings['regression'] > 0:
            findings.append({'signature': f"Visual regressions ({self.regressions})", 'count': self.regressions, 'level': 'ERROR', 'category': 'visual', 'kind': 'regression', 'first_line': first_line, 'codes': {}})
        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return len(self.visual_diffs)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if REGRESSION_RE.search(line): return 'ERROR', 'visual', 'regression'
        if VISUAL_DIFF_RE.search(line): return 'WARN', 'visual', 'diff'
        return None

    def finding_component(self, line: str) -> str | None:
        if REGRESSION_RE.search(line): return 'Visual regression'
        if VISUAL_DIFF_RE.search(line): return 'Visual diff'
        return None

    def context_pid(self, line: str) -> str | None:
        return None
