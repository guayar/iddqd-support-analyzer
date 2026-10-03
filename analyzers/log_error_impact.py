"""Error impact assessment: Users affected, outage duration, recovery time."""
from __future__ import annotations
import collections, re
from typing import Any

ERROR_RE = re.compile(r'(?:error|outage|unavailable)', re.IGNORECASE)
USERS_RE = re.compile(r'users?.*?(?:affected|impact)[:\s=]*(\d+)', re.IGNORECASE)
DURATION_RE = re.compile(r'(?:duration|lasted)[:\s=]*(\d+)\s*(?:s|m|ms)', re.IGNORECASE)

class ErrorImpactCorrelator:
    def __init__(self):
        self.errors: int = 0
        self.users_affected: int = 0
        self.max_duration: int = 0
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.first_error_line: int = 0
        self.total_lines = 0

    def hint(self, line: str) -> bool:
        return any(kw in line.lower() for kw in ['error', 'outage', 'impact', 'affected', 'unavailable'])

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if not self.hint(line): return
        if any(kw in line.lower() for kw in ['error', 'outage', 'unavailable']):
            if self.first_error_line == 0: self.first_error_line = idx
        
        if ERROR_RE.search(line):
            self.findings['error'] += 1
            self.errors += 1
        if m := USERS_RE.search(line):
            self.users_affected = max(self.users_affected, int(m.group(1)))
        if m := DURATION_RE.search(line):
            self.max_duration = max(self.max_duration, int(m.group(1)))

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        findings = []
        first_line = self.first_error_line if self.first_error_line > 0 else 0
        
        if self.findings['error'] > 0:
            findings.append({'signature': f"Error events ({self.errors}, {self.users_affected} users, {self.max_duration}s)", 'count': self.errors, 'level': 'CRITICAL' if self.users_affected > 100 else 'ERROR', 'category': 'incident', 'kind': 'error_impact', 'first_line': first_line, 'codes': {}})
        return findings, len(findings)

    def overflow_unique(self) -> int:
        return self.findings['error']

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if ERROR_RE.search(line): return 'ERROR', 'impact', 'error_event'
        return None

    def finding_component(self, line: str) -> str | None:
        if ERROR_RE.search(line): return 'Error event'
        return None

    def context_pid(self, line: str) -> str | None:
        return None
