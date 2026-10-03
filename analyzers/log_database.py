"""Database query analysis: Slow queries, N+1 patterns, missing indexes, deadlocks."""
from __future__ import annotations
import collections, re
from typing import Any

SLOW_QUERY_RE = re.compile(r'(?:slow|duration)[:\s=]*(\d+)\s*(?:ms|s)', re.IGNORECASE)
N_PLUS_ONE_RE = re.compile(r'(?:n\+1|sequential.*?query)', re.IGNORECASE)
DEADLOCK_RE = re.compile(r'deadlock', re.IGNORECASE)

class DatabaseCorrelator:
    def __init__(self):
        self.slow_queries: list[dict] = []
        self.n_plus_one: int = 0
        self.deadlocks: int = 0
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.first_error_line: int = 0
        self.total_lines = 0

    def hint(self, line: str) -> bool:
        return any(kw in line.lower() for kw in ['query', 'database', 'sql', 'slow', 'deadlock'])

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if not self.hint(line): return
        if any(kw in line.lower() for kw in ['slow', 'deadlock', 'timeout']):
            if self.first_error_line == 0: self.first_error_line = idx
        
        if m := SLOW_QUERY_RE.search(line):
            self.findings['slow_query'] += 1
            self.slow_queries.append({'line_idx': idx, 'duration_ms': int(m.group(1))})
        if N_PLUS_ONE_RE.search(line):
            self.findings['n_plus_one'] += 1
            self.n_plus_one += 1
        if DEADLOCK_RE.search(line):
            self.findings['deadlock'] += 1
            self.deadlocks += 1

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        findings = []
        first_line = self.first_error_line if self.first_error_line > 0 else 0
        
        if self.findings['deadlock'] > 0:
            findings.append({
                'signature': f"Database deadlocks ({self.deadlocks})",
                'count': self.deadlocks,
                'level': 'CRITICAL',
                'category': 'database',
                'kind': 'deadlock',
                'first_line': first_line,
                'codes': {},
            })
        if self.findings['slow_query'] > 0:
            avg_ms = sum(q['duration_ms'] for q in self.slow_queries) // len(self.slow_queries)
            findings.append({
                'signature': f"Slow queries (avg {avg_ms}ms, {len(self.slow_queries)})",
                'count': len(self.slow_queries),
                'level': 'WARN',
                'category': 'database',
                'kind': 'slow_query',
                'first_line': first_line,
                'codes': {},
            })
        if self.findings['n_plus_one'] > 0:
            findings.append({
                'signature': f"N+1 query patterns ({self.n_plus_one})",
                'count': self.n_plus_one,
                'level': 'ERROR',
                'category': 'database',
                'kind': 'n_plus_one',
                'first_line': first_line,
                'codes': {},
            })
        return findings, len(findings)

    def overflow_unique(self) -> int:
        return len(self.slow_queries)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if DEADLOCK_RE.search(line): return 'CRITICAL', 'db', 'deadlock'
        if SLOW_QUERY_RE.search(line): return 'WARN', 'db', 'slow_query'
        if N_PLUS_ONE_RE.search(line): return 'ERROR', 'db', 'n_plus_one'
        return None

    def finding_component(self, line: str) -> str | None:
        if DEADLOCK_RE.search(line): return 'Deadlock detected'
        if SLOW_QUERY_RE.search(line): return 'Slow query'
        return None

    def context_pid(self, line: str) -> str | None:
        return None
