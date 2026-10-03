"""User journey tracking: Session correlation, funnel completion, dropouts."""
from __future__ import annotations
import collections, re
from typing import Any

SESSION_RE = re.compile(r'(?:session|user_id)[:\s=]*([a-z0-9_]+)', re.IGNORECASE)
ACTION_RE = re.compile(r'(?:action|event)[:\s=]*([a-z_]+)', re.IGNORECASE)
DROPOUT_RE = re.compile(r'(?:dropout|abandon|exit)', re.IGNORECASE)

class UserJourneyCorrelator:
    def __init__(self):
        self.sessions: dict[str, int] = collections.defaultdict(int)
        self.actions: int = 0
        self.dropouts: int = 0
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.total_lines = 0

    def hint(self, line: str) -> bool:
        return any(kw in line.lower() for kw in ['session', 'user', 'action', 'journey', 'funnel', 'dropout'])

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if not self.hint(line): return
        
        if m := SESSION_RE.search(line):
            self.sessions[m.group(1)] += 1
        if ACTION_RE.search(line):
            self.findings['action'] += 1
            self.actions += 1
        if DROPOUT_RE.search(line):
            self.findings['dropout'] += 1
            self.dropouts += 1

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        findings = []
        
        if self.findings['dropout'] > 0:
            findings.append({'signature': f"User dropouts ({self.dropouts})", 'count': self.dropouts, 'level': 'WARN', 'category': 'analytics', 'kind': 'dropout', 'first_line': 0, 'codes': {}})
        if self.findings['action'] > 0:
            findings.append({'signature': f"User actions ({self.actions})", 'count': self.actions, 'level': 'INFO', 'category': 'analytics', 'kind': 'action', 'first_line': 0, 'codes': {}})
        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return len(self.sessions)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if DROPOUT_RE.search(line): return 'WARN', 'user', 'dropout'
        return None

    def finding_component(self, line: str) -> str | None:
        if DROPOUT_RE.search(line): return 'User dropout'
        return None

    def context_pid(self, line: str) -> str | None:
        if m := SESSION_RE.search(line): return m.group(1)[:16]
        return None
