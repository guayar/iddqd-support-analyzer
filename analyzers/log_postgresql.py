"""PostgreSQL log correlator: deadlocks, query timeouts, connection exhaustion.

Real escalation scenarios:
- Deadlock detected (concurrent transaction conflict)
- Statement timeout (long-running query)
- Connection pool exhaustion (too many clients)
- Authentication failures (password/role issues)
- Disk/checkpoint issues (write performance)
"""

from __future__ import annotations

import collections
import re
from typing import Any

# PostgreSQL log formats
PG_TIMESTAMP_RE = re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})')
PG_LEVEL_RE = re.compile(r'\s+(ERROR|WARNING|NOTICE|LOG|DEBUG|FATAL|PANIC)\s+')
PG_USER_RE = re.compile(r'user=([a-zA-Z0-9_\-]+)', re.I)
PG_DATABASE_RE = re.compile(r'database=([a-zA-Z0-9_\-]+)', re.I)
PG_PID_RE = re.compile(r'\[(\d+)\]')

# PostgreSQL error keywords
DEADLOCK_KEYWORDS = [
    'deadlock detected',
    'could not serialize access',
    'concurrent update',
]

TIMEOUT_KEYWORDS = [
    'timeout',
    'statement timeout',
    'lock timeout',
    'canceling statement',
]

CONNECTION_KEYWORDS = [
    'too many connections',
    'connection limit exceeded',
    'role limit exceeded',
]

AUTH_KEYWORDS = [
    'authentication failed',
    'permission denied',
    'role.*does not exist',
    'invalid password',
]

DISK_KEYWORDS = [
    'no space left on device',
    'disk full',
    'write failed',
    'checkpoint',
]

SLOWNESS_KEYWORDS = [
    'slow query',
    'query took',
    'duration:',
]

# Query patterns
QUERY_TIME_RE = re.compile(r'duration:\s*([\d.]+)\s*ms')
QUERY_ROWS_RE = re.compile(r'rows?\s*=\s*(\d+)')


def pg_log_hint(line: str) -> bool:
    """Cheap check: PostgreSQL keywords."""
    return any(kw in line.lower() for kw in [
        'postgres', 'postgresql', 'pg', 'pgsql',
        'deadlock', 'statement timeout', 'too many connections',
        'authentication failed', 'error', 'warning'
    ])


class PostgreSQLCorrelator:
    """Correlate PostgreSQL issues."""

    def __init__(self):
        # Event tracking
        self.deadlocks: list[dict[str, Any]] = []
        self.timeouts: list[dict[str, Any]] = []
        self.connection_errors: list[dict[str, Any]] = []
        self.auth_failures: list[dict[str, Any]] = []
        self.disk_issues: list[dict[str, Any]] = []
        self.slow_queries: list[dict[str, Any]] = []

        # Aggregation
        self.user_failures: dict[str, int] = collections.defaultdict(int)
        self.database_issues: dict[str, list[str]] = collections.defaultdict(list)

        # Findings
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

        self.total_lines = 0
        self.pg_lines = 0

    def hint(self, line: str) -> bool:
        return pg_log_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not pg_log_hint(line):
            return

        self.pg_lines += 1

        # Extract context
        user_match = PG_USER_RE.search(line)
        user = user_match.group(1) if user_match else None

        db_match = PG_DATABASE_RE.search(line)
        database = db_match.group(1) if db_match else None

        pid_match = PG_PID_RE.search(line)
        pid = pid_match.group(1) if pid_match else None

        # Deadlock detection (CRITICAL)
        if any(kw in line.lower() for kw in DEADLOCK_KEYWORDS):
            self.findings['deadlock'] += 1
            self.deadlocks.append({
                'line_idx': idx,
                'user': user,
                'database': database,
                'pid': pid,
            })
            self.finding_details['deadlock'].append({
                'line_idx': idx,
                'database': database,
            })

        # Timeout detection (ERROR)
        if any(kw in line.lower() for kw in TIMEOUT_KEYWORDS):
            self.findings['timeout'] += 1
            self.timeouts.append({
                'line_idx': idx,
                'user': user,
                'database': database,
            })
            # Extract query duration if available
            time_match = QUERY_TIME_RE.search(line)
            if time_match:
                duration_ms = float(time_match.group(1))
                self.slow_queries.append({
                    'duration_ms': duration_ms,
                    'database': database,
                    'user': user,
                })
            self.finding_details['timeout'].append({
                'line_idx': idx,
                'user': user,
            })

        # Connection exhaustion (ERROR)
        if any(kw in line.lower() for kw in CONNECTION_KEYWORDS):
            self.findings['connection_exhausted'] += 1
            self.connection_errors.append({
                'line_idx': idx,
                'database': database,
            })
            self.finding_details['connection_exhausted'].append({
                'line_idx': idx,
                'database': database,
            })

        # Authentication failure (WARN)
        if any(kw in line.lower() for kw in AUTH_KEYWORDS):
            self.findings['auth_failure'] += 1
            if user:
                self.user_failures[user] += 1
            self.auth_failures.append({
                'line_idx': idx,
                'user': user,
                'database': database,
            })
            self.finding_details['auth_failure'].append({
                'line_idx': idx,
                'user': user,
            })

        # Disk issue detection (CRITICAL)
        if any(kw in line.lower() for kw in DISK_KEYWORDS):
            self.findings['disk_issue'] += 1
            self.disk_issues.append({
                'line_idx': idx,
                'database': database,
            })
            self.finding_details['disk_issue'].append({
                'line_idx': idx,
            })

        # Slow query tracking (WARN)
        if 'duration:' in line.lower():
            time_match = QUERY_TIME_RE.search(line)
            if time_match:
                duration_ms = float(time_match.group(1))
                if duration_ms > 1000:  # > 1 second
                    self.slow_queries.append({
                        'duration_ms': duration_ms,
                        'database': database,
                        'user': user,
                        'line_idx': idx,
                    })

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings."""
        findings = []

        # Deadlock (CRITICAL)
        if self.findings['deadlock'] > 0:
            findings.append({
                'level': 'CRITICAL',
                'category': 'concurrency',
                'kind': 'deadlock',
                'count': self.findings['deadlock'],
                'affected_databases': list(set(d['database'] for d in self.deadlocks if d.get('database'))),
                'remediation': 'Review transaction order; use consistent lock ordering',
            })

        # Timeouts (ERROR)
        if self.findings['timeout'] > 0:
            findings.append({
                'level': 'ERROR',
                'category': 'performance',
                'kind': 'query_timeout',
                'count': self.findings['timeout'],
                'avg_affected_users': list(set(t['user'] for t in self.timeouts if t.get('user'))),
                'remediation': 'Optimize queries; increase statement_timeout if appropriate',
            })

        # Connection exhaustion (ERROR)
        if self.findings['connection_exhausted'] > 0:
            findings.append({
                'level': 'ERROR',
                'category': 'connection',
                'kind': 'connection_exhausted',
                'count': self.findings['connection_exhausted'],
                'affected_databases': list(set(c['database'] for c in self.connection_errors if c.get('database'))),
                'remediation': 'Increase max_connections; check for connection leaks',
            })

        # Auth failures (WARN)
        if self.findings['auth_failure'] > 0:
            findings.append({
                'level': 'WARN',
                'category': 'security',
                'kind': 'auth_failure',
                'count': self.findings['auth_failure'],
                'failed_users': list(dict(sorted(self.user_failures.items(), key=lambda x: x[1], reverse=True)[:5]).keys()),
                'remediation': 'Verify credentials; check role permissions',
            })

        # Disk issue (CRITICAL)
        if self.findings['disk_issue'] > 0:
            findings.append({
                'level': 'CRITICAL',
                'category': 'storage',
                'kind': 'disk_issue',
                'count': self.findings['disk_issue'],
                'remediation': 'Free disk space immediately; check VACUUM status',
            })

        # Slow queries (WARN)
        if len(self.slow_queries) >= 3:
            avg_duration = sum(q['duration_ms'] for q in self.slow_queries) / len(self.slow_queries)
            findings.append({
                'level': 'WARN',
                'category': 'performance',
                'kind': 'slow_queries',
                'count': len(self.slow_queries),
                'avg_duration_ms': avg_duration,
                'max_duration_ms': max(q['duration_ms'] for q in self.slow_queries),
                'remediation': 'Run EXPLAIN; add indexes; review query plans',
            })

        return findings, len(findings)

    def overflow_unique(self) -> int:
        return len(self.database_issues)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if 'deadlock' in line.lower():
            return 'CRITICAL', 'concurrency', 'deadlock'
        if 'timeout' in line.lower():
            return 'ERROR', 'performance', 'timeout'
        if 'too many connections' in line.lower():
            return 'ERROR', 'connection', 'exhaustion'
        if 'no space left' in line.lower():
            return 'CRITICAL', 'storage', 'disk_full'
        return None

    def finding_component(self, line: str) -> str | None:
        if 'deadlock' in line.lower():
            return 'Database deadlock detected'
        if 'timeout' in line.lower():
            return 'Query timeout'
        if 'too many connections' in line.lower():
            return 'Connection pool exhausted'
        if 'no space' in line.lower():
            return 'Disk space exhausted'
        return None

    def context_pid(self, line: str) -> str | None:
        user_match = PG_USER_RE.search(line)
        return user_match.group(1)[:16] if user_match else None
