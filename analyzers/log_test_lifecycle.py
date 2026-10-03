"""Test fixture lifecycle correlator: Track test data creation, cleanup, state leakage.

Real QA scenarios:
- Test data creation/teardown events
- Database rollback failures
- Orphaned test data detection
- State leakage between tests
- Mock service availability
"""

from __future__ import annotations

import collections
import re
from typing import Any

# Test lifecycle patterns
TEST_SETUP_RE = re.compile(
    r'(?:test|fixture|setup).*?(?:created|started|initialized)',
    re.IGNORECASE
)
TEST_TEARDOWN_RE = re.compile(
    r'(?:test|fixture|teardown|cleanup).*?(?:completed|finished|destroyed)',
    re.IGNORECASE
)
TEST_DATA_CREATE_RE = re.compile(
    r'(?:fixture|test.*?data).*?created[:\s]+(?P<table>\w+)[:\s]*(?P<rows>\d+)?',
    re.IGNORECASE
)
TEST_DATA_CLEANUP_RE = re.compile(
    r'(?:cleanup|delete|remove).*?(?:test.*?data|fixture)[:\s]*(?P<table>\w+)?',
    re.IGNORECASE
)
DB_ROLLBACK_RE = re.compile(
    r'(?:rollback|transaction.*?(?:fail|abort|cancel))',
    re.IGNORECASE
)
ORPHANED_DATA_RE = re.compile(
    r'(?:orphan|stale|abandoned|cleanup.*?fail)',
    re.IGNORECASE
)
STATE_LEAKAGE_RE = re.compile(
    r'(?:state.*?leak|cross-test.*?pollution|isolation.*?fail)',
    re.IGNORECASE
)
MOCK_SERVICE_RE = re.compile(
    r'(?:mock|stub|fake).*?(?:service|server).*?(?:start|stop|unavailable)',
    re.IGNORECASE
)
TEST_DURATION_RE = re.compile(
    r'(?:duration|took|elapsed)[:\s=]*(\d+)\s*(?:ms|s)',
    re.IGNORECASE
)
TEST_NAME_RE = re.compile(
    r'(?:test|scenario)[:\s=]*["\']?([^"\'\s,;]+)',
    re.IGNORECASE
)


def test_lifecycle_hint(line: str) -> bool:
    """Cheap check: test lifecycle keywords."""
    return any(kw in line.lower() for kw in [
        'test', 'fixture', 'setup', 'teardown', 'cleanup', 'mock', 'database',
        'rollback', 'transaction', 'orphan', 'state', 'isolation', 'fixture_id',
        'test_user', 'test_data'
    ])


class TestLifecycleCorrelator:
    """Correlate test setup/teardown events."""

    def __init__(self):
        # Test tracking
        self.tests_started: dict[str, dict[str, Any]] = {}
        self.tests_completed: list[dict[str, Any]] = []
        self.test_durations: list[int] = []

        # Data lifecycle
        self.data_created: dict[str, int] = collections.defaultdict(int)
        self.data_cleanup_failed: list[dict[str, Any]] = []
        self.orphaned_data: list[dict[str, Any]] = []

        # Issues
        self.rollback_failures: list[dict[str, Any]] = []
        self.state_leakages: list[dict[str, Any]] = []
        self.mock_unavailable: list[dict[str, Any]] = []

        # Findings
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        self.first_error_line: int = 0

        self.total_lines = 0
        self.test_lines = 0

    def hint(self, line: str) -> bool:
        return test_lifecycle_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not test_lifecycle_hint(line):
            return

        self.test_lines += 1

        # Track first issue
        if any(kw in line.lower() for kw in ['fail', 'error', 'orphan', 'rollback', 'unavailable']):
            if self.first_error_line == 0:
                self.first_error_line = idx

        # Test setup
        if TEST_SETUP_RE.search(line):
            test_match = TEST_NAME_RE.search(line)
            test_name = test_match.group(1) if test_match else f"test_{idx}"
            self.tests_started[test_name] = {
                'line_idx': idx,
                'name': test_name,
                'start_line': idx,
            }

        # Test teardown/completion
        if TEST_TEARDOWN_RE.search(line):
            test_match = TEST_NAME_RE.search(line)
            test_name = test_match.group(1) if test_match else f"test_{idx}"
            duration_match = TEST_DURATION_RE.search(line)
            duration_ms = int(duration_match.group(1)) if duration_match else 0

            if test_name in self.tests_started:
                self.tests_started[test_name]['duration_ms'] = duration_ms
                self.test_durations.append(duration_ms)
                self.tests_completed.append(self.tests_started[test_name])
            else:
                self.tests_completed.append({
                    'line_idx': idx,
                    'name': test_name,
                    'duration_ms': duration_ms,
                })

        # Test data creation
        data_match = TEST_DATA_CREATE_RE.search(line)
        if data_match:
            table = data_match.group('table')
            rows = int(data_match.group('rows')) if data_match.group('rows') else 1
            self.data_created[table] += rows
            self.finding_details['data_created'].append({
                'line_idx': idx,
                'table': table,
                'rows': rows,
            })

        # Cleanup failures
        if 'cleanup' in line.lower() and 'fail' in line.lower():
            self.findings['cleanup_failure'] += 1
            cleanup_match = TEST_DATA_CLEANUP_RE.search(line)
            table = cleanup_match.group('table') if cleanup_match and cleanup_match.group('table') else 'unknown'

            rows_match = re.search(r'(\d+)\s*rows?', line, re.IGNORECASE)
            rows = int(rows_match.group(1)) if rows_match else 0

            self.data_cleanup_failed.append({
                'line_idx': idx,
                'table': table,
                'rows': rows,
                'line': line[:100],
            })
            self.finding_details['cleanup_failure'].append({
                'line_idx': idx,
                'table': table,
                'rows': rows,
            })

        # Orphaned data
        if ORPHANED_DATA_RE.search(line):
            self.findings['orphaned_data'] += 1
            rows_match = re.search(r'(\d+)\s*rows?', line, re.IGNORECASE)
            rows = int(rows_match.group(1)) if rows_match else 0
            table_match = re.search(r'(?:table|from)\s*=?\s*(\w+)', line, re.IGNORECASE)
            table = table_match.group(1) if table_match else 'unknown'

            self.orphaned_data.append({
                'line_idx': idx,
                'table': table,
                'rows': rows,
                'line': line[:100],
            })
            self.finding_details['orphaned_data'].append({
                'line_idx': idx,
                'table': table,
                'rows': rows,
            })

        # Rollback failures
        if DB_ROLLBACK_RE.search(line):
            self.findings['rollback_failure'] += 1
            self.rollback_failures.append({
                'line_idx': idx,
                'line': line[:100],
            })
            self.finding_details['rollback_failure'].append({
                'line_idx': idx,
            })

        # State leakage
        if STATE_LEAKAGE_RE.search(line):
            self.findings['state_leakage'] += 1
            self.state_leakages.append({
                'line_idx': idx,
                'line': line[:100],
            })
            self.finding_details['state_leakage'].append({
                'line_idx': idx,
            })

        # Mock service issues
        if MOCK_SERVICE_RE.search(line):
            if 'unavailable' in line.lower() or 'fail' in line.lower():
                self.findings['mock_unavailable'] += 1
                service_match = re.search(r'(?:service|mock)[:\s=]*(\w+)', line, re.IGNORECASE)
                service = service_match.group(1) if service_match else 'unknown'

                self.mock_unavailable.append({
                    'line_idx': idx,
                    'service': service,
                    'line': line[:100],
                })
                self.finding_details['mock_unavailable'].append({
                    'line_idx': idx,
                    'service': service,
                })

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings."""
        findings = []

        first_line = self.first_error_line if self.first_error_line > 0 else 0

        # Rollback failures (CRITICAL)
        if self.findings['rollback_failure'] > 0:
            findings.append({
                'signature': f"Database rollback failures ({self.findings['rollback_failure']} events)",
                'count': self.findings['rollback_failure'],
                'level': 'CRITICAL',
                'category': 'test-infrastructure',
                'kind': 'rollback_failure',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([rf['line'] for rf in self.rollback_failures[:3]]),
            })

        # State leakage (ERROR)
        if self.findings['state_leakage'] > 0:
            findings.append({
                'signature': f"Test state leakage/isolation failures ({self.findings['state_leakage']} events)",
                'count': self.findings['state_leakage'],
                'level': 'ERROR',
                'category': 'test-flakiness',
                'kind': 'state_leakage',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([sl['line'] for sl in self.state_leakages[:3]]),
            })

        # Cleanup failures (ERROR)
        if self.findings['cleanup_failure'] > 0:
            total_orphaned_rows = sum(cf['rows'] for cf in self.data_cleanup_failed)
            tables_affected = list(set(cf['table'] for cf in self.data_cleanup_failed))

            findings.append({
                'signature': f"Test data cleanup failures ({self.findings['cleanup_failure']} events, {total_orphaned_rows} rows)",
                'count': self.findings['cleanup_failure'],
                'level': 'ERROR',
                'category': 'test-infrastructure',
                'kind': 'cleanup_failure',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': f"Tables: {tables_affected[:3]}",
                'orphaned_rows': total_orphaned_rows,
                'affected_tables': tables_affected[:5],
            })

        # Orphaned data (WARN)
        if self.findings['orphaned_data'] > 0:
            total_rows = sum(od['rows'] for od in self.orphaned_data)
            tables = list(set(od['table'] for od in self.orphaned_data))

            findings.append({
                'signature': f"Orphaned test data ({self.findings['orphaned_data']} records, {total_rows} rows)",
                'count': self.findings['orphaned_data'],
                'level': 'WARN',
                'category': 'test-infrastructure',
                'kind': 'orphaned_data',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': f"Tables: {tables[:3]}",
                'total_orphaned_rows': total_rows,
                'orphaned_tables': tables[:5],
            })

        # Mock unavailable (ERROR)
        if self.findings['mock_unavailable'] > 0:
            services = list(set(mu['service'] for mu in self.mock_unavailable))
            findings.append({
                'signature': f"Mock services unavailable ({self.findings['mock_unavailable']} events)",
                'count': self.findings['mock_unavailable'],
                'level': 'ERROR',
                'category': 'test-infrastructure',
                'kind': 'mock_unavailable',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': ", ".join(services[:3]),
                'unavailable_services': services[:5],
            })

        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return len(self.tests_completed) + len(self.data_created)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if DB_ROLLBACK_RE.search(line):
            return 'CRITICAL', 'test', 'rollback_failure'
        if STATE_LEAKAGE_RE.search(line):
            return 'ERROR', 'test', 'state_leakage'
        if ORPHANED_DATA_RE.search(line):
            return 'WARN', 'test', 'orphaned_data'
        if 'cleanup' in line.lower() and 'fail' in line.lower():
            return 'ERROR', 'test', 'cleanup_failure'
        if MOCK_SERVICE_RE.search(line) and 'unavailable' in line.lower():
            return 'ERROR', 'test', 'mock_unavailable'
        return None

    def finding_component(self, line: str) -> str | None:
        if DB_ROLLBACK_RE.search(line):
            return 'Database rollback failed'
        if STATE_LEAKAGE_RE.search(line):
            return 'Test state leakage detected'
        if ORPHANED_DATA_RE.search(line):
            return 'Orphaned test data found'
        if 'cleanup' in line.lower() and 'fail' in line.lower():
            return 'Test cleanup failed'
        if MOCK_SERVICE_RE.search(line):
            return 'Mock service unavailable'
        return None

    def context_pid(self, line: str) -> str | None:
        test_match = TEST_NAME_RE.search(line)
        if test_match:
            return test_match.group(1)[:16]
        service_match = re.search(r'(?:service|mock)[:\s=]*(\w+)', line, re.IGNORECASE)
        return service_match.group(1)[:16] if service_match else None
