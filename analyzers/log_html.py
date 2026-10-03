"""HTML error page correlator: Parse HTML error logs, stack traces in HTML format.

Real escalation scenarios:
- HTML 500/502/503 error pages (service down)
- HTML stack traces (Python/PHP/Node.js errors)
- HTML status dashboards (uptime pages)
"""

from __future__ import annotations

import collections
import re
from typing import Any

# HTML patterns
HTML_STATUS_RE = re.compile(r'<(?:title|h\d)>.*?(\d{3}).*?(?:error|error)',  re.I | re.DOTALL)
HTML_ERROR_CODE_RE = re.compile(r'<[^>]*>(\d{3})[<\s]', re.I)
HTML_EXCEPTION_RE = re.compile(
    r'(?:<[^>]*>)?(?P<exception>(?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*(?:Exception|Error))[<:\s]',
    re.I
)
HTML_TRACEBACK_RE = re.compile(
    r'(?:File|at)\s+["\']?(?P<file>[^"\'<>\s]+)["\']?.*?(?:line|:)\s+(?P<line>\d+)',
    re.I
)
HTML_TIMESTAMP_RE = re.compile(
    r'(?:timestamp|time|date)[\'":\s]*([^<>\'"]+?)[\'"<]',
    re.I
)

# Status code severity
HTML_ERROR_SEVERITY = {
    400: ('WARN', 'bad_request'),
    401: ('WARN', 'unauthorized'),
    403: ('WARN', 'forbidden'),
    404: ('INFO', 'not_found'),
    429: ('ERROR', 'rate_limited'),
    500: ('CRITICAL', 'internal_error'),
    502: ('CRITICAL', 'bad_gateway'),
    503: ('CRITICAL', 'unavailable'),
    504: ('CRITICAL', 'timeout'),
}

# HTML keywords for errors
HTML_ERROR_KEYWORDS = [
    'error', 'exception', 'fatal', 'critical', 'failed', 'failure',
    'panic', 'crash', 'broken', 'invalid', 'traceback', 'stack trace'
]


def html_log_hint(line: str) -> bool:
    """Cheap check: HTML or error keywords."""
    return any(kw in line.lower() for kw in [
        '<html', '<body', '<div', '<p', 'error', 'exception',
        '500', '502', '503', '504', 'traceback', 'stack trace'
    ])


class HTMLCorrelator:
    """Correlate HTML error pages and stack traces."""

    def __init__(self):
        # Error tracking
        self.html_errors: list[dict[str, Any]] = []
        self.exceptions_found: dict[str, int] = collections.defaultdict(int)
        self.status_codes: dict[int, int] = collections.defaultdict(int)
        self.files_with_errors: set[str] = set()

        # Findings
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        self.first_error_line: int = 0

        self.total_lines = 0
        self.html_lines = 0

    def hint(self, line: str) -> bool:
        return html_log_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not html_log_hint(line):
            return

        self.html_lines += 1

        # Track first error line for sorting
        if self.first_error_line == 0:
            self.first_error_line = idx

        # Extract status code
        status_match = HTML_ERROR_CODE_RE.search(line)
        if status_match:
            try:
                status = int(status_match.group(1))
                self.status_codes[status] += 1

                if status >= 500:
                    self.findings['server_error'] += 1
                    self.html_errors.append({
                        'line_idx': idx,
                        'status': status,
                        'type': 'server_error',
                    })
                elif status >= 400:
                    self.findings['client_error'] += 1
            except ValueError:
                pass

        # Extract exceptions
        exc_match = HTML_EXCEPTION_RE.search(line)
        if exc_match:
            exc_name = exc_match.group('exception')
            self.exceptions_found[exc_name] += 1
            self.findings['exception_found'] += 1
            self.finding_details['exception_found'].append({
                'line_idx': idx,
                'exception': exc_name,
            })

        # Extract file/line from traceback
        trace_match = HTML_TRACEBACK_RE.search(line)
        if trace_match:
            file_path = trace_match.group('file')
            self.files_with_errors.add(file_path)
            self.findings['stack_trace'] += 1

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings."""
        findings = []

        first_line = self.first_error_line if self.first_error_line > 0 else 0

        # Server errors (CRITICAL)
        if self.findings['server_error'] > 0:
            findings.append({
                'signature': f"HTML server error ({self.findings['server_error']} occurrences)",
                'count': self.findings['server_error'],
                'level': 'CRITICAL',
                'category': 'http-error',
                'kind': 'server_error',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': str(dict(sorted(self.status_codes.items(), key=lambda x: x[1], reverse=True)[:5])),
                'status_codes': dict(sorted(
                    ((k, v) for k, v in self.status_codes.items() if k >= 500),
                    key=lambda x: x[1], reverse=True
                )),
            })

        # Exceptions found (ERROR)
        if self.findings['exception_found'] > 0:
            top_exc = sorted(self.exceptions_found.items(), key=lambda x: x[1], reverse=True)[:5]
            findings.append({
                'signature': f"HTML exceptions found ({self.findings['exception_found']} occurrences)",
                'count': self.findings['exception_found'],
                'level': 'ERROR',
                'category': 'code-error',
                'kind': 'exception',
                'root_cause': None,
                'top_exception': top_exc[0][0] if top_exc else None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([f"{name} ({count})" for name, count in top_exc]),
                'top_exceptions': top_exc,
            })

        # Stack traces (WARN)
        if self.findings['stack_trace'] > 0:
            findings.append({
                'signature': f"HTML stack traces ({self.findings['stack_trace']} lines)",
                'count': self.findings['stack_trace'],
                'level': 'WARN',
                'category': 'debugging',
                'kind': 'stack_trace',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join(list(self.files_with_errors)[:5]),
                'affected_files': list(self.files_with_errors)[:10],
            })

        # Client errors (INFO)
        if self.findings['client_error'] > 0:
            findings.append({
                'signature': f"HTML client errors ({self.findings['client_error']} occurrences)",
                'count': self.findings['client_error'],
                'level': 'INFO',
                'category': 'http-error',
                'kind': 'client_error',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': '',
            })

        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return len(self.files_with_errors) + len(self.exceptions_found)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if any(str(code) in line for code in [500, 502, 503, 504]):
            return 'CRITICAL', 'http', 'server_error'
        if 'Exception' in line or 'Error' in line:
            return 'ERROR', 'code', 'exception'
        if 'stack' in line.lower() or 'traceback' in line.lower():
            return 'WARN', 'debug', 'trace'
        return None

    def finding_component(self, line: str) -> str | None:
        if '500' in line or '502' in line:
            return 'Server error in HTML'
        if 'Exception' in line or 'Error' in line:
            return 'Exception detected'
        if 'stack' in line.lower():
            return 'Stack trace'
        return None

    def context_pid(self, line: str) -> str | None:
        exc_match = HTML_EXCEPTION_RE.search(line)
        return exc_match.group('exception')[:16] if exc_match else None
