"""API response time correlator: Track performance, latency spikes, SLA violations.

Real escalation scenarios:
- Slow endpoint detection (p95, p99 latencies)
- Latency spikes (sudden performance degradation)
- Response time distribution analysis
- Rate limiting (429 throttling patterns)
- Timeout patterns
"""

from __future__ import annotations

import collections
import re
from typing import Any

# API performance patterns
API_RESPONSE_TIME_RE = re.compile(
    r'(?:response_time|duration|elapsed|took|latency)\s*[:=]\s*(\d+)\s*(?:ms|milliseconds)?',
    re.IGNORECASE
)
API_ENDPOINT_RE = re.compile(
    r'(?:endpoint|uri|path|request)\s*[:=]\s*["\']?(/[^\s"\']+)',
    re.IGNORECASE
)
API_METHOD_RE = re.compile(
    r'(?:method|verb)\s*[:=]\s*["\']?(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)',
    re.IGNORECASE
)
API_STATUS_RE = re.compile(
    r'(?:status|code)\s*[:=]\s*(\d{3})',
    re.IGNORECASE
)
API_TIMEOUT_RE = re.compile(
    r'(?:timeout|timed out|exceeded.*?timeout)',
    re.IGNORECASE
)
API_RATE_LIMIT_RE = re.compile(
    r'(?:429|rate.*?limit|throttl)',
    re.IGNORECASE
)
API_PERCENTILE_RE = re.compile(
    r'(?:p95|p99|percentile)["\']?\s*[:=]\s*(\d+)',
    re.IGNORECASE
)

# Performance thresholds
SLOW_API_THRESHOLD_MS = 1000  # 1 second
CRITICAL_THRESHOLD_MS = 5000  # 5 seconds
TIMEOUT_THRESHOLD_MS = 30000  # 30 seconds


def api_performance_hint(line: str) -> bool:
    """Cheap check: API performance keywords."""
    return any(kw in line.lower() for kw in [
        'response_time', 'duration', 'elapsed', 'took', 'latency',
        'endpoint', 'api', 'timeout', 'rate_limit', '429',
        'p95', 'p99', 'slow', 'throttle'
    ])


class APIPerformanceCorrelator:
    """Correlate API response times and performance issues."""

    def __init__(self):
        # Performance tracking
        self.response_times: list[dict[str, Any]] = []
        self.endpoints: dict[str, list[int]] = collections.defaultdict(list)  # endpoint -> [times]
        self.slow_endpoints: dict[str, int] = collections.defaultdict(int)  # endpoint -> count
        self.timeout_events: list[dict[str, Any]] = []
        self.rate_limit_events: list[dict[str, Any]] = []
        self.status_codes: dict[int, int] = collections.defaultdict(int)

        # Findings
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        self.first_error_line: int = 0

        self.total_lines = 0
        self.api_lines = 0

    def hint(self, line: str) -> bool:
        return api_performance_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not api_performance_hint(line):
            return

        self.api_lines += 1

        # Track first performance issue
        if any(kw in line.lower() for kw in ['slow', 'timeout', 'rate_limit', '429']):
            if self.first_error_line == 0:
                self.first_error_line = idx

        # Extract response time
        time_match = API_RESPONSE_TIME_RE.search(line)
        if time_match:
            try:
                response_time_ms = int(time_match.group(1))

                # Extract endpoint
                endpoint_match = API_ENDPOINT_RE.search(line)
                endpoint = endpoint_match.group(1) if endpoint_match else 'unknown'

                # Extract method
                method_match = API_METHOD_RE.search(line)
                method = method_match.group(1) if method_match else 'UNKNOWN'

                # Extract status
                status_match = API_STATUS_RE.search(line)
                status = int(status_match.group(1)) if status_match else 0
                if status:
                    self.status_codes[status] += 1

                self.response_times.append({
                    'line_idx': idx,
                    'endpoint': endpoint,
                    'method': method,
                    'response_time_ms': response_time_ms,
                    'status': status,
                })

                self.endpoints[endpoint].append(response_time_ms)

                # Classify performance
                if response_time_ms >= CRITICAL_THRESHOLD_MS:
                    self.findings['critical_slow'] += 1
                    self.slow_endpoints[endpoint] += 1
                    self.finding_details['critical_slow'].append({
                        'line_idx': idx,
                        'endpoint': endpoint,
                        'response_time_ms': response_time_ms,
                    })
                elif response_time_ms >= SLOW_API_THRESHOLD_MS:
                    self.findings['slow_api'] += 1
                    self.slow_endpoints[endpoint] += 1
                    self.finding_details['slow_api'].append({
                        'line_idx': idx,
                        'endpoint': endpoint,
                        'response_time_ms': response_time_ms,
                    })
            except ValueError:
                pass

        # Timeout detection
        if API_TIMEOUT_RE.search(line):
            self.findings['timeout'] += 1
            endpoint_match = API_ENDPOINT_RE.search(line)
            endpoint = endpoint_match.group(1) if endpoint_match else 'unknown'
            self.timeout_events.append({
                'line_idx': idx,
                'endpoint': endpoint,
                'line': line[:100],
            })
            self.finding_details['timeout'].append({
                'line_idx': idx,
                'endpoint': endpoint,
            })

        # Rate limiting
        if API_RATE_LIMIT_RE.search(line):
            self.findings['rate_limit'] += 1
            endpoint_match = API_ENDPOINT_RE.search(line)
            endpoint = endpoint_match.group(1) if endpoint_match else 'unknown'
            self.rate_limit_events.append({
                'line_idx': idx,
                'endpoint': endpoint,
                'line': line[:100],
            })
            self.finding_details['rate_limit'].append({
                'line_idx': idx,
                'endpoint': endpoint,
            })

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings."""
        findings = []

        first_line = self.first_error_line if self.first_error_line > 0 else 0

        # Critical slow responses (>5s)
        if self.findings['critical_slow'] > 0:
            # Find slowest endpoint
            slowest_endpoint = None
            slowest_count = 0
            for ep, count in self.slow_endpoints.items():
                if count > slowest_count:
                    slowest_count = count
                    slowest_endpoint = ep

            avg_time = sum(rt['response_time_ms'] for rt in self.finding_details['critical_slow']) / len(self.finding_details['critical_slow']) if self.finding_details['critical_slow'] else 0

            findings.append({
                'signature': f"Critical slow API responses (>{CRITICAL_THRESHOLD_MS}ms, {self.findings['critical_slow']} events)",
                'count': self.findings['critical_slow'],
                'level': 'CRITICAL',
                'category': 'performance',
                'kind': 'critical_slow',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': f"Slowest: {slowest_endpoint} ({slowest_count} times slow)",
                'avg_response_time_ms': int(avg_time),
                'slowest_endpoint': slowest_endpoint,
            })

        # Slow responses (>1s)
        if self.findings['slow_api'] > 0:
            avg_time = sum(rt['response_time_ms'] for rt in self.finding_details['slow_api']) / len(self.finding_details['slow_api']) if self.finding_details['slow_api'] else 0

            findings.append({
                'signature': f"Slow API responses (>{SLOW_API_THRESHOLD_MS}ms, {self.findings['slow_api']} events)",
                'count': self.findings['slow_api'],
                'level': 'WARN',
                'category': 'performance',
                'kind': 'slow_api',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': f"Average response time: {int(avg_time)}ms",
                'avg_response_time_ms': int(avg_time),
            })

        # Timeout events
        if self.findings['timeout'] > 0:
            timeout_endpoints = list(set(te['endpoint'] for te in self.timeout_events))
            findings.append({
                'signature': f"API timeout events ({self.findings['timeout']} events)",
                'count': self.findings['timeout'],
                'level': 'ERROR',
                'category': 'reliability',
                'kind': 'timeout',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([te['line'] for te in self.timeout_events[:3]]),
                'affected_endpoints': timeout_endpoints[:5],
            })

        # Rate limiting
        if self.findings['rate_limit'] > 0:
            rate_limit_endpoints = list(set(re['endpoint'] for re in self.rate_limit_events))
            findings.append({
                'signature': f"Rate limit events ({self.findings['rate_limit']} events)",
                'count': self.findings['rate_limit'],
                'level': 'WARN',
                'category': 'reliability',
                'kind': 'rate_limit',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([re['line'] for re in self.rate_limit_events[:3]]),
                'affected_endpoints': rate_limit_endpoints[:5],
            })

        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return len(self.endpoints) + len(self.slow_endpoints)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        time_match = API_RESPONSE_TIME_RE.search(line)
        if time_match:
            try:
                response_time_ms = int(time_match.group(1))
                if response_time_ms >= CRITICAL_THRESHOLD_MS:
                    return 'CRITICAL', 'performance', 'critical_slow'
                elif response_time_ms >= SLOW_API_THRESHOLD_MS:
                    return 'WARN', 'performance', 'slow_api'
            except ValueError:
                pass

        if API_TIMEOUT_RE.search(line):
            return 'ERROR', 'reliability', 'timeout'
        if API_RATE_LIMIT_RE.search(line):
            return 'WARN', 'reliability', 'rate_limit'
        return None

    def finding_component(self, line: str) -> str | None:
        time_match = API_RESPONSE_TIME_RE.search(line)
        if time_match:
            try:
                response_time_ms = int(time_match.group(1))
                if response_time_ms >= CRITICAL_THRESHOLD_MS:
                    return f'Critical slow API ({response_time_ms}ms)'
                elif response_time_ms >= SLOW_API_THRESHOLD_MS:
                    return f'Slow API ({response_time_ms}ms)'
            except ValueError:
                pass

        if API_TIMEOUT_RE.search(line):
            return 'API timeout'
        if API_RATE_LIMIT_RE.search(line):
            return 'Rate limit (429)'
        return None

    def context_pid(self, line: str) -> str | None:
        endpoint_match = API_ENDPOINT_RE.search(line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            return endpoint[:16]
        return None
