"""Service-to-service communication: Circuit breaker, retries, timeouts, cascades.

Real integration scenarios:
- Service discovery failures
- Circuit breaker trips
- Retry/backoff patterns
- Timeout cascades
"""

from __future__ import annotations

import collections
import re
from typing import Any

DISCOVERY_FAIL_RE = re.compile(r'(?:service.*?discovery|lookup).*?(?:fail|not.*?found)', re.IGNORECASE)
CIRCUIT_BREAKER_RE = re.compile(r'(?:circuit.*?breaker|open|trip)', re.IGNORECASE)
RETRY_RE = re.compile(r'retry[:\s=]*(\d+)/(\d+)', re.IGNORECASE)
TIMEOUT_CASCADE_RE = re.compile(r'(?:cascad|chain).*?timeout', re.IGNORECASE)
BACKOFF_RE = re.compile(r'(?:backoff|exponential|retry.*?backoff)', re.IGNORECASE)


def service_comms_hint(line: str) -> bool:
    return any(kw in line.lower() for kw in ['service', 'circuit', 'retry', 'timeout', 'discovery', 'unavailable', 'endpoint'])


class ServiceCommsCorrelator:
    """Correlate service-to-service communication."""

    def __init__(self):
        self.discovery_failures: int = 0
        self.circuit_breaker_events: list[dict[str, Any]] = []
        self.timeout_cascades: list[dict[str, Any]] = []
        self.retry_exhausted: list[dict[str, Any]] = []
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.first_error_line: int = 0
        self.total_lines = 0

    def hint(self, line: str) -> bool:
        return service_comms_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if not service_comms_hint(line):
            return

        if any(kw in line.lower() for kw in ['fail', 'error', 'timeout']):
            if self.first_error_line == 0:
                self.first_error_line = idx

        if DISCOVERY_FAIL_RE.search(line):
            self.findings['discovery_failure'] += 1
        elif CIRCUIT_BREAKER_RE.search(line):
            self.findings['circuit_breaker'] += 1
            self.circuit_breaker_events.append({'line_idx': idx})
        elif TIMEOUT_CASCADE_RE.search(line):
            self.findings['timeout_cascade'] += 1
            self.timeout_cascades.append({'line_idx': idx})

        retry_match = RETRY_RE.search(line)
        if retry_match and int(retry_match.group(1)) >= int(retry_match.group(2)):
            self.findings['retry_exhausted'] += 1
            self.retry_exhausted.append({'line_idx': idx})

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        findings = []
        first_line = self.first_error_line if self.first_error_line > 0 else 0

        if self.findings['circuit_breaker'] > 0:
            findings.append({
                'signature': f"Circuit breaker events ({self.findings['circuit_breaker']})",
                'count': self.findings['circuit_breaker'],
                'level': 'CRITICAL',
                'category': 'service-reliability',
                'kind': 'circuit_breaker',
                'first_line': first_line,
                'codes': {},
            })

        if self.findings['timeout_cascade'] > 0:
            findings.append({
                'signature': f"Timeout cascades ({self.findings['timeout_cascade']})",
                'count': self.findings['timeout_cascade'],
                'level': 'ERROR',
                'category': 'service-reliability',
                'kind': 'timeout_cascade',
                'first_line': first_line,
                'codes': {},
            })

        if self.findings['retry_exhausted'] > 0:
            findings.append({
                'signature': f"Retry exhaustion ({self.findings['retry_exhausted']})",
                'count': self.findings['retry_exhausted'],
                'level': 'ERROR',
                'category': 'service-reliability',
                'kind': 'retry_exhausted',
                'first_line': first_line,
                'codes': {},
            })

        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return self.findings['circuit_breaker'] + self.findings['timeout_cascade']

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if CIRCUIT_BREAKER_RE.search(line):
            return 'CRITICAL', 'service', 'circuit_breaker'
        if TIMEOUT_CASCADE_RE.search(line):
            return 'ERROR', 'service', 'timeout_cascade'
        return None

    def finding_component(self, line: str) -> str | None:
        if CIRCUIT_BREAKER_RE.search(line):
            return 'Circuit breaker open'
        if TIMEOUT_CASCADE_RE.search(line):
            return 'Timeout cascade'
        return None

    def context_pid(self, line: str) -> str | None:
        return None
