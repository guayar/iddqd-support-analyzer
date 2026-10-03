"""Nginx log correlator: auth cascades, status code patterns, timing anomalies.

Real escalation scenarios:
- 403 cascade: attacker probing admin panels
- 401 chain: broken OAuth refresh flow
- 502 surge: backend service down
- Latency spike: slow DB queries or resource exhaustion
"""

from __future__ import annotations

import collections
import re
from datetime import datetime
from typing import Any

# Real Nginx formats encountered in production
NGINX_COMBINED_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/[\d.]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

NGINX_EXTENDED_RE = re.compile(
    r'^(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/[\d.]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"\s+'
    r'(?P<response_time>[\d.]+)'
)

NGINX_JSON_RE = re.compile(
    r'^\s*\{\s*"remote_addr":\s*"(?P<ip>[^"]+)".*?"status":\s*(?P<status>\d{3})'
)

# Status code severity (escalation perspective)
STATUS_SEVERITY = {
    # 4xx: client errors (sometimes attacks)
    401: ('WARN', 'auth_required'),
    403: ('WARN', 'forbidden'),
    404: ('INFO', 'not_found'),
    429: ('ERROR', 'rate_limited'),

    # 5xx: server errors (escalation!)
    500: ('ERROR', 'internal_error'),
    502: ('ERROR', 'bad_gateway'),
    503: ('ERROR', 'service_unavailable'),
    504: ('ERROR', 'gateway_timeout'),
}

# Real attack patterns from escalation logs
ATTACK_PATTERNS = [
    (re.compile(r'/admin|/wp-admin|/panel|/phpmyadmin', re.I), 'admin_probe'),
    (re.compile(r'\.php\?|\.asp\?|shell\.php', re.I), 'webshell_probe'),
    (re.compile(r'\.env|\.git|\.aws', re.I), 'dotfile_probe'),
    (re.compile(r'sql|union|select|drop|insert', re.I), 'sql_injection'),
    (re.compile(r'\.\./|\.\.\\', re.I), 'path_traversal'),
]

# Real OAuth/API issues
API_PATTERNS = [
    (re.compile(r'/api/auth|/oauth|/token', re.I), 'auth_endpoint'),
    (re.compile(r'/api/user|/me|/profile', re.I), 'profile_endpoint'),
    (re.compile(r'/api/data|/api/v\d+', re.I), 'data_endpoint'),
]

STATUS_INCIDENT_CAP = 500
SLOW_REQUEST_THRESHOLD_MS = 1000
SLOW_REQUESTS_FOR_INCIDENT = 3


def nginx_log_hint(line: str) -> bool:
    """Cheap check: Nginx logs have status codes."""
    return bool(re.search(r'\d{3}\s+\d+', line))


class NginxCorrelator:
    """Stateful Nginx log correlator for escalation scenarios."""

    def __init__(self):
        # Status code tracking
        self.status_counts: dict[int, int] = collections.defaultdict(int)
        self.status_incidents: dict[int, list[dict[str, Any]]] = collections.defaultdict(list)

        # Attack detection
        self.attack_ips: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        self.attack_summary: dict[str, int] = collections.defaultdict(int)

        # Timing analysis
        self.slow_requests: list[dict[str, Any]] = []
        self.response_times: list[float] = []

        # Auth flow tracking
        self.auth_cascades: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

        self.total_lines = 0
        self.parsed_lines = 0

    def hint(self, line: str) -> bool:
        return nginx_log_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        # Try all formats
        match = NGINX_COMBINED_RE.search(line)
        if not match:
            match = NGINX_EXTENDED_RE.search(line)
        if not match:
            return

        self.parsed_lines += 1

        ip = match.group('ip')
        status = int(match.group('status'))
        path = match.group('path')
        method = match.group('method')

        # Extract response time if available
        response_time_ms = None
        if match.lastindex and 'response_time' in match.groupdict():
            try:
                response_time_ms = float(match.group('response_time')) * 1000
                self.response_times.append(response_time_ms)
            except (ValueError, TypeError):
                pass

        # Track status codes
        self.status_counts[status] += 1
        self.status_incidents[status].append({
            'line_idx': idx,
            'ip': ip,
            'path': path,
            'method': method,
        })

        # Detect attacks
        for pattern, attack_type in ATTACK_PATTERNS:
            if pattern.search(path):
                self.attack_summary[attack_type] += 1
                self.attack_ips[ip].append({
                    'type': attack_type,
                    'path': path,
                    'status': status,
                    'line_idx': idx,
                })
                break

        # Track auth cascades (401/403 chains)
        if status in (401, 403):
            self.auth_cascades[ip].append({
                'status': status,
                'path': path,
                'method': method,
                'line_idx': idx,
            })

        # Track slow requests (for performance degradation escalations)
        if response_time_ms and response_time_ms > SLOW_REQUEST_THRESHOLD_MS:
            self.slow_requests.append({
                'ip': ip,
                'path': path,
                'response_time_ms': response_time_ms,
                'status': status,
                'line_idx': idx,
            })

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings for escalation."""
        findings = []

        # Get first line for sorting
        first_line = 0
        if self.status_incidents:
            for incidents in self.status_incidents.values():
                if incidents:
                    first_line = min(first_line or incidents[0]['line_idx'], incidents[0]['line_idx'])
                    break
        if not first_line and self.attack_ips:
            for events in self.attack_ips.values():
                if events:
                    first_line = events[0]['line_idx']
                    break
        if not first_line and self.auth_cascades:
            for events in self.auth_cascades.values():
                if events:
                    first_line = events[0]['line_idx']
                    break
        if not first_line and self.slow_requests:
            first_line = self.slow_requests[0]['line_idx']

        # ERROR status codes (5xx)
        for status in [500, 502, 503, 504]:
            if self.status_counts[status] > 0:
                severity, kind = STATUS_SEVERITY.get(status, ('ERROR', f'status_{status}'))
                findings.append({
                    'level': severity,
                    'category': 'http',
                    'kind': kind,
                    'status': status,
                    'count': self.status_counts[status],
                    'ips': list({item['ip'] for item in self.status_incidents[status]}),
                    'first_line': first_line or 0,
                    'signature': f"HTTP {status} errors ({self.status_counts[status]} occurrences)",
                    'sample': '',
                })

        # 401/403 cascades (potential auth attacks)
        if self.auth_cascades:
            for ip, events in self.auth_cascades.items():
                if len(events) >= 3:  # 3+ auth failures from same IP
                    findings.append({
                        'level': 'WARN',
                        'category': 'security-auth',
                        'kind': 'auth_cascade',
                        'ip': ip,
                        'count': len(events),
                        'status_distribution': {e['status'] for e in events},
                        'first_line': events[0]['line_idx'],
                        'signature': f"Auth cascade from {ip} ({len(events)} attempts)",
                        'sample': '',
                    })

        # Attack detection
        if self.attack_ips:
            for ip, events in self.attack_ips.items():
                if len(events) >= 2:  # 2+ attack attempts
                    findings.append({
                        'level': 'ERROR',
                        'category': 'security',
                        'kind': 'attack_probe',
                        'ip': ip,
                        'attack_types': list(set(e['type'] for e in events)),
                        'count': len(events),
                        'first_line': events[0]['line_idx'],
                        'signature': f"Attack probe from {ip} ({len(events)} attempts)",
                        'sample': '',
                    })

        # Slow requests / performance degradation
        if len(self.slow_requests) >= SLOW_REQUESTS_FOR_INCIDENT:
            findings.append({
                'level': 'WARN',
                'category': 'performance',
                'kind': 'slow_requests',
                'count': len(self.slow_requests),
                'avg_response_time_ms': sum(r['response_time_ms'] for r in self.slow_requests) / len(self.slow_requests),
                'p95_response_time_ms': sorted([r['response_time_ms'] for r in self.slow_requests])[int(0.95 * len(self.slow_requests))],
                'first_line': self.slow_requests[0]['line_idx'],
                'signature': f"Slow requests detected ({len(self.slow_requests)} slow)",
                'sample': '',
            })

        return findings, self.total_lines

    def overflow_unique(self) -> int:
        """Track unique IPs for correlator cap."""
        return len(self.attack_ips) + len(self.auth_cascades)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        """Return (level, category, kind) for incident reporting."""
        match = NGINX_COMBINED_RE.search(line)
        if not match:
            return None

        status = int(match.group('status'))
        if status in STATUS_SEVERITY:
            level, kind = STATUS_SEVERITY[status]
            return level, 'http', kind

        return None

    def finding_component(self, line: str) -> str | None:
        """Extract the meaningful error message from Nginx log."""
        match = NGINX_COMBINED_RE.search(line)
        if not match:
            return None

        status = match.group('status')
        path = match.group('path')
        return f"HTTP {status}: {path}"

    def context_pid(self, line: str) -> str | None:
        """Nginx doesn't use PIDs like SSH, but track remote IP."""
        match = NGINX_COMBINED_RE.search(line)
        if not match:
            return None
        return match.group('ip')
