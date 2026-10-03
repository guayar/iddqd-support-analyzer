"""OAuth2 log analyzer: CSRF risk, token exposure, flow failures.

Real escalation scenarios from support:
- Missing state parameter: CSRF vulnerability
- Token exposure in logs: credentials leaked
- Code reuse: replay attack attempt
- Invalid grant: token rotation failure (app down?)
- Redirect URI mismatch: attacker trying account takeover
- Implicit flow: deprecated, security risk
- Missing PKCE: native app vulnerable to auth code interception
"""

from __future__ import annotations

import collections
import re
from typing import Any

# OAuth2 flow indicators
OAUTH2_GRANT_TYPES = [
    'authorization_code',
    'implicit',
    'client_credentials',
    'refresh_token',
    'password',
]

OAUTH2_SCOPE_SENSITIVE = {
    'admin', 'write', 'delete', 'email', 'profile', 'openid', 'offline_access',
    'user:email', 'repo', 'admin:repo_hook', 'admin:org_hook',
}

# Real patterns from escalation logs
OAUTH2_PATTERNS = {
    # Authorization endpoint
    'auth_request': re.compile(
        r'(?:auth|authorization).*?(?:endpoint|code)\s*[=:]\s*',
        re.I
    ),
    'client_id': re.compile(r'client_id\s*[=:]\s*(?P<id>\S+)', re.I),
    'client_secret': re.compile(
        r'(?:client_secret|secret)\s*[=:]\s*(?P<secret>[^\s,;]+)',
        re.I
    ),
    'redirect_uri': re.compile(r'redirect_uri\s*[=:]\s*(?P<uri>[^\s,;]+)', re.I),
    'state': re.compile(r'state\s*[=:]\s*(?P<state>\S+)', re.I),
    'scope': re.compile(r'scope\s*[=:]\s*(?P<scope>[^\s,;]+)', re.I),
    'code': re.compile(r'(?:code|auth_code)\s*[=:]\s*(?P<code>[A-Za-z0-9._-]+)', re.I),
    'response_type': re.compile(r'response_type\s*[=:]\s*(?P<type>\S+)', re.I),

    # Token endpoint
    'access_token': re.compile(
        r'(?:access_token|Bearer)\s*[=:]\s*(?P<token>eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
        re.I
    ),
    'refresh_token': re.compile(
        r'refresh_token\s*[=:]\s*(?P<token>[A-Za-z0-9._-]+)',
        re.I
    ),
    'id_token': re.compile(
        r'id_token\s*[=:]\s*(?P<token>eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
        re.I
    ),
    'grant_type': re.compile(r'grant_type\s*[=:]\s*(?P<type>\S+)', re.I),
    'expires_in': re.compile(r'expires_in\s*[=:]\s*(?P<time>\d+)', re.I),
    'token_type': re.compile(r'token_type\s*[=:]\s*(?P<type>\S+)', re.I),

    # Errors & issues
    'invalid_grant': re.compile(r'invalid_grant|error.*grant', re.I),
    'invalid_scope': re.compile(r'invalid_scope|error.*scope', re.I),
    'code_reuse': re.compile(
        r'(?:code.*(?:already used|reuse|duplicate)|'
        r'authorization code.*(?:invalid|expired|used))',
        re.I
    ),
    'token_expired': re.compile(r'(?:token|access).*(?:expired|invalid)', re.I),
    'pkce_missing': re.compile(
        r'(?:code_challenge|pkce).*missing|'
        r'native.*app.*(?:without|no).*pkce',
        re.I
    ),
    'implicit_flow': re.compile(
        r'response_type.*token|'
        r'grant_type.*implicit|'
        r'implicit.*flow.*deprecated',
        re.I
    ),
}

# Severity levels
FINDING_SEVERITY = {
    'missing_state': ('CRITICAL', 'CSRF vulnerability - attacker can hijack authorization'),
    'token_exposure': ('CRITICAL', 'Bearer token exposed in logs - credentials compromised'),
    'client_secret_exposure': ('CRITICAL', 'Client secret exposed - attacker can impersonate app'),
    'code_reuse': ('HIGH', 'Authorization code reuse - possible replay attack'),
    'implicit_flow': ('HIGH', 'Deprecated implicit flow - use authorization_code + PKCE'),
    'missing_pkce': ('HIGH', 'Missing PKCE in native app - vulnerable to auth code interception'),
    'invalid_grant': ('WARN', 'Invalid grant error - token rotation may have failed'),
    'token_validation_fail': ('WARN', 'Token validation failed - possible clock skew or signature issue'),
    'redirect_uri_mismatch': ('WARN', 'Redirect URI mismatch - possible misconfiguration or attack'),
    'invalid_scope': ('WARN', 'Scope not authorized - permission denied'),
}


def oauth2_log_hint(line: str) -> bool:
    """Cheap check: OAuth2 keywords."""
    return any(kw in line.lower() for kw in [
        'oauth', 'token', 'grant_type', 'client_id', 'scope', 'authorization',
        'refresh_token', 'access_token', 'bearer', 'code='
    ])


class OAuth2Correlator:
    """Correlate OAuth2 flow events and detect security issues."""

    def __init__(self):
        # Flow state tracking
        self.flows: dict[str, dict[str, Any]] = {}  # keyed by state or correlation id
        self.auth_requests: list[dict[str, Any]] = []
        self.token_exchanges: list[dict[str, Any]] = []
        self.token_refreshes: list[dict[str, Any]] = []

        # Security issues found
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

        # Token tracking (for exposure detection)
        self.tokens_seen: set[str] = set()
        self.client_secrets_seen: set[str] = set()

        # Flow type detection
        self.grant_types: collections.Counter[str] = collections.Counter()

        self.total_lines = 0
        self.oauth2_lines = 0

    def hint(self, line: str) -> bool:
        return oauth2_log_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not oauth2_log_hint(line):
            return

        self.oauth2_lines += 1

        # Extract all OAuth2 components
        client_id_match = OAUTH2_PATTERNS['client_id'].search(line)
        client_id = client_id_match.group('id') if client_id_match else None

        state_match = OAUTH2_PATTERNS['state'].search(line)
        state = state_match.group('state') if state_match else None

        code_match = OAUTH2_PATTERNS['code'].search(line)
        code = code_match.group('code') if code_match else None

        redirect_uri_match = OAUTH2_PATTERNS['redirect_uri'].search(line)
        redirect_uri = redirect_uri_match.group('uri') if redirect_uri_match else None

        scope_match = OAUTH2_PATTERNS['scope'].search(line)
        scope = scope_match.group('scope') if scope_match else None

        grant_type_match = OAUTH2_PATTERNS['grant_type'].search(line)
        grant_type = grant_type_match.group('type') if grant_type_match else None

        response_type_match = OAUTH2_PATTERNS['response_type'].search(line)
        response_type = response_type_match.group('type') if response_type_match else None

        # Token exposure detection (CRITICAL)
        access_token_match = OAUTH2_PATTERNS['access_token'].search(line)
        if access_token_match:
            token = access_token_match.group('token')
            if token not in self.tokens_seen:
                self.tokens_seen.add(token)
                self.findings['token_exposure'] += 1
                self.finding_details['token_exposure'].append({
                    'line_idx': idx,
                    'token_sample': token[:20] + '...',
                    'line_snippet': line[:200],
                })

        refresh_token_match = OAUTH2_PATTERNS['refresh_token'].search(line)
        if refresh_token_match:
            token = refresh_token_match.group('token')
            self.findings['token_exposure'] += 1

        # Client secret exposure (CRITICAL)
        client_secret_match = OAUTH2_PATTERNS['client_secret'].search(line)
        if client_secret_match:
            secret = client_secret_match.group('secret')
            if secret not in self.client_secrets_seen:
                self.client_secrets_seen.add(secret)
                self.findings['client_secret_exposure'] += 1
                self.finding_details['client_secret_exposure'].append({
                    'line_idx': idx,
                    'secret_sample': secret[:10] + '***',
                })

        # CSRF: missing state parameter (CRITICAL)
        if OAUTH2_PATTERNS['auth_request'].search(line):
            # Authorization endpoint
            if not state and 'authorization' in line.lower():
                self.findings['missing_state'] += 1
                self.finding_details['missing_state'].append({
                    'line_idx': idx,
                    'client_id': client_id,
                })

        # Code reuse detection (HIGH)
        if OAUTH2_PATTERNS['code_reuse'].search(line):
            self.findings['code_reuse'] += 1
            self.finding_details['code_reuse'].append({
                'line_idx': idx,
                'code': code,
            })

        # Implicit flow detection (HIGH - deprecated)
        if OAUTH2_PATTERNS['implicit_flow'].search(line) or response_type == 'token':
            self.findings['implicit_flow'] += 1
            self.finding_details['implicit_flow'].append({
                'line_idx': idx,
                'grant_type': grant_type,
                'response_type': response_type,
            })

        # Missing PKCE in native app (HIGH)
        if grant_type == 'authorization_code' and 'native' in line.lower():
            if 'pkce' not in line.lower() and 'code_challenge' not in line.lower():
                self.findings['missing_pkce'] += 1
                self.finding_details['missing_pkce'].append({
                    'line_idx': idx,
                    'client_id': client_id,
                })

        # Token validation failures (WARN)
        if OAUTH2_PATTERNS['token_expired'].search(line):
            self.findings['token_validation_fail'] += 1
            self.finding_details['token_validation_fail'].append({
                'line_idx': idx,
                'issue': 'token_expired',
            })

        # Invalid grant errors (WARN)
        if OAUTH2_PATTERNS['invalid_grant'].search(line):
            self.findings['invalid_grant'] += 1
            self.finding_details['invalid_grant'].append({
                'line_idx': idx,
                'grant_type': grant_type,
            })

        # Invalid scope (WARN)
        if OAUTH2_PATTERNS['invalid_scope'].search(line):
            self.findings['invalid_scope'] += 1
            self.finding_details['invalid_scope'].append({
                'line_idx': idx,
                'scope': scope,
            })

        # Redirect URI mismatch (WARN)
        if 'redirect_uri' in line.lower() and 'mismatch' in line.lower():
            self.findings['redirect_uri_mismatch'] += 1
            self.finding_details['redirect_uri_mismatch'].append({
                'line_idx': idx,
                'redirect_uri': redirect_uri,
            })

        # Track grant types for reporting
        if grant_type:
            self.grant_types[grant_type] += 1

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit security findings."""
        findings = []

        # Get first line for sorting
        first_line = 0
        for details in self.finding_details.values():
            if details:
                first_line = min(first_line or details[0]['line_idx'], details[0]['line_idx'])
                break

        for issue_type, count in self.findings.items():
            if count == 0:
                continue

            severity, description = FINDING_SEVERITY.get(
                issue_type,
                ('WARN', 'OAuth2 security concern')
            )

            details = self.finding_details[issue_type][:5]  # First 5 occurrences
            first_detail_line = details[0]['line_idx'] if details else first_line

            findings.append({
                'level': severity,
                'category': 'oauth2',
                'kind': issue_type,
                'count': count,
                'description': description,
                'details': details,
                'first_line': first_detail_line or 0,
                'signature': f"OAuth2 {issue_type} ({count} occurrences)",
                'sample': '',
            })

        return findings, self.total_lines

    def overflow_unique(self) -> int:
        """Track unique OAuth2 issues."""
        return len(self.findings)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        """Return severity for line-based reporting."""
        if OAUTH2_PATTERNS['token_exposure'].search(line):
            return 'CRITICAL', 'oauth2', 'token_exposure'
        if OAUTH2_PATTERNS['client_secret'].search(line):
            return 'CRITICAL', 'oauth2', 'client_secret_exposure'
        if OAUTH2_PATTERNS['code_reuse'].search(line):
            return 'HIGH', 'oauth2', 'code_reuse'
        if OAUTH2_PATTERNS['implicit_flow'].search(line):
            return 'HIGH', 'oauth2', 'implicit_flow'
        if OAUTH2_PATTERNS['invalid_grant'].search(line):
            return 'WARN', 'oauth2', 'invalid_grant'
        return None

    def finding_component(self, line: str) -> str | None:
        """Extract meaningful error message."""
        if 'invalid_grant' in line.lower():
            return 'OAuth2 invalid_grant error'
        if 'token' in line.lower() and 'expired' in line.lower():
            return 'OAuth2 token validation failure'
        if 'redirect_uri' in line.lower():
            return 'OAuth2 redirect_uri issue'
        return None

    def context_pid(self, line: str) -> str | None:
        """Extract client ID or correlation ID."""
        match = OAUTH2_PATTERNS['client_id'].search(line)
        if match:
            return match.group('id')[:16]  # First 16 chars of client_id
        return None
