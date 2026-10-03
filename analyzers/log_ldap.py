"""LDAP/AD log correlator: bind failures, lockouts, permission issues.

Real escalation scenarios from IAM:
- User account lockout (brute force or legitimate failures)
- Bind failures (wrong password or invalid DN)
- Group membership changes
- Password expiration
- Failed permission checks
"""

from __future__ import annotations

import collections
import re
from typing import Any

# LDAP log patterns
LDAP_BIND_RE = re.compile(
    r'(?:bind|auth).*?(?:DN|user)=([^\s,]+)',
    re.I
)
LDAP_ERROR_RE = re.compile(
    r'(?:error|failure|failed|invalid).*?(?:code|reason)[:=\s]*([^\s,;]+)',
    re.I
)

LDAP_USER_RE = re.compile(r'(?:uid|user|account)=([a-zA-Z0-9._\-]+)')
LDAP_GROUP_RE = re.compile(r'(?:cn|group)=([a-zA-Z0-9._\-]+)')

# AD patterns (Windows)
AD_LOGON_RE = re.compile(r'Logon Name:\s*([a-zA-Z0-9._\-\\]+)')
AD_ACCOUNT_RE = re.compile(r'Account Name:\s*([a-zA-Z0-9._\-]+)')

# Error codes
BIND_FAILURE_KEYWORDS = [
    'bind failed',
    'invalid credentials',
    'invalid password',
    'authentication failed',
    'invalid dn',
]

LOCKOUT_KEYWORDS = [
    'account locked',
    'too many failures',
    'failed login attempts',
    'lockout threshold',
    'password incorrect',
]

EXPIRATION_KEYWORDS = [
    'password expired',
    'account expired',
    'grace logins',
    'password must change',
]

GROUP_CHANGE_KEYWORDS = [
    'added to group',
    'removed from group',
    'group membership',
    'group change',
]

PERMISSION_KEYWORDS = [
    'access denied',
    'permission denied',
    'insufficient privileges',
    'authorization failed',
]

MFA_KEYWORDS = [
    'mfa required',
    'mfa failed',
    'mfa timeout',
    'mfa challenge',
    '2fa',
    'totp',
]


def ldap_log_hint(line: str) -> bool:
    """Cheap check: LDAP/AD keywords."""
    return any(kw in line.lower() for kw in [
        'ldap', 'active directory', 'ad', 'bind', 'auth', 'account',
        'lockout', 'password', 'authentication', 'domain'
    ])


class LDAPCorrelator:
    """Correlate LDAP/AD authentication events."""

    def __init__(self):
        # User tracking
        self.users: dict[str, dict[str, Any]] = {}
        self.failed_binds: dict[str, int] = collections.defaultdict(int)
        self.lockouts: list[dict[str, Any]] = []
        self.password_changes: list[dict[str, Any]] = []
        self.group_changes: list[dict[str, Any]] = []
        self.permission_issues: list[dict[str, Any]] = []
        self.mfa_failures: list[dict[str, Any]] = []

        # Findings
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

        self.total_lines = 0
        self.ldap_lines = 0

    def hint(self, line: str) -> bool:
        return ldap_log_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not ldap_log_hint(line):
            return

        self.ldap_lines += 1

        # Extract user info
        user_match = LDAP_USER_RE.search(line)
        user = user_match.group(1) if user_match else None

        # Also try AD format
        if not user:
            ad_match = AD_ACCOUNT_RE.search(line)
            user = ad_match.group(1) if ad_match else None

        # Extract group info
        group_match = LDAP_GROUP_RE.search(line)
        group = group_match.group(1) if group_match else None

        # Bind failure detection (WARN)
        if any(kw in line.lower() for kw in BIND_FAILURE_KEYWORDS):
            self.findings['bind_failure'] += 1
            if user:
                self.failed_binds[user] += 1
            self.finding_details['bind_failure'].append({
                'line_idx': idx,
                'user': user,
            })

        # Account lockout detection (CRITICAL)
        if any(kw in line.lower() for kw in LOCKOUT_KEYWORDS):
            self.findings['account_lockout'] += 1
            self.lockouts.append({
                'line_idx': idx,
                'user': user,
            })
            self.finding_details['account_lockout'].append({
                'line_idx': idx,
                'user': user,
            })

        # Password expiration (WARN)
        if any(kw in line.lower() for kw in EXPIRATION_KEYWORDS):
            self.findings['password_expiration'] += 1
            self.password_changes.append({
                'line_idx': idx,
                'user': user,
                'event': 'expiration',
            })
            self.finding_details['password_expiration'].append({
                'line_idx': idx,
                'user': user,
            })

        # Group membership changes (INFO)
        if any(kw in line.lower() for kw in GROUP_CHANGE_KEYWORDS):
            self.findings['group_change'] += 1
            self.group_changes.append({
                'line_idx': idx,
                'user': user,
                'group': group,
            })

        # Permission issues (WARN)
        if any(kw in line.lower() for kw in PERMISSION_KEYWORDS):
            self.findings['permission_denied'] += 1
            self.permission_issues.append({
                'line_idx': idx,
                'user': user,
            })
            self.finding_details['permission_denied'].append({
                'line_idx': idx,
                'user': user,
            })

        # MFA failures (ERROR)
        if any(kw in line.lower() for kw in MFA_KEYWORDS):
            if 'failed' in line.lower() or 'timeout' in line.lower():
                self.findings['mfa_failure'] += 1
                self.mfa_failures.append({
                    'line_idx': idx,
                    'user': user,
                })
                self.finding_details['mfa_failure'].append({
                    'line_idx': idx,
                    'user': user,
                })

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings."""
        findings = []

        # Account lockout (CRITICAL)
        if self.findings['account_lockout'] > 0:
            locked_users = list(set(l['user'] for l in self.lockouts if l.get('user')))
            findings.append({
                'level': 'CRITICAL',
                'category': 'iam',
                'kind': 'account_lockout',
                'count': self.findings['account_lockout'],
                'affected_users': locked_users,
                'remediation': 'Unlock accounts; check for brute force or password reset needs',
            })

        # Bind failures - track per user (WARN)
        if self.findings['bind_failure'] > 0:
            # Users with 5+ failures (potential attack)
            suspicious_users = {u: c for u, c in self.failed_binds.items() if c >= 5}
            findings.append({
                'level': 'WARN',
                'category': 'iam',
                'kind': 'bind_failures',
                'total_failures': self.findings['bind_failure'],
                'suspicious_users': list(suspicious_users.keys()),
                'remediation': 'Verify user credentials; check for brute force attempts',
            })

        # MFA failures (ERROR)
        if self.findings['mfa_failure'] > 0:
            findings.append({
                'level': 'ERROR',
                'category': 'iam',
                'kind': 'mfa_failure',
                'count': self.findings['mfa_failure'],
                'affected_users': list(set(m['user'] for m in self.mfa_failures if m.get('user'))),
                'remediation': 'Check MFA configuration; verify user devices; reset MFA if needed',
            })

        # Password expiration (WARN)
        if self.findings['password_expiration'] > 0:
            findings.append({
                'level': 'WARN',
                'category': 'iam',
                'kind': 'password_expiration',
                'count': self.findings['password_expiration'],
                'affected_users': list(set(p['user'] for p in self.password_changes if p.get('user'))),
            })

        # Permission denied (WARN)
        if self.findings['permission_denied'] > 0:
            findings.append({
                'level': 'WARN',
                'category': 'iam',
                'kind': 'permission_denied',
                'count': self.findings['permission_denied'],
                'affected_users': list(set(p['user'] for p in self.permission_issues if p.get('user'))),
                'remediation': 'Review group memberships and role assignments',
            })

        # Group changes (INFO)
        if self.findings['group_change'] > 0:
            findings.append({
                'level': 'INFO',
                'category': 'iam',
                'kind': 'group_membership_change',
                'count': self.findings['group_change'],
            })

        return findings, len(findings)

    def overflow_unique(self) -> int:
        return len(self.users) + len(self.failed_binds)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if 'account locked' in line.lower():
            return 'CRITICAL', 'iam', 'lockout'
        if 'mfa failed' in line.lower() or 'mfa timeout' in line.lower():
            return 'ERROR', 'iam', 'mfa_failure'
        if 'bind failed' in line.lower() or 'authentication failed' in line.lower():
            return 'WARN', 'iam', 'bind_failure'
        if 'permission denied' in line.lower():
            return 'WARN', 'iam', 'permission'
        return None

    def finding_component(self, line: str) -> str | None:
        if 'account locked' in line.lower():
            return 'Account lockout'
        if 'mfa' in line.lower():
            return 'MFA authentication failure'
        if 'bind' in line.lower():
            return 'LDAP bind failure'
        if 'permission' in line.lower():
            return 'Permission denied'
        return None

    def context_pid(self, line: str) -> str | None:
        user_match = LDAP_USER_RE.search(line)
        return user_match.group(1)[:16] if user_match else None
