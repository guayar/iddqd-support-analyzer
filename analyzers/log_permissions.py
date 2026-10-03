"""Permission/role change audit: Track access control changes, escalations, group changes.

Real UAT scenarios:
- Role assignment/revocation
- Permission escalation attempts
- Group membership changes (cascading)
- Service account permission changes
- Cross-tenant access
"""

from __future__ import annotations

import collections
import re
from typing import Any

# Permission patterns
ROLE_GRANT_RE = re.compile(r'(?:role|permission).*?(?:grant|assign|add)[:\s]+(?P<role>\w+).*?(?:user|account)[:\s]+(?P<user>\w+)', re.IGNORECASE)
ROLE_REVOKE_RE = re.compile(r'(?:role|permission).*?(?:revok|remov|deniy)[:\s]+(?P<role>\w+).*?(?:user|account)[:\s]+(?P<user>\w+)', re.IGNORECASE)
ESCALATION_ATTEMPT_RE = re.compile(r'(?:permission|privilege).*?escalat|attempted.*?(?:admin|sudo|root)', re.IGNORECASE)
GROUP_CHANGE_RE = re.compile(r'(?:group|team).*?(?:add|remove|member)[:\s]+(?P<member>\w+).*?group[:\s]+(?P<group>\w+)', re.IGNORECASE)
SERVICE_ACCOUNT_RE = re.compile(r'(?:service.*?account|bot|automation).*?permission', re.IGNORECASE)
CROSS_TENANT_RE = re.compile(r'(?:cross-tenant|multi-tenant|inter-org).*?access', re.IGNORECASE)


def permissions_log_hint(line: str) -> bool:
    """Cheap check: permission keywords."""
    return any(kw in line.lower() for kw in [
        'role', 'permission', 'grant', 'deny', 'access', 'group', 'admin',
        'escalat', 'revok', 'assign', 'privilege', 'service', 'account', 'tenant'
    ])


class PermissionsCorrelator:
    """Correlate permission and role changes."""

    def __init__(self):
        self.role_grants: list[dict[str, Any]] = []
        self.role_revokes: list[dict[str, Any]] = []
        self.escalation_attempts: list[dict[str, Any]] = []
        self.group_changes: list[dict[str, Any]] = []
        self.service_account_changes: list[dict[str, Any]] = []
        self.cross_tenant_accesses: list[dict[str, Any]] = []

        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        self.users_affected: set[str] = set()
        self.first_error_line: int = 0

        self.total_lines = 0
        self.perm_lines = 0

    def hint(self, line: str) -> bool:
        return permissions_log_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not permissions_log_hint(line):
            return

        self.perm_lines += 1

        if any(kw in line.lower() for kw in ['fail', 'error', 'escalat', 'unauth']):
            if self.first_error_line == 0:
                self.first_error_line = idx

        # Role grants
        grant_match = ROLE_GRANT_RE.search(line)
        if grant_match:
            role = grant_match.group('role')
            user = grant_match.group('user')
            self.findings['role_grant'] += 1
            self.role_grants.append({'line_idx': idx, 'role': role, 'user': user})
            self.users_affected.add(user)
            self.finding_details['role_grant'].append({'line_idx': idx, 'role': role, 'user': user})

        # Role revokes
        revoke_match = ROLE_REVOKE_RE.search(line)
        if revoke_match:
            role = revoke_match.group('role')
            user = revoke_match.group('user')
            self.findings['role_revoke'] += 1
            self.role_revokes.append({'line_idx': idx, 'role': role, 'user': user})
            self.users_affected.add(user)
            self.finding_details['role_revoke'].append({'line_idx': idx, 'role': role, 'user': user})

        # Escalation attempts
        if ESCALATION_ATTEMPT_RE.search(line):
            self.findings['escalation_attempt'] += 1
            self.escalation_attempts.append({'line_idx': idx, 'line': line[:100]})
            self.finding_details['escalation_attempt'].append({'line_idx': idx})

        # Group changes
        group_match = GROUP_CHANGE_RE.search(line)
        if group_match:
            member = group_match.group('member')
            group = group_match.group('group')
            self.findings['group_change'] += 1
            self.group_changes.append({'line_idx': idx, 'member': member, 'group': group})
            self.users_affected.add(member)
            self.finding_details['group_change'].append({'line_idx': idx, 'member': member, 'group': group})

        # Service account changes
        if SERVICE_ACCOUNT_RE.search(line):
            self.findings['service_account_change'] += 1
            self.service_account_changes.append({'line_idx': idx, 'line': line[:100]})
            self.finding_details['service_account_change'].append({'line_idx': idx})

        # Cross-tenant access
        if CROSS_TENANT_RE.search(line):
            self.findings['cross_tenant'] += 1
            self.cross_tenant_accesses.append({'line_idx': idx, 'line': line[:100]})
            self.finding_details['cross_tenant'].append({'line_idx': idx})

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings."""
        findings = []
        first_line = self.first_error_line if self.first_error_line > 0 else 0

        if self.findings['escalation_attempt'] > 0:
            findings.append({
                'signature': f"Permission escalation attempts ({self.findings['escalation_attempt']})",
                'count': self.findings['escalation_attempt'],
                'level': 'CRITICAL',
                'category': 'access-control',
                'kind': 'escalation_attempt',
                'first_line': first_line,
                'codes': {},
                'sample': "\n".join([ea['line'] for ea in self.escalation_attempts[:3]]),
            })

        if self.findings['cross_tenant'] > 0:
            findings.append({
                'signature': f"Cross-tenant access detected ({self.findings['cross_tenant']})",
                'count': self.findings['cross_tenant'],
                'level': 'CRITICAL',
                'category': 'multi-tenancy',
                'kind': 'cross_tenant',
                'first_line': first_line,
                'codes': {},
                'sample': "\n".join([cta['line'] for cta in self.cross_tenant_accesses[:2]]),
            })

        if self.findings['role_grant'] > 0:
            affected_roles = list(set(rg['role'] for rg in self.role_grants))
            findings.append({
                'signature': f"Roles granted ({self.findings['role_grant']} events)",
                'count': self.findings['role_grant'],
                'level': 'INFO',
                'category': 'access-control',
                'kind': 'role_grant',
                'first_line': first_line,
                'codes': {},
                'affected_roles': affected_roles[:5],
            })

        if self.findings['role_revoke'] > 0:
            findings.append({
                'signature': f"Roles revoked ({self.findings['role_revoke']} events)",
                'count': self.findings['role_revoke'],
                'level': 'INFO',
                'category': 'access-control',
                'kind': 'role_revoke',
                'first_line': first_line,
                'codes': {},
            })

        if self.findings['group_change'] > 0:
            affected_groups = list(set(gc['group'] for gc in self.group_changes))
            findings.append({
                'signature': f"Group membership changes ({self.findings['group_change']})",
                'count': self.findings['group_change'],
                'level': 'INFO',
                'category': 'group-management',
                'kind': 'group_change',
                'first_line': first_line,
                'codes': {},
                'affected_groups': affected_groups[:5],
            })

        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return len(self.users_affected)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if ESCALATION_ATTEMPT_RE.search(line):
            return 'CRITICAL', 'access', 'escalation'
        if CROSS_TENANT_RE.search(line):
            return 'CRITICAL', 'access', 'cross_tenant'
        if ROLE_GRANT_RE.search(line):
            return 'INFO', 'access', 'role_grant'
        return None

    def finding_component(self, line: str) -> str | None:
        if ESCALATION_ATTEMPT_RE.search(line):
            return 'Privilege escalation'
        if ROLE_GRANT_RE.search(line):
            return 'Role granted'
        return None

    def context_pid(self, line: str) -> str | None:
        return None
