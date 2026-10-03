"""SSH key audit log correlator: key generation, rotation, deletion, compromises.

Real IAM escalation scenarios:
- Unauthorized key generation (possible account compromise)
- Key deletion without rotation (access loss risk)
- Weak key types (RSA < 2048 bits, DSA deprecated)
- Old keys still in use (stale credentials)
- Keys with suspicious patterns
"""

from __future__ import annotations

import collections
import re
from typing import Any

# SSH key patterns
SSH_KEYGEN_RE = re.compile(
    r'(?:keygen|new key|generating.*key|ssh-key-gen)',
    re.I
)
SSH_KEY_TYPE_RE = re.compile(
    r'(?:rsa|dsa|ecdsa|ed25519)[-_]?(\d+)?',
    re.I
)
SSH_KEY_FINGERPRINT_RE = re.compile(
    r'(?:fingerprint|MD5|SHA256)[:=\s]*([a-f0-9:]+)'
)
SSH_AUTHORIZED_KEYS_RE = re.compile(
    r'(?:authorized_keys|pubkey|public key)',
    re.I
)
SSH_KEY_LOCATION_RE = re.compile(
    r'(?:\.ssh|authorized_keys|id_rsa|id_ed25519)',
    re.I
)

SSH_USER_RE = re.compile(
    r'(?:user|for user)[:=\s]+([a-zA-Z0-9_\-]+)',
    re.I
)
SSH_HOST_RE = re.compile(
    r'(?:host|server)[:=\s]+([a-zA-Z0-9_\-.:]+)',
    re.I
)

# Key events
KEY_GENERATION_KEYWORDS = [
    'key generated',
    'new key created',
    'keygen',
    'generating key',
    'key creation',
]

KEY_DELETION_KEYWORDS = [
    'key deleted',
    'key removed',
    'removed from authorized',
    'revoked key',
    'key revocation',
]

KEY_ROTATION_KEYWORDS = [
    'key rotation',
    'rotating key',
    'replace.*key',
    'update.*key',
]

WEAK_KEY_KEYWORDS = [
    'weak key',
    'rsa.*1024',
    'dsa',
    'deprecated',
    'insufficient key',
    'key size too small',
]

UNAUTHORIZED_ACCESS_KEYWORDS = [
    'unauthorized key',
    'unexpected key',
    'unknown key',
    'suspicious key',
    'unauthorized access',
]

STALE_KEY_KEYWORDS = [
    'stale key',
    'old key',
    'obsolete',
    'not rotated',
]


def ssh_key_hint(line: str) -> bool:
    """Cheap check: SSH key audit keywords."""
    return any(kw in line.lower() for kw in [
        'ssh', 'key', 'authorized_keys', 'rsa', 'ed25519',
        'keygen', 'fingerprint', 'pubkey', 'authentication'
    ])


class SSHKeyCorrelator:
    """Correlate SSH key lifecycle events (IAM audit)."""

    def __init__(self):
        # Key events
        self.key_generations: list[dict[str, Any]] = []
        self.key_deletions: list[dict[str, Any]] = []
        self.key_rotations: list[dict[str, Any]] = []
        self.weak_keys: list[dict[str, Any]] = []
        self.unauthorized_keys: list[dict[str, Any]] = []
        self.stale_keys: list[dict[str, Any]] = []

        # User tracking
        self.users_with_key_events: dict[str, list[str]] = collections.defaultdict(list)
        self.key_types_used: collections.Counter[str] = collections.Counter()

        # Findings
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

        self.total_lines = 0
        self.ssh_key_lines = 0

    def hint(self, line: str) -> bool:
        return ssh_key_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not ssh_key_hint(line):
            return

        self.ssh_key_lines += 1

        # Extract context
        user_match = SSH_USER_RE.search(line)
        user = user_match.group(1) if user_match else None

        host_match = SSH_HOST_RE.search(line)
        host = host_match.group(1) if host_match else None

        fingerprint_match = SSH_KEY_FINGERPRINT_RE.search(line)
        fingerprint = fingerprint_match.group(1) if fingerprint_match else None

        key_type_match = SSH_KEY_TYPE_RE.search(line)
        key_type = key_type_match.group(0) if key_type_match else None

        # Key generation detection (INFO, but track for pattern analysis)
        if any(kw in line.lower() for kw in KEY_GENERATION_KEYWORDS):
            self.findings['key_generation'] += 1
            self.key_generations.append({
                'line_idx': idx,
                'user': user,
                'host': host,
                'key_type': key_type,
                'fingerprint': fingerprint,
            })
            if user:
                self.users_with_key_events[user].append('generation')
            if key_type:
                self.key_types_used[key_type] += 1

        # Key deletion detection (WARN - potential access loss)
        if any(kw in line.lower() for kw in KEY_DELETION_KEYWORDS):
            self.findings['key_deletion'] += 1
            self.key_deletions.append({
                'line_idx': idx,
                'user': user,
                'fingerprint': fingerprint,
            })
            if user:
                self.users_with_key_events[user].append('deletion')
            self.finding_details['key_deletion'].append({
                'line_idx': idx,
                'user': user,
            })

        # Key rotation detection (GOOD - security practice)
        if any(kw in line.lower() for kw in KEY_ROTATION_KEYWORDS):
            self.findings['key_rotation'] += 1
            self.key_rotations.append({
                'line_idx': idx,
                'user': user,
            })
            if user:
                self.users_with_key_events[user].append('rotation')

        # Weak key detection (CRITICAL)
        if any(kw in line.lower() for kw in WEAK_KEY_KEYWORDS):
            self.findings['weak_key'] += 1
            self.weak_keys.append({
                'line_idx': idx,
                'user': user,
                'issue': key_type or 'unknown',
            })
            self.finding_details['weak_key'].append({
                'line_idx': idx,
                'user': user,
            })

        # Unauthorized key detection (CRITICAL - potential breach)
        if any(kw in line.lower() for kw in UNAUTHORIZED_ACCESS_KEYWORDS):
            self.findings['unauthorized_key'] += 1
            self.unauthorized_keys.append({
                'line_idx': idx,
                'user': user,
                'fingerprint': fingerprint,
            })
            self.finding_details['unauthorized_key'].append({
                'line_idx': idx,
                'user': user,
            })

        # Stale key detection (WARN)
        if any(kw in line.lower() for kw in STALE_KEY_KEYWORDS):
            self.findings['stale_key'] += 1
            self.stale_keys.append({
                'line_idx': idx,
                'user': user,
                'fingerprint': fingerprint,
            })
            self.finding_details['stale_key'].append({
                'line_idx': idx,
                'user': user,
            })

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings."""
        findings = []

        # Unauthorized keys (CRITICAL)
        if self.findings['unauthorized_key'] > 0:
            findings.append({
                'level': 'CRITICAL',
                'category': 'iam-security',
                'kind': 'unauthorized_ssh_key',
                'count': self.findings['unauthorized_key'],
                'affected_users': list(set(k['user'] for k in self.unauthorized_keys if k.get('user'))),
                'remediation': 'Immediately revoke unauthorized keys; audit account for compromise',
            })

        # Weak keys (CRITICAL)
        if self.findings['weak_key'] > 0:
            findings.append({
                'level': 'CRITICAL',
                'category': 'iam-security',
                'kind': 'weak_ssh_key',
                'count': self.findings['weak_key'],
                'affected_users': list(set(k['user'] for k in self.weak_keys if k.get('user'))),
                'remediation': 'Replace with RSA 2048+, ECDSA, or ED25519 keys',
            })

        # Key deletions without rotation (WARN)
        if self.findings['key_deletion'] > 0 and self.findings['key_rotation'] == 0:
            findings.append({
                'level': 'WARN',
                'category': 'iam-operations',
                'kind': 'key_deletion_without_rotation',
                'count': self.findings['key_deletion'],
                'affected_users': list(set(k['user'] for k in self.key_deletions if k.get('user'))),
                'remediation': 'Verify rotation plan; ensure new keys are in place',
            })

        # Stale keys (WARN)
        if self.findings['stale_key'] > 0:
            findings.append({
                'level': 'WARN',
                'category': 'iam-hygiene',
                'kind': 'stale_ssh_key',
                'count': self.findings['stale_key'],
                'affected_users': list(set(k['user'] for k in self.stale_keys if k.get('user'))),
                'remediation': 'Rotate old keys; remove if no longer needed',
            })

        # Key rotation audit (GOOD - but report for tracking)
        if self.findings['key_rotation'] > 0:
            findings.append({
                'level': 'INFO',
                'category': 'iam-hygiene',
                'kind': 'key_rotation_performed',
                'count': self.findings['key_rotation'],
                'note': 'Good security practice detected',
            })

        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return len(self.users_with_key_events)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if 'unauthorized key' in line.lower():
            return 'CRITICAL', 'iam-security', 'unauthorized_key'
        if 'weak key' in line.lower() or 'rsa 1024' in line.lower():
            return 'CRITICAL', 'iam-security', 'weak_key'
        if 'key deletion' in line.lower():
            return 'WARN', 'iam-operations', 'deletion'
        if 'stale key' in line.lower():
            return 'WARN', 'iam-hygiene', 'stale'
        return None

    def finding_component(self, line: str) -> str | None:
        if 'unauthorized' in line.lower():
            return 'Unauthorized SSH key detected'
        if 'weak' in line.lower():
            return 'Weak SSH key type detected'
        if 'deletion' in line.lower():
            return 'SSH key deleted'
        if 'stale' in line.lower():
            return 'Stale SSH key'
        return None

    def context_pid(self, line: str) -> str | None:
        user_match = SSH_USER_RE.search(line)
        return user_match.group(1)[:16] if user_match else None
