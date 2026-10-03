"""MFA audit correlator: Track TOTP failures, SMS delivery, backup codes, bypass attempts.

Real escalation scenarios:
- TOTP validation failures (time skew, wrong code)
- SMS delivery failures (retry exhaustion)
- Backup codes exhaustion
- MFA bypass attempts
- Hardware token issues
"""

from __future__ import annotations

import collections
import re
from typing import Any

# MFA patterns
MFA_METHOD_RE = re.compile(
    r'(?:mfa|2fa|two.*?factor).*?(?:totp|sms|hardware|push|backup)',
    re.IGNORECASE
)
TOTP_FAILURE_RE = re.compile(
    r'(?:totp|time.*?based.*?otp).*?(?:fail|invalid|mismatch|expired)',
    re.IGNORECASE
)
TOTP_TIME_SKEW_RE = re.compile(
    r'(?:totp|otp).*?(?:time.*?skew|clock.*?drift|time_diff)[:\s=]*(\d+)',
    re.IGNORECASE
)
SMS_DELIVERY_RE = re.compile(
    r'sms.*?(?:sent|delivery|send)',
    re.IGNORECASE
)
SMS_FAILURE_RE = re.compile(
    r'sms.*?(?:fail|error|unable|rejected|timeout)',
    re.IGNORECASE
)
SMS_RETRY_RE = re.compile(
    r'sms.*?retry[:\s=]*(\d+)/(\d+)',
    re.IGNORECASE
)
BACKUP_CODE_RE = re.compile(
    r'backup.*?code',
    re.IGNORECASE
)
BACKUP_EXHAUSTED_RE = re.compile(
    r'(?:backup.*?code|backup).*?(?:exhausted|depleted|empty|no.*?remaining)',
    re.IGNORECASE
)
MFA_BYPASS_RE = re.compile(
    r'(?:mfa|2fa).*?(?:bypass|circumvent|skip|disable)',
    re.IGNORECASE
)
HARDWARE_TOKEN_RE = re.compile(
    r'(?:hardware|yubikey|hardware token).*?(?:fail|error|not.*?responding)',
    re.IGNORECASE
)
PUSH_NOTIFICATION_RE = re.compile(
    r'push.*?(?:notification|auth).*?(?:sent|approve|deny)',
    re.IGNORECASE
)
PUSH_TIMEOUT_RE = re.compile(
    r'push.*?(?:timeout|expired|no.*?response)',
    re.IGNORECASE
)
USER_IDENTIFIER_RE = re.compile(
    r'(?:user|username|uid)[:\s=]*([^,\s;]+)',
    re.IGNORECASE
)


def mfa_log_hint(line: str) -> bool:
    """Cheap check: MFA keywords."""
    return any(kw in line.lower() for kw in [
        'mfa', '2fa', 'totp', 'sms', 'backup', 'code', 'token', 'hardware',
        'yubikey', 'push', 'notification', 'authenticator', 'factor',
        'otp', 'time_skew', 'bypass'
    ])


class MFACorrelator:
    """Correlate MFA events and detect security/availability issues."""

    def __init__(self):
        # TOTP tracking
        self.totp_failures: list[dict[str, Any]] = []
        self.totp_time_skews: list[dict[str, Any]] = []

        # SMS tracking
        self.sms_sent: int = 0
        self.sms_failures: list[dict[str, Any]] = []
        self.sms_retry_exhausted: list[dict[str, Any]] = []

        # Backup codes
        self.backup_codes_exhausted: dict[str, int] = collections.defaultdict(int)

        # MFA bypasses
        self.bypass_attempts: list[dict[str, Any]] = []

        # Hardware tokens
        self.hardware_failures: list[dict[str, Any]] = []

        # Push notifications
        self.push_timeout: list[dict[str, Any]] = []

        # Users affected
        self.users_affected: set[str] = set()

        # Findings
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        self.first_error_line: int = 0

        self.total_lines = 0
        self.mfa_lines = 0

    def hint(self, line: str) -> bool:
        return mfa_log_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not mfa_log_hint(line):
            return

        self.mfa_lines += 1

        # Track first error
        if any(kw in line.lower() for kw in ['fail', 'error', 'bypass', 'exhausted']):
            if self.first_error_line == 0:
                self.first_error_line = idx

        # Extract user
        user_match = USER_IDENTIFIER_RE.search(line)
        user = user_match.group(1) if user_match else 'unknown'
        if user != 'unknown':
            self.users_affected.add(user)

        # TOTP failures
        if TOTP_FAILURE_RE.search(line):
            self.findings['totp_failure'] += 1
            self.totp_failures.append({
                'line_idx': idx,
                'user': user,
                'line': line[:100],
            })
            self.finding_details['totp_failure'].append({
                'line_idx': idx,
                'user': user,
            })

        # TOTP time skew
        skew_match = TOTP_TIME_SKEW_RE.search(line)
        if skew_match:
            time_diff = int(skew_match.group(1))
            self.findings['totp_time_skew'] += 1
            threshold = 30
            if time_diff > threshold:
                self.totp_time_skews.append({
                    'line_idx': idx,
                    'user': user,
                    'time_diff_sec': time_diff,
                    'line': line[:100],
                })
                self.finding_details['totp_time_skew'].append({
                    'line_idx': idx,
                    'user': user,
                    'time_diff_sec': time_diff,
                })

        # SMS sent
        if SMS_DELIVERY_RE.search(line) and 'fail' not in line.lower():
            self.sms_sent += 1

        # SMS failures
        if SMS_FAILURE_RE.search(line):
            self.findings['sms_failure'] += 1
            self.sms_failures.append({
                'line_idx': idx,
                'user': user,
                'line': line[:100],
            })
            self.finding_details['sms_failure'].append({
                'line_idx': idx,
                'user': user,
            })

        # SMS retry exhausted
        retry_match = SMS_RETRY_RE.search(line)
        if retry_match:
            current = int(retry_match.group(1))
            max_retries = int(retry_match.group(2))
            if current >= max_retries:
                self.findings['sms_retry_exhausted'] += 1
                self.sms_retry_exhausted.append({
                    'line_idx': idx,
                    'user': user,
                    'retries': current,
                    'max': max_retries,
                    'line': line[:100],
                })
                self.finding_details['sms_retry_exhausted'].append({
                    'line_idx': idx,
                    'user': user,
                    'retries': current,
                })

        # Backup codes exhausted
        if BACKUP_EXHAUSTED_RE.search(line):
            self.findings['backup_codes_exhausted'] += 1
            self.backup_codes_exhausted[user] += 1
            self.finding_details['backup_codes_exhausted'].append({
                'line_idx': idx,
                'user': user,
            })

        # MFA bypass attempts
        if MFA_BYPASS_RE.search(line):
            self.findings['mfa_bypass'] += 1
            self.bypass_attempts.append({
                'line_idx': idx,
                'user': user,
                'line': line[:100],
            })
            self.finding_details['mfa_bypass'].append({
                'line_idx': idx,
                'user': user,
            })

        # Hardware token failures
        if HARDWARE_TOKEN_RE.search(line):
            self.findings['hardware_failure'] += 1
            token_type = 'yubikey' if 'yubikey' in line.lower() else 'hardware_token'
            self.hardware_failures.append({
                'line_idx': idx,
                'user': user,
                'token_type': token_type,
                'line': line[:100],
            })
            self.finding_details['hardware_failure'].append({
                'line_idx': idx,
                'user': user,
                'token_type': token_type,
            })

        # Push notification timeout
        if PUSH_TIMEOUT_RE.search(line):
            self.findings['push_timeout'] += 1
            self.push_timeout.append({
                'line_idx': idx,
                'user': user,
                'line': line[:100],
            })
            self.finding_details['push_timeout'].append({
                'line_idx': idx,
                'user': user,
            })

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings."""
        findings = []

        first_line = self.first_error_line if self.first_error_line > 0 else 0

        # Backup codes exhausted (CRITICAL)
        if self.findings['backup_codes_exhausted'] > 0:
            users_affected = list(self.backup_codes_exhausted.keys())
            findings.append({
                'signature': f"Backup MFA codes exhausted ({self.findings['backup_codes_exhausted']} users)",
                'count': self.findings['backup_codes_exhausted'],
                'level': 'CRITICAL',
                'category': 'mfa',
                'kind': 'backup_codes_exhausted',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': f"Users: {users_affected[:5]}",
                'affected_users': users_affected[:10],
            })

        # MFA bypass attempts (CRITICAL)
        if self.findings['mfa_bypass'] > 0:
            bypass_users = list(set(ba['user'] for ba in self.bypass_attempts))
            findings.append({
                'signature': f"MFA bypass attempts detected ({self.findings['mfa_bypass']} events)",
                'count': self.findings['mfa_bypass'],
                'level': 'CRITICAL',
                'category': 'security-auth',
                'kind': 'mfa_bypass',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([ba['line'] for ba in self.bypass_attempts[:3]]),
                'involved_users': bypass_users[:10],
            })

        # SMS retry exhausted (ERROR)
        if self.findings['sms_retry_exhausted'] > 0:
            affected_users = list(set(sre['user'] for sre in self.sms_retry_exhausted))
            findings.append({
                'signature': f"SMS delivery retries exhausted ({self.findings['sms_retry_exhausted']} users)",
                'count': self.findings['sms_retry_exhausted'],
                'level': 'ERROR',
                'category': 'mfa-delivery',
                'kind': 'sms_retry_exhausted',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': f"Users: {affected_users[:5]}",
                'affected_users': affected_users[:10],
            })

        # Hardware token failures (ERROR)
        if self.findings['hardware_failure'] > 0:
            affected_users = list(set(hf['user'] for hf in self.hardware_failures))
            token_types = list(set(hf['token_type'] for hf in self.hardware_failures))

            findings.append({
                'signature': f"Hardware MFA token failures ({self.findings['hardware_failure']} events)",
                'count': self.findings['hardware_failure'],
                'level': 'ERROR',
                'category': 'mfa',
                'kind': 'hardware_failure',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': f"Token types: {token_types}",
                'affected_users': affected_users[:10],
                'token_types': token_types,
            })

        # TOTP failures (WARN)
        if self.findings['totp_failure'] > 0:
            totp_users = list(set(tf['user'] for tf in self.totp_failures))
            findings.append({
                'signature': f"TOTP validation failures ({self.findings['totp_failure']} events)",
                'count': self.findings['totp_failure'],
                'level': 'WARN',
                'category': 'mfa',
                'kind': 'totp_failure',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([tf['line'] for tf in self.totp_failures[:3]]),
                'affected_users': totp_users[:10],
            })

        # TOTP time skew (WARN)
        if self.findings['totp_time_skew'] > 0:
            max_skew = max(ts['time_diff_sec'] for ts in self.totp_time_skews) if self.totp_time_skews else 0

            findings.append({
                'signature': f"TOTP time skew issues ({self.findings['totp_time_skew']} events, max_skew={max_skew}s)",
                'count': self.findings['totp_time_skew'],
                'level': 'WARN',
                'category': 'mfa',
                'kind': 'totp_time_skew',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': f"Max time skew: {max_skew}s (threshold: 30s)",
                'max_time_skew': max_skew,
            })

        # SMS failures (WARN)
        if self.findings['sms_failure'] > 0:
            sms_users = list(set(sf['user'] for sf in self.sms_failures))
            findings.append({
                'signature': f"SMS delivery failures ({self.findings['sms_failure']} events)",
                'count': self.findings['sms_failure'],
                'level': 'WARN',
                'category': 'mfa-delivery',
                'kind': 'sms_failure',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([sf['line'] for sf in self.sms_failures[:3]]),
                'affected_users': sms_users[:10],
            })

        # Push timeout (WARN)
        if self.findings['push_timeout'] > 0:
            push_users = list(set(pt['user'] for pt in self.push_timeout))
            findings.append({
                'signature': f"Push authentication timeouts ({self.findings['push_timeout']} events)",
                'count': self.findings['push_timeout'],
                'level': 'WARN',
                'category': 'mfa-delivery',
                'kind': 'push_timeout',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([pt['line'] for pt in self.push_timeout[:3]]),
                'affected_users': push_users[:10],
            })

        return findings, len(findings)

    def overflow_unique(self) -> int:
        return len(self.users_affected)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if BACKUP_EXHAUSTED_RE.search(line):
            return 'CRITICAL', 'mfa', 'backup_codes_exhausted'
        if MFA_BYPASS_RE.search(line):
            return 'CRITICAL', 'mfa', 'mfa_bypass'
        if SMS_RETRY_RE.search(line) and int(SMS_RETRY_RE.search(line).group(1)) >= int(SMS_RETRY_RE.search(line).group(2)):
            return 'ERROR', 'mfa', 'sms_retry_exhausted'
        if HARDWARE_TOKEN_RE.search(line):
            return 'ERROR', 'mfa', 'hardware_failure'
        if TOTP_FAILURE_RE.search(line):
            return 'WARN', 'mfa', 'totp_failure'
        if SMS_FAILURE_RE.search(line):
            return 'WARN', 'mfa', 'sms_failure'
        if PUSH_TIMEOUT_RE.search(line):
            return 'WARN', 'mfa', 'push_timeout'
        return None

    def finding_component(self, line: str) -> str | None:
        if BACKUP_EXHAUSTED_RE.search(line):
            return 'MFA backup codes exhausted'
        if MFA_BYPASS_RE.search(line):
            return 'MFA bypass attempt detected'
        if HARDWARE_TOKEN_RE.search(line):
            return 'Hardware token failure'
        if TOTP_FAILURE_RE.search(line):
            return 'TOTP validation failed'
        if SMS_FAILURE_RE.search(line):
            return 'SMS delivery failed'
        if PUSH_TIMEOUT_RE.search(line):
            return 'Push auth timeout'
        return None

    def context_pid(self, line: str) -> str | None:
        user_match = USER_IDENTIFIER_RE.search(line)
        if user_match:
            return user_match.group(1)[:16]
        return None
