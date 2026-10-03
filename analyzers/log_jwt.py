"""JWT token validation correlator: Track token lifecycle, validation failures, key rotation.

Real escalation scenarios:
- Token signature validation failures
- Token expiry edge cases
- JWKS key rotation events
- Token claim extraction issues
- Token revocation tracking
"""

from __future__ import annotations

import collections
import re
from typing import Any

# JWT patterns
JWT_TOKEN_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*',
    re.IGNORECASE
)
JWT_SIGNATURE_FAIL_RE = re.compile(
    r'(?:jwt|token).*?(?:signature|verify).*?(?:fail|invalid|mismatch)',
    re.IGNORECASE
)
JWT_EXPIRED_RE = re.compile(
    r'(?:token|jwt).*?(?:expired|exp|expir)',
    re.IGNORECASE
)
JWT_CLAIM_RE = re.compile(
    r'(?:claim|payload).*?(?:invalid|mismatch|missing)',
    re.IGNORECASE
)
JWT_REVOKED_RE = re.compile(
    r'(?:token|jwt).*?(?:revok|blacklist|logout)',
    re.IGNORECASE
)
JWKS_ROTATION_RE = re.compile(
    r'(?:jwks|key.*?rotation|key.*?update)',
    re.IGNORECASE
)
JWT_KEY_ID_RE = re.compile(
    r'kid["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]+)',
    re.IGNORECASE
)
JWT_CLAIM_EXTRACT_RE = re.compile(
    r'claim["\']?\s*[:=]\s*["\']?(\w+)["\']?',
    re.IGNORECASE
)

# JWT finding severity
JWT_SEVERITY = {
    'signature_validation_fail': ('CRITICAL', 'token_compromise'),
    'token_expired': ('WARN', 'token_lifecycle'),
    'claim_validation_fail': ('ERROR', 'token_payload'),
    'token_revoked': ('ERROR', 'token_revocation'),
    'jwks_rotation': ('INFO', 'key_management'),
    'key_id_mismatch': ('ERROR', 'key_mismatch'),
    'claim_missing': ('WARN', 'token_payload'),
}


def jwt_log_hint(line: str) -> bool:
    """Cheap check: JWT keywords or token pattern."""
    return any(kw in line.lower() for kw in [
        'jwt', 'token', 'signature', 'expired', 'jwks', 'claim',
        'revok', 'payload', 'kid', 'aud', 'iss', 'sub'
    ]) or JWT_TOKEN_RE.search(line) is not None


class JWTCorrelator:
    """Correlate JWT token validation events."""

    def __init__(self):
        # Token tracking
        self.tokens_seen: set[str] = set()
        self.signature_failures: list[dict[str, Any]] = []
        self.expired_tokens: list[dict[str, Any]] = []
        self.claim_failures: dict[str, int] = collections.defaultdict(int)
        self.revoked_tokens: list[dict[str, Any]] = []
        self.key_rotations: list[dict[str, Any]] = []
        self.key_ids: dict[str, int] = collections.defaultdict(int)
        self.claims_missing: dict[str, int] = collections.defaultdict(int)

        # Findings
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        self.first_error_line: int = 0

        self.total_lines = 0
        self.jwt_lines = 0

    def hint(self, line: str) -> bool:
        return jwt_log_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not jwt_log_hint(line):
            return

        self.jwt_lines += 1

        # Track first error
        if self.first_error_line == 0:
            self.first_error_line = idx

        # JWT token presence
        token_match = JWT_TOKEN_RE.search(line)
        if token_match:
            token = token_match.group(0)
            self.tokens_seen.add(token[:20])  # Track first 20 chars

        # Signature validation failures (CRITICAL)
        if JWT_SIGNATURE_FAIL_RE.search(line):
            self.findings['signature_validation_fail'] += 1
            kid = None
            kid_match = JWT_KEY_ID_RE.search(line)
            if kid_match:
                kid = kid_match.group(1)
            self.signature_failures.append({
                'line_idx': idx,
                'kid': kid,
                'line': line[:100],
            })
            self.finding_details['signature_validation_fail'].append({
                'line_idx': idx,
                'kid': kid,
            })

        # Token expiry (WARN)
        if JWT_EXPIRED_RE.search(line):
            self.findings['token_expired'] += 1
            self.expired_tokens.append({
                'line_idx': idx,
                'line': line[:100],
            })
            self.finding_details['token_expired'].append({
                'line_idx': idx,
            })

        # Claim validation failures (ERROR)
        if JWT_CLAIM_RE.search(line):
            self.findings['claim_validation_fail'] += 1
            claim_match = JWT_CLAIM_EXTRACT_RE.search(line)
            claim_name = claim_match.group(1) if claim_match else 'unknown'
            self.claim_failures[claim_name] += 1
            self.finding_details['claim_validation_fail'].append({
                'line_idx': idx,
                'claim': claim_name,
            })

        # Token revocation (ERROR)
        if JWT_REVOKED_RE.search(line):
            self.findings['token_revoked'] += 1
            self.revoked_tokens.append({
                'line_idx': idx,
                'line': line[:100],
            })
            self.finding_details['token_revoked'].append({
                'line_idx': idx,
            })

        # JWKS key rotation (INFO)
        if JWKS_ROTATION_RE.search(line):
            self.findings['jwks_rotation'] += 1
            # Extract number of keys rotated if present
            import re
            keys_match = re.search(r'(\d+)\s*keys?', line, re.IGNORECASE)
            num_keys = int(keys_match.group(1)) if keys_match else 1
            self.key_rotations.append({
                'line_idx': idx,
                'num_keys': num_keys,
                'line': line[:100],
            })
            self.finding_details['jwks_rotation'].append({
                'line_idx': idx,
                'num_keys': num_keys,
            })

        # Key ID tracking
        kid_match = JWT_KEY_ID_RE.search(line)
        if kid_match:
            kid = kid_match.group(1)
            self.key_ids[kid] += 1

        # Missing claims
        if 'missing' in line.lower() and any(c in line.lower() for c in ['claim', 'aud', 'iss', 'sub', 'exp']):
            claim_match = JWT_CLAIM_EXTRACT_RE.search(line)
            claim_name = claim_match.group(1) if claim_match else 'unknown'
            self.claims_missing[claim_name] += 1
            self.findings['claim_missing'] += 1
            self.finding_details['claim_missing'].append({
                'line_idx': idx,
                'claim': claim_name,
            })

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings."""
        findings = []

        first_line = self.first_error_line if self.first_error_line > 0 else 0

        # Signature validation failures (CRITICAL)
        if self.findings['signature_validation_fail'] > 0:
            failed_kids = [sf['kid'] for sf in self.signature_failures if sf['kid']]
            findings.append({
                'signature': f"JWT signature validation failures ({self.findings['signature_validation_fail']} events)",
                'count': self.findings['signature_validation_fail'],
                'level': 'CRITICAL',
                'category': 'security-token',
                'kind': 'signature_validation_fail',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([sf['line'] for sf in self.signature_failures[:3]]),
                'affected_keys': list(set(failed_kids[:5])),
            })

        # Token expiry
        if self.findings['token_expired'] > 0:
            findings.append({
                'signature': f"Expired JWT tokens ({self.findings['token_expired']} events)",
                'count': self.findings['token_expired'],
                'level': 'WARN',
                'category': 'token-lifecycle',
                'kind': 'token_expired',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([et['line'] for et in self.expired_tokens[:3]]),
            })

        # Claim validation failures
        if self.findings['claim_validation_fail'] > 0:
            top_claims = sorted(self.claim_failures.items(), key=lambda x: x[1], reverse=True)[:5]
            findings.append({
                'signature': f"JWT claim validation failures ({self.findings['claim_validation_fail']} events)",
                'count': self.findings['claim_validation_fail'],
                'level': 'ERROR',
                'category': 'token-payload',
                'kind': 'claim_validation_fail',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': ", ".join([f"{c}({n})" for c, n in top_claims]),
                'affected_claims': top_claims,
            })

        # Token revocation
        if self.findings['token_revoked'] > 0:
            findings.append({
                'signature': f"Revoked JWT tokens ({self.findings['token_revoked']} events)",
                'count': self.findings['token_revoked'],
                'level': 'ERROR',
                'category': 'token-revocation',
                'kind': 'token_revoked',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': "\n".join([rt['line'] for rt in self.revoked_tokens[:3]]),
            })

        # JWKS key rotation
        if self.findings['jwks_rotation'] > 0:
            total_keys = sum(kr['num_keys'] for kr in self.key_rotations)
            findings.append({
                'signature': f"JWKS key rotation events ({self.findings['jwks_rotation']} events, {total_keys} keys)",
                'count': self.findings['jwks_rotation'],
                'level': 'INFO',
                'category': 'key-management',
                'kind': 'jwks_rotation',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': f"Total keys rotated: {total_keys}",
                'total_keys_rotated': total_keys,
            })

        # Missing claims
        if self.findings['claim_missing'] > 0:
            top_missing = sorted(self.claims_missing.items(), key=lambda x: x[1], reverse=True)[:5]
            findings.append({
                'signature': f"Missing JWT claims ({self.findings['claim_missing']} events)",
                'count': self.findings['claim_missing'],
                'level': 'WARN',
                'category': 'token-payload',
                'kind': 'claim_missing',
                'root_cause': None,
                'top_exception': None,
                'causes': [],
                'exception_chain': [],
                'exit_code': None,
                'codes': {},
                'first_line': first_line,
                'sample': ", ".join([f"{c}({n})" for c, n in top_missing]),
                'missing_claims': top_missing,
            })

        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return len(self.tokens_seen) + len(self.key_ids)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if JWT_SIGNATURE_FAIL_RE.search(line):
            return 'CRITICAL', 'token', 'signature_validation_fail'
        if JWT_EXPIRED_RE.search(line):
            return 'WARN', 'token', 'token_expired'
        if JWT_CLAIM_RE.search(line):
            return 'ERROR', 'token', 'claim_validation_fail'
        if JWT_REVOKED_RE.search(line):
            return 'ERROR', 'token', 'token_revoked'
        if JWKS_ROTATION_RE.search(line):
            return 'INFO', 'token', 'jwks_rotation'
        return None

    def finding_component(self, line: str) -> str | None:
        if JWT_SIGNATURE_FAIL_RE.search(line):
            return 'JWT signature validation failed'
        if JWT_EXPIRED_RE.search(line):
            return 'JWT token expired'
        if JWT_CLAIM_RE.search(line):
            return 'JWT claim validation failed'
        if JWT_REVOKED_RE.search(line):
            return 'JWT token revoked'
        if JWKS_ROTATION_RE.search(line):
            return 'JWKS key rotation'
        return None

    def context_pid(self, line: str) -> str | None:
        kid_match = JWT_KEY_ID_RE.search(line)
        if kid_match:
            return kid_match.group(1)[:16]
        claim_match = JWT_CLAIM_EXTRACT_RE.search(line)
        return claim_match.group(1)[:16] if claim_match else None
