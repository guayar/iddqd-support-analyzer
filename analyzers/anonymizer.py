from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# The anonymizer is intentionally deterministic within one run: the same input value
# always receives the same pseudonym (e.g. 10.0.0.7 -> IP_001 everywhere).

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b", re.I)
URL_RE = re.compile(r"\bhttps?://[^\s<>'\"]+", re.I)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
MAC_RE = re.compile(r"\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b", re.I)
UUID_RE = re.compile(r"\b[0-9A-F]{8}-[0-9A-F]{4}-[1-5][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\b", re.I)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,62}[A-Z0-9])?\.)+(?:[A-Z]{2,24}|local|internal|lan|corp|home|test)\b",
    re.I,
)

# Avoid treating common Java/Python package/class names as customer domains.
PACKAGE_PREFIXES = (
    "java.", "javax.", "jakarta.", "org.", "com.", "net.", "io.", "sun.", "jdk.",
    "python.", "urllib.", "requests.", "gradio.", "xml.", "saml.", "samlp.",
)

# Contextual single-label hostnames: only redact when the field itself tells us it is a host.
HOST_FIELD_RE = re.compile(
    r"(?P<prefix>\b(?:host(?:name)?|server|node|machine|gateway|gw|mx)\s*[:=]\s*)(?P<value>[A-Z0-9][A-Z0-9._-]{1,252})",
    re.I,
)

# Common secret-bearing key/value patterns. This is not meant to replace a DLP product,
# but catches the accidental high-risk values that most often appear in support logs.
SECRET_KV_RE = re.compile(
    r"(?P<prefix>\b(?:password|passwd|pwd|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?id)\s*[:=]\s*)"
    r"(?P<value>[^\s,;]+)",
    re.I,
)
AUTH_RE = re.compile(r"(?P<prefix>\bAuthorization\s*:\s*(?:Bearer|Basic)\s+)(?P<value>[^\s,;]+)", re.I)
COOKIE_RE = re.compile(r"(?P<prefix>\b(?:Cookie|Set-Cookie)\s*:\s*)(?P<value>[^\r\n]+)", re.I)

SENSITIVE_QUERY_KEYS = {
    "token", "access_token", "refresh_token", "id_token", "code", "password", "passwd", "pwd",
    "client_secret", "api_key", "apikey", "key", "session", "sessionid", "sid", "auth",
}


@dataclass
class _Mapper:
    values: dict[str, OrderedDict[str, str]] = field(default_factory=dict)

    def map(self, category: str, original: str) -> str:
        bucket = self.values.setdefault(category, OrderedDict())
        if original in bucket:
            return bucket[original]
        replacement = f"{category}_{len(bucket) + 1:03d}"
        bucket[original] = replacement
        return replacement

    def as_rows(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for category, values in self.values.items():
            for original, replacement in values.items():
                rows.append({"type": category, "original": original, "replacement": replacement})
        return rows

    def counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in self.values.items() if v}


def _valid_ip(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


def _anonymize_host(host: str, mapper: _Mapper) -> str:
    if not host:
        return host
    clean = host.strip("[]")
    if clean.lower() in {"localhost", "localhost.localdomain"}:
        return host
    if _valid_ip(clean, 4) or _valid_ip(clean, 6):
        rep = mapper.map("IP", clean)
    else:
        rep = mapper.map("DOMAIN", clean)
    return f"[{rep}]" if host.startswith("[") and host.endswith("]") else rep


def _replace_urls(text: str, mapper: _Mapper) -> str:
    def repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        # Strip punctuation that often follows a URL in prose/logs, then append it back.
        core = raw.rstrip(".,);]")
        suffix = raw[len(core):]
        try:
            parts = urlsplit(core)
            host = parts.hostname
            if not host:
                return raw
            anon_host = _anonymize_host(host, mapper)
            # Preserve explicit port and userinfo shape, but redact userinfo values.
            userinfo = ""
            if parts.username is not None:
                userinfo = mapper.map("USER", parts.username)
                if parts.password is not None:
                    userinfo += ":" + mapper.map("SECRET", parts.password)
                userinfo += "@"
            port = f":{parts.port}" if parts.port is not None else ""
            netloc = f"{userinfo}{anon_host}{port}"

            query_pairs = []
            for key, value in parse_qsl(parts.query, keep_blank_values=True):
                if key.lower() in SENSITIVE_QUERY_KEYS and value:
                    value = mapper.map("SECRET", value)
                query_pairs.append((key, value))
            query = urlencode(query_pairs, doseq=True) if parts.query else ""
            return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment)) + suffix
        except Exception:
            # Fall back to replacing the entire URL rather than leaking it.
            return mapper.map("URL", core) + suffix

    return URL_RE.sub(repl, text)


def anonymize_text(text: str) -> dict[str, Any]:
    """Return anonymized text plus deterministic mapping and summary.

    Designed for support logs: preserves timestamps, error codes, stack traces and message
    structure while pseudonymizing common customer/environment identifiers.
    """
    mapper = _Mapper()
    out = text

    # High-risk secrets first.
    out = JWT_RE.sub(lambda m: mapper.map("SECRET", m.group(0)), out)
    out = AUTH_RE.sub(lambda m: m.group("prefix") + mapper.map("SECRET", m.group("value")), out)
    out = COOKIE_RE.sub(lambda m: m.group("prefix") + mapper.map("SECRET", m.group("value")), out)
    out = SECRET_KV_RE.sub(lambda m: m.group("prefix") + mapper.map("SECRET", m.group("value")), out)

    # Emails before bare domains, so the address is kept as one pseudonym.
    out = EMAIL_RE.sub(lambda m: mapper.map("EMAIL", m.group(0)), out)

    # URLs get special handling so paths/ports remain useful for troubleshooting while hosts are hidden.
    out = _replace_urls(out, mapper)

    # IPs and network identifiers.
    def ipv4_repl(m: re.Match[str]) -> str:
        value = m.group(0)
        return mapper.map("IP", value) if _valid_ip(value, 4) else value

    def ipv6_repl(m: re.Match[str]) -> str:
        value = m.group(0)
        return mapper.map("IP", value) if _valid_ip(value, 6) else value

    out = IPV4_RE.sub(ipv4_repl, out)
    out = IPV6_CANDIDATE_RE.sub(ipv6_repl, out)
    out = MAC_RE.sub(lambda m: mapper.map("MAC", m.group(0)), out)
    out = UUID_RE.sub(lambda m: mapper.map("UUID", m.group(0)), out)

    # Bare FQDNs/internal domains. Skip package/class-like names to preserve stack traces.
    def domain_repl(m: re.Match[str]) -> str:
        value = m.group(0)
        low = value.lower()
        if low.startswith(PACKAGE_PREFIXES):
            return value
        # Do not remap our own placeholders.
        if re.fullmatch(r"(?:DOMAIN|IP|EMAIL|HOST|SECRET|UUID|MAC|USER)_\d{3}", value, re.I):
            return value
        return mapper.map("DOMAIN", value)

    out = DOMAIN_RE.sub(domain_repl, out)

    # Single-label hosts only when explicitly labeled as a host/server/node/etc.
    def host_repl(m: re.Match[str]) -> str:
        value = m.group("value")
        if re.fullmatch(r"(?:DOMAIN|IP|HOST)_\d{3}", value, re.I) or value.lower() == "localhost":
            return m.group(0)
        return m.group("prefix") + mapper.map("HOST", value)

    out = HOST_FIELD_RE.sub(host_repl, out)

    return {
        "text": out,
        "mapping": mapper.as_rows(),
        "counts": mapper.counts(),
        "replacements": sum(mapper.counts().values()),
        "limitations": [
            "The anonymizer is pattern-based, not a certified DLP engine.",
            "It preserves troubleshooting structure and uses stable pseudonyms within one run.",
            "Review the anonymized preview before sharing externally; free-form names or business data may require additional rules.",
        ],
    }
