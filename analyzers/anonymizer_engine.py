from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import zlib
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qsl, quote_plus, unquote, unquote_plus, urlencode, urlsplit, urlunsplit

from lxml import etree

from .xml_safe import decompress_limited, lxml_fromstring

# The anonymizer is deterministic within one run: repeated input values receive the
# same pseudonym. SAML is handled structurally so protocol/namespace URIs are not
# mistaken for customer domains.

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

SAML_PARAM_RE = re.compile(
    r"(?P<prefix>\bSAML(?:Response|Request)\s*[=:]\s*)(?P<quote>['\"]?)(?P<value>[A-Za-z0-9%+/_=-]{40,})(?P=quote)",
    re.I,
)
BASE64_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])(?P<value>[A-Za-z0-9+/_-]{80,}={0,2})(?![A-Za-z0-9+/=_-])"
)
SAML_XML_RE = re.compile(
    r"<\s*(?:[A-Za-z_][\w.-]*:)?(?:AuthnRequest|Response|Assertion|LogoutRequest|LogoutResponse|EntityDescriptor|EntitiesDescriptor)\b",
    re.I,
)
RELAYSTATE_RE = re.compile(
    r"(?P<prefix>\bRelayState\s*[=:]\s*)(?P<quote>['\"]?)(?P<value>[^\s&'\"]+)(?P=quote)",
    re.I,
)

PACKAGE_PREFIXES = (
    "java.", "javax.", "jakarta.", "sun.", "jdk.",
    "org.springframework.", "org.apache.", "org.hibernate.", "org.slf4j.",
    "org.eclipse.", "org.junit.", "org.w3c.", "org.xml.", "org.omg.",
    "org.bouncycastle.", "org.yaml.",
    "com.sun.", "com.fasterxml.", "com.google.", "com.mysql.", "com.zaxxer.",
    "com.oracle.", "com.ibm.",
    "io.netty.", "io.micrometer.", "io.undertow.", "io.lettuce.",
    "net.bytebuddy.", "ch.qos.logback.",
    "python.", "urllib.", "requests.", "gradio.",
    "xml.", "saml.", "samlp.",
)
DNS_TLDS = {
    "com", "org", "net", "io", "co", "us", "uk", "eu", "de", "fr", "nl", "pl",
    "info", "biz", "app", "dev", "cloud", "xyz", "edu", "gov",
    "local", "internal", "lan", "corp", "home", "test",
}
CUSTOMER_PACKAGE_RE = re.compile(
    r"(?<!java\.)(?<!javax\.)\b(?P<pkg>(?:com|net)\.(?!sun\.|fasterxml\.|google\.|mysql\.|oracle\.|zaxxer\.|ibm\.|apple\.|microsoft\.|bytebuddy\.)"
    r"[a-z][a-z0-9]{1,32})\b",
    re.I,
)
STARTED_BY_RE = re.compile(
    r"(?P<prefix>started by )(?P<name>.+?)(?P<mid> in )(?P<dir>\S+?)(?P<suffix>\))",
    re.I,
)
WIN_ROOT_RE = re.compile(
    r"(?P<root>[A-Za-z]:\\(?!(?:Windows|Program Files(?: \(x86\))?|ProgramData|Users)\\)[^\\\s\]]+)",
    re.I,
)
SPRING_APP_RE = re.compile(r"(?P<prefix> --- \[)(?P<app>[^\]]+)(?P<suffix>\] \[)")
MAVEN_ARTIFACT_RE = re.compile(
    r"(?P<prefix>(?:on project |@ |:))(?P<art>[A-Za-z][A-Za-z0-9-]{2,})(?P<suffix>(?:\s|$|>|:|---|>>>|<<<))",
)
MAVEN_BUILDING_RE = re.compile(r"(?P<prefix>Building )(?P<name>.+?)(?P<suffix> \d+(?:\.\d+)+)")
STARTING_CLASS_RE = re.compile(r"(?P<prefix>Starting )(?P<cls>[A-Z][A-Za-z0-9]+)(?P<suffix> using )")
MAVEN_SKIP_ARTIFACTS = {
    "run", "compile", "jar", "war", "ear", "test", "resources", "install", "package",
    "deploy", "clean", "validate", "site", "help", "exec", "start", "test-compile",
    "default-cli", "default-compile", "default-testcompile", "default-resources",
    "testresources", "default-testresources", "pom", "info",
}
SPRING_THREAD_NAMES = {"main", "background", "system"}

HOST_FIELD_RE = re.compile(
    r"(?P<prefix>\b(?:host(?:name)?|server|node|machine|gateway|gw|mx)\s*[:=]\s*)(?P<value>[A-Z0-9][A-Z0-9._-]{1,252})",
    re.I,
)
SECRET_KV_RE = re.compile(
    r"(?P<prefix>\b(?:password|passwd|pwd|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?id|jwt[_./-]?secret)\s*[:=]\s*)"
    r"(?P<value>[^\s,;]+)",
    re.I,
)
AUTH_RE = re.compile(r"(?P<prefix>\bAuthorization\s*:\s*(?:Bearer|Basic)\s+)(?P<value>[^\s,;]+)", re.I)
COOKIE_RE = re.compile(r"(?P<prefix>\b(?:Cookie|Set-Cookie)\s*:\s*)(?P<value>[^\r\n]+)", re.I)
WINDOWS_USER_RE = re.compile(
    r"(?P<prefix>(?:[A-Za-z]:\\|\\\\)Users\\)(?P<user>[^\\/]+)",
    re.I,
)
UNIX_HOME_RE = re.compile(r"(?P<prefix>/(?:Users|home)/)(?P<user>[^/\s]+)")

SENSITIVE_QUERY_KEYS = {
    "token", "access_token", "refresh_token", "id_token", "code", "password", "passwd", "pwd",
    "client_secret", "api_key", "apikey", "key", "session", "sessionid", "sid", "auth", "relaystate",
}

STANDARD_URI_PREFIXES = (
    "urn:oasis:names:tc:SAML:",
    "urn:oasis:names:tc:SAML:2.0:",
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://w3.org/",
    "https://w3.org/",
    "http://schemas.xmlsoap.org/",
    "https://schemas.xmlsoap.org/",
    "http://docs.oasis-open.org/",
    "https://docs.oasis-open.org/",
    "http://www.oasis-open.org/",
    "https://www.oasis-open.org/",
)
STANDARD_HOSTS = {
    "www.w3.org", "w3.org", "schemas.xmlsoap.org", "docs.oasis-open.org", "www.oasis-open.org", "oasis-open.org"
}
PUBLIC_INFRA_HOST_SUFFIXES = (
    ".apache.org",
    ".spring.io",
    ".oracle.com",
    ".maven.org",
    ".ietf.org",
    ".github.com",
    ".githubusercontent.com",
)
# Last labels that are source/build artifacts, not DNS TLDs.
CODE_LAST_LABELS = {
    "java", "jar", "class", "kt", "kts", "scala", "groovy", "xml", "properties",
    "yml", "yaml", "gradle", "json", "log", "txt", "call", "inject", "secret",
    "conf", "cfg", "ini", "md", "pom",
}

PLACEHOLDER_RE = re.compile(
    r"(?:DOMAIN|IP|EMAIL|HOST|SECRET|UUID|MAC|USER|URL|ENTITY|NAMEID|ATTR_VALUE|SAML_ID|SESSION|RELAYSTATE|ADDRESS|X509_CERT|SIGNATURE|DIGEST|PACKAGE|PATH|APP)_\d{3}",
    re.I,
)
TEMPLATE_PLACEHOLDER_RE = re.compile(r"^\{[A-Za-z0-9_.:-]+\}$")

SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_METADATA_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
SAML_DOCUMENT_NAMES = (
    "EntitiesDescriptor",
    "EntityDescriptor",
    "AuthnRequest",
    "LogoutRequest",
    "LogoutResponse",
    "Response",
    "Assertion",
)


@dataclass
class _Mapper:
    values: dict[str, OrderedDict[str, str]] = field(default_factory=dict)
    certificate_replacements: dict[str, str] = field(default_factory=dict)

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


def _is_well_known_public_host(host: str) -> bool:
    low = (host or "").strip("[]").lower()
    if not low:
        return False
    if low in STANDARD_HOSTS or low in {"apache.org", "spring.io", "oracle.com", "maven.org"}:
        return True
    return any(low.endswith(suffix) for suffix in PUBLIC_INFRA_HOST_SUFFIXES)


def _is_vendor_package_root(pkg: str) -> bool:
    low = (pkg or "").lower() + "."
    return any(low.startswith(prefix) or prefix.startswith(low) for prefix in PACKAGE_PREFIXES)


def _is_placeholder(value: str) -> bool:
    value = (value or "").strip()
    return bool(PLACEHOLDER_RE.fullmatch(value) or TEMPLATE_PLACEHOLDER_RE.fullmatch(value))


def _looks_like_dns_hostname(value: str) -> bool:
    """True for customer-looking hostnames; false for Java frames, loggers, filenames."""
    if not value or _is_placeholder(value):
        return False
    low = value.lower().strip(".")
    if low.startswith(PACKAGE_PREFIXES) or _is_well_known_public_host(low):
        return False
    labels = [part for part in value.split(".") if part]
    if len(labels) < 2:
        return False
    tld = labels[-1].lower()
    if tld in CODE_LAST_LABELS:
        return False
    if tld not in DNS_TLDS:
        return False
    if sum(1 for lab in labels if len(lab) == 1) >= 2:
        return False
    for lab in labels:
        if any(ch.isupper() for ch in lab) and any(ch.islower() for ch in lab):
            return False
        if any(ch in lab for ch in "()[]$"):
            return False
    return True


def _is_standard_uri(value: str) -> bool:
    value = (value or "").strip()
    return any(value.startswith(prefix) for prefix in STANDARD_URI_PREFIXES)


def _valid_ip(value: str, version: int | None = None) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return version is None or ip.version == version
    except ValueError:
        return False


def _with_original_ws(original: str, replacement: str) -> str:
    if not original:
        return replacement
    left = original[: len(original) - len(original.lstrip())]
    right = original[len(original.rstrip()):]
    return left + replacement + right


def _anonymize_host(host: str, mapper: _Mapper) -> str:
    if not host:
        return host
    clean = host.strip("[]")
    low = clean.lower()
    if low in {"localhost", "localhost.localdomain"} or _is_well_known_public_host(clean) or _is_placeholder(clean):
        return host
    if _valid_ip(clean):
        rep = mapper.map("IP", clean)
    else:
        rep = mapper.map("DOMAIN", clean)
    return f"[{rep}]" if host.startswith("[") and host.endswith("]") else rep


def _replace_urls(text: str, mapper: _Mapper) -> str:
    def repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        core = raw.rstrip(".,);]")
        suffix = raw[len(core):]
        if _is_standard_uri(core):
            return raw
        try:
            parts = urlsplit(core)
            host = parts.hostname
            if not host:
                return raw
            anon_host = _anonymize_host(host, mapper)
            userinfo = ""
            if parts.username is not None:
                userinfo = parts.username if _is_placeholder(parts.username) else mapper.map("USER", parts.username)
                if parts.password is not None:
                    userinfo += ":" + (parts.password if _is_placeholder(parts.password) else mapper.map("SECRET", parts.password))
                userinfo += "@"
            port = f":{parts.port}" if parts.port is not None else ""
            netloc = f"{userinfo}{anon_host}{port}"
            query_pairs = []
            for key, value in parse_qsl(parts.query, keep_blank_values=True):
                if key.lower() in SENSITIVE_QUERY_KEYS and value and not _is_placeholder(value):
                    value = mapper.map("SECRET", value)
                query_pairs.append((key, value))
            query = urlencode(query_pairs, doseq=True) if parts.query else ""
            return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment)) + suffix
        except Exception:
            return mapper.map("URL", core) + suffix

    return URL_RE.sub(repl, text)


def _anonymize_patterns(text: str, mapper: _Mapper) -> str:
    out = text
    out = JWT_RE.sub(lambda m: m.group(0) if _is_placeholder(m.group(0)) else mapper.map("SECRET", m.group(0)), out)
    out = AUTH_RE.sub(lambda m: m.group("prefix") + (m.group("value") if _is_placeholder(m.group("value")) else mapper.map("SECRET", m.group("value"))), out)
    out = COOKIE_RE.sub(lambda m: m.group("prefix") + (m.group("value") if _is_placeholder(m.group("value")) else mapper.map("SECRET", m.group("value"))), out)
    out = SECRET_KV_RE.sub(lambda m: m.group("prefix") + (m.group("value") if _is_placeholder(m.group("value")) else mapper.map("SECRET", m.group("value"))), out)
    out = EMAIL_RE.sub(lambda m: m.group(0) if _is_placeholder(m.group(0)) else mapper.map("EMAIL", m.group(0)), out)
    out = _replace_urls(out, mapper)

    def ipv4_repl(m: re.Match[str]) -> str:
        value = m.group(0)
        return mapper.map("IP", value) if _valid_ip(value, 4) and not _is_placeholder(value) else value

    def ipv6_repl(m: re.Match[str]) -> str:
        value = m.group(0)
        if not _valid_ip(value, 6) or _is_placeholder(value):
            return value
        ip = ipaddress.ip_address(value)
        if ip.is_unspecified or ip.is_loopback or ip.is_link_local:
            return value
        return mapper.map("IP", value)

    out = IPV4_RE.sub(ipv4_repl, out)
    out = IPV6_CANDIDATE_RE.sub(ipv6_repl, out)
    out = MAC_RE.sub(lambda m: m.group(0) if _is_placeholder(m.group(0)) else mapper.map("MAC", m.group(0)), out)
    out = UUID_RE.sub(lambda m: m.group(0) if _is_placeholder(m.group(0)) else mapper.map("UUID", m.group(0)), out)

    def domain_repl(m: re.Match[str]) -> str:
        value = m.group(0)
        if not _looks_like_dns_hostname(value):
            return value
        return mapper.map("DOMAIN", value)

    out = DOMAIN_RE.sub(domain_repl, out)

    def pkg_repl(m: re.Match[str]) -> str:
        pkg = m.group("pkg")
        if _is_placeholder(pkg) or _is_vendor_package_root(pkg):
            return m.group(0)
        return mapper.map("PACKAGE", pkg)

    out = CUSTOMER_PACKAGE_RE.sub(pkg_repl, out)
    for original, replacement in list(mapper.values.get("PACKAGE", {}).items()):
        for sep in ("\\", "/"):
            out = re.sub(re.escape(original.replace(".", sep)), replacement, out, flags=re.I)

    def started_repl(m: re.Match[str]) -> str:
        name = m.group("name")
        directory = m.group("dir")
        if not _is_placeholder(name):
            name = mapper.map("USER", name)
        if not _is_placeholder(directory):
            directory = mapper.map("PATH", directory.rstrip("\\/"))
        return m.group("prefix") + name + m.group("mid") + directory + m.group("suffix")

    out = STARTED_BY_RE.sub(started_repl, out)

    def win_root_repl(m: re.Match[str]) -> str:
        root = m.group("root")
        if _is_placeholder(root):
            return m.group(0)
        return mapper.map("PATH", root)

    out = WIN_ROOT_RE.sub(win_root_repl, out)

    def spring_app_repl(m: re.Match[str]) -> str:
        app = m.group("app").strip()
        low = app.lower()
        if _is_placeholder(app) or low in SPRING_THREAD_NAMES:
            return m.group(0)
        if re.search(r"exec-\d+|nio-|scheduling-|http-nio", low):
            return m.group(0)
        return m.group("prefix") + mapper.map("APP", app) + m.group("suffix")

    out = SPRING_APP_RE.sub(spring_app_repl, out)

    def maven_art_repl(m: re.Match[str]) -> str:
        art = m.group("art")
        if _is_placeholder(art) or art.lower() in MAVEN_SKIP_ARTIFACTS:
            return m.group(0)
        return m.group("prefix") + mapper.map("APP", art) + m.group("suffix")

    out = MAVEN_ARTIFACT_RE.sub(maven_art_repl, out)

    def maven_building_repl(m: re.Match[str]) -> str:
        name = m.group("name").strip()
        if _is_placeholder(name) or not name:
            return m.group(0)
        return m.group("prefix") + mapper.map("APP", name) + m.group("suffix")

    out = MAVEN_BUILDING_RE.sub(maven_building_repl, out)

    def starting_class_repl(m: re.Match[str]) -> str:
        cls = m.group("cls")
        if _is_placeholder(cls):
            return m.group(0)
        return m.group("prefix") + mapper.map("APP", cls) + m.group("suffix")

    out = STARTING_CLASS_RE.sub(starting_class_repl, out)

    def host_repl(m: re.Match[str]) -> str:
        value = m.group("value")
        if _is_placeholder(value) or value.lower() == "localhost":
            return m.group(0)
        return m.group("prefix") + mapper.map("HOST", value)

    out = HOST_FIELD_RE.sub(host_repl, out)

    def win_user_repl(m: re.Match[str]) -> str:
        user = m.group("user")
        if _is_placeholder(user):
            return m.group(0)
        return m.group("prefix") + mapper.map("USER", user)

    out = WINDOWS_USER_RE.sub(win_user_repl, out)
    out = UNIX_HOME_RE.sub(win_user_repl, out)
    out = RELAYSTATE_RE.sub(
        lambda m: m.group("prefix") + (m.group("quote") or "") + (
            m.group("value") if _is_placeholder(m.group("value")) else mapper.map("RELAYSTATE", unquote_plus(m.group("value")))
        ) + (m.group("quote") or ""),
        out,
    )
    return out


def _residual_allow(value: str) -> bool:
    value = (value or "").strip()
    if not value or _is_placeholder(value) or PLACEHOLDER_RE.search(value):
        return True
    if _is_standard_uri(value):
        return True
    low = value.lower()
    if low.startswith(PACKAGE_PREFIXES) or low in STANDARD_HOSTS:
        return True
    if low in {"localhost", "localhost.localdomain"}:
        return True
    if low.endswith(".invalid"):
        return True
    if _is_well_known_public_host(value):
        return True
    if "." in value and not _valid_ip(value) and not EMAIL_RE.fullmatch(value) and not _looks_like_dns_hostname(value):
        return True
    if _valid_ip(value):
        ip = ipaddress.ip_address(value)
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            return True
    return False


def scan_residual_leaks(text: str, limit: int = 50) -> list[dict[str, Any]]:
    """Second-pass detectors on already anonymized text. Placeholders and standard URIs are ignored."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()

    def add(kind: str, line_no: int, value: str) -> None:
        value = (value or "").strip()
        if not value or _residual_allow(value):
            return
        key = (kind, line_no, value)
        if key in seen:
            return
        seen.add(key)
        findings.append({"kind": kind, "line": line_no, "value": value[:120]})

    lines = text.splitlines() or [text]
    for line_no, line in enumerate(lines, 1):
        for m in EMAIL_RE.finditer(line):
            add("EMAIL", line_no, m.group(0))
        for m in JWT_RE.finditer(line):
            add("JWT", line_no, m.group(0))
        for m in AUTH_RE.finditer(line):
            add("AUTH", line_no, m.group("value"))
        for m in IPV4_RE.finditer(line):
            if _valid_ip(m.group(0), 4):
                add("IP", line_no, m.group(0))
        for m in IPV6_CANDIDATE_RE.finditer(line):
            if _valid_ip(m.group(0), 6):
                add("IP", line_no, m.group(0))
        for m in MAC_RE.finditer(line):
            add("MAC", line_no, m.group(0))
        for m in UUID_RE.finditer(line):
            add("UUID", line_no, m.group(0))
        for m in URL_RE.finditer(line):
            raw = m.group(0).rstrip(".,);]")
            if _is_standard_uri(raw):
                continue
            try:
                host = urlsplit(raw).hostname
            except Exception:
                host = None
            if host:
                add("URL", line_no, host)
        for m in DOMAIN_RE.finditer(line):
            add("DOMAIN", line_no, m.group(0))
        for m in WINDOWS_USER_RE.finditer(line):
            add("USER", line_no, m.group("user"))
        for m in UNIX_HOME_RE.finditer(line):
            add("USER", line_no, m.group("user"))
        if len(findings) >= limit:
            break
    return findings[:limit]


def _looks_like_saml_xml(text: str) -> bool:
    return bool(
        ("urn:oasis:names:tc:SAML:2.0:" in text or "urn:oasis:names:tc:SAML:2.0:metadata" in text)
        and SAML_XML_RE.search(text)
    )


_AUDIT_ROOT_RE = re.compile(
    r"<(?:[A-Za-z_][\w.-]*:)?(AuthnRequest|Response|Assertion|LogoutRequest|LogoutResponse|"
    r"EntityDescriptor|EntitiesDescriptor)\b",
    re.I,
)
_AUDIT_SLUG = {
    "AuthnRequest": "authnrequest",
    "Response": "response",
    "Assertion": "assertion",
    "LogoutRequest": "logoutrequest",
    "LogoutResponse": "logoutresponse",
    "EntityDescriptor": "metadata",
    "EntitiesDescriptor": "metadata",
}


def _audit_stem(source_name: str | None) -> str:
    raw = (source_name or "pasted").strip()
    if raw in {"pasted text", "pasted-log.txt"}:
        return "pasted"
    name = raw.replace("\\", "/").rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._")
    return (stem or "pasted")[:80]


def _document_type_from_xml(xml: str) -> str:
    match = _AUDIT_ROOT_RE.search(xml or "")
    if not match:
        return "SAML"
    found = match.group(1)
    canonical = {name.lower(): name for name in _AUDIT_SLUG}
    return canonical.get(found.lower(), found)


def _append_xml_audit(
    artifacts: list[dict[str, Any]],
    seen: set[str],
    decoded_xml: str,
    anonymized_xml: str,
    transport: str,
) -> None:
    if not decoded_xml or decoded_xml in seen:
        return
    seen.add(decoded_xml)
    artifacts.append({
        "transport": transport,
        "document_type": _document_type_from_xml(decoded_xml),
        "decoded_xml": decoded_xml,
        "anonymized_xml": anonymized_xml,
    })


def _assign_xml_audit_names(items: list[dict[str, Any]], source_name: str | None) -> list[dict[str, Any]]:
    stem = _audit_stem(source_name)
    counts: dict[str, int] = {}
    named: list[dict[str, Any]] = []
    for item in items:
        slug = _AUDIT_SLUG.get(str(item.get("document_type") or ""), "saml")
        counts[slug] = counts.get(slug, 0) + 1
        n = counts[slug]
        row = dict(item)
        row["source_name"] = source_name or "pasted text"
        row["decoded_export_name"] = f"{stem}.{slug}_{n:02d}.decoded.xml"
        row["anonymized_export_name"] = f"{stem}.{slug}_{n:02d}.anonymized.xml"
        named.append(row)
    return named


def _decode_base64(value: str) -> bytes | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 16:
        return None
    compact += "=" * ((4 - len(compact) % 4) % 4)
    try:
        return base64.b64decode(compact, altchars=b"-_", validate=False)
    except Exception:
        return None


def _decode_saml_payload(value: str) -> tuple[str, str] | None:
    candidates = [value]
    if "%" in value:
        candidates.extend([unquote(value), unquote_plus(value)])
    seen: set[str] = set()
    for candidate in candidates:
        candidate = candidate.strip()
        if candidate in seen:
            continue
        seen.add(candidate)
        raw = _decode_base64(candidate)
        if raw is None:
            continue
        payloads: list[tuple[bytes, str]] = [(raw, "BASE64")]
        for wbits in (-15, zlib.MAX_WBITS):
            try:
                payloads.append((decompress_limited(raw, wbits), "DEFLATE_BASE64"))
            except Exception:
                pass
        for payload, transport in payloads:
            try:
                xml = payload.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if _looks_like_saml_xml(xml):
                return xml, transport
    return None


def _encode_saml_payload(xml: str, transport: str) -> str:
    raw = xml.encode("utf-8")
    if transport == "DEFLATE_BASE64":
        compressor = zlib.compressobj(wbits=-15)
        raw = compressor.compress(raw) + compressor.flush()
    return base64.b64encode(raw).decode("ascii")


def _qname_local(element: etree._Element) -> str:
    try:
        return etree.QName(element).localname
    except Exception:
        return str(element.tag).rsplit("}", 1)[-1]


def _anonymize_endpoint(value: str, mapper: _Mapper, category: str = "ENTITY") -> str:
    if not value or _is_placeholder(value) or _is_standard_uri(value):
        return value
    stripped = value.strip()
    if stripped.startswith(("http://", "https://")):
        return _replace_urls(value, mapper)
    if _valid_ip(stripped):
        return mapper.map("IP", stripped)
    if DOMAIN_RE.fullmatch(stripped):
        return mapper.map("DOMAIN", stripped)
    return _with_original_ws(value, mapper.map(category, stripped))


def _anonymize_scalar(value: str, mapper: _Mapper, category: str) -> str:
    if not value or _is_placeholder(value):
        return value
    stripped = value.strip()
    if not stripped:
        return value
    if EMAIL_RE.fullmatch(stripped):
        replacement = mapper.map("EMAIL", stripped)
    elif _valid_ip(stripped):
        replacement = mapper.map("IP", stripped)
    elif stripped.startswith(("http://", "https://")):
        return _replace_urls(value, mapper)
    elif DOMAIN_RE.fullmatch(stripped):
        replacement = mapper.map("DOMAIN", stripped)
    else:
        replacement = mapper.map(category, stripped)
    return _with_original_ws(value, replacement)


def _safe_digest_key(value: str) -> str:
    compact = re.sub(r"\s+", "", value or "")
    return hashlib.sha256(compact.encode("utf-8", errors="ignore")).hexdigest().upper()


def _synthetic_certificate_b64(label: str) -> str:
    # Keep anonymized SAML structurally useful: replace identifying certificates with
    # valid synthetic X.509 certificates rather than invalid placeholder text.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ZZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Anonymized Test Data"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{label.lower()}.invalid"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _replace_x509_certificate(element: etree._Element, mapper: _Mapper) -> None:
    original = "".join((element.text or "").split())
    if not original:
        return
    try:
        der = base64.b64decode(original + "=" * ((4 - len(original) % 4) % 4), validate=False)
        key = hashlib.sha256(der).hexdigest().upper()
    except Exception:
        key = _safe_digest_key(original)
    label = mapper.map("X509_CERT", key)
    if key not in mapper.certificate_replacements:
        mapper.certificate_replacements[key] = _synthetic_certificate_b64(label)
    element.text = mapper.certificate_replacements[key]


def _replace_base64_value(element: etree._Element, mapper: _Mapper, category: str) -> None:
    original = "".join((element.text or "").split())
    if not original:
        return
    label = mapper.map(category, _safe_digest_key(original))
    element.text = base64.b64encode(label.encode("ascii")).decode("ascii")


def _anonymize_saml_tree(root: etree._Element, mapper: _Mapper) -> dict[str, int]:
    stats = {"ids": 0, "attributes": 0, "certificates": 0, "signatures": 0}

    # Pre-register IDs before references so numbering is stable and broken/mismatched
    # references remain broken/mismatched after anonymization rather than being "fixed".
    for element in root.iter():
        original_id = element.get("ID")
        if original_id and not _is_placeholder(original_id):
            mapper.map("SAML_ID", original_id)

    for element in root.iter():
        local = _qname_local(element)

        if element.get("ID"):
            old = element.get("ID")
            if old and not _is_placeholder(old):
                element.set("ID", mapper.map("SAML_ID", old))
                stats["ids"] += 1

        if element.get("InResponseTo"):
            old = element.get("InResponseTo")
            if old and not _is_placeholder(old):
                element.set("InResponseTo", mapper.map("SAML_ID", old))
                stats["ids"] += 1

        if element.get("SessionIndex"):
            old = element.get("SessionIndex")
            if old and not _is_placeholder(old):
                element.set("SessionIndex", mapper.map("SESSION", old))
                stats["ids"] += 1

        for attr in ("Destination", "Recipient", "AssertionConsumerServiceURL", "Location", "ResponseLocation", "entityID"):
            value = element.get(attr)
            if value:
                new_value = _anonymize_endpoint(value, mapper)
                if new_value != value:
                    element.set(attr, new_value)
                    stats["attributes"] += 1

        if local == "SubjectLocality" and element.get("Address"):
            old = element.get("Address")
            if old and not _is_placeholder(old):
                element.set("Address", _anonymize_scalar(old, mapper, "ADDRESS"))
                stats["attributes"] += 1

        if local == "NameID":
            for attr in ("NameQualifier", "SPNameQualifier", "SPProvidedID"):
                value = element.get(attr)
                if value:
                    element.set(attr, _anonymize_endpoint(value, mapper, "ENTITY"))
            if element.text:
                element.text = _anonymize_scalar(element.text, mapper, "NAMEID")

        elif local in {"Issuer", "Audience", "AuthenticatingAuthority", "OrganizationURL"} and element.text:
            element.text = _anonymize_endpoint(element.text, mapper, "ENTITY")

        elif local == "AttributeValue" and element.text:
            element.text = _anonymize_scalar(element.text, mapper, "ATTR_VALUE")

        elif local in {"GivenName", "SurName", "TelephoneNumber", "Company"} and element.text:
            element.text = _anonymize_scalar(element.text, mapper, "ATTR_VALUE")

        elif local == "EmailAddress" and element.text:
            element.text = _anonymize_scalar(element.text, mapper, "EMAIL")

        elif local in {"OrganizationName", "OrganizationDisplayName"} and element.text:
            element.text = _anonymize_scalar(element.text, mapper, "ENTITY")

        elif local == "StatusMessage" and element.text:
            element.text = _anonymize_patterns(element.text, mapper)

        if element.tag == f"{{{DS_NS}}}Reference":
            uri = element.get("URI")
            if uri and uri.startswith("#") and len(uri) > 1 and not _is_placeholder(uri[1:]):
                element.set("URI", "#" + mapper.map("SAML_ID", uri[1:]))
                stats["ids"] += 1

        elif element.tag == f"{{{DS_NS}}}X509Certificate":
            _replace_x509_certificate(element, mapper)
            stats["certificates"] += 1

        elif element.tag == f"{{{DS_NS}}}SignatureValue":
            _replace_base64_value(element, mapper, "SIGNATURE")
            stats["signatures"] += 1

        elif element.tag == f"{{{DS_NS}}}DigestValue":
            _replace_base64_value(element, mapper, "DIGEST")
            stats["signatures"] += 1

    return stats


def _anonymize_saml_xml(xml: str, mapper: _Mapper) -> tuple[str, bool, dict[str, int]]:
    if not _looks_like_saml_xml(xml):
        return xml, False, {}
    if "<!DOCTYPE" in xml.upper():
        return _anonymize_patterns(xml, mapper), False, {}

    try:
        root = lxml_fromstring(xml)
    except Exception:
        return _anonymize_patterns(xml, mapper), False, {}

    stats = _anonymize_saml_tree(root, mapper)
    had_declaration = xml.lstrip().startswith("<?xml")
    output = etree.tostring(root, encoding="utf-8", xml_declaration=had_declaration, pretty_print=False).decode("utf-8")
    return output, True, stats


def _embedded_saml_spans(text: str) -> list[tuple[int, int]]:
    """Return non-nested spans of complete SAML XML documents inside mixed text."""
    found: list[tuple[int, int]] = []
    for name in SAML_DOCUMENT_NAMES:
        pattern = re.compile(
            rf"<(?:[A-Za-z_][\w.-]*:)?{name}\b.*?</(?:[A-Za-z_][\w.-]*:)?{name}>",
            re.I | re.S,
        )
        found.extend((match.start(), match.end()) for match in pattern.finditer(text))
    found.sort(key=lambda span: (span[0], -(span[1] - span[0])))
    outer: list[tuple[int, int]] = []
    for start, end in found:
        if any(os <= start and end <= oe for os, oe in outer):
            continue
        outer.append((start, end))
    return sorted(outer)


def _anonymize_embedded_saml_xml(
    text: str,
    mapper: _Mapper,
    audit: list[dict[str, Any]],
    seen: set[str],
) -> tuple[str, int]:
    """Structurally anonymize SAML XML documents embedded in logs or multi-doc pastes.

    A tracer bundle is not one well-formed XML document, so a whole-input parse fails.
    Nested Assertion fragments inside a Response are left to the outer document.
    """
    spans = _embedded_saml_spans(text)
    if not spans:
        return text, 0
    pieces: list[str] = []
    last = 0
    structured_count = 0
    for start, end in spans:
        pieces.append(text[last:start])
        original_xml = text[start:end]
        anonymized, structured, _stats = _anonymize_saml_xml(original_xml, mapper)
        _append_xml_audit(audit, seen, original_xml, anonymized, "embedded XML")
        pieces.append(anonymized)
        if structured:
            structured_count += 1
        last = end
    pieces.append(text[last:])
    return "".join(pieces), structured_count


def _anonymize_encoded_saml(
    text: str,
    mapper: _Mapper,
    audit: list[dict[str, Any]],
    seen: set[str],
) -> tuple[str, int, set[str], int]:
    changed = 0
    transports: set[str] = set()
    structured_count = 0

    def named_repl(match: re.Match[str]) -> str:
        nonlocal changed, structured_count
        original = match.group("value")
        decoded = _decode_saml_payload(original)
        if decoded is None:
            return match.group(0)
        xml, transport = decoded
        anonymized_xml, structured, _stats = _anonymize_saml_xml(xml, mapper)
        _append_xml_audit(audit, seen, xml, anonymized_xml, transport)
        if structured:
            structured_count += 1
        encoded = _encode_saml_payload(anonymized_xml, transport)
        if "%" in original:
            encoded = quote_plus(encoded, safe="")
        changed += 1
        transports.add(transport)
        quote = match.group("quote") or ""
        return match.group("prefix") + quote + encoded + quote

    out = SAML_PARAM_RE.sub(named_repl, text)

    def blob_repl(match: re.Match[str]) -> str:
        nonlocal changed, structured_count
        before = out[max(0, match.start() - 48):match.start()]
        if re.search(r"SAML(?:Response|Request)\s*[=:]\s*['\"]?$", before, re.I):
            return match.group(0)
        original = match.group("value")
        decoded = _decode_saml_payload(original)
        if decoded is None:
            return original
        xml, transport = decoded
        anonymized_xml, structured, _stats = _anonymize_saml_xml(xml, mapper)
        _append_xml_audit(audit, seen, xml, anonymized_xml, transport)
        if structured:
            structured_count += 1
        changed += 1
        transports.add(transport)
        return _encode_saml_payload(anonymized_xml, transport)

    out = BASE64_TOKEN_RE.sub(blob_repl, out)
    return out, changed, transports, structured_count


def anonymize_text(text: str, source_name: str | None = None) -> dict[str, Any]:
    """Return anonymized text plus deterministic mapping and summary.

    SAML-aware behavior:
    - Base64/Redirect SAML is decoded, structurally anonymized, and re-encoded.
    - raw standalone SAML XML, tracer bundles and SAML XML embedded in logs are parsed and anonymized structurally.
    - standard SAML/XML/XMLDSig namespace and algorithm URIs are preserved.
    - IDs and their references are pseudonymized consistently.
    - NameID, AttributeValue, endpoints, SessionIndex, SubjectLocality and metadata contacts are anonymized.
    - X.509 certificates are replaced with parseable synthetic certificates.
    - SignatureValue/DigestValue are replaced because modifying signed XML invalidates the original signature anyway.
    """
    mapper = _Mapper()
    encoded_saml_count = 0
    structured_encoded_count = 0
    saml_transports: set[str] = set()
    structured_count = 0
    attempted_raw_saml = False
    xml_audit: list[dict[str, Any]] = []
    xml_audit_seen: set[str] = set()

    stripped = text.strip()
    if _looks_like_saml_xml(stripped) and stripped.startswith("<"):
        attempted_raw_saml = True
        saml_out, structured, _stats = _anonymize_saml_xml(stripped, mapper)
        _append_xml_audit(xml_audit, xml_audit_seen, stripped, saml_out, "raw XML")
        if structured:
            left = text[: len(text) - len(text.lstrip())]
            right = text[len(text.rstrip()):]
            out = left + saml_out + right
            structured_count = 1
        else:
            out = text
    else:
        out = text

    if structured_count == 0:
        out, encoded_saml_count, saml_transports, structured_encoded_count = _anonymize_encoded_saml(
            out, mapper, xml_audit, xml_audit_seen
        )
        structured_count += structured_encoded_count
        out, embedded_count = _anonymize_embedded_saml_xml(out, mapper, xml_audit, xml_audit_seen)
        structured_count += embedded_count
        if embedded_count:
            attempted_raw_saml = True
        out = _anonymize_patterns(out, mapper)

    limitations = [
        "The anonymizer is deterministic within one run but is not a certified DLP engine.",
        "SAML/XML protocol, namespace, binding, NameID-format, AuthnContext and XMLDSig algorithm URIs are preserved rather than treated as customer domains.",
        "Review the anonymized preview before external sharing; arbitrary extension elements or free-form business data may require additional rules.",
    ]
    if encoded_saml_count or structured_count:
        limitations.append(
            "SAML content was modified for privacy. Any original XML Signature/DigestValue is no longer cryptographically valid; signature/digest values and identifying X.509 certificates are replaced in the anonymized copy."
        )
    if (encoded_saml_count and structured_encoded_count < encoded_saml_count) or (
        attempted_raw_saml and structured_count == 0
    ):
        limitations.append(
            "At least one SAML payload could not be parsed structurally and received fallback pattern-based anonymization; review it manually before sharing."
        )

    residual = scan_residual_leaks(out)
    if residual:
        limitations.append(
            f"Residual scan found {len(residual)} leftover match(es) after anonymization. Review them before external sharing."
        )

    return {
        "text": out,
        "mapping": mapper.as_rows(),
        "counts": mapper.counts(),
        "replacements": sum(mapper.counts().values()),
        "encoded_saml_payloads_anonymized": encoded_saml_count,
        "encoded_saml_transports": sorted(saml_transports),
        "structured_saml_payloads_anonymized": structured_count,
        "residual_findings": residual,
        "residual_count": len(residual),
        "xml_audit_artifacts": _assign_xml_audit_names(xml_audit, source_name),
        "limitations": limitations,
    }
