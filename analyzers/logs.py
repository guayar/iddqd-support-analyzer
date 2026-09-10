from __future__ import annotations

import collections
import os
import re
import sys
import time
from datetime import datetime
from typing import Any, NamedTuple

_TIME = r"[0-2]\d:[0-5]\d:[0-5]\d(?:[.,]\d+)?"
_TZ = r"(?:Z|[+-]\d{2}:?\d{2})?"
_MON = r"Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
_DOW = r"Sun|Mon|Tue|Wed|Thu|Fri|Sat"
_MONTH_NUM = {name.lower(): i for i, name in enumerate(_MON.split("|"), 1)}
TS_TOKEN_RE = re.compile(
    rf"(?P<iso>\d{{4}}-\d{{2}}-\d{{2}}[T ]{_TIME}{_TZ})"
    rf"|(?P<ymd_slash>\d{{4}}/\d{{2}}/\d{{2}}[ T]{_TIME})"
    rf"|(?P<dmy_mon>\d{{2}}-(?:{_MON})-\d{{4}}[ T]{_TIME})"
    rf"|(?P<slash>\d{{2}}/\d{{2}}/(?:\d{{4}}|\d{{2}})[ T]{_TIME})"
    rf"|(?P<oracle>(?:(?:{_DOW}) +)?(?:{_MON}) +\d{{1,2}}[ T]{_TIME} +\d{{4}})"
    rf"|(?P<syslog>(?:{_MON}) +\d{{1,2}}[ T]{_TIME})",
    re.I,
)
SLASH_DATE_HINT_RE = re.compile(r"\d{2}/\d{2}/\d")
LEVEL_NAMES = r"TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|SEVERE|CRITICAL"
ERROR_LEVELS = {"ERROR", "FATAL", "SEVERE", "CRITICAL"}
BRACKET_RE = re.compile(rf"^\[(?P<level>{LEVEL_NAMES})\](?P<rest>.*)$", re.I)
TS_LEVEL_RE = re.compile(rf"^(?P<pad>\s+)(?P<level>{LEVEL_NAMES})\b")
TS_BRACKET_LEVEL_RE = re.compile(
    rf"^\s*\[(?P<level>{LEVEL_NAMES}|NOTICE)\](?P<rest>.*)$",
    re.I,
)
BARE_ERROR_RE = re.compile(r"^(?P<level>ERROR|FATAL|SEVERE|CRITICAL)(?:[:\s]|$)")
CAUSE_LINE_RE = re.compile(r"^(?P<prefix>Caused by:\s+)(?P<body>.+)$", re.I)
SUPPRESSED_LINE_RE = re.compile(r"^(?P<prefix>Suppressed:\s+)(?P<body>.+)$", re.I)
STACK_AT_RE = re.compile(r"^(?:at |\.\.\.\s*\d+\s+(?:common frames omitted|more)\b)", re.I)
# FQCN (has a dot) ending in Exception/Error/Throwable, or an *Exception name. Bare "Error" is not enough.
EXC_HEAD_RE = re.compile(
    r"^(?P<cls>(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*(?:Exception|Error|Throwable)|[A-Za-z_]\w*Exception)"
    r"(?::\s*(?P<msg>.*))?$"
)
EXIT_CODE_RE = re.compile(r"exit code:\s*(\d+)", re.I)
JUNK_TITLE_RE = re.compile(r"^[\s\[\](){}:.,;_\-/=*#]+$")
CLIENT_BRACKET_PREFIX_RE = re.compile(r"^\[client [^\]]+\]\s*", re.I)
MAVEN_ADVISORY_RE = re.compile(
    r"^(?:to see the full stack trace|re-run maven|for more information about the errors|\[help\s+\d+\])",
    re.I,
)
VENDOR_HEAD_RE = re.compile(r"^(?P<family>[A-Z][A-Z0-9]{1,15})-(?P<num>\d{3,8})\b")
VENDOR_FIND_RE = re.compile(r"\b(?P<family>[A-Z][A-Z0-9]{1,15})-(?P<num>\d{3,8})\b")
CODE_AUX_PATTERNS = [
    re.compile(r"\b(SQLSTATE\s*[:=]?\s*[0-9A-Z]{5})\b", re.I),
    re.compile(r"\b(HTTP(?:\s+STATUS)?\s*[:=]?\s*[45]\d\d)\b", re.I),
    re.compile(r"\b(error\s*code\s*[:=]\s*[A-Za-z0-9_.-]+)\b", re.I),
    re.compile(r"\b(status\s*code\s*[:=]\s*[45]\d\d)\b", re.I),
]
VENDOR_CODE_STORE_CAP = 2000
VENDOR_CODE_JSON_CAP = 500
VENDOR_CODE_REPORT_CAP = 40
VENDOR_EXAMPLE_REPORT_CAP = 8
VENDOR_FAMILY_REPORT_CAP = 12
VENDOR_AUX_JSON_CAP = 50
MAX_EVENT_LINES = 500
SAMPLE_CHARS = 50_000
INLINE_EXC_RE = re.compile(
    r"Exception:\s*(?P<cls>(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*(?:Exception|Error))"
    r"(?:\.\s*Message:\s*(?P<msg>.*))?",
    re.I,
)
LEVEL_COLON_RE = re.compile(rf"(?i)\b(?P<level>{LEVEL_NAMES}):")
SSHD_PID_RE = re.compile(r"\bsshd\[(?P<pid>\d+)\]")
IPV4_RE = re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
REPEAT_RE = re.compile(r"message repeated (?P<n>\d+) times:\s*\[(?P<body>.*)\]\s*$", re.I)
SSH_USER_RES = [
    re.compile(r"invalid user\s+(?P<user>\S+)", re.I),
    re.compile(r"Failed (?:password|none) for (?:invalid user )?(?P<user>\S+) from", re.I),
    re.compile(r"failures? for (?P<user>\S+)", re.I),
    re.compile(r"\buser=(?P<user>\S+)", re.I),
]
SSH_RULES = [
    (re.compile(r"POSSIBLE BREAK-IN ATTEMPT", re.I), "WARN", "security", "reverse_dns_mismatch"),
    (re.compile(r"\bfatal:", re.I), "ERROR", "ssh", "fatal"),
    (re.compile(r"Too many authentication failures", re.I), "ERROR", "security", "too_many_failures"),
    (re.compile(r"No more user authentication methods available", re.I), "ERROR", "security-auth", "no_more_methods"),
    (re.compile(r"PAM\b.*\bauthentication failures?\b", re.I), "ERROR", "security-auth", "pam_failures"),
    (re.compile(r"\berror:", re.I), "ERROR", "ssh", "error"),
    (re.compile(r"Failed password", re.I), "WARN", "security-auth", "failed_password"),
    (re.compile(r"Failed none", re.I), "WARN", "security-auth", "failed_none"),
    (re.compile(r"authentication failure", re.I), "WARN", "security-auth", "auth_failure"),
    (re.compile(r"Invalid user", re.I), "WARN", "security-auth", "invalid_user"),
]
_AUTH_KINDS = {
    "reverse_dns_mismatch",
    "fatal",
    "too_many_failures",
    "no_more_methods",
    "pam_failures",
    "error",
    "failed_password",
    "failed_none",
    "auth_failure",
    "invalid_user",
}
_FAILED_AUTH_KINDS = {
    "failed_password",
    "failed_none",
    "auth_failure",
    "invalid_user",
    "too_many_failures",
    "pam_failures",
    "no_more_methods",
}
_LEVEL_RANK = {
    "CRITICAL": 0,
    "FATAL": 1,
    "SEVERE": 2,
    "ERROR": 3,
    "WARN": 4,
    "WARNING": 4,
}
BRUTE_FORCE_MIN_SESSIONS = 5
BRUTE_FORCE_GAP_SECONDS = 15 * 60
BRUTE_FORCE_RAPID_WINDOW_SECONDS = 60
INCIDENT_RESULT_CAP = 100
# Display caps for explicit source markers only (not semantic SSH_RULES).
LINE_FINDING_CAPS = {
    "FATAL": 200,
    "CRITICAL": 100,
    "SEVERE": 100,
    "ERROR": 5,
}
LINE_FINDING_CONTEXT_LOOKBACK = 40
LINE_FINDING_CONTEXT_MAX = 8
_LINE_FINDING_ORDER = {"FATAL": 0, "CRITICAL": 1, "SEVERE": 2, "ERROR": 3}


class _TsPolicy(NamedTuple):
    dayfirst: bool | None
    unamb: frozenset[tuple[int, int, int]]


class _PrefixSpan:
    def __init__(self, end: int):
        self._end = end

    def end(self, *_args) -> int:
        return self._end


def _expand_year(year: int) -> int:
    if year >= 100:
        return year
    return 2000 + year if year < 70 else 1900 + year


def _clock(raw: str) -> tuple[int, int, int, int]:
    raw = raw.replace(",", ".")
    raw = re.sub(r"(Z|[+-]\d{2}:?\d{2})$", "", raw, flags=re.I)
    parts = raw.split(":")
    hour, minute = int(parts[0]), int(parts[1])
    sec = float(parts[2]) if len(parts) > 2 else 0.0
    second = int(sec)
    micro = int(round((sec - second) * 1_000_000))
    if micro == 1_000_000:
        second += 1
        micro = 0
    return hour, minute, second, micro


def _combine(year: int, month: int, day: int, time_raw: str) -> datetime | None:
    try:
        hour, minute, second, micro = _clock(time_raw)
        return datetime(year, month, day, hour, minute, second, micro)
    except ValueError:
        return None


def _split_date_time(raw: str) -> tuple[str, str]:
    raw = raw.strip()
    if len(raw) > 10 and raw[10] == "T":
        raw = raw.replace("T", " ", 1)
    return raw.split(" ", 1)


def _from_iso(raw: str) -> datetime | None:
    s = raw.replace(",", ".")
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _from_oracle(raw: str) -> datetime | None:
    m = re.match(
        rf"(?:(?:{_DOW}) +)?(?P<mon>{_MON}) +(?P<day>\d{{1,2}})[ T](?P<time>{_TIME}) +(?P<year>\d{{4}})",
        raw.strip(),
        re.I,
    )
    if not m:
        return None
    return _combine(int(m.group("year")), _MONTH_NUM[m.group("mon")[:3].lower()], int(m.group("day")), m.group("time"))


def _datetime_from_match(m: re.Match[str], policy: _TsPolicy) -> datetime | None:
    if m.group("iso"):
        return _from_iso(m.group("iso"))
    if m.group("ymd_slash"):
        date, time = _split_date_time(m.group("ymd_slash"))
        year, month, day = (int(x) for x in date.split("/"))
        return _combine(year, month, day, time)
    if m.group("dmy_mon"):
        date, time = _split_date_time(m.group("dmy_mon"))
        day_s, mon_s, year_s = date.split("-")
        return _combine(int(year_s), _MONTH_NUM[mon_s[:3].lower()], int(day_s), time)
    if m.group("oracle"):
        return _from_oracle(m.group("oracle"))
    if m.group("syslog"):
        return None
    raw = m.group("slash")
    if not raw:
        return None
    date, time = _split_date_time(raw)
    a_s, b_s, y_s = date.split("/")
    a, b, year = int(a_s), int(b_s), _expand_year(int(y_s))
    if a < 1 or b < 1 or a > 31 or b > 31:
        return None
    if a > 12 and b > 12:
        return None
    if a > 12:
        return _combine(year, b, a, time)
    if b > 12:
        return _combine(year, a, b, time)
    dmy = _combine(year, b, a, time)
    mdy = _combine(year, a, b, time)
    if policy.dayfirst is True:
        return dmy
    if policy.dayfirst is False:
        return mdy
    in_dmy = dmy is not None and (dmy.year, dmy.month, dmy.day) in policy.unamb
    in_mdy = mdy is not None and (mdy.year, mdy.month, mdy.day) in policy.unamb
    if in_dmy and not in_mdy:
        return dmy
    if in_mdy and not in_dmy:
        return mdy
    return None


def _forced_slash_order(m: re.Match[str]) -> bool | None:
    raw = m.group("slash")
    if not raw:
        return None
    a_s, b_s, _y = _split_date_time(raw)[0].split("/")
    a, b = int(a_s), int(b_s)
    if a > 12 and b <= 12:
        return True
    if b > 12 and a <= 12:
        return False
    return None


def _ts_policy(lines: list[str], text: str | None = None) -> _TsPolicy:
    unamb: set[tuple[int, int, int]] = set()
    saw_dmy = False
    saw_mdy = False
    empty = _TsPolicy(None, frozenset())
    if text is not None and not SLASH_DATE_HINT_RE.search(text):
        return empty
    for line in lines:
        for m in TS_TOKEN_RE.finditer(line):
            forced = _forced_slash_order(m)
            if forced is True:
                saw_dmy = True
            elif forced is False:
                saw_mdy = True
            dt = _datetime_from_match(m, empty)
            if dt is not None:
                unamb.add((dt.year, dt.month, dt.day))
    dayfirst: bool | None
    if saw_dmy and not saw_mdy:
        dayfirst = True
    elif saw_mdy and not saw_dmy:
        dayfirst = False
    else:
        dayfirst = None
    return _TsPolicy(dayfirst, frozenset(unamb))


def _parse_ts(line: str, policy: _TsPolicy | None = None) -> datetime | None:
    pol = policy or _TsPolicy(None, frozenset())
    for m in TS_TOKEN_RE.finditer(line):
        dt = _datetime_from_match(m, pol)
        if dt is None:
            continue
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt
    return None


def syslog_stamp(line: str) -> str | None:
    """RFC3164 prefix (`MMM d HH:mm:ss` / `MMM dd HH:mm:ss`) as written, without a year."""
    s = line.lstrip()
    if s.startswith("["):
        return None
    m = TS_TOKEN_RE.match(s)
    if not m or not m.group("syslog"):
        return None
    return m.group("syslog")


def _syslog_sort_key(raw: str) -> tuple[int, int, int, int, int] | None:
    m = re.match(
        rf"(?P<mon>{_MON})\s+(?P<day>\d{{1,2}})\s+(?P<time>{_TIME})\b",
        raw.strip(),
        re.I,
    )
    if not m:
        return None
    hour, minute, second, _micro = _clock(m.group("time"))
    return (_MONTH_NUM[m.group("mon")[:3].lower()], int(m.group("day")), hour, minute, second)


def _syslog_internal_dt(raw: str) -> datetime | None:
    key = _syslog_sort_key(raw)
    if key is None:
        return None
    month, day, hour, minute, second = key
    try:
        return datetime(2000, month, day, hour, minute, second)
    except ValueError:
        return None


def _vendor_leads_record(line: str) -> bool:
    s = line.lstrip()
    ts = _timestamp_at_start(line)
    rest = s[ts.end():].lstrip() if ts else s
    return bool(VENDOR_HEAD_RE.match(rest))


def colon_severity(line: str) -> str | None:
    if _vendor_leads_record(line):
        return None
    m = LEVEL_COLON_RE.search(line)
    if not m:
        return None
    return _normalize_level(m.group("level"))


def ssh_rule(line: str) -> tuple[str, str, str] | None:
    body = line
    repeated = REPEAT_RE.search(line)
    if repeated:
        body = repeated.group("body")
    for pat, level, category, kind in SSH_RULES:
        if pat.search(body):
            return level, category, kind
    return None


def _ssh_pid(line: str) -> str | None:
    m = SSHD_PID_RE.search(line)
    return m.group("pid") if m else None


def _source_line_context(lines: list[str], idx: int, pid: str | None) -> list[str]:
    """Same-PID lines up to and including the finding (1-based idx). Isolated line if no PID."""
    if not pid:
        return [lines[idx - 1]]
    start = max(1, idx - LINE_FINDING_CONTEXT_LOOKBACK)
    ctx = [
        lines[i - 1]
        for i in range(start, idx + 1)
        if _ssh_pid(lines[i - 1]) == pid
    ]
    if not ctx:
        return [lines[idx - 1]]
    return ctx[-LINE_FINDING_CONTEXT_MAX:]


def _ssh_ip(line: str) -> str | None:
    from_m = re.search(r"\bfrom (?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b", line, re.I)
    if from_m:
        return from_m.group("ip")
    by_m = re.search(r"\b(?:closed by|disconnect from) (?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b", line, re.I)
    if by_m:
        return by_m.group("ip")
    rhost = re.search(r"\brhost=(?P<host>\S+)", line, re.I)
    if rhost:
        host = rhost.group("host").rstrip(",")
        if IPV4_RE.fullmatch(host):
            return host
    br = re.search(r"\[(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\]", line)
    if br:
        return br.group("ip")
    m = IPV4_RE.search(line)
    return m.group("ip") if m else None


def _ssh_user(line: str) -> str | None:
    for pat in SSH_USER_RES:
        m = pat.search(line)
        if m:
            return m.group("user")
    return None


def session_incident_level(kinds: set[str]) -> str:
    """Correlated sshd[pid] incident level — not max(line rule)."""
    failed_auth = bool(kinds & _FAILED_AUTH_KINDS)
    reverse_dns = "reverse_dns_mismatch" in kinds
    if reverse_dns and failed_auth:
        return "ERROR"
    if kinds & {"too_many_failures", "pam_failures", "no_more_methods"}:
        return "ERROR"
    if "error" in kinds:
        return "ERROR"
    if reverse_dns:
        return "WARN"
    if "fatal" in kinds:
        return "ERROR"
    if failed_auth:
        return "WARN"
    return "WARN"


def _ssh_session_title(sess: dict[str, Any]) -> str:
    kinds = sess["kinds"]
    ip = sess.get("ip")
    user = sess.get("user")
    where = f" from {ip}" if ip else ""
    who = f" for {user}" if user else ""
    if "too_many_failures" in kinds:
        return f"SSH too many authentication failures{who}{where}"
    if "no_more_methods" in kinds:
        return f"SSH authentication methods exhausted{who}{where}"
    if kinds & {"failed_password", "auth_failure", "invalid_user", "failed_none", "pam_failures"}:
        return f"SSH authentication failure{who}{where}"
    if "reverse_dns_mismatch" in kinds:
        return f"SSH reverse-DNS mismatch{where}{who}"
    if "fatal" in kinds:
        return f"SSH fatal{where}{who}"
    if "error" in kinds:
        return f"SSH error{where}"
    return f"SSH security event{where}"


def _incident_from_session(sess: dict[str, Any]) -> dict[str, Any]:
    return {
        "signature": _ssh_session_title(sess),
        "count": 1,
        "level": sess["level"],
        "category": sess.get("category"),
        "kind": "ssh_session",
        "root_cause": None,
        "top_exception": None,
        "causes": [],
        "exception_chain": [],
        "exit_code": None,
        "codes": {},
        "first_line": sess["first_line"],
        "sample": "\n".join(sess["lines"])[:SAMPLE_CHARS],
    }


def _cluster_duration_seconds(cluster: list[dict[str, Any]]) -> float | None:
    first_dt = _syslog_internal_dt(cluster[0]["stamp"]) if cluster[0].get("stamp") else None
    last_dt = _syslog_internal_dt(cluster[-1]["stamp"]) if cluster[-1].get("stamp") else None
    if first_dt is None or last_dt is None:
        return None
    return (last_dt - first_dt).total_seconds()


def _brute_force_level_and_title(ip: str, n: int, duration: float | None) -> tuple[str, str]:
    rapid = duration is not None and duration <= BRUTE_FORCE_RAPID_WINDOW_SECONDS
    if n >= 10 or (n >= BRUTE_FORCE_MIN_SESSIONS and rapid):
        return "ERROR", f"SSH brute-force from {ip} ({n} authentication attempts)"
    return "WARN", f"Suspected SSH brute-force from {ip} ({n} authentication attempts)"


def _brute_force_incidents(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ip: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for sess in sessions:
        ip = sess.get("ip")
        if ip:
            by_ip[ip].append(sess)
    out: list[dict[str, Any]] = []
    for ip, group in by_ip.items():
        dated = []
        for sess in group:
            dt = _syslog_internal_dt(sess["stamp"]) if sess.get("stamp") else None
            dated.append((dt, sess))
        dated.sort(key=lambda x: (x[0] is None, x[0] or datetime.min, x[1]["first_line"]))
        cluster: list[dict[str, Any]] = []
        prev: datetime | None = None

        def flush_cluster():
            if len(cluster) < BRUTE_FORCE_MIN_SESSIONS:
                return
            duration = _cluster_duration_seconds(cluster)
            level, signature = _brute_force_level_and_title(ip, len(cluster), duration)
            first = cluster[0]
            sample_lines = []
            for s in cluster[:8]:
                sample_lines.extend(s["lines"][:3])
            out.append({
                "signature": signature,
                "count": len(cluster),
                "level": level,
                "category": "security-auth",
                "kind": "brute_force",
                "root_cause": None,
                "top_exception": None,
                "causes": [],
                "exception_chain": [],
                "exit_code": None,
                "codes": {},
                "first_line": first["first_line"],
                "sample": "\n".join(sample_lines)[:SAMPLE_CHARS],
            })

        for dt, sess in dated:
            if not cluster:
                cluster = [sess]
                prev = dt
                continue
            gap_ok = True
            if dt is not None and prev is not None:
                gap_ok = (dt - prev).total_seconds() <= BRUTE_FORCE_GAP_SECONDS
            if gap_ok:
                cluster.append(sess)
                prev = dt or prev
            else:
                flush_cluster()
                cluster = [sess]
                prev = dt
        flush_cluster()
    return out


def collect_ssh_incidents(lines: list[str], enabled: bool = True) -> tuple[list[dict[str, Any]], int]:
    if not enabled:
        return [], 0
    sessions: dict[str, dict[str, Any]] = {}
    for idx, line in enumerate(lines, 1):
        if "sshd[" not in line:
            continue
        pid = _ssh_pid(line)
        rule = ssh_rule(line)
        if not pid:
            continue
        sess = sessions.setdefault(pid, {
            "pid": pid,
            "lines": [],
            "first_line": idx,
            "ip": None,
            "user": None,
            "kinds": set(),
            "level": None,
            "category": None,
            "stamp": syslog_stamp(line),
        })
        sess["lines"].append(line)
        ip = _ssh_ip(line)
        if ip:
            sess["ip"] = ip
        user = _ssh_user(line)
        if user:
            sess["user"] = user
        stamp = syslog_stamp(line)
        if stamp:
            sess["stamp"] = stamp
        if rule:
            _, category, kind = rule
            sess["kinds"].add(kind)
            sess["category"] = category
    auth_sessions = [s for s in sessions.values() if s["kinds"] & _AUTH_KINDS]
    for sess in auth_sessions:
        sess["level"] = session_incident_level(sess["kinds"])
    incidents = [_incident_from_session(s) for s in auth_sessions]
    incidents.extend(_brute_force_incidents(auth_sessions))
    return incidents, len(auth_sessions)


def _timestamp_at_start(line: str) -> _PrefixSpan | None:
    s = line.lstrip()
    if s.startswith("["):
        inner = s[1:]
        m = TS_TOKEN_RE.match(inner)
        if not m:
            return None
        close = inner.find("]")
        if close < m.end():
            return None
        return _PrefixSpan(close + 2)
    m = TS_TOKEN_RE.match(s)
    return _PrefixSpan(m.end()) if m else None


def _normalize_level(level: str) -> str:
    level = level.upper()
    if level == "WARNING":
        return "WARN"
    if level == "NOTICE":
        return "INFO"
    return level


def _first_vendor_code(line: str) -> str | None:
    s = line.lstrip()
    ts = _timestamp_at_start(line)
    after_ts = s[ts.end():] if ts else s
    stripped = after_ts.lstrip()
    has_level = False
    payload = stripped
    bm = BRACKET_RE.match(stripped)
    if bm:
        has_level = True
        payload = bm.group("rest") or ""
    else:
        lm = TS_LEVEL_RE.match(after_ts)
        if lm:
            has_level = True
            payload = after_ts[lm.end():]
        else:
            bm2 = BARE_ERROR_RE.match(stripped)
            if bm2:
                has_level = True
                payload = stripped[bm2.end():]
    if has_level or ts:
        m = VENDOR_FIND_RE.search(payload)
        return f"{m.group('family')}-{m.group('num')}" if m else None
    m = VENDOR_HEAD_RE.match(stripped)
    return f"{m.group('family')}-{m.group('num')}" if m else None


def _aux_codes(line: str) -> list[str]:
    if (
        "HTTP" not in line
        and "http" not in line
        and "SQLSTATE" not in line
        and "sqlstate" not in line
        and "error code" not in line
        and "Error code" not in line
        and "status code" not in line
        and "Status code" not in line
    ):
        return []
    found = []
    for pat in CODE_AUX_PATTERNS:
        found.extend(m.group(1).strip() for m in pat.finditer(line))
    return found


def _code_list(text: str) -> list[str]:
    found: list[str] = []
    for line in text.splitlines() or [text]:
        vendor = _first_vendor_code(line)
        if vendor:
            found.append(vendor)
        found.extend(_aux_codes(line))
    return list(dict.fromkeys(found))


def log_record_prefix(line: str) -> dict[str, Any] | None:
    """Return a recognized log-record prefix, or None for continuations / message text."""
    stripped = line.strip()
    if not stripped:
        return None
    bm = BRACKET_RE.match(stripped)
    if bm:
        return {"level": _normalize_level(bm.group("level")), "style": "bracket", "rest": bm.group("rest")}
    ts = _timestamp_at_start(line)
    if ts:
        rest = line.lstrip()[ts.end():]
        lm = TS_LEVEL_RE.match(rest)
        if lm:
            return {"level": _normalize_level(lm.group("level")), "style": "timestamped", "rest": rest[lm.end():]}
        bm_ts = TS_BRACKET_LEVEL_RE.match(rest)
        if bm_ts:
            return {
                "level": _normalize_level(bm_ts.group("level")),
                "style": "timestamp_bracket",
                "rest": bm_ts.group("rest") or "",
            }
        return None
    bm2 = BARE_ERROR_RE.match(stripped)
    if bm2:
        return {"level": _normalize_level(bm2.group("level")), "style": "bare", "rest": stripped[bm2.end():]}
    return None


def is_new_log_record(line: str) -> bool:
    if log_record_prefix(line):
        return True
    return _timestamp_at_start(line) is not None


def _is_maven_advisory(line: str) -> bool:
    rec = log_record_prefix(line)
    if not rec or rec["style"] != "bracket" or rec["level"] not in ERROR_LEVELS:
        return False
    rest = (rec.get("rest") or "").strip()
    if not rest:
        return True
    return bool(MAVEN_ADVISORY_RE.match(rest))


def _is_stack_continuation(line: str) -> bool:
    s = line.strip()
    if not s:
        return True
    if CAUSE_LINE_RE.match(s) or SUPPRESSED_LINE_RE.match(s):
        return True
    if STACK_AT_RE.match(s) or s.startswith("at "):
        return True
    if EXC_HEAD_RE.match(s):
        return True
    if line[:1] in {" ", "\t"}:
        return True
    return False


def _iter_error_events(lines: list[str]):
    current: dict[str, Any] | None = None

    def flush():
        nonlocal current
        if current:
            yield current
            current = None

    for idx, line in enumerate(lines, 1):
        rec = log_record_prefix(line)
        if rec and rec["level"] in ERROR_LEVELS:
            if current and current.get("style") == "bracket" and _is_maven_advisory(line):
                current["lines"].append(line)
                continue
            yield from flush()
            current = {"start_line": idx, "lines": [line], "level": rec["level"], "style": rec["style"]}
            continue
        if rec or _timestamp_at_start(line):
            yield from flush()
            continue
        if current and len(current["lines"]) < MAX_EVENT_LINES and _is_stack_continuation(line):
            current["lines"].append(line)
            continue
        if current and not line.strip():
            current["lines"].append(line)
            continue
        yield from flush()
    yield from flush()


def _split_events(lines: list[str]) -> list[dict[str, Any]]:
    return list(_iter_error_events(lines))


def _exc_class(body: str) -> str | None:
    m = EXC_HEAD_RE.match(body.strip())
    return m.group("cls") if m else None


def parse_java_exception_chain(lines: list[str]) -> dict[str, Any]:
    top: str | None = None
    causes: list[str] = []
    suppressed: list[str] = []
    for raw in lines:
        if log_record_prefix(raw):
            continue
        s = raw.strip()
        if not s:
            continue
        cm = CAUSE_LINE_RE.match(s)
        if cm:
            causes.append(cm.group("body").strip())
            continue
        sm = SUPPRESSED_LINE_RE.match(s)
        if sm:
            suppressed.append(sm.group("body").strip())
            continue
        if STACK_AT_RE.match(s):
            continue
        em = EXC_HEAD_RE.match(s)
        if em and top is None:
            msg = (em.group("msg") or "").strip()
            top = f"{em.group('cls')}: {msg}".strip(": ") if msg else em.group("cls")
    if top is None:
        for raw in lines:
            rec = log_record_prefix(raw)
            if not rec:
                continue
            im = INLINE_EXC_RE.search(raw)
            if im:
                msg = (im.group("msg") or "").strip()
                top = f"{im.group('cls')}: {msg}".strip(": ") if msg else im.group("cls")
                break
    root = causes[-1] if causes else top
    chain_classes: list[str] = []
    for body in ([top] if top else []) + causes:
        cls = _exc_class(body)
        if cls:
            chain_classes.append(cls)
    return {
        "top_exception": top,
        "causes": causes,
        "suppressed": suppressed,
        "root_cause": root,
        "exception_chain": chain_classes,
    }


def _header_message(first_line: str) -> str:
    rec = log_record_prefix(first_line)
    if rec and rec["style"] == "bracket":
        rest = (rec.get("rest") or "").strip()
        rest = re.sub(r"\s*->\s*\[Help\s+\d+\]\s*$", "", rest, flags=re.I)
        return rest
    if rec and rec["style"] in {"timestamped", "timestamp_bracket"}:
        if rec["style"] == "timestamped" and " : " in first_line:
            return first_line.rsplit(" : ", 1)[-1].strip()
        rest = (rec.get("rest") or "").strip()
        if rec["style"] == "timestamp_bracket":
            rest = CLIENT_BRACKET_PREFIX_RE.sub("", rest, count=1)
        return rest
    if rec and rec["style"] == "bare":
        return (rec.get("rest") or "").strip()
    return first_line.strip()


def _meaningful_title(text: str | None) -> str | None:
    if not text:
        return None
    t = " ".join(text.split())
    if not t or JUNK_TITLE_RE.match(t):
        return None
    if len(t) < 2:
        return None
    return t[:500]


def _normalize_for_group(text: str) -> str:
    t = " ".join(text.split())
    t = re.sub(r"defined in file \[[^\]]+\]", "defined in file [<path>]", t)
    t = re.sub(r"\([^)]+\.java:\d+\)", "()", t)
    t = re.sub(r"\[client [^\]]+\]", "[client <ip>]", t)
    t = re.sub(r"\bchild \d+\b", "child <id>", t)
    return t[:500]


def _grouping_key(event: dict[str, Any], chain: dict[str, Any]) -> tuple[str, str]:
    root = chain.get("root_cause")
    if root:
        cls = _exc_class(root) or ""
        return ("root", _normalize_for_group(f"{cls}: {root}"))
    top = chain.get("top_exception")
    if top:
        cls = _exc_class(top) or ""
        return ("top", _normalize_for_group(f"{cls}: {top}"))
    msg = _meaningful_title(_header_message(event["lines"][0]))
    if msg:
        return ("msg", _normalize_for_group(msg))
    return ("unk", "Unknown error")


def _incident_title(event: dict[str, Any], chain: dict[str, Any]) -> str:
    header = _meaningful_title(_header_message(event["lines"][0]))
    if header:
        if event.get("style") == "timestamp_bracket":
            return _normalize_for_group(header)
        return header
    if chain.get("root_cause"):
        titled = _meaningful_title(chain["root_cause"])
        if titled:
            return titled
    if chain.get("top_exception"):
        titled = _meaningful_title(chain["top_exception"])
        if titled:
            return titled
    cls = (chain.get("exception_chain") or [None])[-1]
    if cls:
        return cls
    return "Unknown error"


def _profile_log(t0: float, label: str) -> float:
    now = time.perf_counter()
    if os.environ.get("IDDQD_LOG_PROFILE") == "1":
        print(f"iddqd log profile: {label} {(now - t0) * 1000:.1f} ms", file=sys.stderr)
    return now


def analyze_log_text(text: str, filename: str | None = None) -> dict[str, Any]:
    t0 = time.perf_counter()
    lines = text.splitlines()
    levels = collections.Counter()
    codes = collections.Counter()
    aux_counts = collections.Counter()
    families = collections.Counter()
    code_details: dict[str, dict[str, Any]] = {}
    n_cal = 0
    ts_min: datetime | None = None
    ts_max: datetime | None = None
    n_syslog = 0
    syslog_min: tuple[tuple[int, int, int, int, int], str] | None = None
    syslog_max: tuple[tuple[int, int, int, int, int], str] | None = None
    saw_sshd = False

    policy = _ts_policy(lines, text)
    t1 = _profile_log(t0, "ts_policy")
    line_findings: list[dict[str, Any]] = []
    finding_shown = collections.Counter()
    for idx, line in enumerate(lines, 1):
        if "sshd[" in line:
            saw_sshd = True
        ts = _parse_ts(line, policy)
        if ts:
            n_cal += 1
            if ts_min is None or ts < ts_min:
                ts_min = ts
            if ts_max is None or ts > ts_max:
                ts_max = ts
        raw = syslog_stamp(line)
        if raw:
            key = _syslog_sort_key(raw)
            if key:
                n_syslog += 1
                item = (key, raw)
                if syslog_min is None or key < syslog_min[0]:
                    syslog_min = item
                if syslog_max is None or key > syslog_max[0]:
                    syslog_max = item
        source_level = None
        rule = None
        rec = log_record_prefix(line)
        if rec:
            levels[rec["level"]] += 1
            source_level = rec["level"]
        else:
            colon = colon_severity(line)
            if colon:
                levels[colon] += 1
                source_level = colon
            elif "sshd" in line:
                rule = ssh_rule(line)
                if rule:
                    levels[_normalize_level(rule[0])] += 1
        cap = LINE_FINDING_CAPS.get(source_level or "")
        if cap and finding_shown[source_level] < cap:
            finding_shown[source_level] += 1
            pid = _ssh_pid(line) if "sshd[" in line else None
            if rule is None and pid:
                rule = ssh_rule(line)
            line_findings.append({
                "line": idx,
                "source_level": source_level,
                "semantic_level": _normalize_level(rule[0]) if rule else None,
                "kind": "explicit_source_marker",
                "component": f"sshd[{pid}]" if pid else None,
                "message": line,
                "context": _source_line_context(lines, idx, pid),
            })
        vendor = _first_vendor_code(line)
        if vendor:
            family = vendor.split("-", 1)[0]
            families[family] += 1
            codes[vendor] += 1
            if vendor in code_details:
                det = code_details[vendor]
                det["count"] += 1
                det["last_line"] = idx
            elif len(code_details) < VENDOR_CODE_STORE_CAP:
                code_details[vendor] = {
                    "code": vendor,
                    "family": family,
                    "count": 1,
                    "first_line": idx,
                    "last_line": idx,
                    "example": line.strip()[:240],
                }
        for aux in _aux_codes(line):
            aux_counts[aux] += 1
    line_findings.sort(
        key=lambda f: (_LINE_FINDING_ORDER.get(f["source_level"] or "", 50), f["line"])
    )
    t2 = _profile_log(t1, "line_scan")

    if ts_min is not None and ts_max is not None:
        time_range = {
            "from": ts_min.isoformat(),
            "to": ts_max.isoformat(),
            "year_present": True,
        }
    elif syslog_min is not None and syslog_max is not None:
        time_range = {
            "from": syslog_min[1],
            "to": syslog_max[1],
            "year_present": False,
        }
    else:
        time_range = {"from": None, "to": None}

    event_count = 0
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for ev in _iter_error_events(lines):
        event_count += 1
        chain = parse_java_exception_chain(ev["lines"])
        key = _grouping_key(ev, chain)
        sample = "\n".join(ev["lines"])[:SAMPLE_CHARS]
        exit_m = EXIT_CODE_RE.search(sample)
        entry = grouped.setdefault(key, {
            "signature": _incident_title(ev, chain),
            "count": 0,
            "level": ev["level"],
            "root_cause": chain["root_cause"],
            "top_exception": chain["top_exception"],
            "causes": chain["causes"],
            "exception_chain": chain["exception_chain"],
            "exit_code": int(exit_m.group(1)) if exit_m else None,
            "codes": collections.Counter(),
            "first_line": ev["start_line"],
            "sample": sample,
        })
        entry["count"] += 1
        entry["first_line"] = min(entry["first_line"], ev["start_line"])
        if len(sample) > len(entry["sample"]):
            entry["sample"] = sample
        if chain["root_cause"] and not entry["root_cause"]:
            entry["root_cause"] = chain["root_cause"]
            entry["top_exception"] = chain["top_exception"]
            entry["causes"] = chain["causes"]
            entry["exception_chain"] = chain["exception_chain"]
        for c in _code_list(sample):
            entry["codes"][c] += 1
    t3 = _profile_log(t2, "split_events")

    groups = []
    for v in grouped.values():
        v = dict(v)
        v["codes"] = dict(v["codes"])
        groups.append(v)

    ssh_incidents, ssh_event_count = collect_ssh_incidents(lines, enabled=saw_sshd)
    _profile_log(t3, "ssh_and_groups")
    groups.extend(ssh_incidents)
    groups.sort(
        key=lambda x: (
            0 if x.get("kind") == "brute_force" else 1,
            _LEVEL_RANK.get(x.get("level") or "", 50),
            x["first_line"],
        )
    )
    incident_unique_count = len(groups)
    shown = groups[:INCIDENT_RESULT_CAP]
    stored_occurrences = sum(codes.values())
    unique_n = len(codes)
    listed = dict(codes.most_common(VENDOR_CODE_JSON_CAP))
    details_out = []
    for code, count in list(listed.items())[:VENDOR_CODE_REPORT_CAP]:
        if code in code_details:
            det = dict(code_details[code])
            det["count"] = count
            details_out.append(det)
        else:
            details_out.append({
                "code": code,
                "family": code.split("-", 1)[0],
                "count": count,
            })
    _profile_log(t0, "total")

    return {
        "kind": "log",
        "filename": filename,
        "line_count": len(lines),
        "timestamped_lines": n_cal if n_cal else n_syslog,
        "time_range": time_range,
        "levels": dict(levels),
        "line_findings": line_findings,
        "error_codes": listed,
        "aux_codes": dict(aux_counts.most_common(VENDOR_AUX_JSON_CAP)),
        "vendor_code_families": dict(families),
        "vendor_code_unique": unique_n,
        "vendor_code_occurrences": stored_occurrences,
        "vendor_code_list_truncated": unique_n > VENDOR_CODE_REPORT_CAP,
        "vendor_code_json_truncated": unique_n > VENDOR_CODE_JSON_CAP,
        "vendor_code_details": details_out,
        "error_event_count": event_count + ssh_event_count,
        "incident_unique_count": incident_unique_count,
        "error_groups": shown,
        "incidents": shown,
        "limitations": [
            "A timestamp may be followed by a bracketed level (`[ts] [error] message`). Apache `notice` is counted as INFO and is not an incident. `crit` / `alert` / `emerg` are not mapped. Repeated messages are grouped on the text after the level; `[client …]` and `child <digits>` are treated as context, not identity. Trailing status numbers such as `error state 6` are kept distinct.",
            "RFC3164/syslog stamps (`MMM d HH:mm:ss`) are used as written for time_range; a year is not invented when the source has none. Oracle-style stamps with a weekday and a year (`Wed Jul 01 15:00:00 2026`) are calendar times.",
            "Vendor codes (ORA-01555, RMAN-03015, TNS-12500, and similar PREFIX-NUMBER) are taken from the start of a record after an optional timestamp, or from the message after an explicit log level. Tokens embedded later in the same line are ignored. Occurrence count is not importance. Codes are identifiers, not correlated incidents; Oracle messages are not classified from an error-number dictionary. The report lists a bounded subset when many distinct codes are present; family totals and unique/occurrence counts include all vendor codes.",
            "OpenSSH/auth lines are correlated by sshd PID into authentication attempts; repeated attempts from one IP can raise a brute-force incident when the gap between attempts is at most 15 minutes. Five or more attempts in a 60-second window, or ten or more in a slower cluster, are ERROR; five to nine slower attempts are suspected (WARN). Connection closed by itself is not an error. Reverse-DNS mismatch is not treated as a proven break-in.",
            "Line severity counts mix explicit source markers with deterministic per-line classification; they are not the same as incident severity. English `error:` inside an Oracle vendor-code message is not counted as a source ERROR.",
            "Explicit FATAL/CRITICAL/SEVERE source markers are listed under Notable line findings with source line numbers, independently of the incident display cap. A few explicit ERROR examples may be included; semantic WARN lines (for example Failed password) are not listed there.",
            "Incident totals are computed before the displayed list is truncated.",
            "Numeric dates such as 09/01/26 are treated as record boundaries; ISO time_range is filled only when day/month order is unambiguous in this log.",
            "Product-specific message IDs can be added as optional profiles when representative log samples are available.",
        ],
    }
