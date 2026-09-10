"""Deterministic log scan: shared record prefix, then hint-gated correlators.

New log families should not add a full-file pass. Cheap hint, then on_line/flush.
"""

from __future__ import annotations

import collections
import os
import re
import sys
import time
from datetime import datetime
from typing import Any, NamedTuple, Protocol

from .log_ssh import SshCorrelator, ssh_pid as _ssh_pid


class LogFamily(Protocol):
    """Stateful line family on the shared scan. Hints must stay cheap (substring / prefix)."""

    def hint(self, line: str) -> bool: ...
    def on_line(self, idx: int, line: str, stamp: str | None) -> None: ...
    def flush(self) -> tuple[list[dict[str, Any]], int]: ...
    def overflow_unique(self) -> int: ...
    def line_rule(self, line: str) -> tuple[str, str, str] | None: ...
    def finding_component(self, line: str) -> str | None: ...
    def context_pid(self, line: str) -> str | None: ...


# New SSH-style families: implement LogFamily, append here. Do not add a full-file pass.
LINE_FAMILY_TYPES: tuple[type[LogFamily], ...] = (SshCorrelator,)


class LogScanTimeout(Exception):
    """Log scan exceeded LOG_ANALYZE_MAX_SECONDS."""

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
GROUP_STORE_CAP = 2000
LOG_ANALYZE_MAX_SECONDS = int(os.getenv("LOG_ANALYZE_MAX_SECONDS", "90"))
MAX_EVENT_LINES = 500
SAMPLE_CHARS = 50_000
INLINE_EXC_RE = re.compile(
    r"Exception:\s*(?P<cls>(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*(?:Exception|Error))"
    r"(?:\.\s*Message:\s*(?P<msg>.*))?",
    re.I,
)
LEVEL_COLON_RE = re.compile(rf"(?i)\b(?P<level>{LEVEL_NAMES}):")
_LEVEL_RANK = {
    "CRITICAL": 0,
    "FATAL": 1,
    "SEVERE": 2,
    "ERROR": 3,
    "WARN": 4,
    "WARNING": 4,
}
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


def _first_vendor_code(line: str, prefix: dict[str, Any] | None = None) -> str | None:
    if prefix is not None:
        m = VENDOR_FIND_RE.search(prefix.get("rest") or "")
        return f"{m.group('family')}-{m.group('num')}" if m else None
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


def _split_record(line: str) -> tuple[dict[str, Any] | None, bool]:
    """Parse record prefix once. Second value is True when this line starts a new record."""
    stripped = line.strip()
    if not stripped:
        return None, False
    bm = BRACKET_RE.match(stripped)
    if bm:
        return (
            {"level": _normalize_level(bm.group("level")), "style": "bracket", "rest": bm.group("rest")},
            True,
        )
    ts = _timestamp_at_start(line)
    if ts:
        rest = line.lstrip()[ts.end():]
        lm = TS_LEVEL_RE.match(rest)
        if lm:
            return (
                {
                    "level": _normalize_level(lm.group("level")),
                    "style": "timestamped",
                    "rest": rest[lm.end():],
                },
                True,
            )
        bm_ts = TS_BRACKET_LEVEL_RE.match(rest)
        if bm_ts:
            return (
                {
                    "level": _normalize_level(bm_ts.group("level")),
                    "style": "timestamp_bracket",
                    "rest": bm_ts.group("rest") or "",
                },
                True,
            )
        return None, True
    bm2 = BARE_ERROR_RE.match(stripped)
    if bm2:
        return (
            {
                "level": _normalize_level(bm2.group("level")),
                "style": "bare",
                "rest": stripped[bm2.end():],
            },
            True,
        )
    return None, False


def log_record_prefix(line: str) -> dict[str, Any] | None:
    """Return a recognized log-record prefix, or None for continuations / message text."""
    prefix, _ = _split_record(line)
    return prefix


def is_new_log_record(line: str) -> bool:
    _prefix, new_rec = _split_record(line)
    return new_rec


def _is_maven_advisory(line: str, rec: dict[str, Any] | None = None) -> bool:
    rec = rec if rec is not None else log_record_prefix(line)
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


class _ErrorEventAssembler:
    """Multiline ERROR records (Java/Maven/[ts][error]) with pending-event state."""

    def __init__(self) -> None:
        self.current: dict[str, Any] | None = None

    def _flush(self):
        if self.current:
            ev = self.current
            self.current = None
            yield ev

    def push(self, idx: int, line: str, rec: dict[str, Any] | None, new_record: bool):
        if rec and rec["level"] in ERROR_LEVELS:
            if self.current and self.current.get("style") == "bracket" and _is_maven_advisory(line, rec):
                if len(self.current["lines"]) < MAX_EVENT_LINES:
                    self.current["lines"].append(line)
                return
            yield from self._flush()
            self.current = {
                "start_line": idx,
                "lines": [line],
                "level": rec["level"],
                "style": rec["style"],
            }
            return
        if rec or new_record:
            yield from self._flush()
            return
        if self.current and len(self.current["lines"]) < MAX_EVENT_LINES and _is_stack_continuation(line):
            self.current["lines"].append(line)
            return
        if self.current and not line.strip():
            if len(self.current["lines"]) < MAX_EVENT_LINES:
                self.current["lines"].append(line)
            return
        yield from self._flush()

    def finish(self):
        yield from self._flush()


def _iter_error_events(lines: list[str]):
    asm = _ErrorEventAssembler()
    for idx, line in enumerate(lines, 1):
        rec, new_record = _split_record(line)
        yield from asm.push(idx, line, rec, new_record)
    yield from asm.finish()


def _split_events(lines: list[str]) -> list[dict[str, Any]]:
    return list(_iter_error_events(lines))


_EMPTY_JAVA_CHAIN = {
    "top_exception": None,
    "causes": [],
    "suppressed": [],
    "root_cause": None,
    "exception_chain": [],
}


def _looks_like_java_event(ev: dict[str, Any]) -> bool:
    lines = ev.get("lines") or []
    if len(lines) > 1:
        return True
    first = lines[0] if lines else ""
    return bool(INLINE_EXC_RE.search(first) or "Caused by:" in first)


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


def _add_grouped_event(
    ev: dict[str, Any],
    grouped: dict[tuple[str, str], dict[str, Any]],
    unique_seen: set[tuple[str, str]],
) -> None:
    if _looks_like_java_event(ev):
        chain = parse_java_exception_chain(ev["lines"])
    else:
        chain = _EMPTY_JAVA_CHAIN
    key = _grouping_key(ev, chain)
    unique_seen.add(key)
    if key not in grouped:
        if len(grouped) >= GROUP_STORE_CAP:
            return
        sample = "\n".join(ev["lines"])[:SAMPLE_CHARS]
        exit_m = EXIT_CODE_RE.search(sample)
        grouped[key] = {
            "signature": _incident_title(ev, chain),
            "count": 1,
            "level": ev["level"],
            "root_cause": chain["root_cause"],
            "top_exception": chain["top_exception"],
            "causes": chain["causes"],
            "exception_chain": chain["exception_chain"],
            "exit_code": int(exit_m.group(1)) if exit_m else None,
            "codes": collections.Counter(),
            "first_line": ev["start_line"],
            "sample": sample,
        }
        for c in _code_list(sample):
            grouped[key]["codes"][c] += 1
        return
    entry = grouped[key]
    entry["count"] += 1
    entry["first_line"] = min(entry["first_line"], ev["start_line"])
    sample = "\n".join(ev["lines"])[:SAMPLE_CHARS]
    if len(sample) > len(entry["sample"]):
        entry["sample"] = sample
    if chain["root_cause"] and not entry["root_cause"]:
        entry["root_cause"] = chain["root_cause"]
        entry["top_exception"] = chain["top_exception"]
        entry["causes"] = chain["causes"]
        entry["exception_chain"] = chain["exception_chain"]
    for c in _code_list(sample):
        entry["codes"][c] += 1


def _profile_log(t0: float, label: str) -> float:
    now = time.perf_counter()
    if os.environ.get("IDDQD_LOG_PROFILE") == "1":
        print(f"iddqd log profile: {label} {(now - t0) * 1000:.1f} ms", file=sys.stderr)
    return now


def analyze_log_text(
    text: str,
    filename: str | None = None,
    max_seconds: float | None = None,
) -> dict[str, Any]:
    """One shared scan after an optional slash-date policy pass. New families: hint + correlator."""
    t0 = time.perf_counter()
    budget = LOG_ANALYZE_MAX_SECONDS if max_seconds is None else max_seconds
    deadline = (t0 + budget) if budget and budget > 0 else None
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

    policy = _ts_policy(lines, text)
    t1 = _profile_log(t0, "ts_policy")
    line_findings: list[dict[str, Any]] = []
    finding_shown = collections.Counter()
    events = _ErrorEventAssembler()
    line_families: list[LogFamily] = [cls() for cls in LINE_FAMILY_TYPES]
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    unique_seen: set[tuple[str, str]] = set()
    event_count = 0

    def on_error_event(ev: dict[str, Any]) -> None:
        nonlocal event_count
        event_count += 1
        _add_grouped_event(ev, grouped, unique_seen)

    for idx, line in enumerate(lines, 1):
        if deadline is not None and idx % 4096 == 1 and time.perf_counter() > deadline:
            raise LogScanTimeout(
                f"Log scan exceeded {budget:g}s time budget at line {idx:,} of {len(lines):,}. "
                "Raise LOG_ANALYZE_MAX_SECONDS or split the file."
            )
        rec, new_record = _split_record(line)
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
        matched = [fam for fam in line_families if fam.hint(line)]
        for fam in matched:
            fam.on_line(idx, line, raw)
        if rec:
            levels[rec["level"]] += 1
            source_level = rec["level"]
        else:
            colon = colon_severity(line)
            if colon:
                levels[colon] += 1
                source_level = colon
            else:
                for fam in matched:
                    rule = fam.line_rule(line)
                    if rule:
                        levels[_normalize_level(rule[0])] += 1
                        break
        cap = LINE_FINDING_CAPS.get(source_level or "")
        if cap and finding_shown[source_level] < cap:
            finding_shown[source_level] += 1
            pid = None
            component = None
            for fam in matched:
                if pid is None:
                    pid = fam.context_pid(line)
                if component is None:
                    component = fam.finding_component(line)
                if rule is None:
                    rule = fam.line_rule(line)
            line_findings.append({
                "line": idx,
                "source_level": source_level,
                "semantic_level": _normalize_level(rule[0]) if rule else None,
                "kind": "explicit_source_marker",
                "component": component,
                "message": line,
                "context": _source_line_context(lines, idx, pid),
            })
        vendor = _first_vendor_code(line, rec)
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
        for ev in events.push(idx, line, rec, new_record):
            on_error_event(ev)
    for ev in events.finish():
        on_error_event(ev)
    family_incidents: list[dict[str, Any]] = []
    family_event_count = 0
    family_overflow = 0
    for fam in line_families:
        inc, n = fam.flush()
        family_incidents.extend(inc)
        family_event_count += n
        family_overflow += fam.overflow_unique()
    line_findings.sort(
        key=lambda f: (_LINE_FINDING_ORDER.get(f["source_level"] or "", 50), f["line"])
    )
    t2 = _profile_log(t1, "scan")

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

    groups = []
    for v in grouped.values():
        v = dict(v)
        v["codes"] = dict(v["codes"])
        groups.append(v)

    groups.extend(family_incidents)
    groups.sort(
        key=lambda x: (
            0 if x.get("kind") == "brute_force" else 1,
            _LEVEL_RANK.get(x.get("level") or "", 50),
            x["first_line"],
        )
    )
    incident_unique_count = (
        len(unique_seen) + len(family_incidents) + family_overflow
    )
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
    _profile_log(t2, "scan")
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
        "error_event_count": event_count + family_event_count,
        "incident_unique_count": incident_unique_count,
        "error_groups": shown,
        "incidents": shown,
        "limitations": [
            "A timestamp may be followed by a bracketed level (`[ts] [error] message`). Apache `notice` is counted as INFO and is not an incident. `crit` / `alert` / `emerg` are not mapped. Repeated messages are grouped on the text after the level; `[client …]` and `child <digits>` are treated as context, not identity. Trailing status numbers such as `error state 6` are kept distinct.",
            "RFC3164/syslog stamps (`MMM d HH:mm:ss`) are used as written for time_range; a year is not invented when the source has none. Oracle-style stamps with a weekday and a year (`Wed Jul 01 15:00:00 2026`) are calendar times.",
            "Vendor codes (ORA-01555, RMAN-03015, TNS-12500, and similar PREFIX-NUMBER) are taken from the start of a record after an optional timestamp, or from the message after an explicit log level. Tokens embedded later in the same line are ignored. Occurrence count is not importance. Codes are identifiers, not correlated incidents; Oracle messages are not classified from an error-number dictionary. The report lists a bounded subset when many distinct codes are present; family totals and unique/occurrence counts include all vendor codes.",
            "OpenSSH/auth lines are correlated by sshd PID into authentication attempts; repeated attempts from one IP can raise a brute-force incident when the gap between attempts is at most 15 minutes. Five or more attempts in a 60-second window, or ten or more in a slower cluster, are ERROR; five to nine slower attempts are suspected (WARN). Connection closed by itself is not an error. Reverse-DNS mismatch is not treated as a proven break-in. Stored SSH sessions are capped; authentication-event counts still include overflow PIDs.",
            "Line severity counts mix explicit source markers with deterministic per-line classification; they are not the same as incident severity. English `error:` inside an Oracle vendor-code message is not counted as a source ERROR.",
            "Explicit FATAL/CRITICAL/SEVERE source markers are listed under Notable line findings with source line numbers, independently of the incident display cap. A few explicit ERROR examples may be included; semantic WARN lines (for example Failed password) are not listed there.",
            "Incident totals are computed before the displayed list is truncated. Stored incident details are capped; unique counts still include every signature.",
            "Numeric dates such as 09/01/26 are treated as record boundaries; ISO time_range is filled only when day/month order is unambiguous in this log.",
            "A new stateful log family implements LogFamily (cheap hint, on_line, flush) and is appended to LINE_FAMILY_TYPES. Do not add a separate full-file pass or a named branch in the shared scan. PREFIX-NUMBER vendors stay a single generic detector. Product-specific message IDs can be added as profiles when samples exist.",
        ],
    }
