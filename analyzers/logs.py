from __future__ import annotations

import collections
import re
from datetime import datetime
from typing import Any, NamedTuple

_TIME = r"[0-2]\d:[0-5]\d:[0-5]\d(?:[.,]\d+)?"
_TZ = r"(?:Z|[+-]\d{2}:?\d{2})?"
_MON = r"Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
_MONTH_NUM = {name.lower(): i for i, name in enumerate(_MON.split("|"), 1)}
TS_TOKEN_RE = re.compile(
    rf"(?P<iso>\d{{4}}-\d{{2}}-\d{{2}}[T ]{_TIME}{_TZ})"
    rf"|(?P<ymd_slash>\d{{4}}/\d{{2}}/\d{{2}}[ T]{_TIME})"
    rf"|(?P<dmy_mon>\d{{2}}-(?:{_MON})-\d{{4}}[ T]{_TIME})"
    rf"|(?P<slash>\d{{2}}/\d{{2}}/(?:\d{{4}}|\d{{2}})[ T]{_TIME})"
    rf"|(?P<syslog>(?:{_MON}) +\d{{1,2}}[ T]{_TIME})",
    re.I,
)
LEVEL_NAMES = r"TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|SEVERE|CRITICAL"
ERROR_LEVELS = {"ERROR", "FATAL", "SEVERE", "CRITICAL"}
BRACKET_RE = re.compile(rf"^\[(?P<level>{LEVEL_NAMES})\](?P<rest>.*)$", re.I)
TS_LEVEL_RE = re.compile(rf"^(?P<pad>\s+)(?P<level>{LEVEL_NAMES})\b")
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
MAVEN_ADVISORY_RE = re.compile(
    r"^(?:to see the full stack trace|re-run maven|for more information about the errors|\[help\s+\d+\])",
    re.I,
)
CODE_PATTERNS = [
    re.compile(r"\b(ORA-\d{3,6})\b", re.I),
    re.compile(r"\b(SQLSTATE\s*[:=]?\s*[0-9A-Z]{5})\b", re.I),
    re.compile(r"\b(HTTP(?:\s+STATUS)?\s*[:=]?\s*[45]\d\d)\b", re.I),
    re.compile(r"\b([A-Z][A-Z0-9_]{1,20}[-_][0-9]{3,8})\b"),
    re.compile(r"\b(error\s*code\s*[:=]\s*[A-Za-z0-9_.-]+)\b", re.I),
    re.compile(r"\b(status\s*code\s*[:=]\s*[45]\d\d)\b", re.I),
]
MAX_EVENT_LINES = 500
SAMPLE_CHARS = 50_000
INLINE_EXC_RE = re.compile(
    r"Exception:\s*(?P<cls>(?:[A-Za-z_]\w*\.)+[A-Za-z_]\w*(?:Exception|Error))"
    r"(?:\.\s*Message:\s*(?P<msg>.*))?",
    re.I,
)


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


def _ts_policy(lines: list[str]) -> _TsPolicy:
    unamb: set[tuple[int, int, int]] = set()
    saw_dmy = False
    saw_mdy = False
    empty = _TsPolicy(None, frozenset())
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
    return "WARN" if level == "WARNING" else level


def _code_list(text: str) -> list[str]:
    found = []
    for pat in CODE_PATTERNS:
        found.extend(m.group(1).strip() for m in pat.finditer(text))
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


def _split_events(lines: list[str]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    def flush():
        nonlocal current
        if current:
            events.append(current)
            current = None

    for idx, line in enumerate(lines, 1):
        rec = log_record_prefix(line)
        if rec and rec["level"] in ERROR_LEVELS:
            if current and current.get("style") == "bracket" and _is_maven_advisory(line):
                current["lines"].append(line)
                continue
            flush()
            current = {"start_line": idx, "lines": [line], "level": rec["level"], "style": rec["style"]}
            continue
        if rec or _timestamp_at_start(line):
            flush()
            continue
        if current and len(current["lines"]) < MAX_EVENT_LINES and _is_stack_continuation(line):
            current["lines"].append(line)
            continue
        if current and not line.strip():
            current["lines"].append(line)
            continue
        flush()
    flush()
    return events


def _exc_class(body: str) -> str | None:
    m = EXC_HEAD_RE.match(body.strip())
    return m.group("cls") if m else None


def parse_java_exception_chain(lines: list[str]) -> dict[str, Any]:
    top: str | None = None
    causes: list[str] = []
    suppressed: list[str] = []
    for raw in lines:
        if log_record_prefix(line := raw):
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
    if rec and rec["style"] == "timestamped" and " : " in first_line:
        return first_line.rsplit(" : ", 1)[-1].strip()
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


def analyze_log_text(text: str, filename: str | None = None) -> dict[str, Any]:
    lines = text.splitlines()
    timestamps = []
    levels = collections.Counter()
    codes = collections.Counter()

    policy = _ts_policy(lines)
    for line in lines:
        ts = _parse_ts(line, policy)
        if ts:
            timestamps.append(ts)
        rec = log_record_prefix(line)
        if rec:
            levels[rec["level"]] += 1
        for code in _code_list(line):
            codes[code] += 1

    events = _split_events(lines)
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for ev in events:
        chain = parse_java_exception_chain(ev["lines"])
        key = _grouping_key(ev, chain)
        sample = "\n".join(ev["lines"])[:SAMPLE_CHARS]
        exit_m = EXIT_CODE_RE.search("\n".join(ev["lines"]))
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
        for c in _code_list("\n".join(ev["lines"])):
            entry["codes"][c] += 1

    groups = []
    for v in grouped.values():
        v = dict(v)
        v["codes"] = dict(v["codes"])
        groups.append(v)
    groups.sort(key=lambda x: (-len(x.get("exception_chain") or []), x["first_line"]))

    return {
        "kind": "log",
        "filename": filename,
        "line_count": len(lines),
        "timestamped_lines": len(timestamps),
        "time_range": {
            "from": min(timestamps).isoformat() if timestamps else None,
            "to": max(timestamps).isoformat() if timestamps else None,
        },
        "levels": dict(levels),
        "error_codes": dict(codes.most_common()),
        "error_event_count": len(events),
        "error_groups": groups[:100],
        "incidents": groups[:100],
        "limitations": [
            "The analyzer groups multiline ERROR/FATAL/SEVERE/CRITICAL records, Java exception chains and Maven [ERROR] blocks using generic log heuristics.",
            "Numeric dates such as 09/01/26 are treated as record boundaries; time_range is filled only when day/month order is unambiguous in this log.",
            "Product-specific message IDs can be added as optional profiles when representative log samples are available.",
        ],
    }
