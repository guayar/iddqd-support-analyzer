from __future__ import annotations

import collections
import re
from datetime import datetime
from typing import Any

from dateutil import parser as dateparser

TS_PATTERNS = [
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"(?P<ts>\d{4}/\d{2}/\d{2}[ T][0-2]\d:[0-5]\d:[0-5]\d(?:[.,]\d+)?)"),
    re.compile(r"(?P<ts>\d{2}/\d{2}/\d{4}[ T][0-2]\d:[0-5]\d:[0-5]\d(?:[.,]\d+)?)"),
    re.compile(r"(?P<ts>\d{2}-[A-Za-z]{3}-\d{4}[ T][0-2]\d:[0-5]\d:[0-5]\d(?:[.,]\d+)?)"),
]
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


def _parse_ts(line: str) -> datetime | None:
    for pat in TS_PATTERNS:
        m = pat.search(line)
        if not m:
            continue
        raw = m.group("ts").replace(",", ".")
        try:
            return dateparser.parse(raw)
        except Exception:
            continue
    return None


def _normalize_level(level: str) -> str:
    level = level.upper()
    return "WARN" if level == "WARNING" else level


def _code_list(text: str) -> list[str]:
    found = []
    for pat in CODE_PATTERNS:
        found.extend(m.group(1).strip() for m in pat.finditer(text))
    return list(dict.fromkeys(found))


def _timestamp_at_start(line: str) -> re.Match | None:
    s = line.lstrip()
    for pat in TS_PATTERNS:
        m = pat.match(s)
        if m:
            return m
    return None


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

    for line in lines:
        ts = _parse_ts(line)
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
            "Product-specific message IDs can be added as optional profiles when representative log samples are available.",
        ],
    }
