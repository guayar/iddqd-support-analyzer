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
LEVEL_RE = re.compile(r"(?<![A-Z])(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|SEVERE|CRITICAL)(?![A-Z])", re.I)
CAUSE_RE = re.compile(r"\bCaused by:\s*(.+)", re.I)
EXC_RE = re.compile(r"\b([\w.$]+(?:Exception|Error))(?::\s*(.*))?")
CODE_PATTERNS = [
    re.compile(r"\b(ORA-\d{3,6})\b", re.I),
    re.compile(r"\b(SQLSTATE\s*[:=]?\s*[0-9A-Z]{5})\b", re.I),
    re.compile(r"\b(HTTP(?:\s+STATUS)?\s*[:=]?\s*[45]\d\d)\b", re.I),
    re.compile(r"\b([A-Z][A-Z0-9_]{1,20}[-_][0-9]{3,8})\b"),
    re.compile(r"\b(error\s*code\s*[:=]\s*[A-Za-z0-9_.-]+)\b", re.I),
    re.compile(r"\b(status\s*code\s*[:=]\s*[45]\d\d)\b", re.I),
]


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
    # preserve order
    return list(dict.fromkeys(found))


def _event_blocks(lines: list[str]) -> list[dict[str, Any]]:
    blocks = []
    current = None
    for idx, line in enumerate(lines, 1):
        level_m = LEVEL_RE.search(line)
        starts = bool(level_m and _normalize_level(level_m.group(1)) in {"ERROR", "FATAL", "SEVERE", "CRITICAL"})
        if starts:
            if current:
                blocks.append(current)
            current = {"start_line": idx, "lines": [line], "level": _normalize_level(level_m.group(1))}
            continue
        if current:
            continuation = (
                line.startswith((" ", "\t"))
                or "Caused by:" in line
                or line.lstrip().startswith(("at ", "... ", "Suppressed:"))
                or EXC_RE.search(line) is not None
            )
            if continuation and len(current["lines"]) < 80:
                current["lines"].append(line)
            else:
                blocks.append(current)
                current = None
    if current:
        blocks.append(current)
    return blocks


def _event_signature(block: dict[str, Any]) -> tuple[str, str | None]:
    joined = "\n".join(block["lines"])
    causes = [m.group(1).strip() for m in CAUSE_RE.finditer(joined)]
    root_cause = causes[-1] if causes else None
    ex = list(EXC_RE.finditer(joined))
    if root_cause:
        sig = root_cause
    elif ex:
        sig = f"{ex[-1].group(1)}: {(ex[-1].group(2) or '').strip()}".strip(": ")
    else:
        first = block["lines"][0]
        # Strip timestamp/thread-ish prefixes enough to group repeated log messages.
        sig = re.sub(r"^.*?\b(?:ERROR|FATAL|SEVERE|CRITICAL)\b\s*[-:]?\s*", "", first, flags=re.I).strip()
    return sig[:500], root_cause


def analyze_log_text(text: str, filename: str | None = None) -> dict[str, Any]:
    lines = text.splitlines()
    timestamps = []
    levels = collections.Counter()
    codes = collections.Counter()

    for line in lines:
        ts = _parse_ts(line)
        if ts:
            timestamps.append(ts)
        for m in LEVEL_RE.finditer(line):
            levels[_normalize_level(m.group(1))] += 1
        for code in _code_list(line):
            codes[code] += 1

    blocks = _event_blocks(lines)
    grouped: dict[str, dict[str, Any]] = {}
    for b in blocks:
        sig, root = _event_signature(b)
        entry = grouped.setdefault(sig, {
            "signature": sig,
            "count": 0,
            "level": b["level"],
            "root_cause": root,
            "codes": collections.Counter(),
            "first_line": b["start_line"],
            "sample": "\n".join(b["lines"][:25]),
        })
        entry["count"] += 1
        entry["first_line"] = min(entry["first_line"], b["start_line"])
        for c in _code_list("\n".join(b["lines"])):
            entry["codes"][c] += 1

    groups = []
    for v in grouped.values():
        v = dict(v)
        v["codes"] = dict(v["codes"])
        groups.append(v)
    groups.sort(key=lambda x: (-x["count"], x["first_line"]))

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
        "error_event_count": len(blocks),
        "error_groups": groups[:100],
        "limitations": [
            "The analyzer groups stack traces and explicit ERROR/FATAL/SEVERE/CRITICAL events using generic application-log heuristics.",
            "Product-specific message IDs can be added as optional profiles when representative log samples are available.",
        ],
    }
