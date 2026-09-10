"""OpenSSH correlator: cheap `sshd[` hint, then PID state. No full-log pass of its own."""

from __future__ import annotations

import collections
import re
from datetime import datetime
from typing import Any

BRUTE_FORCE_MIN_SESSIONS = 5
BRUTE_FORCE_GAP_SECONDS = 15 * 60
BRUTE_FORCE_RAPID_WINDOW_SECONDS = 60
_SESSION_SAMPLE_CHARS = 50_000
_SESSION_LINE_CAP = 32
SSH_SESSION_STORE_CAP = 2000

_MON = r"Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
_TIME = r"[0-2]\d:[0-5]\d:[0-5]\d(?:[.,]\d+)?"
_MONTH_NUM = {name.lower(): i for i, name in enumerate(_MON.split("|"), 1)}

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


def ssh_line_hint(line: str) -> bool:
    return "sshd[" in line


def ssh_rule(line: str) -> tuple[str, str, str] | None:
    body = line
    repeated = REPEAT_RE.search(line)
    if repeated:
        body = repeated.group("body")
    for pat, level, category, kind in SSH_RULES:
        if pat.search(body):
            return level, category, kind
    return None


def ssh_pid(line: str) -> str | None:
    m = SSHD_PID_RE.search(line)
    return m.group("pid") if m else None


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
        "sample": "\n".join(sess["lines"])[:_SESSION_SAMPLE_CHARS],
    }


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


def _syslog_internal_dt(raw: str) -> datetime | None:
    m = re.match(
        rf"(?P<mon>{_MON})\s+(?P<day>\d{{1,2}})\s+(?P<time>{_TIME})\b",
        raw.strip(),
        re.I,
    )
    if not m:
        return None
    hour, minute, second, _micro = _clock(m.group("time"))
    month, day = _MONTH_NUM[m.group("mon")[:3].lower()], int(m.group("day"))
    try:
        return datetime(2000, month, day, hour, minute, second)
    except ValueError:
        return None


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
                "sample": "\n".join(sample_lines)[:_SESSION_SAMPLE_CHARS],
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


class SshCorrelator:
    """Call on_line only after ssh_line_hint. flush() at end of the shared scan."""

    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, Any]] = {}
        self.overflow_auth_pids: set[str] = set()

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        pid = ssh_pid(line)
        if not pid:
            return
        rule = ssh_rule(line)
        sess = self.sessions.get(pid)
        if sess is None:
            if len(self.sessions) >= SSH_SESSION_STORE_CAP:
                if rule and rule[2] in _AUTH_KINDS:
                    self.overflow_auth_pids.add(pid)
                return
            sess = {
                "pid": pid,
                "lines": [],
                "first_line": idx,
                "ip": None,
                "user": None,
                "kinds": set(),
                "level": None,
                "category": None,
                "stamp": stamp,
            }
            self.sessions[pid] = sess
        if len(sess["lines"]) < _SESSION_LINE_CAP:
            sess["lines"].append(line)
        ip = _ssh_ip(line)
        if ip:
            sess["ip"] = ip
        user = _ssh_user(line)
        if user:
            sess["user"] = user
        if stamp:
            sess["stamp"] = stamp
        if rule:
            _, category, kind = rule
            sess["kinds"].add(kind)
            sess["category"] = category

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        auth_sessions = [s for s in self.sessions.values() if s["kinds"] & _AUTH_KINDS]
        for sess in auth_sessions:
            sess["level"] = session_incident_level(sess["kinds"])
        incidents = [_incident_from_session(s) for s in auth_sessions]
        incidents.extend(_brute_force_incidents(auth_sessions))
        return incidents, len(auth_sessions) + len(self.overflow_auth_pids)
