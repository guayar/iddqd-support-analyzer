#!/usr/bin/env python3
"""Run human-reviewed invariants against fetched third-party corpora when present."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from regression_manifest import ROOT, destination_for, load_manifest, load_simple_yaml  # noqa: E402

sys.path.insert(0, str(ROOT))
from analyzers.logs import analyze_log_text  # noqa: E402
from analyzers.saml import analyze_saml_input  # noqa: E402

EXPECT_DIR = ROOT / "tests" / "regression" / "expectations"


def _cell(ok: bool | None) -> str:
    if ok is True:
        return "PASS"
    if ok is False:
        return "FAIL"
    return "SKIP"


def evaluate(spec: dict, text: str) -> dict[str, bool | None]:
    analyzer = spec["analyzer"]
    crashed = False
    result = None
    try:
        if analyzer == "log":
            result = analyze_log_text(text, spec.get("filename"))
        elif analyzer == "saml":
            result = analyze_saml_input(text)
        else:
            raise ValueError(f"Unknown analyzer {analyzer!r}")
    except Exception:
        crashed = True
    out: dict[str, bool | None] = {
        "parse": None,
        "timestamp": None,
        "events": None,
        "incidents": None,
        "crash": not crashed,
    }
    if crashed or result is None:
        out["parse"] = False
        out["crash"] = False
        return out
    expect = spec.get("expect") or {}
    out["parse"] = result.get("kind") == expect.get("kind", result.get("kind"))
    if analyzer == "log":
        tr = result.get("time_range") or {}
        if "year_present" in expect:
            out["timestamp"] = tr.get("year_present") is expect["year_present"] and bool(tr.get("from"))
        elif expect.get("timestamp_from_required"):
            out["timestamp"] = bool(tr.get("from"))
        else:
            out["timestamp"] = None
        out["events"] = True
        levels = result.get("levels") or {}
        for needle, forbidden in (expect.get("when_text_contains") or {}).items():
            if needle in text:
                for level in forbidden.get("levels_must_not_contain") or []:
                    if levels.get(level, 0):
                        out["incidents"] = False
        if out["incidents"] is None:
            out["incidents"] = True
        if expect.get("no_critical_incidents"):
            if any((g.get("level") or "").upper() == "CRITICAL" for g in result.get("incidents") or []):
                out["incidents"] = False
    else:
        out["timestamp"] = None
        summary = result.get("summary") or {}
        mins = expect.get("summary_min") or {}
        out["events"] = all(summary.get(k, 0) >= v for k, v in mins.items())
        out["incidents"] = True
        if expect.get("must_not_crash_only"):
            out["events"] = True
    return out


def main() -> int:
    manifest = load_manifest()
    sources = manifest["sources"]
    rows = []
    failed = False
    missing = 0
    for path in sorted(EXPECT_DIR.glob("*.yml")):
        spec = load_simple_yaml(path.read_text(encoding="utf-8"))
        source = sources[spec["corpus"]]
        dest = destination_for(spec["corpus"], source, spec["upstream_path"])
        name = spec.get("dataset") or path.stem
        if not dest.is_file():
            missing += 1
            rows.append((name, None, None, None, None, None))
            continue
        text = dest.read_text(encoding="utf-8", errors="replace")
        result = evaluate(spec, text)
        if result["crash"] is False or result["parse"] is False or result.get("incidents") is False:
            failed = True
        if result.get("events") is False or result.get("timestamp") is False:
            failed = True
        rows.append(
            (
                name,
                result["parse"],
                result["timestamp"],
                result["events"],
                result["incidents"],
                result["crash"],
            )
        )
    print(f"{'Dataset':<22} {'Parse':<8} {'Timestamp':<12} {'Events':<8} {'Incidents':<12} {'NoCrash':<8}")
    for name, parse, ts, events, incidents, crash in rows:
        print(
            f"{name:<22} {_cell(parse):<8} {_cell(ts):<12} {_cell(events):<8} {_cell(incidents):<12} {_cell(crash):<8}"
        )
    if missing:
        print(
            f"\n{missing} corpus file(s) not present. "
            "Fetch with: python scripts/fetch_regression_data.py"
        )
    if failed:
        print("\nOne or more fetched corpora failed invariants.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
