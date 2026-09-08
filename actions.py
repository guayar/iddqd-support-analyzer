from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from analyzers import analyze_log_text, analyze_saml_input
from analyzers.saml import looks_like_saml_input, saml_root_types
from analyzers.saml_supplied_cert import extract_pem_certificates_from_text
from reporting import render_log_report, render_mixed_report, render_saml_output
from uploads import (
    InputError,
    collect_analyze_artifacts,
    join_analyze_artifacts,
    join_saml_artifacts,
    read_signing_certificate,
    read_text_file_and_paste,
)


_SAML_PROTOCOL_ROOTS = {"AuthnRequest", "Response", "Assertion"}
_SAML_METADATA_ROOTS = {"EntityDescriptor", "EntitiesDescriptor"}


def _run_saml(artifacts: list[tuple[str, str]], signing_cert_file, all_artifacts: list[tuple[str, str]]):
    cert_data = read_signing_certificate(signing_cert_file)
    if cert_data is None:
        cert_data = extract_pem_certificates_from_text("\n".join(t for _n, t in all_artifacts))

    def run(arts: list[tuple[str, str]]):
        return analyze_saml_input(join_saml_artifacts(arts), signing_cert=cert_data)

    if len(artifacts) <= 1:
        return run(artifacts)

    typed = [(name, text, saml_root_types(text)) for name, text in artifacts]
    meta_arts = [(n, t) for n, t, kinds in typed if kinds and kinds <= _SAML_METADATA_ROOTS]
    protocol_arts = [(n, t, kinds) for n, t, kinds in typed if kinds & _SAML_PROTOCOL_ROOTS]
    protocol_kinds = set().union(*(kinds for _n, _t, kinds in protocol_arts)) if protocol_arts else set()
    together = (
        not protocol_arts
        or len(protocol_arts) <= 1
        or ("AuthnRequest" in protocol_kinds and protocol_kinds & {"Response", "Assertion"})
    )
    if together:
        return run(artifacts)

    return {
        "kind": "saml_multi",
        "analyses": [
            {"name": name, "result": run([(name, text)] + meta_arts)}
            for name, text, _kinds in protocol_arts
        ],
    }


def _run_log(artifacts: list[tuple[str, str]]):
    names = [name for name, _text in artifacts if name != "pasted text"]
    return analyze_log_text(join_analyze_artifacts(artifacts), filename=", ".join(names) if names else None)


def analyze(files, pasted, mode, signing_cert_file=None) -> tuple[str, str, dict[str, Any]]:
    artifacts = collect_analyze_artifacts(files, pasted)
    if not artifacts:
        raise InputError("Upload a log/SAML tracer or paste text first.")

    if mode == "SAML":
        result = _run_saml(artifacts, signing_cert_file, artifacts)
        md = render_saml_output(result)
    elif mode == "Log":
        result = _run_log(artifacts)
        md = render_log_report(result)
    else:
        classified = [
            (name, text, "SAML" if looks_like_saml_input(text) else "Log")
            for name, text in artifacts
        ]
        saml_arts = [(n, t) for n, t, kind in classified if kind == "SAML"]
        log_arts = [(n, t) for n, t, kind in classified if kind == "Log"]
        if saml_arts and log_arts:
            saml_result = _run_saml(saml_arts, signing_cert_file, artifacts)
            log_result = _run_log(log_arts)
            result = {
                "kind": "mixed",
                "artifacts": [{"name": n, "kind": k} for n, _t, k in classified],
                "saml": saml_result,
                "log": log_result,
            }
            md = render_mixed_report(result)
        elif saml_arts:
            result = _run_saml(saml_arts, signing_cert_file, artifacts)
            md = render_saml_output(result)
        else:
            result = _run_log(log_arts)
            md = render_log_report(result)

    return md, json.dumps(result, indent=2, ensure_ascii=False), result


def anonymize(file, pasted) -> tuple[str, str, str, str]:
    from analyzers.anonymizer import anonymize_text
    from reporting import render_anonymize_summary

    text, filename = read_text_file_and_paste(file, pasted)
    if not text.strip():
        raise InputError("Upload a log or paste text first.")

    result = anonymize_text(text)
    summary = render_anonymize_summary(result)

    base = Path(filename or "pasted-log.txt")
    safe_name = f"{base.stem}.anonymized{base.suffix or '.txt'}"
    out_dir = Path(tempfile.mkdtemp(prefix="support_anonymized_"))
    out_path = out_dir / safe_name
    out_path.write_text(result["text"], encoding="utf-8")

    mapping_json = json.dumps(
        {
            "counts": result["counts"],
            "mapping": result["mapping"],
            "residual_count": result.get("residual_count", 0),
            "residual_findings": result.get("residual_findings") or [],
            "limitations": result["limitations"],
        },
        indent=2,
        ensure_ascii=False,
    )
    return summary, result["text"], mapping_json, str(out_path)
