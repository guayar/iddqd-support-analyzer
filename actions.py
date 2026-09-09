from __future__ import annotations

import json
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from analyzers import analyze_log_text, analyze_saml_input
from analyzers.saml import decoded_artifacts_for_named_inputs, looks_like_saml_input, saml_root_types
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
        result = analyze_saml_input(join_saml_artifacts(arts), signing_cert=cert_data)
        result["decoded_artifacts"] = decoded_artifacts_for_named_inputs(arts)
        return result

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

    analyses = []
    for name, text, _kinds in protocol_arts:
        inner = run([(name, text)] + meta_arts)
        inner.pop("decoded_artifacts", None)
        analyses.append({"name": name, "result": inner})
    return {
        "kind": "saml_multi",
        "analyses": analyses,
        "decoded_artifacts": decoded_artifacts_for_named_inputs(
            [(name, text) for name, text, _kinds in protocol_arts] + meta_arts
        ),
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


def decoded_artifacts_from_result(result: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not result:
        return []
    kind = result.get("kind")
    if kind == "mixed":
        return decoded_artifacts_from_result(result.get("saml") if isinstance(result.get("saml"), dict) else None)
    return list(result.get("decoded_artifacts") or [])


def write_decoded_artifact_download(result: dict[str, Any] | None) -> str | None:
    items = decoded_artifacts_from_result(result)
    if not items:
        return None
    out_dir = Path(tempfile.mkdtemp(prefix="iddqd_decoded_"))
    if len(items) == 1:
        path = out_dir / items[0]["export_name"]
        path.write_bytes(items[0]["xml"].encode("utf-8"))
        return str(path)
    zip_path = out_dir / "decoded-saml-artifacts.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for item in items:
            zf.writestr(item["export_name"], item["xml"].encode("utf-8"))
    return str(zip_path)


def write_anonymize_audit_download(
    items: list[dict[str, Any]],
    *,
    xml_key: str,
    name_key: str,
    zip_name: str,
) -> str | None:
    if not items:
        return None
    out_dir = Path(tempfile.mkdtemp(prefix="iddqd_anon_audit_"))
    if len(items) == 1:
        path = out_dir / items[0][name_key]
        path.write_bytes(items[0][xml_key].encode("utf-8"))
        return str(path)
    zip_path = out_dir / zip_name
    with zipfile.ZipFile(zip_path, "w") as zf:
        for item in items:
            zf.writestr(item[name_key], item[xml_key].encode("utf-8"))
    return str(zip_path)


def anonymize(file, pasted) -> tuple[str, str, str, str, str | None, str | None]:
    from analyzers.anonymizer import anonymize_text
    from reporting import render_anonymize_summary

    text, filename = read_text_file_and_paste(file, pasted)
    if not text.strip():
        raise InputError("Upload a log or paste text first.")

    result = anonymize_text(text, source_name=filename or "pasted-log.txt")
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
    audit = list(result.get("xml_audit_artifacts") or [])
    decoded_path = write_anonymize_audit_download(
        audit,
        xml_key="decoded_xml",
        name_key="decoded_export_name",
        zip_name="original-decoded-saml-SENSITIVE.zip",
    )
    anonymized_xml_path = write_anonymize_audit_download(
        audit,
        xml_key="anonymized_xml",
        name_key="anonymized_export_name",
        zip_name="anonymized-saml-xml.zip",
    )
    return summary, result["text"], mapping_json, str(out_path), decoded_path, anonymized_xml_path
