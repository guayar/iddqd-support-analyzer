from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from analyzers import analyze_log_text, analyze_saml_input, anonymize_text
from analyzers.saml import looks_like_saml_input
from reporting import render_anonymize_summary, render_log_report, render_saml_report
from uploads import InputError, read_signing_certificate, read_text_file_and_paste, read_text_files


def analyze(files, pasted, mode, signing_cert_file=None) -> tuple[str, str, dict[str, Any]]:
    file_text, names = read_text_files(files)
    text = (file_text + "\n" + (pasted or "")).strip()
    if not text:
        raise InputError("Upload a log/SAML tracer or paste text first.")
    chosen = mode
    if mode == "Auto-detect":
        chosen = "SAML" if looks_like_saml_input(text) else "Log"
    if chosen == "SAML":
        cert_data = read_signing_certificate(signing_cert_file)
        result = analyze_saml_input(text, signing_cert=cert_data)
        md = render_saml_report(result)
    else:
        result = analyze_log_text(text, filename=", ".join(names) if names else None)
        md = render_log_report(result)
    return md, json.dumps(result, indent=2, ensure_ascii=False), result


def anonymize(file, pasted) -> tuple[str, str, str, str]:
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
        {"counts": result["counts"], "mapping": result["mapping"], "limitations": result["limitations"]},
        indent=2,
        ensure_ascii=False,
    )
    return summary, result["text"], mapping_json, str(out_path)
