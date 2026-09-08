from __future__ import annotations

from pathlib import Path

from config import MAX_FILE_MB, SIGNING_CERT_MAX_BYTES


class InputError(Exception):
    """User-facing input problem, mapped to a UI error by the Gradio layer."""


def read_text_files(files) -> tuple[str, list[str]]:
    artifacts = read_uploaded_text_artifacts(files)
    if not artifacts:
        return "", []
    chunks = [f"\n===== FILE: {name} =====\n{text}" for name, text in artifacts]
    return "\n".join(chunks), [name for name, _text in artifacts]


def read_uploaded_text_artifacts(files) -> list[tuple[str, str]]:
    if not files:
        return []
    if not isinstance(files, list):
        files = [files]
    artifacts: list[tuple[str, str]] = []
    for f in files:
        p = Path(getattr(f, "name", f))
        if p.stat().st_size > MAX_FILE_MB * 1024 * 1024:
            raise InputError(f"{p.name}: file exceeds {MAX_FILE_MB} MB limit")
        text = p.read_bytes().decode("utf-8", errors="replace")
        artifacts.append((p.name, text))
    return artifacts


def collect_analyze_artifacts(files, pasted: str | None) -> list[tuple[str, str]]:
    artifacts = read_uploaded_text_artifacts(files)
    paste = (pasted or "").strip()
    if paste:
        artifacts.append(("pasted text", paste))
    return artifacts


def join_analyze_artifacts(artifacts: list[tuple[str, str]]) -> str:
    chunks: list[str] = []
    for name, text in artifacts:
        if name == "pasted text":
            chunks.append(text)
        else:
            chunks.append(f"\n===== FILE: {name} =====\n{text}")
    return "\n".join(chunks).strip()


SAML_ARTIFACT_SEP = "\n\n<!-- iddqd-artifact -->\n\n"


def join_saml_artifacts(artifacts: list[tuple[str, str]]) -> str:
    """Join SAML artifacts without gluing Base64 payloads into one decode input."""
    return SAML_ARTIFACT_SEP.join(text.strip() for _name, text in artifacts if (text or "").strip())


def read_signing_certificate(file) -> bytes | None:
    if not file:
        return None
    p = Path(getattr(file, "name", file))
    if p.stat().st_size > SIGNING_CERT_MAX_BYTES:
        raise InputError(f"{p.name}: signing certificate file exceeds 5 MB limit")
    return p.read_bytes()


def should_clear_paste_for_file(file) -> bool:
    return bool(file)


def should_clear_file_for_paste(text: str | None) -> bool:
    return bool((text or "").strip())


def read_text_file_and_paste(file, pasted: str | None) -> tuple[str, str | None]:
    """Anonymize source: uploaded file XOR pasted text. Never concatenate both."""
    has_file = bool(file)
    has_paste = bool((pasted or "").strip())
    if has_file and has_paste:
        raise InputError("Use either an uploaded file or pasted text, not both.")
    if has_file:
        p = Path(getattr(file, "name", file))
        if p.stat().st_size > MAX_FILE_MB * 1024 * 1024:
            raise InputError(f"{p.name}: file exceeds {MAX_FILE_MB} MB limit")
        return p.read_bytes().decode("utf-8", errors="replace"), p.name
    return pasted or "", None
