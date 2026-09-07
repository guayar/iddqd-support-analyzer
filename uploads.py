from __future__ import annotations

from pathlib import Path

from config import MAX_FILE_MB, SIGNING_CERT_MAX_BYTES


class InputError(Exception):
    """User-facing input problem, mapped to a UI error by the Gradio layer."""


def read_text_files(files) -> tuple[str, list[str]]:
    if not files:
        return "", []
    if not isinstance(files, list):
        files = [files]
    chunks = []
    names = []
    for f in files:
        p = Path(getattr(f, "name", f))
        if p.stat().st_size > MAX_FILE_MB * 1024 * 1024:
            raise InputError(f"{p.name}: file exceeds {MAX_FILE_MB} MB limit")
        text = p.read_bytes().decode("utf-8", errors="replace")
        names.append(p.name)
        chunks.append(f"\n===== FILE: {p.name} =====\n{text}")
    return "\n".join(chunks), names


def read_signing_certificate(file) -> bytes | None:
    if not file:
        return None
    p = Path(getattr(file, "name", file))
    if p.stat().st_size > SIGNING_CERT_MAX_BYTES:
        raise InputError(f"{p.name}: signing certificate file exceeds 5 MB limit")
    return p.read_bytes()


def read_text_file_and_paste(file, pasted: str | None) -> tuple[str, str | None]:
    text = pasted or ""
    filename = None
    if file:
        p = Path(getattr(file, "name", file))
        if p.stat().st_size > MAX_FILE_MB * 1024 * 1024:
            raise InputError(f"{p.name}: file exceeds {MAX_FILE_MB} MB limit")
        text = p.read_bytes().decode("utf-8", errors="replace") + ("\n" + text if text else "")
        filename = p.name
    return text, filename
