from __future__ import annotations

import base64
import io
from pathlib import Path
from typing import Any

from PIL import Image, ImageOps, UnidentifiedImageError

from config import (
    ASSISTANT_IMAGE_MAX_BYTES,
    ASSISTANT_IMAGE_MAX_PIXELS,
    ASSISTANT_IMAGES_PER_MESSAGE,
    OCR_TIMEOUT_SECONDS,
)

ALLOWED_FORMATS = {
    "PNG": "image/png",
    "JPEG": "image/jpeg",
    "WEBP": "image/webp",
}

_OCR_CACHE: dict[tuple[str, int, int], dict[str, Any]] = {}


class VisionError(Exception):
    """User-facing image problem for the Assistant attachment path."""


def clear_vision_cache() -> None:
    _OCR_CACHE.clear()


def _reject_remote(raw: str) -> None:
    text = raw.strip()
    lowered = text.lower()
    if "://" in text or lowered.startswith(("http:", "https:", "file:", "//")):
        raise VisionError("Remote image URLs are not allowed. Attach a local screenshot.")


def _open_validated(path: Path) -> Image.Image:
    Image.MAX_IMAGE_PIXELS = ASSISTANT_IMAGE_MAX_PIXELS
    try:
        image = Image.open(path)
        image.load()
    except Image.DecompressionBombError as exc:
        raise VisionError("Image exceeds the pixel safety limit.") from exc
    except (UnidentifiedImageError, OSError) as exc:
        raise VisionError(f"{path.name}: not a readable PNG, JPEG or WEBP image.") from exc
    fmt = (image.format or "").upper()
    if fmt == "JPG":
        fmt = "JPEG"
    if fmt not in ALLOWED_FORMATS:
        raise VisionError(f"{path.name}: unsupported image type {fmt or 'unknown'}. Use PNG, JPEG or WEBP.")
    width, height = image.size
    if width * height > ASSISTANT_IMAGE_MAX_PIXELS:
        raise VisionError(f"{path.name}: image is too large ({width}x{height} pixels).")
    return image


def inspect_image(raw_path: str) -> dict[str, Any]:
    """Validate a local image and return metadata. Does not run OCR."""
    _reject_remote(str(raw_path))
    path = Path(raw_path).expanduser()
    try:
        path = path.resolve(strict=True)
    except OSError as exc:
        raise VisionError("Attached image file was not found on disk.") from exc
    if not path.is_file():
        raise VisionError("Attached image is not a regular file.")
    size = path.stat().st_size
    if size > ASSISTANT_IMAGE_MAX_BYTES:
        mb = ASSISTANT_IMAGE_MAX_BYTES // (1024 * 1024)
        raise VisionError(f"{path.name}: image exceeds {mb} MB limit.")
    with _open_validated(path) as image:
        fmt = (image.format or "PNG").upper()
        if fmt == "JPG":
            fmt = "JPEG"
        width, height = image.size
        mime = ALLOWED_FORMATS[fmt]
    return {
        "path": str(path),
        "name": path.name,
        "mime": mime,
        "width": width,
        "height": height,
        "size": size,
    }


def encode_image_png_base64(path: str) -> str:
    """Pixels for Ollama, without EXIF. Original file is not modified."""
    with _open_validated(Path(path)) as image:
        rgb = ImageOps.exif_transpose(image)
        if rgb.mode not in {"RGB", "RGBA", "L"}:
            rgb = rgb.convert("RGB")
        buf = io.BytesIO()
        rgb.save(buf, format="PNG", optimize=True)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def _ocr_prepared(image: Image.Image) -> Image.Image:
    work = ImageOps.exif_transpose(image).convert("L")
    smallest = min(work.size)
    if smallest and smallest < 900:
        scale = 900 / smallest
        work = work.resize((int(work.size[0] * scale), int(work.size[1] * scale)), Image.Resampling.LANCZOS)
    return work


def ocr_image(path: str) -> dict[str, Any]:
    """Local Tesseract OCR. Never raises for engine absence; returns an error string instead."""
    resolved = inspect_image(path)
    key = (resolved["path"], resolved["size"], resolved["width"] * resolved["height"])
    cached = _OCR_CACHE.get(key)
    if cached is not None:
        return cached
    result = {"text": "", "error": None, **resolved}
    try:
        import pytesseract
    except Exception as exc:
        result["error"] = f"OCR library unavailable: {exc}"
        _OCR_CACHE[key] = result
        return result
    try:
        with _open_validated(Path(resolved["path"])) as image:
            prepared = _ocr_prepared(image)
        text = ""
        last_exc: Exception | None = None
        for lang in ("eng+pol", "eng"):
            try:
                text = pytesseract.image_to_string(prepared, lang=lang, config="--psm 6", timeout=OCR_TIMEOUT_SECONDS)
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
        if last_exc is not None and not (text or "").strip():
            raise last_exc
        result["text"] = (text or "").strip()
    except Exception as exc:
        name = type(exc).__name__
        if "NotFound" in name:
            result["error"] = "Tesseract is not installed locally."
        else:
            result["error"] = f"OCR failed: {exc}"
    _OCR_CACHE[key] = result
    return result


def attach_images(raw_paths: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate, OCR and cap the number of images. Partial success is allowed."""
    attachments: list[dict[str, Any]] = []
    notes: list[str] = []
    seen: set[str] = set()
    for raw in raw_paths:
        if len(attachments) >= ASSISTANT_IMAGES_PER_MESSAGE:
            notes.append(f"Only the first {ASSISTANT_IMAGES_PER_MESSAGE} screenshots were sent to the model.")
            break
        try:
            meta = inspect_image(raw)
        except VisionError as exc:
            notes.append(str(exc))
            continue
        if meta["path"] in seen:
            continue
        seen.add(meta["path"])
        ocr = ocr_image(meta["path"])
        attachments.append({**meta, "ocr_text": ocr.get("text") or "", "ocr_error": ocr.get("error")})
    return attachments, notes
