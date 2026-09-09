from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse

import requests

from config import ALLOW_REMOTE_LLM, OLLAMA_MODEL, OLLAMA_URL

_VISION_CAPABLE: dict[str, bool | None] = {}


def endpoint_is_local(url: str) -> bool:
    host = urlparse(url).hostname
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    if not host:
        return False
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if not (ip.is_loopback or ip.is_private):
                return False
        return True
    except Exception:
        return False


def model_supports_vision(model: str | None = None) -> bool | None:
    """True/False from Ollama /api/show, or None if capability metadata is unavailable."""
    name = model or OLLAMA_MODEL
    if name in _VISION_CAPABLE:
        return _VISION_CAPABLE[name]
    try:
        r = requests.post(f"{OLLAMA_URL}/api/show", json={"model": name}, timeout=8)
        r.raise_for_status()
        caps = r.json().get("capabilities") or []
        if not isinstance(caps, list) or not caps:
            _VISION_CAPABLE[name] = None
            return None
        supported = "vision" in {str(c).lower() for c in caps}
        _VISION_CAPABLE[name] = supported
        return supported
    except Exception:
        _VISION_CAPABLE[name] = None
        return None


def _payload_messages(messages: list[dict[str, Any]], *, include_images: bool) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in messages:
        row: dict[str, Any] = {"role": item.get("role") or "user", "content": item.get("content") or ""}
        images = item.get("images") or []
        if include_images and images:
            row["images"] = images
        out.append(row)
    return out


def complete(messages: list[dict[str, Any]], temperature: float = 0.2) -> str:
    if not ALLOW_REMOTE_LLM and not endpoint_is_local(OLLAMA_URL):
        raise RuntimeError("Remote LLM endpoint blocked. Set ALLOW_REMOTE_LLM=true only if you intentionally want it.")
    wants_images = any(m.get("images") for m in messages)
    vision = model_supports_vision() if wants_images else False
    include_images = bool(wants_images and vision is not False)
    body = {
        "model": OLLAMA_MODEL,
        "messages": _payload_messages(messages, include_images=include_images),
        "stream": False,
        "options": {"temperature": temperature},
    }
    r = requests.post(f"{OLLAMA_URL}/api/chat", json=body, timeout=600)
    if r.status_code >= 400 and include_images and vision is not True:
        fallback = {
            "model": OLLAMA_MODEL,
            "messages": _payload_messages(messages, include_images=False),
            "stream": False,
            "options": {"temperature": temperature},
        }
        r = requests.post(f"{OLLAMA_URL}/api/chat", json=fallback, timeout=600)
    r.raise_for_status()
    return r.json()["message"]["content"]


def llm_unavailable(exc: BaseException, *, analyzer_still_works: bool = False) -> str:
    extra = "\n\nThe deterministic analyzer still works. " if analyzer_still_works else "\n\n"
    return (
        f"LLM unavailable: `{exc}`{extra}"
        f"Check that Ollama is running and `{OLLAMA_MODEL}` is installed."
    )
