from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import requests

from config import ALLOW_REMOTE_LLM, OLLAMA_MODEL, OLLAMA_URL


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


def complete(messages: list[dict[str, str]], temperature: float = 0.2) -> str:
    if not ALLOW_REMOTE_LLM and not endpoint_is_local(OLLAMA_URL):
        raise RuntimeError("Remote LLM endpoint blocked. Set ALLOW_REMOTE_LLM=true only if you intentionally want it.")
    r = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={"model": OLLAMA_MODEL, "messages": messages, "stream": False, "options": {"temperature": temperature}},
        timeout=600,
    )
    r.raise_for_status()
    return r.json()["message"]["content"]


def llm_unavailable(exc: BaseException, *, analyzer_still_works: bool = False) -> str:
    extra = "\n\nThe deterministic analyzer still works. " if analyzer_still_works else "\n\n"
    return (
        f"LLM unavailable: `{exc}`{extra}"
        f"Check that Ollama is running and `{OLLAMA_MODEL}` is installed."
    )
