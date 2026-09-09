from __future__ import annotations

import os
from pathlib import Path

APP_TITLE = "IDDQD Support Analyzer"
APP_VERSION = (Path(__file__).resolve().parent / "VERSION").read_text(encoding="utf-8").strip()
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.6:27b")
ALLOW_REMOTE_LLM = os.getenv("ALLOW_REMOTE_LLM", "false").lower() == "true"
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "150"))
SIGNING_CERT_MAX_BYTES = 5 * 1024 * 1024
APP_PORT = int(os.getenv("APP_PORT", "7860"))
WEB_SEARCH_RESULTS = int(os.getenv("WEB_SEARCH_RESULTS", "6"))
WEB_FETCH_RESULTS = int(os.getenv("WEB_FETCH_RESULTS", "3"))
WEB_FETCH_CHARS = int(os.getenv("WEB_FETCH_CHARS", "16000"))
WEB_SEARCH_REGION = os.getenv("WEB_SEARCH_REGION", "wt-wt")
WEB_SEARCH_BACKEND = os.getenv("WEB_SEARCH_BACKEND", "auto").strip() or "auto"
ASSISTANT_IMAGE_MAX_BYTES = int(os.getenv("ASSISTANT_IMAGE_MAX_MB", "8")) * 1024 * 1024
ASSISTANT_IMAGE_MAX_PIXELS = int(os.getenv("ASSISTANT_IMAGE_MAX_PIXELS", "12000000"))
ASSISTANT_IMAGES_PER_MESSAGE = int(os.getenv("ASSISTANT_IMAGES_PER_MESSAGE", "3"))
OCR_TIMEOUT_SECONDS = int(os.getenv("OCR_TIMEOUT_SECONDS", "5"))
_UI_THEME = os.getenv("UI_THEME", "system").strip().lower()
UI_THEME = _UI_THEME if _UI_THEME in {"light", "dark", "system"} else "system"
