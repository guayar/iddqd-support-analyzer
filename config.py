from __future__ import annotations

import os

APP_TITLE = "IDDQD Support Analyzer"
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
