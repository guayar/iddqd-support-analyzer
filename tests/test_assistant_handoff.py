from __future__ import annotations

import inspect
from pathlib import Path

from app import (
    analyze,
    analyze_with_assistant,
    clear_assistant_context,
    clear_assistant_conversation,
    clear_general_chat_conversation,
    send_to_assistant,
    _hero_text,
)
from config import OLLAMA_MODEL
from chats import assistant_system_prompt, empty_assistant_history, assistant_chat, web_chat

analysis_a = {"kind": "saml", "case": "A", "findings": [{"code": "X"}]}
analysis_b = {"kind": "saml", "case": "B", "findings": [{"code": "Y"}]}

# A: core analyze() stays a 3-tuple and does not know about Assistant.
analyze_src = inspect.getsource(analyze)
assert "send_to_assistant" not in analyze_src
assert "_context_badge" not in analyze_src
assert "assistant_context" not in analyze_src
sync_src = inspect.getsource(analyze_with_assistant)
assert "send_to_assistant" in sync_src

ui = Path("app.py").read_text(encoding="utf-8")
assert "Attach latest analysis" not in ui
assert "Open in Assistant" not in ui
assert "analyze_with_assistant" in ui

# G: no attached analysis -> no analyzer JSON in the system prompt.
plain = assistant_system_prompt(None)
assert "ANALYZER OUTPUT" not in plain
assert "Open in Assistant" not in plain
assert "Attach latest analysis" not in plain
assert "Support Mail" not in ui
assert "psa-assistant-mode" not in ui
assert "OLLAMA_MODEL" in ui
assert "qwen3.6:27b" not in ui
assert "qwen3.6:35b" not in ui
assert "gemma4:31b" not in ui
assert "Web search enabled" in ui
assert 'label="Assistant"' in ui
assert 'label="General Chat"' in ui
assert "Assistant and General Chat" not in ui
assert "PLUGIN_ASSISTANT" in ui
assert "PLUGIN_GENERAL_CHAT" in ui
assert "psa-chat-tab" in ui
assert "Clear conversation" in ui
assert "clear_assistant_conversation" in ui
assert "clear_general_chat_conversation" in ui
assert "Clear analysis context" in ui
assert OLLAMA_MODEL not in _hero_text()
assert "Model:" not in _hero_text()

# B: Analyze-with-assistant sync attaches that analysis and starts a clean chat.
ctx, badge, history = send_to_assistant(analysis_a)
assert ctx == analysis_a
assert "Analysis context attached" in badge
assert "psa-context-on" in badge
assert f"Model: {OLLAMA_MODEL}" in badge
assert "psa-model" in badge
assert history == empty_assistant_history() == []
attached = assistant_system_prompt(ctx)
assert "ANALYZER OUTPUT" in attached
assert '"case": "A"' in attached
assert "latest Analyze run" in attached

# C: a later Analyze result replaces A in Assistant (no extra attach step).
ctx, badge, history = send_to_assistant(analysis_b)
assert ctx == analysis_b
assert '"case": "B"' in assistant_system_prompt(ctx)
assert '"case": "A"' not in assistant_system_prompt(ctx)
assert history == []

# F: clear analysis context removes structured context and chat history.
ctx, badge, history = clear_assistant_context()
assert ctx is None
assert "No analysis context attached" in badge
assert "psa-context-off" in badge
assert f"Model: {OLLAMA_MODEL}" in badge
assert history == []
assert "ANALYZER OUTPUT" not in assistant_system_prompt(ctx)

# F2: clear conversation wipes this chat/OCR cache and keeps attached analysis.
from vision import SCOPE_ASSISTANT, SCOPE_GENERAL_CHAT, _OCR_CACHES

ctx, badge, history = send_to_assistant(analysis_a)
_OCR_CACHES[SCOPE_ASSISTANT][("a", 1, 1)] = {"text": "x"}
_OCR_CACHES[SCOPE_GENERAL_CHAT][("g", 1, 1)] = {"text": "y"}
wiped = clear_assistant_conversation()
assert wiped == []
assert ctx == analysis_a
assert "ANALYZER OUTPUT" in assistant_system_prompt(ctx)
assert _OCR_CACHES[SCOPE_ASSISTANT] == {}
assert _OCR_CACHES[SCOPE_GENERAL_CHAT][("g", 1, 1)]["text"] == "y"
assert clear_general_chat_conversation() == []
assert _OCR_CACHES[SCOPE_GENERAL_CHAT] == {}
assert "ANALYZER OUTPUT" in assistant_system_prompt(ctx)

# H: General Chat has no analysis argument; model hint is informational only.
assert "assistant_context" not in inspect.signature(web_chat).parameters
assert "analysis_state" not in inspect.signature(web_chat).parameters

sig = inspect.signature(assistant_chat)
assert list(sig.parameters) == ["message", "history", "assistant_context"]
assert "mode" not in sig.parameters

empty_failed = False
try:
    send_to_assistant(None)
except Exception as e:
    assert "Analyze" in str(e)
    empty_failed = True
assert empty_failed

print("ASSISTANT HANDOFF TESTS OK")
