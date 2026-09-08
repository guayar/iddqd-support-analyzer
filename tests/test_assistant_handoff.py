from __future__ import annotations

import inspect

from app import analyze, clear_assistant_context, send_to_assistant
from chats import assistant_system_prompt, empty_assistant_history, assistant_chat, web_chat

analysis_a = {"kind": "saml", "case": "A", "findings": [{"code": "X"}]}
analysis_b = {"kind": "saml", "case": "B", "findings": [{"code": "Y"}]}

# A: Analyze does not attach Assistant context.
analyze_src = inspect.getsource(analyze)
assert "send_to_assistant" not in analyze_src
assert "_context_badge" not in analyze_src
assert "assistant_context" not in analyze_src
assert "assistant_detached" not in analyze_src

# G: no attached analysis -> no analyzer JSON in the system prompt.
plain = assistant_system_prompt("General", None)
assert "ANALYZER OUTPUT" not in plain
assert "Open in Assistant" not in plain
assert "Attach latest analysis" not in plain

# B: explicit handoff attaches that analysis and starts a clean chat.
ctx, badge, history = send_to_assistant(analysis_a)
assert ctx == analysis_a
assert "Analysis context attached" in badge
assert "psa-context-on" in badge
assert history == empty_assistant_history() == []
attached = assistant_system_prompt("General", ctx)
assert "ANALYZER OUTPUT" in attached
assert '"case": "A"' in attached

# C: a later Analyze result is a separate object; Assistant keeps A until handoff.
latest = analysis_b
assert ctx == analysis_a
assert latest != ctx

# D + E: attaching B replaces A and clears conversation history.
ctx, badge, history = send_to_assistant(analysis_b)
assert ctx == analysis_b
assert '"case": "B"' in assistant_system_prompt("Code", ctx)
assert '"case": "A"' not in assistant_system_prompt("General", ctx)
assert history == []

# F: clear removes structured context and chat history.
ctx, badge, history = clear_assistant_context()
assert ctx is None
assert "No analysis context attached" in badge
assert "psa-context-off" in badge
assert history == []
assert "ANALYZER OUTPUT" not in assistant_system_prompt("Support Mail", ctx)

# H: General Chat has no analysis argument.
assert "assistant_context" not in inspect.signature(web_chat).parameters
assert "analysis_state" not in inspect.signature(web_chat).parameters

# Assistant chat signature is the explicit context only.
sig = inspect.signature(assistant_chat)
assert list(sig.parameters) == ["message", "history", "mode", "assistant_context"]

empty_failed = False
try:
    send_to_assistant(None)
except Exception as e:
    assert "Analyze" in str(e)
    empty_failed = True
assert empty_failed

print("ASSISTANT HANDOFF TESTS OK")
