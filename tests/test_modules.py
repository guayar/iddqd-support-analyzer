from __future__ import annotations

import inspect
import json
import os
import sys
import tempfile
from pathlib import Path

td = Path(tempfile.mkdtemp(prefix="iddqd-modules-"))
os.environ["IDDQD_MODULES_FILE"] = str(td / ".iddqd-modules.json")

import modules  # noqa: E402

assert modules.read_saved_plugins() == ()
assert modules.write_saved_plugins(["llm", "unknown", "anonymize", "llm"]) == ("anonymize", "llm")
assert json.loads(modules.MODULES_FILE.read_text(encoding="utf-8"))["plugins"] == ["anonymize", "llm"]
assert modules.normalize_plugins(["oidc", "anonymize"]) == ("anonymize",)
modules.write_saved_plugins([])
assert modules.read_saved_plugins() == ()
modules.MODULES_FILE.write_text("{not-json", encoding="utf-8")
assert modules.read_saved_plugins() == ()

from analyzers import analyze_log_text, analyze_saml_input  # noqa: E402
import actions  # noqa: E402

assert "analyzers.anonymizer" not in sys.modules
assert "analyzers.anonymizer_engine" not in sys.modules
assert "websearch" not in sys.modules
assert "chats" not in sys.modules
assert "llm" not in sys.modules

import app  # noqa: E402

assert app.ANONYMIZE_ON is False
assert app.LLM_ON is False
assert "websearch" not in sys.modules
assert "chats" not in sys.modules
src_flags = (app.ANONYMIZE_ON, app.LLM_ON)
assert src_flags == (False, False)

from chats import assistant_chat, web_chat  # noqa: E402

assert "websearch" not in sys.modules
assert "web_search" not in inspect.getsource(assistant_chat)
assert "websearch" not in inspect.getsource(assistant_chat)
web_src = inspect.getsource(web_chat)
assert "web_search" in web_src
assert "analysis_state" not in inspect.signature(web_chat).parameters
sig = inspect.signature(assistant_chat)
assert "assistant_context" in sig.parameters
assert "mode" not in sig.parameters
assert "analysis_state" not in sig.parameters
assert "assistant_context" not in inspect.signature(web_chat).parameters

# J: Core-only UI is Analyze + Config (optional modules off).
assert app.ANONYMIZE_ON is False
assert app.LLM_ON is False

print("MODULE PLUGIN TESTS OK")
