from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PLUGIN_ANONYMIZE = "anonymize"
PLUGIN_ASSISTANT = "assistant"
PLUGIN_GENERAL_CHAT = "general_chat"
# Pre-0.13 combined flag. Still accepted on read and expands to both chat modules.
PLUGIN_LLM = "llm"
KNOWN_PLUGINS = (PLUGIN_ANONYMIZE, PLUGIN_ASSISTANT, PLUGIN_GENERAL_CHAT)

_DEFAULT_MODULES_FILE = Path(__file__).resolve().parent / ".iddqd-modules.json"
MODULES_FILE = Path(os.environ["IDDQD_MODULES_FILE"]) if os.environ.get("IDDQD_MODULES_FILE") else _DEFAULT_MODULES_FILE


def normalize_plugins(values) -> tuple[str, ...]:
    wanted = {str(item).strip() for item in values or []}
    if PLUGIN_LLM in wanted:
        wanted.add(PLUGIN_ASSISTANT)
        wanted.add(PLUGIN_GENERAL_CHAT)
    return tuple(name for name in KNOWN_PLUGINS if name in wanted)


def read_saved_plugins() -> tuple[str, ...]:
    if not MODULES_FILE.is_file():
        return ()
    try:
        data = json.loads(MODULES_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Warning: could not read {MODULES_FILE}: {exc}. Optional modules are off until Config is saved.", file=sys.stderr)
        return ()
    if isinstance(data, dict):
        return normalize_plugins(data.get("plugins"))
    if isinstance(data, list):
        return normalize_plugins(data)
    print(f"Warning: {MODULES_FILE} has an unexpected shape. Optional modules are off until Config is saved.", file=sys.stderr)
    return ()


def write_saved_plugins(values) -> tuple[str, ...]:
    plugins = normalize_plugins(values)
    payload = json.dumps({"plugins": list(plugins)}, indent=2) + "\n"
    tmp = MODULES_FILE.with_name(MODULES_FILE.name + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, MODULES_FILE)
    return plugins


def plugin_enabled(plugin_id: str, enabled: tuple[str, ...] | None = None) -> bool:
    return plugin_id in (enabled if enabled is not None else RUNNING_PLUGINS)


def restart_application() -> None:
    python = sys.executable
    argv = [python, *sys.argv]
    os.execv(python, argv)


# Snapshot of the file at process start. Config checkboxes may differ until restart.
RUNNING_PLUGINS: tuple[str, ...] = read_saved_plugins()
