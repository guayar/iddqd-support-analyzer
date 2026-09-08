from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PLUGIN_ANONYMIZE = "anonymize"
PLUGIN_LLM = "llm"
KNOWN_PLUGINS = (PLUGIN_ANONYMIZE, PLUGIN_LLM)

PLUGIN_SPECS = (
    {
        "id": PLUGIN_ANONYMIZE,
        "label": "Anonymize",
        "description": "Local log and SAML pseudonymization. No language model.",
    },
    {
        "id": PLUGIN_LLM,
        "label": "Assistant and General Chat",
        "description": "Local Assistant can read the current Analyze report. General Chat can use the web and never receives that report.",
    },
)

_DEFAULT_MODULES_FILE = Path(__file__).resolve().parent / ".iddqd-modules.json"
MODULES_FILE = Path(os.environ["IDDQD_MODULES_FILE"]) if os.environ.get("IDDQD_MODULES_FILE") else _DEFAULT_MODULES_FILE


def normalize_plugins(values) -> tuple[str, ...]:
    wanted = {str(item).strip() for item in values or []}
    return tuple(name for name in KNOWN_PLUGINS if name in wanted)


def read_saved_plugins() -> tuple[str, ...]:
    if not MODULES_FILE.is_file():
        return ()
    try:
        data = json.loads(MODULES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return ()
    if isinstance(data, dict):
        return normalize_plugins(data.get("plugins"))
    if isinstance(data, list):
        return normalize_plugins(data)
    return ()


def write_saved_plugins(values) -> tuple[str, ...]:
    plugins = normalize_plugins(values)
    MODULES_FILE.write_text(json.dumps({"plugins": list(plugins)}, indent=2) + "\n", encoding="utf-8")
    return plugins


def plugin_enabled(plugin_id: str, enabled: tuple[str, ...] | None = None) -> bool:
    return plugin_id in (enabled if enabled is not None else RUNNING_PLUGINS)


def restart_application() -> None:
    python = sys.executable
    argv = [python, *sys.argv]
    os.execv(python, argv)


# Snapshot of the file at process start. Config checkboxes may differ until restart.
RUNNING_PLUGINS: tuple[str, ...] = read_saved_plugins()
