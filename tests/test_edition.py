from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

td = Path(tempfile.mkdtemp(prefix="iddqd-edition-"))
os.environ["IDDQD_MODULES_FILE"] = str(td / ".iddqd-modules.json")

from config import parse_edition
from modules import PLUGIN_ANONYMIZE, PLUGIN_ASSISTANT, PLUGIN_GENERAL_CHAT, plugin_enabled

ROOT = Path(__file__).resolve().parents[1]


def test_parse_edition():
    assert parse_edition(None) == "full"
    assert parse_edition("") == "full"
    assert parse_edition("CORE") == "light"
    assert parse_edition("light") == "light"
    assert parse_edition("full") == "full"
    try:
        parse_edition("lite")
    except ValueError as exc:
        assert "IDDQD_EDITION" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_full_edition_does_not_force_anonymize():
    assert plugin_enabled(PLUGIN_ANONYMIZE) is False
    assert plugin_enabled(PLUGIN_ASSISTANT) is False
    assert plugin_enabled(PLUGIN_GENERAL_CHAT) is False


def test_core_edition_forces_anonymize_and_blocks_chats():
    env = os.environ.copy()
    env["IDDQD_EDITION"] = "light"
    env["PYTHONPATH"] = str(ROOT)
    env["IDDQD_MODULES_FILE"] = str(td / "core-modules.json")
    script = r"""
import sys
import app
assert app.IS_CORE_EDITION is True
assert app.IS_LIGHT_EDITION is True
assert app.APP_TITLE.endswith("Light")
assert app.ANONYMIZE_ON is True
assert app.ASSISTANT_ON is False
assert app.GENERAL_CHAT_ON is False
assert "chats" not in sys.modules
assert "llm" not in sys.modules
assert "websearch" not in sys.modules
assert "vision" not in sys.modules
print("LIGHT EDITION IMPORT OK")
"""
    subprocess.run([sys.executable, "-c", script], cwd=ROOT, env=env, check=True)


def test_export_core_omits_llm_modules():
    zip_path = subprocess.check_output(
        ["bash", str(ROOT / "scripts/export-light.sh")],
        cwd=ROOT,
        text=True,
    ).strip()
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
    assert "light" in Path(zip_path).name
    assert any(name.endswith("LIGHT_EDITION") for name in names)
    assert any(name.endswith("app.py") for name in names)
    assert any(name.endswith("analyzers/anonymizer.py") for name in names)
    assert any(name.endswith("requirements-core.txt") for name in names)
    assert not any(name.endswith("chats.py") for name in names)
    assert not any(name.endswith("llm.py") for name in names)
    assert not any(name.endswith("vision.py") for name in names)
    assert not any(name.endswith("websearch.py") for name in names)


if __name__ == "__main__":
    test_parse_edition()
    test_full_edition_does_not_force_anonymize()
    test_core_edition_forces_anonymize_and_blocks_chats()
    test_export_core_omits_llm_modules()
    print("EDITION TESTS OK")
