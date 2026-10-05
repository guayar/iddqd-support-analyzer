import json
import sqlite3

import gradio as gr
import pytest

import kb_ui
from analyzers.kb_actions import KnowledgeBaseActions


def test_deleted_last_id_is_not_reused_after_restart(tmp_path):
    path = str(tmp_path / "kb.db")
    kb = KnowledgeBaseActions(path)
    kb.create_article("A", "A")
    last = kb.create_article("B", "B")
    kb.delete_article(last)
    kb = KnowledgeBaseActions(path)
    new = kb.create_article("C", "C")
    assert kb.get_article(new).display_id == "AN00000003"


def test_unknown_exact_id_does_not_match_text(tmp_path):
    kb = KnowledgeBaseActions(str(tmp_path / "kb.db"))
    kb.create_article("Reference", "See AN99999999")
    assert kb.search_articles("an99999999") == []
    assert len(kb.search_articles("Reference")) == 1


def test_import_storage_failure_rolls_back_records_and_sequence(tmp_path):
    kb = KnowledgeBaseActions(str(tmp_path / "kb.db"))
    with pytest.raises(sqlite3.ProgrammingError):
        kb.storage.import_articles([
            {"title": "A", "content": "A", "tags": ["new"]},
            {"title": "B", "content": "B", "summary": {"bad": True}},
        ])
    assert kb.list_articles() == []
    with kb.storage._get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM kb_tags").fetchone()[0] == 0
    first = kb.create_article("C", "C")
    assert kb.get_article(first).display_id == "AN00000001"


def test_import_rejects_invalid_summary_before_writes(tmp_path, monkeypatch):
    kb = KnowledgeBaseActions(str(tmp_path / "kb.db"))
    monkeypatch.setattr(kb_ui, "kb", kb)
    with gr.Blocks() as blocks:
        kb_ui.build_kb_tab()
    callback = next(f.fn for f in blocks.fns.values() if f.fn and f.fn.__name__ == "import_kb")
    path = tmp_path / "import.json"
    path.write_text(json.dumps({"articles": [
        {"title": "A", "content": "A"},
        {"title": "B", "content": "B", "summary": {"bad": True}},
    ]}))
    assert "Invalid" in callback(str(path))
    assert kb.list_articles() == []
