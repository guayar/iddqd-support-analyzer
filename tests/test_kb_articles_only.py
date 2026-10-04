"""Articles-only KB: compatibility, real UI callbacks and persistence."""
import asyncio
import json
import zipfile
from io import BytesIO
from pathlib import Path

import gradio as gr
import pytest
from gradio.state_holder import SessionState
from analyzers.kb_actions import KnowledgeBaseActions
from analyzers.kb_assistant import KBAssistantContext
from analyzers.kb_portability import KnowledgeBasePortability
import kb_ui


@pytest.fixture
def ui(tmp_path, monkeypatch):
    kb = KnowledgeBaseActions(str(tmp_path / "kb.db"))
    monkeypatch.setattr(kb_ui, "kb", kb)
    with gr.Blocks() as blocks:
        kb_ui.build_kb_tab()
    return kb, blocks


def callback(blocks, name):
    return next(fn for fn in blocks.fns.values() if fn.fn and fn.fn.__name__ == name)


def invoke(blocks, fn, state, inputs, event=None):
    return asyncio.run(blocks.process_api(fn, inputs, state=state, event_data=event))["data"]


def test_legacy_cases_and_links_are_not_exposed_or_deleted(tmp_path, monkeypatch):
    path = str(tmp_path / "kb.db")
    kb = KnowledgeBaseActions(path)
    first = kb.create_article("Keep", "Original", tags=["tag"])
    second = kb.create_article("Keep too", "Other")
    kb.update_article(first, content="Revised")
    case = kb.create_case("Test Case", "Discard from UI")
    kb.link_case_to_article(case, first)
    kb.link_articles(first, second)
    display = kb.get_article(first).display_id
    monkeypatch.setattr(kb_ui, "kb", kb)
    with gr.Blocks() as blocks:
        kb_ui.build_kb_tab()
    result = invoke(blocks, callback(blocks, "perform_search"), SessionState(blocks), [""])
    assert {row[1] for row in result[0]["data"]} == {display, kb.get_article(second).display_id}
    reopened = KnowledgeBaseActions(path)
    article = reopened.get_article(first)
    assert (article.display_id, article.content, article.tags) == (display, "Revised", ["tag"])
    assert reopened.get_case(case) is not None
    with reopened.storage._get_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM kb_revisions WHERE article_id = ?", (first,)).fetchone()[0] == 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_ui_has_only_articles_and_static_table(ui):
    _, blocks = ui
    props = [component["props"] for component in blocks.config["components"]]
    text = json.dumps(props, default=str)
    assert "Case View" not in text and "Case Edit" not in text
    assert "Linked" not in text and "Add Selected Link" not in text
    assert "Create Article" in text
    tables = [c for c in blocks.blocks.values() if isinstance(c, gr.Dataframe)]
    assert len(tables) == 1
    assert tables[0].interactive is False and tables[0].col_count == (4, "fixed")


def test_create_select_edit_save_reload_and_delete(ui):
    kb, blocks = ui
    state = SessionState(blocks)
    create = callback(blocks, "create_article")
    assert "Created AN" in invoke(blocks, create, state, ["Title", "old", "Summary", "Original"])[0]
    article = kb.list_articles()[0]
    search = callback(blocks, "perform_search")
    result = invoke(blocks, search, state, [""])
    row = result[0]["data"][0]
    load = callback(blocks, "load_article_view_full")
    event = gr.SelectData(None, {"index": [0, 2], "value": row[2], "row_value": row})
    result = invoke(blocks, load, state, [], event)
    assert result[:2] == [article.display_id, "Title"]
    assert result[-2]["visible"] is True and result[-1]["visible"] is False
    edit = callback(blocks, "toggle_article_edit")
    assert edit.outputs[-2].visible is False  # Initial Edit group is hidden.
    result = invoke(blocks, edit, state, [None])
    assert result[6]["visible"] is False and result[7]["visible"] is True
    save = callback(blocks, "save_article")
    result = invoke(blocks, save, state, [None, "New title", "new, new", "New summary", "New content"])
    assert result[-1] == "✅ Article saved"
    assert result[6]["visible"] is True and result[7]["visible"] is False
    reopened = KnowledgeBaseActions(str(kb.storage.db_path))
    article = reopened.get_article(article.id)
    assert (article.title, article.summary, article.content, article.tags) == ("New title", "New summary", "New content", ["new"])
    delete = callback(blocks, "delete_article")
    result = invoke(blocks, delete, state, [None])
    assert result[-1] == "✅ Article deleted"
    assert reopened.list_articles() == []


def test_cancel_and_invalid_save_preserve_correct_mode(ui):
    kb, blocks = ui
    article_id = kb.create_article("Article", "Content")
    state = SessionState(blocks)
    edit = callback(blocks, "toggle_article_edit")
    state[edit.inputs[0]._id] = article_id
    invoke(blocks, edit, state, [None])
    save = callback(blocks, "save_article")
    assert "required" in invoke(blocks, save, state, [None, "", "", "", ""])[-1]
    assert state[edit.outputs[5]._id] == "edit"
    result = invoke(blocks, callback(blocks, "toggle_article_view"), state, [])
    assert result[1]["visible"] is True and result[2]["visible"] is False


def test_sessions_do_not_share_article_selection(ui):
    kb, blocks = ui
    article = kb.create_article("Article", "Content")
    load = callback(blocks, "load_article_view_full")
    states = [SessionState(blocks), SessionState(blocks)]
    row = ["", kb.get_article(article).display_id, "Article", ""]
    event = gr.SelectData(None, {"index": [0, 1], "value": row[1], "row_value": row})
    invoke(blocks, load, states[0], [], event)
    assert states[0][load.outputs[5]._id] == article
    assert states[1][load.outputs[5]._id] is None


def test_export_import_articles_without_cases_or_record_links(ui, tmp_path, monkeypatch):
    kb, blocks = ui
    kb.create_article("Article", "Content", summary="Summary", tags=["tag"])
    monkeypatch.chdir(tmp_path)
    path, _ = callback(blocks, "export_kb").fn()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert list(data) == ["articles"]
    assert "related_article_ids" not in data["articles"][0]
    data["cases"] = [{"title": "Ignored", "content": "Test"}]
    data["articles"][0]["related_article_ids"] = ["ignored"]
    Path(path).write_text(json.dumps(data), encoding="utf-8")
    assert "Imported 1" in callback(blocks, "import_kb").fn(path)
    assert len(kb.list_articles()) == 2 and kb.list_cases() == []
    assert all(not a.related_article_ids for a in kb.list_articles())


def test_zip_portability_does_not_reintroduce_cases(tmp_path):
    kb = KnowledgeBaseActions(str(tmp_path / "kb.db"))
    article_id = kb.create_article("Article", "Content")
    case_id = kb.create_case("Test", "Discard")
    portability = KnowledgeBasePortability(kb.storage)
    data = portability.export_selected([article_id], [case_id])
    with zipfile.ZipFile(BytesIO(data)) as archive:
        assert not any(name.startswith("cases/") for name in archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["cases_count"] == 0


def test_assistant_saves_analysis_as_article(tmp_path):
    context = KBAssistantContext(str(tmp_path / "kb.db"))
    article_id = context.save_article_from_analysis("Investigation", [{"kind": "JWT", "signature": "Evidence"}], tags=["jwt"])
    article = context.kb.get_article(article_id)
    assert article is not None and "Evidence" in article.content and article.tags == ["jwt"]
    assert context.kb.list_cases() == []
    prompt = context.get_assistant_system_prompt_fragment()
    assert "Cases" not in prompt and "Investigation" in prompt


def test_article_list_pagination(ui):
    kb, blocks = ui
    for index in range(12):
        kb.create_article(f"Article {index}", "Content")
    state = SessionState(blocks)
    result = invoke(blocks, callback(blocks, "perform_search"), state, [""])
    assert result[1:3] == ["12", "1 / 2"]
    assert len(result[0]["data"]) == 10
    result = invoke(blocks, callback(blocks, "next_page"), state, [None, None, None])
    assert result[2] == "2 / 2" and len(result[0]["data"]) == 2
    result = invoke(blocks, callback(blocks, "previous_page"), state, [None, None, None])
    assert result[2] == "1 / 2" and len(result[0]["data"]) == 10
