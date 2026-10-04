"""Regression coverage for the actual Gradio callbacks and SQLite persistence."""
import asyncio
import warnings

import gradio as gr
import pytest
from gradio.state_holder import SessionState
from analyzers.kb_actions import KnowledgeBaseActions
import kb_ui


@pytest.fixture
def ui(tmp_path, monkeypatch):
    kb = KnowledgeBaseActions(str(tmp_path / "kb.db"))
    monkeypatch.setattr(kb_ui, "kb", kb)
    with warnings.catch_warnings(record=True) as captured:
        with gr.Blocks() as blocks:
            kb_ui.build_kb_tab()
    assert not [w for w in captured if "arguments for function" in str(w.message)]
    return kb, blocks


def callback(blocks, name):
    return next(fn for fn in blocks.fns.values() if fn.fn and fn.fn.__name__ == name)


def invoke(blocks, fn, state, inputs, event=None):
    return asyncio.run(blocks.process_api(fn, inputs, state=state, event_data=event))["data"]


def selection_event(row, column=1, selected=True):
    return gr.SelectData(None, {"index": [0, column], "value": row[column],
                                "row_value": row, "selected": selected})


@pytest.mark.parametrize("reverse", [False, True])
def test_wired_add_remove_reload_and_next_add(ui, reverse):
    kb, blocks = ui
    if reverse:
        parent = kb.create_article("Parent", "content")
        children = [kb.create_case(f"link {x}", "content") for x in "ABCD"]
        displays = [kb.get_case(x).display_id for x in children]
        add = callback(blocks, "add_case_to_article")
        search = callback(blocks, "search_cases_for_article")
        remove = callback(blocks, "remove_case_link_handler")
        refresh = callback(blocks, "refresh_article_links")
        read = lambda service: {c.id for c in service.get_cases_for_article(parent)}
    else:
        parent = kb.create_case("Parent", "content")
        children = [kb.create_article(f"link {x}", "content") for x in "ABCD"]
        displays = [kb.get_article(x).display_id for x in children]
        add = callback(blocks, "add_article_to_case")
        search = callback(blocks, "search_articles_for_case")
        remove = callback(blocks, "remove_article_link_handler")
        refresh = callback(blocks, "refresh_case_links")
        read = lambda service: {a.id for a in service.get_articles_for_case(parent)}
    select = next(fn for fn in blocks.fns.values()
                  if fn.fn and fn.fn.__name__ == "select_link_result"
                  and fn.outputs[0]._id == add.inputs[1]._id)
    assert select.collects_event_data and remove.collects_event_data
    state = SessionState(blocks)
    state[add.inputs[0]._id] = parent

    def add_child(index):
        table = invoke(blocks, search, state, [f"link {'ABCD'[index]}"])[0]
        assert state[add.inputs[1]._id] is None
        row = next(row for row in table["data"] if row[1] == displays[index])
        marked = invoke(blocks, select, state, [None, table], selection_event(row))[1]
        assert [row[1] for row in marked["data"] if row[0] == "▶"] == [displays[index]]
        result = invoke(blocks, add, state, [None, None])[0]
        invoke(blocks, refresh, state, [None])
        return result

    for index in range(3):
        assert "Successfully linked" in add_child(index)
    assert read(kb) == set(children[:3])
    assert "already linked" in add_child(1)
    assert read(kb) == set(children[:3])
    row = [displays[1], "link B", "✕"]
    # ID/title clicks are navigation/focus, not deletion.
    for column in (0, 1):
        invoke(blocks, remove, state, [None], selection_event(row, column))
        assert read(kb) == set(children[:3])
    result = invoke(blocks, remove, state, [None], selection_event(row, 2))[0]
    assert "Unlinked" in result
    table = invoke(blocks, refresh, state, [None])[0]
    assert {r[0] for r in table["data"]} == {displays[0], displays[2]}
    reopened = KnowledgeBaseActions(str(kb.storage.db_path))
    assert read(reopened) == {children[0], children[2]}
    assert "Successfully linked" in add_child(3)
    assert read(reopened) == {children[0], children[2], children[3]}
    assert not kb.unlink_case_from_article(*( (children[1], parent) if reverse else (parent, children[1]) ))


def test_sessions_and_stale_selection_are_isolated(ui):
    kb, blocks = ui
    parents = [kb.create_case(x, "content") for x in ("First", "Second")]
    article = kb.create_article("link A", "content")
    display = kb.get_article(article).display_id
    add = callback(blocks, "add_article_to_case")
    sessions = [SessionState(blocks), SessionState(blocks)]
    for state, parent in zip(sessions, parents):
        state[add.inputs[0]._id] = parent
    sessions[0][add.inputs[1]._id] = (parents[0], display)
    assert "Select case and article" in invoke(blocks, add, sessions[1], [None, None])[0]
    assert "Successfully linked" in invoke(blocks, add, sessions[0], [None, None])[0]
    assert kb.get_articles_for_case(parents[1]) == []
    sessions[0][add.inputs[0]._id] = parents[1]
    assert "Select case and article" in invoke(blocks, add, sessions[0], [None, None])[0]
    assert kb.get_articles_for_case(parents[1]) == []


def test_relationship_tables_are_static_and_refresh_keeps_form_fields(ui):
    _, blocks = ui
    tables = [c for c in blocks.blocks.values()
              if isinstance(c, gr.Dataframe) and "kb-link-table" in (c.elem_classes or [])]
    assert len(tables) == 4
    for table in tables:
        assert table.interactive is False
        assert table.col_count == (3, "fixed")
        assert len(table.headers) == 3
    for fn in blocks.fns.values():
        if fn.fn and fn.fn.__name__ in ("refresh_case_links", "refresh_article_links"):
            assert len(fn.outputs) == 1
            assert isinstance(fn.outputs[0], gr.Dataframe)
        if fn.fn and fn.fn.__name__ == "select_link_result":
            assert fn.collects_event_data


def test_main_search_returns_session_state_and_clears_old_parent(ui):
    kb, blocks = ui
    first = kb.create_case("matching first", "content")
    kb.create_article("matching article", "content")
    search = callback(blocks, "perform_search")
    state = SessionState(blocks)
    invoke(blocks, search, state, ["matching"])
    assert [case.id for case in state[search.outputs[-4]._id]] == [first]
    assert len(state[search.outputs[-3]._id]) == 1
    state[search.outputs[-2]._id] = first
    invoke(blocks, search, state, [""])
    assert state[search.outputs[-4]._id] == []
    assert state[search.outputs[-3]._id] == []
    assert state[search.outputs[-2]._id] is None
