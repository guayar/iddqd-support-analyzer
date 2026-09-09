from __future__ import annotations

from unittest.mock import patch

from chats import _history_messages, assistant_chat, assistant_system_prompt
from websearch import history_text

GRADIO_HISTORY = [
    {
        "role": "user",
        "content": [{"type": "text", "text": "What is the main issue in this analysis?"}],
        "metadata": None,
    },
    {
        "role": "assistant",
        "content": [{"type": "text", "text": "The main issue is an expired certificate."}],
    },
]

STRING_HISTORY = [
    {"role": "user", "content": "What is the main issue in this analysis?"},
    {"role": "assistant", "content": "The main issue is an expired certificate."},
]


def test_gradio_blocks_are_flattened():
    msgs = _history_messages(GRADIO_HISTORY, 20, 20000)
    assert msgs == [
        {"role": "user", "content": "What is the main issue in this analysis?"},
        {"role": "assistant", "content": "The main issue is an expired certificate."},
    ]


def test_string_content_still_works():
    assert _history_messages(STRING_HISTORY, 20, 20000) == _history_messages(GRADIO_HISTORY, 20, 20000)


def test_non_text_blocks_are_skipped():
    history = [
        {"role": "user", "content": [{"type": "file", "file": {"path": "/tmp/x"}}]},
        {"role": "assistant", "content": ""},
        {"role": "system", "content": "ignore me"},
        {"role": "user", "content": [{"type": "text", "text": "keep me"}]},
    ]
    assert _history_messages(history, 20, 20000) == [{"role": "user", "content": "keep me"}]


def test_assistant_second_turn_includes_prior_turns_and_analyze_json():
    captured: list[list[dict[str, str]]] = []

    def fake_complete(messages, temperature=0.2):
        captured.append(messages)
        return "ok"

    ctx = {"kind": "saml", "case": "A", "findings": [{"code": "X"}]}
    with patch("chats.complete", fake_complete):
        assert assistant_chat("And what would you check next?", GRADIO_HISTORY, ctx) == "ok"

    msgs = captured[0]
    assert msgs[0]["role"] == "system"
    assert "ANALYZER OUTPUT" in msgs[0]["content"]
    assert '"case": "A"' in msgs[0]["content"]
    assert [(m["role"], m["content"]) for m in msgs[1:]] == [
        ("user", "What is the main issue in this analysis?"),
        ("assistant", "The main issue is an expired certificate."),
        ("user", "And what would you check next?"),
    ]
    assert not msgs[-1].get("images")
    assert assistant_system_prompt(ctx) == msgs[0]["content"]


def test_websearch_history_text_uses_gradio_blocks():
    text = history_text(GRADIO_HISTORY)
    assert "What is the main issue in this analysis?" in text
    assert "The main issue is an expired certificate." in text


def test_search_backend_resolution():
    from websearch import resolve_search_backend, source_footer

    assert resolve_search_backend("auto") == "auto"
    assert resolve_search_backend("all") == "auto"
    assert resolve_search_backend("google, brave, google, ddg") == "google,brave,duckduckgo"
    assert resolve_search_backend("nope, bing") == "auto"
    footer = source_footer(
        [{"title": "Doc", "url": "https://example.com/doc"}],
        ["saml bearer"],
        "google,brave",
    )
    assert "`google`" in footer
    assert "`brave`" in footer
    assert "Search engines:" in footer


if __name__ == "__main__":
    test_gradio_blocks_are_flattened()
    test_string_content_still_works()
    test_non_text_blocks_are_skipped()
    test_assistant_second_turn_includes_prior_turns_and_analyze_json()
    test_websearch_history_text_uses_gradio_blocks()
    test_search_backend_resolution()
    print("CHAT HISTORY TESTS OK")
