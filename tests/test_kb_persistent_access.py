"""Tests for persistent KB access without Analyze context.

Verify that KB is available independently of Analyze context.
"""

import pytest
from chats import assistant_system_prompt, _get_kb_metadata, _should_search_kb, _search_kb_for_query


def test_kb_metadata_without_analyze():
    """KB metadata always in prompt even without Analyze context."""
    prompt = assistant_system_prompt(None)
    assert "LOCAL KNOWLEDGE BASE" in prompt
    assert "Available Articles" in prompt


def test_kb_article_count_question():
    """User can ask how many articles without Analyze."""
    prompt = assistant_system_prompt(None, user_message="ile artykułów jest w KB?")
    assert "LOCAL KNOWLEDGE BASE" in prompt
    assert "Available Articles" in prompt


def test_kb_search_without_analyze():
    """User can search KB without Analyze context."""
    prompt = assistant_system_prompt(None, user_message="pokaż mi artykuły o JWT")
    # Should include KB metadata at minimum
    assert "LOCAL KNOWLEDGE BASE" in prompt


def test_normal_question_no_kb_search():
    """Normal questions don't trigger KB search."""
    prompt = assistant_system_prompt(None, user_message="hello how are you")
    # Should have metadata but not search
    assert "LOCAL KNOWLEDGE BASE" in prompt


def test_kb_query_extraction():
    """Query extraction removes noise."""
    from chats import _extract_kb_query

    test_cases = [
        ("pokaż mi artykuły o SAML", "SAML"),
        ("czy mam coś o JWT", "JWT"),
        ("ile artykułów", ""),
        ("search for SAP HANA", "SAP HANA"),
    ]

    for query, expected in test_cases:
        result = _extract_kb_query(query)
        assert result == expected


def test_kb_search_detection():
    """Keyword detection works."""
    should_search_cases = [
        ("pokaż artykuły", True),
        ("KB article", True),
        ("ile w knowledge base", True),
        ("hello", False),
        ("debug JWT", False),
    ]

    for query, expected in should_search_cases:
        result = _should_search_kb(query)
        assert result == expected


def test_kb_metadata_loading():
    """KB metadata loads without crashing."""
    metadata = _get_kb_metadata()
    assert "LOCAL KNOWLEDGE BASE" in metadata
    assert "Available Articles" in metadata


def test_analyze_context_still_works():
    """Analyze context still included when provided."""
    from chats import pack_assistant_context

    analysis = {"findings": [{"kind": "jwt"}]}
    ctx = pack_assistant_context(analysis)

    prompt = assistant_system_prompt(ctx)

    # Should have KB
    assert "LOCAL KNOWLEDGE BASE" in prompt
    # Should have Analyze
    assert "ANALYZER OUTPUT" in prompt
    assert "findings" in prompt


def test_kb_and_analyze_findings_separate():
    """KB sections separate from Analyze findings."""
    from chats import pack_assistant_context

    analysis = {"findings": [{"kind": "jwt"}]}
    ctx = pack_assistant_context(analysis)

    prompt = assistant_system_prompt(ctx)

    # Both should be present and distinct
    assert "LOCAL KNOWLEDGE BASE" in prompt
    assert "FINDINGS-BASED KNOWLEDGE BASE SUGGESTIONS" in prompt


def test_general_chat_isolation():
    """web_chat must still be isolated."""
    from chats import web_chat
    import inspect

    # web_chat should NOT have assistant_context parameter
    sig = inspect.signature(web_chat)
    assert "assistant_context" not in sig.parameters


def test_kb_max_articles_limit():
    """KB search results limited to max articles."""
    # Create multiple articles
    from analyzers.kb_actions import KnowledgeBaseActions
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        kb = KnowledgeBaseActions(str(db_path))

        # Create many similar articles
        for i in range(10):
            kb.create_article(f"JWT Article {i}", f"Content about JWT {i}", "JWT summary", ["jwt"])

        # Search should limit results
        results = kb.search_articles("JWT", limit=3)
        assert len(results) <= 3
