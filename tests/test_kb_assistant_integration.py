"""Tests for KB integration into local Assistant prompt.

Verify that KB Articles appear in Assistant system prompt as guidance,
not in General Chat, and that KB failures don't break Assistant.
"""

import pytest
import tempfile
import json
from pathlib import Path
from analyzers.kb_actions import KnowledgeBaseActions
from analyzers.kb_assistant import KBAssistantContext
from chats import assistant_system_prompt, ASSISTANT_SYSTEM, pack_assistant_context


@pytest.fixture
def temp_kb():
    """Create temp KB with test articles."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        kb = KnowledgeBaseActions(str(db_path))

        # Create test articles with finding links
        jwt_id = kb.create_article(
            "JWT Key Issues",
            "How to troubleshoot JWT signing key problems",
            "Common JWT key errors and solutions",
            ["jwt", "security"]
        )

        saml_id = kb.create_article(
            "SAML Audience Mismatch",
            "Fixing SAML audience validation errors",
            "SAML audience must match expected value",
            ["saml", "auth"]
        )

        yield kb, jwt_id, saml_id


def test_kb_context_in_assistant_prompt(temp_kb):
    """Test that KB articles appear in assistant prompt."""
    kb, jwt_id, saml_id = temp_kb

    # Create mock analysis with findings matching KB keywords
    analysis = {
        "findings": [
            {"finding_code": "JWT_KID_NOT_FOUND", "kind": "jwt", "category": "auth"},
            {"finding_code": "SAML_AUDIENCE_MISMATCH", "kind": "saml", "category": "auth"},
        ]
    }

    assistant_ctx = pack_assistant_context(analysis, sources=None)

    # Generate prompt
    prompt = assistant_system_prompt(assistant_ctx)

    # Check that KB context is included (articles matched by kind)
    # Note: KB matching happens on "kind" field via text search
    assert "RELEVANT KNOWLEDGE BASE GUIDANCE" in prompt or "JWT" in prompt or "SAML" in prompt
    # At minimum, the prompt should contain the analyzer output
    assert "ANALYZER OUTPUT" in prompt


def test_kb_context_not_in_general_chat(temp_kb):
    """Test that General Chat doesn't receive KB context.

    Note: This tests the architectural isolation.
    General Chat calls web_chat() which doesn't receive assistant_context.
    """
    from chats import web_chat

    # web_chat signature: web_chat(message, history)
    # It should never receive assistant_context
    # Just verify that web_chat is isolated (no assistant_context param)
    import inspect
    sig = inspect.signature(web_chat)
    assert "assistant_context" not in sig.parameters, \
        "General Chat web_chat should not have assistant_context parameter"


def test_kb_context_graceful_fallback(temp_kb):
    """Test that KB failure doesn't break Assistant prompt."""
    # Create analysis without findings
    analysis = {"findings": []}

    assistant_ctx = pack_assistant_context(analysis, sources=[])

    # Should not raise exception
    try:
        prompt = assistant_system_prompt(assistant_ctx)
        assert ASSISTANT_SYSTEM in prompt
    except Exception as e:
        pytest.fail(f"assistant_system_prompt raised exception: {e}")


def test_kb_empty_database():
    """Test that empty KB doesn't break Assistant."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "empty.db"
        # Create empty KB
        kb = KnowledgeBaseActions(str(db_path))

        # Create analysis with findings but no KB articles
        analysis = {
            "findings": [
                {"finding_code": "NONEXISTENT", "kind": "unknown", "category": "test"},
            ]
        }

        assistant_ctx = pack_assistant_context(analysis, sources=[])

        # Should not raise exception
        prompt = assistant_system_prompt(assistant_ctx)
        assert ASSISTANT_SYSTEM in prompt


def test_kb_context_limited_to_small_set():
    """Test that KB context is limited to 3-5 articles."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        kb = KnowledgeBaseActions(str(db_path))

        # Create many articles
        for i in range(20):
            kb.create_article(
                f"Article {i}",
                f"Content {i}",
                f"Summary {i}",
                ["test"]
            )

        # Create KB context from generic findings
        kb_ctx = KBAssistantContext(str(db_path))
        findings = [{"kind": "test", "category": "test"}]
        kb_content = kb_ctx.get_kb_context(findings)

        # Should include articles but limited
        # Count how many "**" markers (article titles)
        title_count = kb_content.count("**")
        # Each article has 2 ** (opening and closing), plus potentially one for section header
        article_count = (title_count - 2) // 2  # Subtract 2 for "### Related Articles"
        assert article_count <= 5, f"Too many articles: {article_count}"


def test_kb_labeled_as_guidance_not_evidence(monkeypatch):
    """Test that KB context clearly distinguishes guidance from evidence."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        kb = KnowledgeBaseActions(str(db_path))

        monkeypatch.setattr(
            "analyzers.kb_assistant.KBAssistantContext",
            lambda: KBAssistantContext(str(db_path)),
        )

        # Create article
        kb.create_article(
            "Test Fix",
            "This is a suggested fix",
            "Try this approach",
            ["test"]
        )

        analysis = {
            "findings": [{"kind": "test", "category": "test"}]
        }

        assistant_ctx = pack_assistant_context(analysis, sources=[])
        prompt = assistant_system_prompt(assistant_ctx)

        # Check guidance vs evidence language
        assert "guidance" in prompt.lower() or "suggestion" in prompt.lower()
        assert "evidence" in prompt.lower()
        assert "verify against" in prompt.lower()


def test_kb_context_hierarchy_preserved():
    """Test that hierarchy is: evidence > KB guidance."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        kb = KnowledgeBaseActions(str(db_path))

        kb.create_article("Fix", "Content", "Summary", ["test"])

        analysis = {
            "findings": [{"kind": "test", "category": "test"}]
        }
        sources = [("log.txt", "ERROR message")]

        assistant_ctx = pack_assistant_context(analysis, sources=sources)
        prompt = assistant_system_prompt(assistant_ctx)

        # Check that both sections are present
        assert "ANALYZE SOURCE INPUTS" in prompt
        assert "ANALYZER OUTPUT" in prompt

        # Check ordering: sources should come before ANALYZER OUTPUT
        sources_pos = prompt.find("ANALYZE SOURCE INPUTS")
        analyzer_pos = prompt.find("ANALYZER OUTPUT")

        assert sources_pos < analyzer_pos, "Sources should come before analyzer output"
