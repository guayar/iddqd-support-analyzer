"""Tests for exact KB article ID search.

Verify that AN######## display IDs can be searched exactly and case-insensitively.
"""

import pytest
import tempfile
from pathlib import Path
from analyzers.kb_actions import KnowledgeBaseActions


@pytest.fixture
def temp_kb():
    """Create temp KB with test articles."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        kb = KnowledgeBaseActions(str(db_path))

        # Create test articles
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

        cert_id = kb.create_article(
            "Certificate Validation",
            "Handling certificate validation failures",
            "Certificate errors and how to resolve them",
            ["certificate", "ssl"]
        )

        yield kb, [jwt_id, saml_id, cert_id]


def test_exact_display_id_search(temp_kb):
    """Test exact display ID search."""
    kb, article_ids = temp_kb

    jwt_article = kb.get_article(article_ids[0])
    an_id = jwt_article.display_id  # e.g., "AN00000001"

    # Search by exact ID
    results = kb.search_articles(an_id)
    assert len(results) == 1
    assert results[0].id == article_ids[0]
    assert results[0].display_id == an_id


def test_exact_display_id_case_insensitive(temp_kb):
    """Test that exact ID search is case-insensitive."""
    kb, article_ids = temp_kb

    jwt_article = kb.get_article(article_ids[0])
    an_id = jwt_article.display_id

    # Test lowercase
    results_lower = kb.search_articles(an_id.lower())
    assert len(results_lower) == 1
    assert results_lower[0].id == article_ids[0]

    # Test uppercase
    results_upper = kb.search_articles(an_id.upper())
    assert len(results_upper) == 1
    assert results_upper[0].id == article_ids[0]

    # Test mixed case
    mixed = "An" + an_id[2:]
    results_mixed = kb.search_articles(mixed)
    assert len(results_mixed) == 1
    assert results_mixed[0].id == article_ids[0]


def test_unknown_display_id_returns_empty(temp_kb):
    """Test that unknown AN ID returns no result."""
    kb, _ = temp_kb

    # Try non-existent ID
    results = kb.search_articles("AN99999999")
    assert results == []


def test_text_search_still_works(temp_kb):
    """Test that normal text search still works."""
    kb, article_ids = temp_kb

    # Search by title keyword
    jwt_results = kb.search_articles("JWT")
    assert len(jwt_results) >= 1
    assert any(a.id == article_ids[0] for a in jwt_results)

    # Search by tag
    saml_results = kb.search_articles("saml")
    assert len(saml_results) >= 1
    assert any(a.id == article_ids[1] for a in saml_results)

    # Search by content keyword
    cert_results = kb.search_articles("certificate")
    assert len(cert_results) >= 1
    assert any(a.id == article_ids[2] for a in cert_results)


def test_empty_query_returns_empty(temp_kb):
    """Test that empty query returns nothing."""
    kb, _ = temp_kb

    assert kb.search_articles("") == []
    assert kb.search_articles("   ") == []
    assert kb.search_articles(None) == []


def test_limit_respected(temp_kb):
    """Test that result limit is respected."""
    kb, article_ids = temp_kb

    # Create many articles with similar content
    for i in range(10):
        kb.create_article(f"Test {i}", f"Test content {i}", "test summary", ["test"])

    # Search with low limit
    results = kb.search_articles("test", limit=3)
    assert len(results) <= 3


def test_exact_id_takes_precedence(temp_kb):
    """Test that exact AN ID match takes precedence."""
    kb, article_ids = temp_kb

    jwt_article = kb.get_article(article_ids[0])
    an_id = jwt_article.display_id

    # Search for the exact ID
    results = kb.search_articles(an_id)

    # Should return exactly that article, not text search results
    assert len(results) == 1
    assert results[0].id == article_ids[0]
