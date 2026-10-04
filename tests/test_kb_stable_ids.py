"""Tests for stable KB article display ID allocation.

Verify that display IDs never reset after deletion/restart.
"""

import pytest
import tempfile
from pathlib import Path
from analyzers.kb_storage import KnowledgeBaseStorage
from analyzers.kb_actions import KnowledgeBaseActions


@pytest.fixture
def temp_db():
    """Create temp DB for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        yield str(db_path)


def test_stable_id_after_deletion(temp_db):
    """Test that IDs don't reset after deletion."""
    kb = KnowledgeBaseActions(temp_db)

    # Create 3 articles
    a1_id = kb.create_article("Article 1", "Content 1", "Summary 1", [])
    a2_id = kb.create_article("Article 2", "Content 2", "Summary 2", [])
    a3_id = kb.create_article("Article 3", "Content 3", "Summary 3", [])

    a1 = kb.get_article(a1_id)
    a2 = kb.get_article(a2_id)
    a3 = kb.get_article(a3_id)

    assert a1.display_id == "AN00000001"
    assert a2.display_id == "AN00000002"
    assert a3.display_id == "AN00000003"

    # Delete A2
    kb.delete_article(a2_id)

    # Create new - should be AN00000004, not AN00000003
    a4_id = kb.create_article("Article 4", "Content 4", "Summary 4", [])
    a4 = kb.get_article(a4_id)
    assert a4.display_id == "AN00000004"

    # Verify A2 is gone
    assert kb.get_article(a2_id) is None

    # Verify others intact
    assert kb.get_article(a1_id).display_id == "AN00000001"
    assert kb.get_article(a3_id).display_id == "AN00000003"
    assert kb.get_article(a4_id).display_id == "AN00000004"


def test_stable_id_after_restart(temp_db):
    """Test that IDs persist correctly after storage restart."""
    # First session
    kb1 = KnowledgeBaseActions(temp_db)
    a1_id = kb1.create_article("Article 1", "Content 1", "Summary 1", [])
    a2_id = kb1.create_article("Article 2", "Content 2", "Summary 2", [])
    a3_id = kb1.create_article("Article 3", "Content 3", "Summary 3", [])

    a1 = kb1.get_article(a1_id)
    a2 = kb1.get_article(a2_id)
    a3 = kb1.get_article(a3_id)

    assert a1.display_id == "AN00000001"
    assert a2.display_id == "AN00000002"
    assert a3.display_id == "AN00000003"

    # Delete A2
    kb1.delete_article(a2_id)

    # New session - storage reinitializes
    kb2 = KnowledgeBaseActions(temp_db)

    # Create new article - should be AN00000004
    a4_id = kb2.create_article("Article 4", "Content 4", "Summary 4", [])
    a4 = kb2.get_article(a4_id)
    assert a4.display_id == "AN00000004"

    # Verify existing still intact
    retrieved_a1 = kb2.get_article(a1_id)
    retrieved_a3 = kb2.get_article(a3_id)

    assert retrieved_a1.display_id == "AN00000001"
    assert retrieved_a3.display_id == "AN00000003"


def test_gaps_preserved(temp_db):
    """Test that gaps are not filled."""
    kb = KnowledgeBaseActions(temp_db)

    # Create 4 articles
    article_ids = [
        kb.create_article(f"Article {i+1}", f"Content {i+1}", f"Summary {i+1}", [])
        for i in range(4)
    ]

    articles = [kb.get_article(aid) for aid in article_ids]

    assert [a.display_id for a in articles] == [
        "AN00000001", "AN00000002", "AN00000003", "AN00000004"
    ]

    # Delete A2 and A3
    kb.delete_article(article_ids[1])
    kb.delete_article(article_ids[2])

    # Create new - should be AN00000005, skip gap
    a5_id = kb.create_article("Article 5", "Content 5", "Summary 5", [])
    a5 = kb.get_article(a5_id)
    assert a5.display_id == "AN00000005"


def test_no_duplicate_after_restart(temp_db):
    """Test that sequence counter never causes duplicates."""
    kb1 = KnowledgeBaseActions(temp_db)

    # Create several articles and delete middle one
    article_ids = []
    for i in range(5):
        aid = kb1.create_article(f"Article {i+1}", f"Content {i+1}", f"Summary {i+1}", [])
        article_ids.append(aid)

    # Delete several
    kb1.delete_article(article_ids[1])
    kb1.delete_article(article_ids[2])

    # Restart and create more
    kb2 = KnowledgeBaseActions(temp_db)

    # Should be AN00000006, not trying to reuse
    a6_id = kb2.create_article("Article 6", "Content 6", "Summary 6", [])
    a6 = kb2.get_article(a6_id)
    assert a6.display_id == "AN00000006"

    # Try to create another
    a7_id = kb2.create_article("Article 7", "Content 7", "Summary 7", [])
    a7 = kb2.get_article(a7_id)
    assert a7.display_id == "AN00000007"

    # Verify unique constraint
    with kb2.storage._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(DISTINCT display_id_seq) FROM kb_articles WHERE display_id_seq IS NOT NULL")
        unique_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM kb_articles WHERE display_id_seq IS NOT NULL")
        total_count = cursor.fetchone()[0]

    assert unique_count == total_count, "Display IDs not unique!"
