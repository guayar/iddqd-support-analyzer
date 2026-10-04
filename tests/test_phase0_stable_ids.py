"""
PHASE 0 Tests: Stable Friendly IDs

Verifies that friendly IDs (AN00000001, CN00000001) are immutable
and not renumbered when records are deleted.
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime

from analyzers.kb_storage import KnowledgeBaseStorage
from analyzers.kb_actions import KnowledgeBaseActions


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        yield str(db_path)


class TestStableArticleIds:
    """Test stable friendly IDs for Articles."""

    def test_create_article_gets_stable_display_id(self, temp_db):
        """Verify created article gets stable display_id_seq."""
        kb = KnowledgeBaseActions(temp_db)

        # Create first article
        article_id_1 = kb.create_article("Article 1", "Content 1")
        article_1 = kb.get_article(article_id_1)

        assert article_1 is not None
        assert article_1.display_id_seq == 1
        assert article_1.display_id == "AN00000001"

    def test_create_multiple_articles_sequential_ids(self, temp_db):
        """Verify multiple articles get sequential IDs."""
        kb = KnowledgeBaseActions(temp_db)

        article_ids = []
        for i in range(1, 4):
            article_id = kb.create_article(f"Article {i}", f"Content {i}")
            article_ids.append(article_id)

        for i, article_id in enumerate(article_ids, start=1):
            article = kb.get_article(article_id)
            assert article.display_id_seq == i
            assert article.display_id == f"AN{i:08d}"

    def test_delete_article_preserves_other_ids(self, temp_db):
        """Verify deleting an article doesn't renumber others."""
        kb = KnowledgeBaseActions(temp_db)

        # Create 3 articles
        article_ids = [
            kb.create_article(f"Article {i}", f"Content {i}") for i in range(1, 4)
        ]

        # Store original IDs
        original_ids = {
            article_ids[0]: "AN00000001",
            article_ids[1]: "AN00000002",
            article_ids[2]: "AN00000003",
        }

        # Delete the second article
        kb.delete_article(article_ids[1])

        # Verify remaining articles keep their IDs
        article_1 = kb.get_article(article_ids[0])
        article_3 = kb.get_article(article_ids[2])

        assert article_1.display_id == "AN00000001"
        assert article_3.display_id == "AN00000003"  # Gap remains!

        # Verify deleted article is gone
        assert kb.get_article(article_ids[1]) is None

    def test_get_article_by_display_id_works(self, temp_db):
        """Verify get_article_by_display_id resolves correctly."""
        kb = KnowledgeBaseActions(temp_db)

        article_id = kb.create_article("Test Article", "Test Content")
        article = kb.get_article(article_id)

        # Lookup by display ID
        found = kb.get_article_by_display_id("AN00000001")

        assert found is not None
        assert found.id == article.id
        assert found.display_id == "AN00000001"

    def test_get_article_by_display_id_invalid_format(self, temp_db):
        """Verify invalid display IDs return None."""
        kb = KnowledgeBaseActions(temp_db)

        assert kb.get_article_by_display_id("CN00000001") is None  # Wrong prefix
        assert kb.get_article_by_display_id("AN00000999") is None  # Doesn't exist
        assert kb.get_article_by_display_id("") is None  # Empty
        assert kb.get_article_by_display_id("invalid") is None  # Invalid format


class TestStableCaseIds:
    """Test stable friendly IDs for Cases."""

    def test_create_case_gets_stable_display_id(self, temp_db):
        """Verify created case gets stable display_id_seq."""
        kb = KnowledgeBaseActions(temp_db)

        # Create first case
        case_id_1 = kb.create_case("Case 1", "Content 1")
        case_1 = kb.get_case(case_id_1)

        assert case_1 is not None
        assert case_1.display_id_seq == 1
        assert case_1.display_id == "CN00000001"

    def test_create_multiple_cases_sequential_ids(self, temp_db):
        """Verify multiple cases get sequential IDs."""
        kb = KnowledgeBaseActions(temp_db)

        case_ids = []
        for i in range(1, 4):
            case_id = kb.create_case(f"Case {i}", f"Content {i}")
            case_ids.append(case_id)

        for i, case_id in enumerate(case_ids, start=1):
            case = kb.get_case(case_id)
            assert case.display_id_seq == i
            assert case.display_id == f"CN{i:08d}"

    def test_delete_case_preserves_other_ids(self, temp_db):
        """Verify deleting a case doesn't renumber others."""
        kb = KnowledgeBaseActions(temp_db)

        # Create 3 cases
        case_ids = [
            kb.create_case(f"Case {i}", f"Content {i}") for i in range(1, 4)
        ]

        # Delete the second case
        kb.delete_case(case_ids[1])

        # Verify remaining cases keep their IDs
        case_1 = kb.get_case(case_ids[0])
        case_3 = kb.get_case(case_ids[2])

        assert case_1.display_id == "CN00000001"
        assert case_3.display_id == "CN00000003"  # Gap remains!

        # Verify deleted case is gone
        assert kb.get_case(case_ids[1]) is None

    def test_get_case_by_display_id_works(self, temp_db):
        """Verify get_case_by_display_id resolves correctly."""
        kb = KnowledgeBaseActions(temp_db)

        case_id = kb.create_case("Test Case", "Test Content")
        case = kb.get_case(case_id)

        # Lookup by display ID
        found = kb.get_case_by_display_id("CN00000001")

        assert found is not None
        assert found.id == case.id
        assert found.display_id == "CN00000001"

    def test_get_case_by_display_id_invalid_format(self, temp_db):
        """Verify invalid display IDs return None."""
        kb = KnowledgeBaseActions(temp_db)

        assert kb.get_case_by_display_id("AN00000001") is None  # Wrong prefix
        assert kb.get_case_by_display_id("CN00000999") is None  # Doesn't exist
        assert kb.get_case_by_display_id("") is None  # Empty
        assert kb.get_case_by_display_id("invalid") is None  # Invalid format


class TestMixedArticlesCases:
    """Test Articles and Cases with independent numbering."""

    def test_articles_and_cases_independent_numbering(self, temp_db):
        """Verify Articles and Cases have separate numbering."""
        kb = KnowledgeBaseActions(temp_db)

        # Create interleaved
        article_1_id = kb.create_article("Article 1", "Content")
        case_1_id = kb.create_case("Case 1", "Content")
        article_2_id = kb.create_article("Article 2", "Content")
        case_2_id = kb.create_case("Case 2", "Content")

        article_1 = kb.get_article(article_1_id)
        case_1 = kb.get_case(case_1_id)
        article_2 = kb.get_article(article_2_id)
        case_2 = kb.get_case(case_2_id)

        # Verify independent numbering
        assert article_1.display_id == "AN00000001"
        assert article_2.display_id == "AN00000002"
        assert case_1.display_id == "CN00000001"
        assert case_2.display_id == "CN00000002"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
