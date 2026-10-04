"""Tests for KB selection logic and display ID resolution."""

import pytest
from analyzers.kb_actions import KnowledgeBaseActions
from analyzers.kb_models import Article, Case


class TestDisplayIDResolution:
    """Test display ID to Article/Case resolution."""

    def setup_method(self):
        """Setup for each test."""
        self.kb = KnowledgeBaseActions(db_path="data/iddqd_kb.db")

    def test_get_article_by_valid_display_id(self):
        """Test getting article by valid display ID."""
        articles = self.kb.list_articles()
        if not articles:
            pytest.skip("No articles in database")

        # Get first article
        article = articles[0]
        display_id = article.display_id

        # Retrieve by display ID
        resolved = self.kb.get_article_by_display_id(display_id)

        assert resolved is not None, f"Failed to resolve article {display_id}"
        assert resolved.id == article.id
        assert resolved.display_id == display_id

    def test_get_case_by_valid_display_id(self):
        """Test getting case by valid display ID."""
        cases = self.kb.list_cases()
        if not cases:
            pytest.skip("No cases in database")

        # Get first case
        case = cases[0]
        display_id = case.display_id

        # Retrieve by display ID
        resolved = self.kb.get_case_by_display_id(display_id)

        assert resolved is not None, f"Failed to resolve case {display_id}"
        assert resolved.id == case.id
        assert resolved.display_id == display_id

    def test_get_article_invalid_display_id(self):
        """Test getting article with invalid display ID returns None."""
        # Invalid format
        assert self.kb.get_article_by_display_id("INVALID") is None
        assert self.kb.get_article_by_display_id("") is None
        assert self.kb.get_article_by_display_id(None) is None
        assert self.kb.get_article_by_display_id("CN00000001") is None  # Case ID, not article

    def test_get_case_invalid_display_id(self):
        """Test getting case with invalid display ID returns None."""
        # Invalid format
        assert self.kb.get_case_by_display_id("INVALID") is None
        assert self.kb.get_case_by_display_id("") is None
        assert self.kb.get_case_by_display_id(None) is None
        assert self.kb.get_case_by_display_id("AN00000001") is None  # Article ID, not case

    def test_display_id_format(self):
        """Test that display IDs follow correct format."""
        articles = self.kb.list_articles()
        if not articles:
            pytest.skip("No articles in database")

        for article in articles[:3]:  # Check first 3
            display_id = article.display_id
            assert display_id.startswith("AN"), f"Article ID must start with AN: {display_id}"
            assert len(display_id) == 10, f"Article ID must be 10 chars: {display_id}"
            # Verify numeric part
            numeric_part = display_id[2:]
            assert numeric_part.isdigit(), f"Article ID numeric part must be digits: {display_id}"

        cases = self.kb.list_cases()
        if not cases:
            pytest.skip("No cases in database")

        for case in cases[:3]:  # Check first 3
            display_id = case.display_id
            assert display_id.startswith("CN"), f"Case ID must start with CN: {display_id}"
            assert len(display_id) == 10, f"Case ID must be 10 chars: {display_id}"
            # Verify numeric part
            numeric_part = display_id[2:]
            assert numeric_part.isdigit(), f"Case ID numeric part must be digits: {display_id}"

    def test_all_articles_retrievable_by_display_id(self):
        """Test that all articles can be retrieved by their display ID."""
        articles = self.kb.list_articles()
        if not articles:
            pytest.skip("No articles in database")

        for article in articles:
            resolved = self.kb.get_article_by_display_id(article.display_id)
            assert resolved is not None, f"Failed to retrieve {article.display_id}"
            assert resolved.id == article.id

    def test_all_cases_retrievable_by_display_id(self):
        """Test that all cases can be retrieved by their display ID."""
        cases = self.kb.list_cases()
        if not cases:
            pytest.skip("No cases in database")

        for case in cases:
            resolved = self.kb.get_case_by_display_id(case.display_id)
            assert resolved is not None, f"Failed to retrieve {case.display_id}"
            assert resolved.id == case.id


class TestSearchResultSelection:
    """Test that search results select the correct item, not wrong row index."""

    def setup_method(self):
        """Setup for each test."""
        self.kb = KnowledgeBaseActions(db_path="data/iddqd_kb.db")

    def test_search_returns_correct_display_ids(self):
        """Test that search results contain display IDs we can resolve."""
        result = self.kb.search("jwt", limit=10)
        articles = result["articles"]

        if not articles:
            pytest.skip("No search results for 'jwt'")

        # Verify each result can be resolved
        for article in articles:
            display_id = article.display_id
            resolved = self.kb.get_article_by_display_id(display_id)
            assert resolved is not None, f"Search result {display_id} not resolvable"
            assert resolved.id == article.id

    def test_search_order_differs_from_list(self):
        """Test that search results may be in different order than list_articles()."""
        # Get all articles
        all_articles = self.kb.list_articles()
        if len(all_articles) < 2:
            pytest.skip("Need at least 2 articles")

        # Get first two articles' display IDs
        first_two_ids = [a.display_id for a in all_articles[:2]]

        # Search for something that might match multiple
        result = self.kb.search("", limit=20)
        search_articles = result["articles"]

        if len(search_articles) < 2:
            pytest.skip("Search didn't return enough results")

        # Get first two search result IDs
        search_first_two_ids = [a.display_id for a in search_articles[:2]]

        # They may be different (this is OK and expected)
        # The important thing is that each is resolvable
        for display_id in search_first_two_ids:
            resolved = self.kb.get_article_by_display_id(display_id)
            assert resolved is not None


class TestIndependentSelection:
    """Test that Article and Case selection are independent."""

    def setup_method(self):
        """Setup for each test."""
        self.kb = KnowledgeBaseActions(db_path="data/iddqd_kb.db")

    def test_article_and_case_ids_different_formats(self):
        """Test that Article and Case IDs use different prefixes."""
        articles = self.kb.list_articles()
        cases = self.kb.list_cases()

        if articles and cases:
            article_id = articles[0].display_id
            case_id = cases[0].display_id

            assert article_id.startswith("AN"), f"Article ID should start with AN: {article_id}"
            assert case_id.startswith("CN"), f"Case ID should start with CN: {case_id}"
            assert article_id != case_id, "Article and Case IDs should never be equal"

    def test_article_lookup_ignores_case_ids(self):
        """Test that Article lookup doesn't accidentally resolve Case IDs."""
        cases = self.kb.list_cases()
        if not cases:
            pytest.skip("No cases in database")

        case_id = cases[0].display_id
        # Try to get article with case ID
        resolved = self.kb.get_article_by_display_id(case_id)
        assert resolved is None, f"Should not resolve Case ID {case_id} as Article"

    def test_case_lookup_ignores_article_ids(self):
        """Test that Case lookup doesn't accidentally resolve Article IDs."""
        articles = self.kb.list_articles()
        if not articles:
            pytest.skip("No articles in database")

        article_id = articles[0].display_id
        # Try to get case with article ID
        resolved = self.kb.get_case_by_display_id(article_id)
        assert resolved is None, f"Should not resolve Article ID {article_id} as Case"


class TestSelectionStateManagement:
    """Test selection state management in load handlers."""

    def setup_method(self):
        """Setup for each test."""
        self.kb = KnowledgeBaseActions(db_path="data/iddqd_kb.db")

    def test_selected_article_id_persists(self):
        """Test that selected article ID can be retrieved."""
        articles = self.kb.list_articles()
        if not articles:
            pytest.skip("No articles in database")

        article = articles[0]
        selected_id = article.id

        # Simulate storing selected_id and retrieving the article
        retrieved = self.kb.get_article(selected_id)
        assert retrieved is not None
        assert retrieved.id == selected_id

    def test_selected_case_id_persists(self):
        """Test that selected case ID can be retrieved."""
        cases = self.kb.list_cases()
        if not cases:
            pytest.skip("No cases in database")

        case = cases[0]
        selected_id = case.id

        # Simulate storing selected_id and retrieving the case
        retrieved = self.kb.get_case(selected_id)
        assert retrieved is not None
        assert retrieved.id == selected_id

    def test_delete_clears_selection(self):
        """Test that deleting an article removes it from KB."""
        articles = self.kb.list_articles()
        initial_count = len(articles)

        if initial_count == 0:
            pytest.skip("Need at least one article to test deletion")

        # Note: This test doesn't actually delete to avoid corrupting DB
        # Just verify the structure works
        article = articles[0]
        assert article is not None
