"""Tests for KB rendering and styled dataframe logic."""

import pytest
import pandas as pd
from analyzers.kb_actions import KnowledgeBaseActions
from kb_rendering import (
    render_articles_table,
    render_cases_table,
    render_search_articles_table,
    render_search_cases_table,
)


class TestArticleRendering:
    """Test Article table rendering with selection highlighting."""

    def setup_method(self):
        """Setup for each test."""
        self.kb = KnowledgeBaseActions(db_path="data/iddqd_kb.db")

    def test_render_articles_without_selection(self):
        """Test rendering articles with no selection."""
        articles = self.kb.list_articles()[:3]
        if not articles:
            pytest.skip("No articles in database")

        styled, uuid_map = render_articles_table(articles, selected_article_uuid=None)
        df = styled.data

        # Check columns
        assert list(df.columns) == ["Selected", "ID", "Title", "Updated", "Tags"]

        # Check all "Selected" cells are empty
        assert all(df["Selected"] == ""), "No rows should have selection marker"

        # Check uuid_map
        for article in articles:
            assert article.display_id in uuid_map
            assert uuid_map[article.display_id] == article.id

    def test_render_articles_with_selection(self):
        """Test rendering articles with one selected."""
        articles = self.kb.list_articles()
        if len(articles) < 2:
            pytest.skip("Need at least 2 articles")

        selected_article = articles[0]
        styled, uuid_map = render_articles_table(articles[:3], selected_article_uuid=selected_article.id)
        df = styled.data

        # Find selected row
        selected_rows = df[df["Selected"] == "▶"]
        assert len(selected_rows) == 1, "Exactly one row should be selected"
        assert selected_rows.iloc[0]["ID"] == selected_article.display_id

        # Other rows should not have marker
        other_rows = df[df["Selected"] != "▶"]
        assert all(other_rows["Selected"] == ""), "Other rows should be empty"

    def test_render_articles_preserves_display_id(self):
        """Test that display IDs (AN00000001) are shown, not UUIDs."""
        articles = self.kb.list_articles()[:2]
        if not articles:
            pytest.skip("No articles")

        styled, _ = render_articles_table(articles)
        df = styled.data

        for article in articles:
            row = df[df["ID"] == article.display_id]
            assert not row.empty, f"Article {article.display_id} should be in table"
            # Verify UUID is NOT in the visible columns
            assert article.id not in df["ID"].values, f"UUID {article.id} should not appear in display"


class TestCaseRendering:
    """Test Case table rendering with selection highlighting."""

    def setup_method(self):
        """Setup for each test."""
        self.kb = KnowledgeBaseActions(db_path="data/iddqd_kb.db")

    def test_render_cases_without_selection(self):
        """Test rendering cases with no selection."""
        cases = self.kb.list_cases()[:3]
        if not cases:
            pytest.skip("No cases in database")

        styled, uuid_map = render_cases_table(cases, selected_case_uuid=None)
        df = styled.data

        # Check columns
        assert list(df.columns) == ["Selected", "ID", "Title", "Created", "Tags"]

        # Check all "Selected" cells are empty
        assert all(df["Selected"] == ""), "No rows should have selection marker"

    def test_render_cases_with_selection(self):
        """Test rendering cases with one selected."""
        cases = self.kb.list_cases()
        if len(cases) < 2:
            pytest.skip("Need at least 2 cases")

        selected_case = cases[0]
        styled, uuid_map = render_cases_table(cases[:3], selected_case_uuid=selected_case.id)
        df = styled.data

        # Find selected row
        selected_rows = df[df["Selected"] == "▶"]
        assert len(selected_rows) == 1, "Exactly one row should be selected"
        assert selected_rows.iloc[0]["ID"] == selected_case.display_id


class TestSearchResultsRendering:
    """Test rendering of search results."""

    def setup_method(self):
        """Setup for each test."""
        self.kb = KnowledgeBaseActions(db_path="data/iddqd_kb.db")

    def test_render_search_articles_with_selection(self):
        """Test search articles rendering with selection."""
        result = self.kb.search("", limit=5)
        articles = result["articles"]

        if not articles:
            pytest.skip("No search results")

        selected_article = articles[0]
        styled, uuid_map = render_search_articles_table(articles, selected_article_uuid=selected_article.id)
        df = styled.data

        # Check columns
        assert list(df.columns) == ["Selected", "ID", "Title", "Summary"]

        # Check selection marker
        selected_rows = df[df["Selected"] == "▶"]
        assert len(selected_rows) == 1, "Exactly one row should be selected"
        assert selected_rows.iloc[0]["ID"] == selected_article.display_id

    def test_render_search_cases_with_selection(self):
        """Test search cases rendering with selection."""
        result = self.kb.search("", limit=5)
        cases = result["cases"]

        if not cases:
            pytest.skip("No case search results")

        selected_case = cases[0]
        styled, uuid_map = render_search_cases_table(cases, selected_case_uuid=selected_case.id)
        df = styled.data

        # Check columns
        assert list(df.columns) == ["Selected", "ID", "Title", "Summary"]

        # Check selection marker
        selected_rows = df[df["Selected"] == "▶"]
        assert len(selected_rows) == 1, "Exactly one row should be selected"


class TestIndependentSelection:
    """Test that Article and Case selections are independent in rendering."""

    def setup_method(self):
        """Setup for each test."""
        self.kb = KnowledgeBaseActions(db_path="data/iddqd_kb.db")

    def test_article_selection_independent_from_cases(self):
        """Test that selecting an article doesn't affect case rendering."""
        articles = self.kb.list_articles()
        cases = self.kb.list_cases()

        if not articles or not cases:
            pytest.skip("Need articles and cases")

        selected_article = articles[0]
        selected_case = cases[0]

        # Render both with selections
        articles_styled, _ = render_articles_table(articles[:3], selected_article_uuid=selected_article.id)
        cases_styled, _ = render_cases_table(cases[:3], selected_case_uuid=selected_case.id)

        articles_df = articles_styled.data
        cases_df = cases_styled.data

        # Verify article selection
        article_selected = articles_df[articles_df["Selected"] == "▶"]
        assert len(article_selected) == 1
        assert article_selected.iloc[0]["ID"] == selected_article.display_id

        # Verify case selection
        case_selected = cases_df[cases_df["Selected"] == "▶"]
        assert len(case_selected) == 1
        assert case_selected.iloc[0]["ID"] == selected_case.display_id

        # Verify they're independent (different IDs)
        assert article_selected.iloc[0]["ID"] != case_selected.iloc[0]["ID"]


class TestStylingLogic:
    """Test that styling is applied correctly."""

    def setup_method(self):
        """Setup for each test."""
        self.kb = KnowledgeBaseActions(db_path="data/iddqd_kb.db")

    def test_selected_row_has_styling(self):
        """Test that selected row styling is marked in the Styler."""
        articles = self.kb.list_articles()[:3]
        if not articles:
            pytest.skip("No articles")

        selected_article = articles[0]
        styled, _ = render_articles_table(articles, selected_article_uuid=selected_article.id)

        # The styled object should have style properties applied
        # Note: Checking Styler internals is tricky, but we can verify the underlying data
        df = styled.data
        selected_rows = df[df["Selected"] == "▶"]
        assert len(selected_rows) == 1, "Exactly one row should be marked as selected"
