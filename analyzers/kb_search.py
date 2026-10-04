"""Knowledge Base search engine using SQLite FTS5."""

import sqlite3
from typing import List, Tuple
from pathlib import Path

from .kb_models import Article, Case
from .kb_storage import KnowledgeBaseStorage


class KnowledgeBaseSearch:
    """Full-text search for KB Articles and Cases."""

    def __init__(self, storage: KnowledgeBaseStorage):
        """Initialize search engine.

        Args:
            storage: KnowledgeBaseStorage instance
        """
        self.storage = storage

    def search_articles(self, query: str, limit: int = 20) -> List[Article]:
        """Search Articles using case-insensitive substring matching.

        Args:
            query: Search query (partial text OK, case-insensitive)
            limit: Max results

        Returns:
            List of Articles matching query
        """
        return self._search_articles_simple(query, limit)

    def search_cases(self, query: str, limit: int = 20) -> List[Case]:
        """Search Cases using case-insensitive substring matching.

        Args:
            query: Search query (partial text OK, case-insensitive)
            limit: Max results

        Returns:
            List of Cases matching query
        """
        return self._search_cases_simple(query, limit)

    def search_by_tag(self, tag_name: str) -> Tuple[List[Article], List[Case]]:
        """Find Articles and Cases by tag.

        Args:
            tag_name: Tag name

        Returns:
            Tuple of (articles, cases)
        """
        articles = []
        cases = []

        db_path = self.storage.db_path

        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Find tag
            cursor.execute("SELECT id FROM kb_tags WHERE name = ?", (tag_name,))
            tag_row = cursor.fetchone()
            if not tag_row:
                return [], []

            tag_id = tag_row[0]

            # Find articles
            cursor.execute(
                """
                SELECT article_id FROM kb_article_tags
                WHERE tag_id = ?
                """,
                (tag_id,),
            )
            for row in cursor.fetchall():
                article = self.storage.get_article(row[0])
                if article:
                    articles.append(article)

            # Find cases
            cursor.execute(
                """
                SELECT case_id FROM kb_case_tags
                WHERE tag_id = ?
                """,
                (tag_id,),
            )
            for row in cursor.fetchall():
                case = self.storage.get_case(row[0])
                if case:
                    cases.append(case)

        return articles, cases

    def search_by_finding(self, finding_code: str) -> List[Article]:
        """Find Articles linked to finding code.

        Args:
            finding_code: Finding code (e.g., JWT_KID_NOT_FOUND)

        Returns:
            List of linked Articles
        """
        return self.storage.find_articles_for_finding(finding_code)

    def _search_articles_simple(self, query: str, limit: int = 20) -> List[Article]:
        """Fallback: simple substring search in Articles (title, summary, content, tags)."""
        query_lower = query.lower()
        all_articles = self.storage.list_articles()

        results = []
        for article in all_articles:
            if (
                query_lower in article.title.lower()
                or query_lower in (article.summary or "").lower()
                or query_lower in article.content.lower()
                or any(query_lower in tag.lower() for tag in (article.tags or []))
            ):
                results.append(article)
                if len(results) >= limit:
                    break

        return results

    def _search_cases_simple(self, query: str, limit: int = 20) -> List[Case]:
        """Fallback: simple substring search in Cases (title, summary, content, tags)."""
        query_lower = query.lower()
        all_cases = self.storage.list_cases()

        results = []
        for case in all_cases:
            if (
                query_lower in case.title.lower()
                or query_lower in (case.summary or "").lower()
                or query_lower in case.content.lower()
                or any(query_lower in tag.lower() for tag in (case.tags or []))
            ):
                results.append(case)
                if len(results) >= limit:
                    break

        return results

    def search(self, query: str, limit: int = 20) -> Tuple[List[Article], List[Case]]:
        """Search both Articles and Cases.

        Args:
            query: Search query
            limit: Max results per type

        Returns:
            Tuple of (articles, cases)
        """
        articles = self.search_articles(query, limit)
        cases = self.search_cases(query, limit)
        return articles, cases
