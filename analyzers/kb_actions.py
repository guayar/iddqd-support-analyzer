"""Knowledge Base actions/operations.

High-level functions for KB operations used by UI and Assistant.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from .kb_storage import KnowledgeBaseStorage
from .kb_search import KnowledgeBaseSearch
from .kb_models import Article, Case


class KnowledgeBaseActions:
    """High-level KB operations."""

    def __init__(self, db_path: str = "data/iddqd_kb.db"):
        """Initialize KB actions.

        Args:
            db_path: Path to SQLite database
        """
        self.storage = KnowledgeBaseStorage(db_path)
        self._search_engine = KnowledgeBaseSearch(self.storage)

    # ========================
    # ARTICLES
    # ========================

    def create_article(
        self,
        title: str,
        content: str,
        summary: Optional[str] = None,
        tags: Optional[List[str]] = None,
        finding_codes: Optional[List[str]] = None,
    ) -> str:
        """Create new Article.

        Returns: Article ID
        """
        return self.storage.create_article(
            title=title,
            content=content,
            summary=summary,
            tags=tags or [],
            finding_codes=finding_codes or [],
        )

    def get_article(self, article_id: str) -> Optional[Article]:
        """Get Article by ID."""
        return self.storage.get_article(article_id)

    def update_article(
        self,
        article_id: str,
        title: Optional[str] = None,
        content: Optional[str] = None,
        summary: Optional[str] = None,
        change_note: Optional[str] = None,
        author: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> bool:
        """Update Article."""
        return self.storage.update_article(
            article_id=article_id,
            title=title,
            content=content,
            summary=summary,
            change_note=change_note,
            created_by=author,
            tags=tags,
        )

    def delete_article(self, article_id: str) -> bool:
        """Delete Article."""
        return self.storage.delete_article(article_id)

    def list_articles(self) -> List[Article]:
        """List all active Articles."""
        return self.storage.list_articles()

    def get_article_by_display_id(self, display_id: str) -> Optional[Article]:
        """Get Article by display ID (e.g., AN00000001).

        Args:
            display_id: Display ID like AN00000001

        Returns:
            Article object or None if not found
        """
        return self.storage.get_article_by_display_id(display_id)

        return None

    # ========================
    # CASES
    # ========================

    def create_case(
        self,
        title: str,
        content: str,
        summary: Optional[str] = None,
        analyze_snapshot: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Create new Case.

        Args:
            title: Case title
            content: Case content (Markdown)
            summary: Optional summary
            analyze_snapshot: Optional Analyze findings snapshot
            tags: Optional tags

        Returns:
            Case ID
        """
        return self.storage.create_case(
            title=title,
            content=content,
            summary=summary,
            analyze_snapshot=analyze_snapshot,
            tags=tags or [],
        )

    def get_case(self, case_id: str) -> Optional[Case]:
        """Get Case by ID."""
        return self.storage.get_case(case_id)

    def update_case(
        self,
        case_id: str,
        title: Optional[str] = None,
        content: Optional[str] = None,
        summary: Optional[str] = None,
    ) -> bool:
        """Update Case."""
        return self.storage.update_case(
            case_id=case_id,
            title=title,
            content=content,
            summary=summary,
        )

    def delete_case(self, case_id: str) -> bool:
        """Delete Case."""
        return self.storage.delete_case(case_id)

    def list_cases(self) -> List[Case]:
        """List all Cases."""
        return self.storage.list_cases()

    def get_case_by_display_id(self, display_id: str) -> Optional[Case]:
        """Get Case by display ID (e.g., CN00000001).

        Args:
            display_id: Display ID like CN00000001

        Returns:
            Case object or None if not found
        """
        return self.storage.get_case_by_display_id(display_id)

    # ========================
    # SEARCH
    # ========================

    def search(self, query: str, limit: int = 20) -> Dict[str, Any]:
        """Search KB.

        Args:
            query: Search query
            limit: Max results per type

        Returns:
            Dict with 'articles' and 'cases' keys
        """
        articles, cases = self._search_engine.search(query, limit)
        return {
            "articles": articles,
            "cases": cases,
        }

    def search_by_tag(self, tag_name: str) -> Dict[str, Any]:
        """Search by tag.

        Args:
            tag_name: Tag name

        Returns:
            Dict with 'articles' and 'cases'
        """
        articles, cases = self._search_engine.search_by_tag(tag_name)
        return {
            "articles": articles,
            "cases": cases,
        }

    def search_by_finding(self, finding_code: str) -> List[Article]:
        """Find Articles linked to finding code.

        Args:
            finding_code: Finding code (e.g., JWT_KID_NOT_FOUND)

        Returns:
            List of Articles
        """
        return self._search_engine.search_by_finding(finding_code)

    # ========================
    # RELATIONSHIPS
    # ========================

    def link_case_to_article(self, case_id: str, article_id: str) -> bool:
        """Link Case to Article."""
        return self.storage.link_case_to_article(case_id, article_id)

    def unlink_case_from_article(self, case_id: str, article_id: str) -> bool:
        """Unlink Case from Article."""
        return self.storage.unlink_case_from_article(case_id, article_id)

    def link_articles(self, article_id: str, related_article_id: str) -> bool:
        """Link two Articles."""
        return self.storage.link_articles(article_id, related_article_id)

    def link_finding_to_article(self, finding_code: str, article_id: str) -> bool:
        """Link finding to Article."""
        return self.storage.link_finding_to_article(finding_code, article_id)

    def get_cases_for_article(self, article_id: str) -> List[Case]:
        """Get all Cases linked to an Article (reverse lookup).

        Args:
            article_id: Article canonical UUID

        Returns:
            List of Case objects
        """
        return self.storage.get_cases_for_article(article_id)

    def get_articles_for_case(self, case_id: str) -> List[Article]:
        """Get all Articles linked to a Case (forward lookup).

        Args:
            case_id: Case canonical UUID

        Returns:
            List of Article objects
        """
        return self.storage.get_articles_for_case(case_id)

    # ========================
    # REVISIONS
    # ========================

    def get_revisions(self, article_id: str) -> List:
        """Get revision history for Article."""
        revisions = self.storage.get_revisions(article_id)
        return [
            {
                "version": r.version,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "created_by": r.created_by,
                "change_note": r.change_note,
            }
            for r in revisions
        ]

    def restore_revision(self, article_id: str, version: int) -> bool:
        """Restore Article to specific revision."""
        return self.storage.restore_revision(article_id, version)

    # ========================
    # ANALYZE -> KB
    # ========================

    def create_case_from_analysis(
        self,
        findings: List[Dict[str, Any]],
        title: str = None,
        summary: str = None,
        content: str = None,
    ) -> str:
        """Create Case from Analyze findings.

        Args:
            findings: List of findings dict
            title: Optional case title
            summary: Optional summary
            content: Optional additional content

        Returns:
            Case ID
        """
        if not title:
            title = f"Case - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

        if not content:
            # Auto-generate case content
            lines = ["# Investigation\n"]
            if summary:
                lines.append(f"{summary}\n")

            lines.append("## Findings\n")
            for finding in findings:
                kind = finding.get("kind", "Unknown")
                category = finding.get("category", "unknown")
                level = finding.get("level", "INFO")
                signature = finding.get("signature", "No description")
                lines.append(f"- **{category}**: {kind} ({level})\n")
                lines.append(f"  {signature}\n")

            content = "".join(lines)

        return self.create_case(
            title=title,
            content=content,
            summary=summary,
            analyze_snapshot={"findings": findings},
        )

    # ========================
    # TAGS
    # ========================

    def get_all_tags(self) -> List[str]:
        """Get all tags."""
        return self.storage.get_all_tags()
