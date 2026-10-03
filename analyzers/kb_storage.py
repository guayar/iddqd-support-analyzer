"""Knowledge Base SQLite storage layer.

Handles all database operations for Articles, Cases, Tags, and relationships.
"""

import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from .kb_models import Article, Case, Tag, FindingLink, Revision


class KnowledgeBaseStorage:
    """SQLite-based Knowledge Base storage."""

    SCHEMA_VERSION = "1.0"

    def __init__(self, db_path: str = "data/iddqd_kb.db"):
        """Initialize KB storage.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize schema
        self._init_schema()

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if schema exists
            cursor.execute(
                "SELECT value FROM kb_metadata WHERE key = 'schema_version'"
            )
            if cursor.fetchone():
                return  # Already initialized

            # Create tables
            cursor.executescript("""
                -- Metadata
                CREATE TABLE kb_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                -- Articles
                CREATE TABLE kb_articles (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    summary TEXT,
                    content TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Cases
                CREATE TABLE kb_cases (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    summary TEXT,
                    content TEXT NOT NULL,
                    analyze_snapshot TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Tags
                CREATE TABLE kb_tags (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL
                );

                -- Article tags
                CREATE TABLE kb_article_tags (
                    article_id TEXT NOT NULL,
                    tag_id TEXT NOT NULL,
                    PRIMARY KEY (article_id, tag_id),
                    FOREIGN KEY (article_id) REFERENCES kb_articles(id) ON DELETE CASCADE,
                    FOREIGN KEY (tag_id) REFERENCES kb_tags(id) ON DELETE CASCADE
                );

                -- Case tags
                CREATE TABLE kb_case_tags (
                    case_id TEXT NOT NULL,
                    tag_id TEXT NOT NULL,
                    PRIMARY KEY (case_id, tag_id),
                    FOREIGN KEY (case_id) REFERENCES kb_cases(id) ON DELETE CASCADE,
                    FOREIGN KEY (tag_id) REFERENCES kb_tags(id) ON DELETE CASCADE
                );

                -- Article relationships
                CREATE TABLE kb_article_relations (
                    article_id TEXT NOT NULL,
                    related_article_id TEXT NOT NULL,
                    PRIMARY KEY (article_id, related_article_id),
                    FOREIGN KEY (article_id) REFERENCES kb_articles(id) ON DELETE CASCADE,
                    FOREIGN KEY (related_article_id) REFERENCES kb_articles(id) ON DELETE CASCADE
                );

                -- Case -> Article relationships
                CREATE TABLE kb_case_articles (
                    case_id TEXT NOT NULL,
                    article_id TEXT NOT NULL,
                    PRIMARY KEY (case_id, article_id),
                    FOREIGN KEY (case_id) REFERENCES kb_cases(id) ON DELETE CASCADE,
                    FOREIGN KEY (article_id) REFERENCES kb_articles(id) ON DELETE CASCADE
                );

                -- Finding links
                CREATE TABLE kb_finding_links (
                    id TEXT PRIMARY KEY,
                    article_id TEXT NOT NULL,
                    finding_code TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (article_id) REFERENCES kb_articles(id) ON DELETE CASCADE,
                    UNIQUE(article_id, finding_code)
                );

                -- Revision history
                CREATE TABLE kb_revisions (
                    id TEXT PRIMARY KEY,
                    article_id TEXT,
                    case_id TEXT,
                    content TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_by TEXT,
                    change_note TEXT,
                    FOREIGN KEY (article_id) REFERENCES kb_articles(id) ON DELETE CASCADE,
                    FOREIGN KEY (case_id) REFERENCES kb_cases(id) ON DELETE CASCADE
                );

                -- Full-text search for articles
                CREATE VIRTUAL TABLE kb_articles_fts USING fts5(
                    title, summary, content,
                    content=kb_articles,
                    content_rowid=id
                );

                -- Full-text search for cases
                CREATE VIRTUAL TABLE kb_cases_fts USING fts5(
                    title, summary, content,
                    content=kb_cases,
                    content_rowid=id
                );

                -- Metadata
                INSERT INTO kb_metadata VALUES ('schema_version', '1.0');
                INSERT INTO kb_metadata VALUES ('created_at', datetime('now'));
            """)
            conn.commit()

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

        Args:
            title: Article title
            content: Markdown content
            summary: Optional summary
            tags: Optional list of tag names
            finding_codes: Optional list of finding codes

        Returns:
            Article ID
        """
        article_id = str(uuid.uuid4())
        now = datetime.now()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Insert article
            cursor.execute(
                """
                INSERT INTO kb_articles (id, title, summary, content, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (article_id, title, summary, content, now, now),
            )

            # Insert into FTS
            cursor.execute(
                """
                INSERT INTO kb_articles_fts (rowid, title, summary, content)
                VALUES (?, ?, ?, ?)
                """,
                (article_id, title, summary or "", content),
            )

            # Add tags
            if tags:
                for tag_name in tags:
                    tag_id = self._ensure_tag(cursor, tag_name)
                    cursor.execute(
                        "INSERT INTO kb_article_tags (article_id, tag_id) VALUES (?, ?)",
                        (article_id, tag_id),
                    )

            # Add finding links
            if finding_codes:
                for finding_code in finding_codes:
                    link_id = str(uuid.uuid4())
                    cursor.execute(
                        """
                        INSERT INTO kb_finding_links (id, article_id, finding_code)
                        VALUES (?, ?, ?)
                        """,
                        (link_id, article_id, finding_code),
                    )

            conn.commit()

        return article_id

    def get_article(self, article_id: str) -> Optional[Article]:
        """Get Article by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM kb_articles WHERE id = ?", (article_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            # Get tags
            cursor.execute(
                """
                SELECT kt.name FROM kb_tags kt
                JOIN kb_article_tags kat ON kt.id = kat.tag_id
                WHERE kat.article_id = ?
                """,
                (article_id,),
            )
            tags = [r[0] for r in cursor.fetchall()]

            # Get finding codes
            cursor.execute(
                "SELECT finding_code FROM kb_finding_links WHERE article_id = ?",
                (article_id,),
            )
            finding_codes = [r[0] for r in cursor.fetchall()]

            # Get related articles
            cursor.execute(
                """
                SELECT related_article_id FROM kb_article_relations
                WHERE article_id = ?
                """,
                (article_id,),
            )
            related_ids = [r[0] for r in cursor.fetchall()]

            return Article(
                id=row["id"],
                title=row["title"],
                summary=row["summary"],
                content=row["content"],
                status=row["status"],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                tags=tags,
                finding_codes=finding_codes,
                related_article_ids=related_ids,
            )

    def update_article(
        self,
        article_id: str,
        title: Optional[str] = None,
        content: Optional[str] = None,
        summary: Optional[str] = None,
        change_note: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> bool:
        """Update Article and save revision.

        Args:
            article_id: Article ID
            title: New title (optional)
            content: New content (optional)
            summary: New summary (optional)
            change_note: Revision note
            created_by: Author of change

        Returns:
            Success
        """
        article = self.get_article(article_id)
        if not article:
            return False

        # Save revision of old version
        revision_id = str(uuid.uuid4())
        max_version = self._get_max_revision_version(article_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Save old content as revision
            cursor.execute(
                """
                INSERT INTO kb_revisions
                (id, article_id, content, version, created_by, change_note)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    revision_id,
                    article_id,
                    article.content,
                    max_version,
                    created_by,
                    change_note,
                ),
            )

            # Update article
            now = datetime.now()
            cursor.execute(
                """
                UPDATE kb_articles
                SET title = ?, content = ?, summary = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    title or article.title,
                    content or article.content,
                    summary if summary is not None else article.summary,
                    now,
                    article_id,
                ),
            )

            # Update FTS
            cursor.execute(
                """
                UPDATE kb_articles_fts
                SET title = ?, summary = ?, content = ?
                WHERE rowid = ?
                """,
                (
                    title or article.title,
                    summary if summary is not None else article.summary or "",
                    content or article.content,
                    article_id,
                ),
            )

            conn.commit()

        return True

    def delete_article(self, article_id: str) -> bool:
        """Delete Article (cascades to related data)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM kb_articles WHERE id = ?", (article_id,))
            cursor.execute(
                "DELETE FROM kb_articles_fts WHERE rowid = ?", (article_id,)
            )
            conn.commit()

        return True

    def list_articles(self) -> List[Article]:
        """List all active Articles."""
        articles = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM kb_articles WHERE status = 'active' ORDER BY updated_at DESC"
            )
            for row in cursor.fetchall():
                article = self.get_article(row[0])
                if article:
                    articles.append(article)

        return articles

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
            content: Markdown content
            summary: Optional summary
            analyze_snapshot: Optional snapshot of Analyze findings
            tags: Optional list of tag names

        Returns:
            Case ID
        """
        case_id = str(uuid.uuid4())
        now = datetime.now()
        snapshot_json = json.dumps(analyze_snapshot) if analyze_snapshot else None

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Insert case
            cursor.execute(
                """
                INSERT INTO kb_cases (id, title, summary, content, analyze_snapshot, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (case_id, title, summary, content, snapshot_json, now, now),
            )

            # Insert into FTS
            cursor.execute(
                """
                INSERT INTO kb_cases_fts (rowid, title, summary, content)
                VALUES (?, ?, ?, ?)
                """,
                (case_id, title, summary or "", content),
            )

            # Add tags
            if tags:
                for tag_name in tags:
                    tag_id = self._ensure_tag(cursor, tag_name)
                    cursor.execute(
                        "INSERT INTO kb_case_tags (case_id, tag_id) VALUES (?, ?)",
                        (case_id, tag_id),
                    )

            conn.commit()

        return case_id

    def get_case(self, case_id: str) -> Optional[Case]:
        """Get Case by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM kb_cases WHERE id = ?", (case_id,))
            row = cursor.fetchone()
            if not row:
                return None

            # Get tags
            cursor.execute(
                """
                SELECT kt.name FROM kb_tags kt
                JOIN kb_case_tags kct ON kt.id = kct.tag_id
                WHERE kct.case_id = ?
                """,
                (case_id,),
            )
            tags = [r[0] for r in cursor.fetchall()]

            # Get related articles
            cursor.execute(
                "SELECT article_id FROM kb_case_articles WHERE case_id = ?",
                (case_id,),
            )
            related_ids = [r[0] for r in cursor.fetchall()]

            analyze_snapshot = None
            if row["analyze_snapshot"]:
                analyze_snapshot = json.loads(row["analyze_snapshot"])

            return Case(
                id=row["id"],
                title=row["title"],
                summary=row["summary"],
                content=row["content"],
                analyze_snapshot=analyze_snapshot,
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                tags=tags,
                related_article_ids=related_ids,
            )

    def update_case(
        self,
        case_id: str,
        title: Optional[str] = None,
        content: Optional[str] = None,
        summary: Optional[str] = None,
        change_note: Optional[str] = None,
    ) -> bool:
        """Update Case."""
        case = self.get_case(case_id)
        if not case:
            return False

        with self._get_connection() as conn:
            cursor = conn.cursor()

            now = datetime.now()
            cursor.execute(
                """
                UPDATE kb_cases
                SET title = ?, content = ?, summary = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    title or case.title,
                    content or case.content,
                    summary if summary is not None else case.summary,
                    now,
                    case_id,
                ),
            )

            # Update FTS
            cursor.execute(
                """
                UPDATE kb_cases_fts
                SET title = ?, summary = ?, content = ?
                WHERE rowid = ?
                """,
                (
                    title or case.title,
                    summary if summary is not None else case.summary or "",
                    content or case.content,
                    case_id,
                ),
            )

            conn.commit()

        return True

    def delete_case(self, case_id: str) -> bool:
        """Delete Case."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM kb_cases WHERE id = ?", (case_id,))
            cursor.execute("DELETE FROM kb_cases_fts WHERE rowid = ?", (case_id,))
            conn.commit()

        return True

    def list_cases(self) -> List[Case]:
        """List all Cases."""
        cases = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM kb_cases ORDER BY updated_at DESC")
            for row in cursor.fetchall():
                case = self.get_case(row[0])
                if case:
                    cases.append(case)

        return cases

    # ========================
    # TAGS
    # ========================

    def _ensure_tag(self, cursor: sqlite3.Cursor, tag_name: str) -> str:
        """Get or create tag."""
        cursor.execute("SELECT id FROM kb_tags WHERE name = ?", (tag_name,))
        row = cursor.fetchone()
        if row:
            return row[0]

        tag_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO kb_tags (id, name) VALUES (?, ?)",
            (tag_id, tag_name),
        )
        return tag_id

    def get_all_tags(self) -> List[str]:
        """Get all tag names."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM kb_tags ORDER BY name")
            return [r[0] for r in cursor.fetchall()]

    # ========================
    # RELATIONSHIPS
    # ========================

    def link_case_to_article(self, case_id: str, article_id: str) -> bool:
        """Link Case to Article."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO kb_case_articles (case_id, article_id)
                VALUES (?, ?)
                """,
                (case_id, article_id),
            )
            conn.commit()

        return True

    def unlink_case_from_article(self, case_id: str, article_id: str) -> bool:
        """Unlink Case from Article."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM kb_case_articles WHERE case_id = ? AND article_id = ?",
                (case_id, article_id),
            )
            conn.commit()

        return True

    def link_articles(self, article_id: str, related_article_id: str) -> bool:
        """Link two Articles."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO kb_article_relations (article_id, related_article_id)
                VALUES (?, ?)
                """,
                (article_id, related_article_id),
            )
            conn.commit()

        return True

    # ========================
    # FINDING LINKS
    # ========================

    def link_finding_to_article(self, finding_code: str, article_id: str) -> bool:
        """Link finding code to Article."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            link_id = str(uuid.uuid4())
            cursor.execute(
                """
                INSERT OR IGNORE INTO kb_finding_links (id, article_id, finding_code)
                VALUES (?, ?, ?)
                """,
                (link_id, article_id, finding_code),
            )
            conn.commit()

        return True

    def find_articles_for_finding(self, finding_code: str) -> List[Article]:
        """Find Articles linked to finding code."""
        articles = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT DISTINCT article_id FROM kb_finding_links
                WHERE finding_code = ?
                """,
                (finding_code,),
            )
            for row in cursor.fetchall():
                article = self.get_article(row[0])
                if article:
                    articles.append(article)

        return articles

    # ========================
    # REVISIONS
    # ========================

    def _get_max_revision_version(self, article_id: str) -> int:
        """Get highest revision version number."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT MAX(version) FROM kb_revisions WHERE article_id = ?",
                (article_id,),
            )
            row = cursor.fetchone()
            return (row[0] or 0) + 1

    def get_revisions(self, article_id: str) -> List[Revision]:
        """Get revision history for Article."""
        revisions = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM kb_revisions
                WHERE article_id = ?
                ORDER BY version DESC
                """,
                (article_id,),
            )
            for row in cursor.fetchall():
                revisions.append(
                    Revision(
                        id=row["id"],
                        article_id=row["article_id"],
                        content=row["content"],
                        version=row["version"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        created_by=row["created_by"],
                        change_note=row["change_note"],
                    )
                )

        return revisions

    def restore_revision(self, article_id: str, version: int) -> bool:
        """Restore Article to specific revision."""
        article = self.get_article(article_id)
        if not article:
            return False

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT content FROM kb_revisions WHERE article_id = ? AND version = ?",
                (article_id, version),
            )
            row = cursor.fetchone()
            if not row:
                return False

            old_content = row[0]

            # Update article with old content
            now = datetime.now()
            cursor.execute(
                """
                UPDATE kb_articles
                SET content = ?, updated_at = ?
                WHERE id = ?
                """,
                (old_content, now, article_id),
            )

            # Update FTS
            cursor.execute(
                """
                UPDATE kb_articles_fts
                SET content = ?
                WHERE rowid = ?
                """,
                (old_content, article_id),
            )

            conn.commit()

        return True
