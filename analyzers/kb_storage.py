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
        conn.execute("PRAGMA foreign_keys = ON")  # CRITICAL: Enable FK enforcement
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if schema exists by checking if metadata table exists
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='kb_metadata'"
            )
            if cursor.fetchone():
                # Schema exists, check if migration is needed
                self._run_migrations()
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
                    display_id_seq INTEGER NOT NULL,
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
                    display_id_seq INTEGER NOT NULL,
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

                -- Unique indexes for display_id_seq
                CREATE UNIQUE INDEX idx_kb_articles_display_id_seq
                    ON kb_articles(display_id_seq);

                CREATE UNIQUE INDEX idx_kb_cases_display_id_seq
                    ON kb_cases(display_id_seq);

                -- Metadata
                INSERT INTO kb_metadata VALUES ('schema_version', '1.0');
                INSERT INTO kb_metadata VALUES ('created_at', datetime('now'));
            """)
            conn.commit()

    def _run_migrations(self):
        """Run schema migrations for existing databases."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if display_id_seq column exists in kb_articles
            cursor.execute("PRAGMA table_info(kb_articles)")
            columns = [col[1] for col in cursor.fetchall()]
            if "display_id_seq" not in columns:
                # Migration 1: Add display_id_seq to kb_articles
                cursor.execute(
                    "ALTER TABLE kb_articles ADD COLUMN display_id_seq INTEGER"
                )
                # Create unique index on display_id_seq
                cursor.execute(
                    "CREATE UNIQUE INDEX idx_kb_articles_display_id_seq ON kb_articles(display_id_seq) WHERE display_id_seq IS NOT NULL"
                )
                # Assign stable display_id_seq based on current ordering
                cursor.execute(
                    """
                    SELECT id FROM kb_articles
                    WHERE status = 'active'
                    ORDER BY created_at ASC, id ASC
                    """
                )
                articles = cursor.fetchall()
                for seq_num, (article_id,) in enumerate(articles, start=1):
                    cursor.execute(
                        "UPDATE kb_articles SET display_id_seq = ? WHERE id = ?",
                        (seq_num, article_id),
                    )

            # Check if display_id_seq column exists in kb_cases
            cursor.execute("PRAGMA table_info(kb_cases)")
            columns = [col[1] for col in cursor.fetchall()]
            if "display_id_seq" not in columns:
                # Migration 2: Add display_id_seq to kb_cases
                cursor.execute(
                    "ALTER TABLE kb_cases ADD COLUMN display_id_seq INTEGER"
                )
                # Create unique index on display_id_seq
                cursor.execute(
                    "CREATE UNIQUE INDEX idx_kb_cases_display_id_seq ON kb_cases(display_id_seq) WHERE display_id_seq IS NOT NULL"
                )
                # Assign stable display_id_seq based on current ordering
                cursor.execute(
                    """
                    SELECT id FROM kb_cases
                    ORDER BY created_at ASC, id ASC
                    """
                )
                cases = cursor.fetchall()
                for seq_num, (case_id,) in enumerate(cases, start=1):
                    cursor.execute(
                        "UPDATE kb_cases SET display_id_seq = ? WHERE id = ?",
                        (seq_num, case_id),
                    )

            # Store next available sequences in metadata
            cursor.execute(
                "SELECT COUNT(*) + 1 FROM kb_articles WHERE display_id_seq IS NOT NULL"
            )
            next_article_seq = cursor.fetchone()[0]

            cursor.execute(
                "SELECT COUNT(*) + 1 FROM kb_cases WHERE display_id_seq IS NOT NULL"
            )
            next_case_seq = cursor.fetchone()[0]

            cursor.execute(
                "INSERT OR REPLACE INTO kb_metadata VALUES (?, ?)",
                ("next_article_seq", str(next_article_seq)),
            )
            cursor.execute(
                "INSERT OR REPLACE INTO kb_metadata VALUES (?, ?)",
                ("next_case_seq", str(next_case_seq)),
            )

            conn.commit()

    def _get_next_article_seq(self, cursor) -> int:
        """Get next available article sequence number (atomic)."""
        cursor.execute(
            "SELECT value FROM kb_metadata WHERE key = 'next_article_seq'"
        )
        row = cursor.fetchone()
        if row:
            seq_num = int(row[0])
        else:
            # Fallback: count existing and add 1
            cursor.execute("SELECT COUNT(*) FROM kb_articles")
            seq_num = cursor.fetchone()[0] + 1

        # Increment for next call
        cursor.execute(
            "INSERT OR REPLACE INTO kb_metadata VALUES (?, ?)",
            ("next_article_seq", str(seq_num + 1)),
        )
        return seq_num

    def _get_next_case_seq(self, cursor) -> int:
        """Get next available case sequence number (atomic)."""
        cursor.execute("SELECT value FROM kb_metadata WHERE key = 'next_case_seq'")
        row = cursor.fetchone()
        if row:
            seq_num = int(row[0])
        else:
            # Fallback: count existing and add 1
            cursor.execute("SELECT COUNT(*) FROM kb_cases")
            seq_num = cursor.fetchone()[0] + 1

        # Increment for next call
        cursor.execute(
            "INSERT OR REPLACE INTO kb_metadata VALUES (?, ?)",
            ("next_case_seq", str(seq_num + 1)),
        )
        return seq_num

    def _get_article_seq(self, cursor, article_id: str) -> int:
        """Get sequential display ID for article (1-based position by created_at)."""
        cursor.execute(
            """
            SELECT COUNT(*) + 1 FROM kb_articles
            WHERE status = 'active' AND created_at <= (
                SELECT created_at FROM kb_articles WHERE id = ?
            )
            """,
            (article_id,),
        )
        result = cursor.fetchone()
        return result[0] if result else 1

    def _get_case_seq(self, cursor, case_id: str) -> int:
        """Get sequential display ID for case (1-based position by created_at)."""
        cursor.execute(
            """
            SELECT COUNT(*) + 1 FROM kb_cases
            WHERE created_at <= (
                SELECT created_at FROM kb_cases WHERE id = ?
            )
            """,
            (case_id,),
        )
        result = cursor.fetchone()
        return result[0] if result else 1

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

            # Allocate stable display sequence number
            display_id_seq = self._get_next_article_seq(cursor)

            # Insert article with persistent display_id_seq
            cursor.execute(
                """
                INSERT INTO kb_articles (id, display_id_seq, title, summary, content, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (article_id, display_id_seq, title, summary, content, now, now),
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
                display_id_seq=row["display_id_seq"],
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

            conn.commit()

        return True

    def delete_article(self, article_id: str) -> bool:
        """Delete Article (cascades to related data)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM kb_articles WHERE id = ?", (article_id,))
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

            # Allocate stable display sequence number
            display_id_seq = self._get_next_case_seq(cursor)

            # Insert case with persistent display_id_seq
            cursor.execute(
                """
                INSERT INTO kb_cases (id, display_id_seq, title, summary, content, analyze_snapshot, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (case_id, display_id_seq, title, summary, content, snapshot_json, now, now),
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
                display_id_seq=row["display_id_seq"],
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

            conn.commit()

        return True

    def delete_case(self, case_id: str) -> bool:
        """Delete Case."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM kb_cases WHERE id = ?", (case_id,))
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

    def get_article_by_display_id(self, display_id: str) -> Optional[Article]:
        """Get Article by display ID (e.g., AN00000001).

        Args:
            display_id: Display ID in format AN########

        Returns:
            Article object or None if not found
        """
        if not display_id or not display_id.startswith("AN"):
            return None

        try:
            display_id_seq = int(display_id[2:])
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id FROM kb_articles WHERE display_id_seq = ?",
                    (display_id_seq,),
                )
                row = cursor.fetchone()
                if row:
                    return self.get_article(row[0])
        except (ValueError, IndexError):
            pass

        return None

    def get_case_by_display_id(self, display_id: str) -> Optional[Case]:
        """Get Case by display ID (e.g., CN00000001).

        Args:
            display_id: Display ID in format CN########

        Returns:
            Case object or None if not found
        """
        if not display_id or not display_id.startswith("CN"):
            return None

        try:
            display_id_seq = int(display_id[2:])
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id FROM kb_cases WHERE display_id_seq = ?",
                    (display_id_seq,),
                )
                row = cursor.fetchone()
                if row:
                    return self.get_case(row[0])
        except (ValueError, IndexError):
            pass

        return None

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

    def get_cases_for_article(self, article_id: str) -> List[Case]:
        """Get all Cases linked to an Article (reverse lookup).

        Args:
            article_id: Article canonical UUID

        Returns:
            List of Case objects
        """
        cases = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT case_id FROM kb_case_articles WHERE article_id = ?",
                (article_id,),
            )
            for row in cursor.fetchall():
                case = self.get_case(row[0])
                if case:
                    cases.append(case)
        return cases

    def get_articles_for_case(self, case_id: str) -> List[Article]:
        """Get all Articles linked to a Case (forward lookup).

        Args:
            case_id: Case canonical UUID

        Returns:
            List of Article objects
        """
        articles = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT article_id FROM kb_case_articles WHERE case_id = ?",
                (case_id,),
            )
            for row in cursor.fetchall():
                article = self.get_article(row[0])
                if article:
                    articles.append(article)
        return articles

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
