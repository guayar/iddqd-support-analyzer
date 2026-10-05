"""Knowledge Base export and import functionality."""

import json
import zipfile
import tempfile
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

from .kb_storage import KnowledgeBaseStorage
from .kb_models import Article


class KnowledgeBasePortability:
    """Export and import KB Articles."""

    def __init__(self, storage: KnowledgeBaseStorage):
        """Initialize portability handler.

        Args:
            storage: KnowledgeBaseStorage instance
        """
        self.storage = storage

    def export_selected(self, article_ids: List[str], case_ids: List[str]) -> bytes:
        """Export selected Articles as ZIP.

        Args:
            article_ids: List of Article IDs to export
            case_ids: Ignored legacy argument; Cases are no longer exported.

        Returns:
            ZIP file as bytes
        """
        manifest = {
            "version": "1.0",
            "exported_at": datetime.now().isoformat(),
            "schema_version": "1.0",
            "articles_count": len(article_ids),
            "cases_count": 0,
        }

        articles_data = []
        for article_id in article_ids:
            article = self.storage.get_article(article_id)
            if article:
                record = article.to_dict()
                record.pop("related_article_ids", None)
                articles_data.append(record)

        # Create ZIP
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            with zipfile.ZipFile(tmp_path, "w") as zf:
                # Manifest
                zf.writestr(
                    "manifest.json",
                    json.dumps(manifest, indent=2),
                )

                # Articles
                for article in articles_data:
                    article_path = f"articles/{article['id']}.json"
                    zf.writestr(article_path, json.dumps(article, indent=2))

            # Read ZIP and return bytes
            return tmp_path.read_bytes()

        finally:
            tmp_path.unlink()

    def export_full_kb(self) -> bytes:
        """Export entire Knowledge Base as ZIP.

        Returns:
            ZIP file as bytes
        """
        all_articles = self.storage.list_articles()

        article_ids = [a.id for a in all_articles]

        return self.export_selected(article_ids, [])

    def import_kb(
        self, zip_bytes: bytes, merge_mode: str = "new"
    ) -> Dict[str, Any]:
        """Import KB from ZIP.

        Args:
            zip_bytes: ZIP file as bytes
            merge_mode: "new" (rename conflicts), "replace", "skip"

        Returns:
            Dict with import results
        """
        result = {
            "success": True,
            "imported_articles": [],
            "imported_cases": [],
            "conflicts": [],
            "errors": [],
        }

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp_path.write_bytes(zip_bytes)

        try:
            with zipfile.ZipFile(tmp_path, "r") as zf:
                # Read manifest
                try:
                    manifest_data = json.loads(zf.read("manifest.json"))
                except KeyError:
                    result["errors"].append("manifest.json not found in package")
                    result["success"] = False
                    return result

                # Check schema version
                if manifest_data.get("schema_version") != "1.0":
                    result["errors"].append(
                        f"Incompatible schema version: {manifest_data.get('schema_version')}"
                    )
                    result["success"] = False
                    return result

                # Import articles
                for name in zf.namelist():
                    if name.startswith("articles/") and name.endswith(".json"):
                        try:
                            article_data = json.loads(zf.read(name))
                            article = Article.from_dict(article_data)

                            # Check for conflicts
                            existing = self.storage.get_article(article.id)
                            if existing:
                                result["conflicts"].append(
                                    {
                                        "type": "article",
                                        "id": article.id,
                                        "title": article.title,
                                    }
                                )
                                if merge_mode == "skip":
                                    continue
                                elif merge_mode == "new":
                                    # Rename with timestamp
                                    import uuid

                                    article.id = str(uuid.uuid4())

                            # Create article
                            self.storage.create_article(
                                title=article.title,
                                content=article.content,
                                summary=article.summary,
                                tags=article.tags,
                                finding_codes=article.finding_codes,
                            )
                            result["imported_articles"].append(article.id)

                        except Exception as e:
                            result["errors"].append(
                                f"Error importing article {name}: {str(e)}"
                            )

        finally:
            tmp_path.unlink()

        return result
