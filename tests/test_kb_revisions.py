"""KB revision history tests."""

from analyzers.kb_storage import KnowledgeBaseStorage
import tempfile


def test_article_revision_history():
    """Test article create-update-retrieve round-trip."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = f"{tmpdir}/test.db"
        storage = KnowledgeBaseStorage(db_path)
        
        # Create article
        article_id = storage.create_article(
            title="Test Article",
            content="Original content",
            summary="Summary"
        )
        
        # Verify create
        article = storage.get_article(article_id)
        assert article is not None
        assert article.content == "Original content"
        
        # Update article
        updated = storage.update_article(
            article_id,
            content="Updated content",
            change_note="Updated test"
        )
        assert updated is True
        
        # Verify update
        article = storage.get_article(article_id)
        assert article.content == "Updated content"


if __name__ == "__main__":
    test_article_revision_history()
    print("✓ KB revision test passed")
