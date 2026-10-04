"""Knowledge Base UI for Gradio.

Builds the Knowledge Base tab with Articles, Cases, and Search.
"""

import gradio as gr
from typing import Optional, Tuple, List
import json

from analyzers.kb_actions import KnowledgeBaseActions


# Initialize KB at module level
kb = KnowledgeBaseActions()


def build_kb_tab() -> Tuple:
    """Build Knowledge Base tab for main UI.

    Returns:
        Tuple of Gradio components for state management
    """

    with gr.Tab("Knowledge Base"):
        with gr.Column(elem_classes=["psa-shell"], scale=1):
            # Header
            gr.Markdown("""
            # Knowledge Base

            **Articles** — Reusable troubleshooting knowledge
            **Cases** — Previous investigations and findings

            Search Articles and Cases, create new ones, and link to Analyze results.
            """)

            # Search
            with gr.Row():
                search_query = gr.Textbox(
                    label="Search Articles and Cases",
                    placeholder="jwt, deadlock, timeout, oauth...",
                    scale=4,
                )
                search_btn = gr.Button("🔍 Search", scale=1, variant="primary")

            # Filter tabs
            with gr.Tabs():
                # ========================
                # ALL KNOWLEDGE
                # ========================
                with gr.Tab("All Knowledge"):
                    with gr.Row():
                        articles_count = gr.Textbox(
                            label="Articles",
                            interactive=False,
                            scale=1
                        )
                        cases_count = gr.Textbox(
                            label="Cases",
                            interactive=False,
                            scale=1
                        )

                    with gr.Tabs():
                        with gr.Tab("Articles"):
                            articles_list = gr.Dataframe(
                                headers=["ID", "Title", "Updated", "Tags"],
                                interactive=False,
                                label="Articles",
                            )

                            gr.Markdown("### Create New Article")
                            with gr.Row():
                                new_article_title = gr.Textbox(
                                    label="Title",
                                    placeholder="JWT signing key troubleshooting",
                                )
                                new_article_tags = gr.Textbox(
                                    label="Tags (comma-separated)",
                                    placeholder="jwt, auth, keys",
                                )

                            new_article_content = gr.Textbox(
                                label="Content (Markdown)",
                                lines=10,
                                placeholder="# Summary\n\n## Things to check\n\n## Possible causes",
                            )

                            create_article_btn = gr.Button(
                                "Create Article",
                                variant="primary"
                            )
                            create_article_status = gr.Textbox(
                                label="Status",
                                interactive=False,
                                value="Ready to create"
                            )

                        with gr.Tab("Cases"):
                            cases_list = gr.Dataframe(
                                headers=["ID", "Title", "Created", "Tags"],
                                interactive=False,
                                label="Cases",
                            )

                            gr.Markdown("### Create New Case")
                            with gr.Row():
                                new_case_title = gr.Textbox(
                                    label="Title",
                                    placeholder="2026-10-03 - JWT key rotation issue",
                                )
                                new_case_tags = gr.Textbox(
                                    label="Tags (comma-separated)",
                                    placeholder="jwt, incident, prod",
                                )

                            new_case_content = gr.Textbox(
                                label="Content (Markdown)",
                                lines=10,
                                placeholder="# Summary\n\n## What happened\n\n## Resolution",
                            )

                            create_case_btn = gr.Button(
                                "Create Case",
                                variant="primary"
                            )
                            create_case_status = gr.Textbox(
                                label="Status",
                                interactive=False,
                                value="Ready to create"
                            )

                # ========================
                # SEARCH RESULTS
                # ========================
                with gr.Tab("Search Results"):
                    search_results_articles = gr.Dataframe(
                        headers=["ID", "Title", "Summary"],
                        interactive=False,
                        label="Articles Found",
                    )

                    search_results_cases = gr.Dataframe(
                        headers=["ID", "Title", "Summary"],
                        interactive=False,
                        label="Cases Found",
                    )

                # ========================
                # ARTICLE EDITOR
                # ========================
                with gr.Tab("Article Editor"):
                    gr.Markdown("### Edit Article")

                    with gr.Row():
                        article_id_edit = gr.Textbox(
                            label="Article ID",
                            interactive=False,
                        )
                        article_status = gr.Textbox(
                            label="Status",
                            interactive=False,
                        )

                    article_title_edit = gr.Textbox(
                        label="Title",
                        interactive=True,
                    )

                    article_summary_edit = gr.Textbox(
                        label="Summary",
                        lines=2,
                        interactive=True,
                    )

                    article_content_edit = gr.Textbox(
                        label="Content (Markdown)",
                        lines=12,
                        interactive=True,
                    )

                    with gr.Row():
                        article_tags_edit = gr.Textbox(
                            label="Tags",
                            interactive=True,
                            scale=3,
                        )
                        article_findings_edit = gr.Textbox(
                            label="Finding codes (comma-separated)",
                            interactive=True,
                            scale=3,
                        )

                    article_history = gr.Textbox(
                        label="Revision History",
                        interactive=False,
                        lines=6,
                    )

                    with gr.Row():
                        save_article_btn = gr.Button("💾 Save", variant="primary")
                        delete_article_btn = gr.Button("🗑️ Delete", variant="stop")

                # ========================
                # CASE EDITOR
                # ========================
                with gr.Tab("Case Editor"):
                    gr.Markdown("### Edit Case")

                    with gr.Row():
                        case_id_edit = gr.Textbox(
                            label="Case ID",
                            interactive=False,
                        )
                        case_status = gr.Textbox(
                            label="Status",
                            interactive=False,
                        )

                    case_title_edit = gr.Textbox(
                        label="Title",
                        interactive=True,
                    )

                    case_summary_edit = gr.Textbox(
                        label="Summary",
                        lines=2,
                        interactive=True,
                    )

                    case_content_edit = gr.Textbox(
                        label="Content (Markdown)",
                        lines=12,
                        interactive=True,
                    )

                    case_tags_edit = gr.Textbox(
                        label="Tags",
                        interactive=True,
                    )

                    case_related_articles = gr.Dataframe(
                        headers=["Article ID", "Title"],
                        interactive=False,
                        label="Related Articles",
                    )

                    with gr.Row():
                        save_case_btn = gr.Button("💾 Save", variant="primary")
                        delete_case_btn = gr.Button("🗑️ Delete", variant="stop")

                # ========================
                # EXPORT/IMPORT
                # ========================
                with gr.Tab("Export/Import"):
                    gr.Markdown("""
                    ### Knowledge Base Backup & Portability

                    **Export** your Articles and Cases as ZIP for backup or sharing.
                    **Import** from ZIP to restore or merge KB content.
                    """)

                    with gr.Tabs():
                        with gr.Tab("Export"):
                            gr.Markdown("#### Export Selected or Full KB")

                            with gr.Row():
                                export_all_btn = gr.Button("📦 Export Full KB", variant="primary", scale=1)
                                export_selected_btn = gr.Button("📋 Export Selected", scale=1)

                            export_status = gr.Textbox(
                                label="Status",
                                interactive=False,
                                value="Ready to export"
                            )

                            export_file = gr.File(
                                label="Download ZIP",
                                interactive=False,
                            )

                        with gr.Tab("Import"):
                            gr.Markdown("#### Import KB from ZIP")

                            import_file = gr.File(
                                label="Upload ZIP file",
                                file_types=[".zip"],
                            )

                            import_merge_mode = gr.Radio(
                                choices=["new (rename conflicts)", "replace", "skip"],
                                value="new (rename conflicts)",
                                label="Conflict handling",
                            )

                            import_btn = gr.Button("📥 Import", variant="primary")

                            import_status = gr.Textbox(
                                label="Import Result",
                                interactive=False,
                                lines=5,
                            )

    # ========================
    # HANDLERS
    # ========================

    def refresh_all_knowledge():
        """Refresh Articles and Cases lists."""
        articles = kb.list_articles()
        cases = kb.list_cases()

        articles_data = [
            [
                a.id,
                a.title,
                a.updated_at.strftime("%Y-%m-%d") if a.updated_at else "—",
                ", ".join(a.tags) if a.tags else "—",
            ]
            for a in articles
        ]

        cases_data = [
            [
                c.id,
                c.title,
                c.created_at.strftime("%Y-%m-%d") if c.created_at else "—",
                ", ".join(c.tags) if c.tags else "—",
            ]
            for c in cases
        ]

        return (
            f"{len(articles)}",
            f"{len(cases)}",
            articles_data if articles else [],
            cases_data if cases else [],
        )

    def perform_search(query):
        """Search KB."""
        if not query:
            return [], []

        results = kb.search(query, limit=20)

        articles_data = [
            [
                a.id,
                a.title,
                a.summary or a.content[:100] + "..." if len(a.content) > 100 else a.content,
            ]
            for a in results["articles"]
        ]

        cases_data = [
            [
                c.id,
                c.title,
                c.summary or c.content[:100] + "..." if len(c.content) > 100 else c.content,
            ]
            for c in results["cases"]
        ]

        return articles_data, cases_data

    def create_new_article(title, tags_str, content):
        """Create new Article."""
        if not title or not content:
            return "⚠️ Title and Content are required"

        tags = [t.strip() for t in tags_str.split(",") if t.strip()]

        try:
            article_id = kb.create_article(
                title=title,
                content=content,
                tags=tags,
            )
            return f"✅ Article created: {article_id}"
        except Exception as e:
            return f"❌ Error: {str(e)}"

    def create_new_case(title, tags_str, content):
        """Create new Case."""
        if not title or not content:
            return "⚠️ Title and Content are required"

        tags = [t.strip() for t in tags_str.split(",") if t.strip()]

        try:
            case_id = kb.create_case(
                title=title,
                content=content,
                tags=tags,
            )
            return f"✅ Case created: {case_id}"
        except Exception as e:
            return f"❌ Error: {str(e)}"

    def export_full_kb():
        """Export entire KB as ZIP."""
        try:
            from analyzers.kb_portability import KnowledgeBasePortability
            portability = KnowledgeBasePortability(kb.storage)
            zip_data = portability.export_full_kb()
            return "✅ Full KB exported successfully", zip_data
        except Exception as e:
            return f"❌ Export failed: {str(e)}", None

    def import_kb_from_file(file_obj, merge_mode):
        """Import KB from ZIP file."""
        if not file_obj:
            return "⚠️ Please select a ZIP file to import"

        try:
            from analyzers.kb_portability import KnowledgeBasePortability
            portability = KnowledgeBasePortability(kb.storage)

            # Read file
            with open(file_obj.name, 'rb') as f:
                zip_data = f.read()

            # Parse merge mode
            mode_map = {
                "new (rename conflicts)": "new",
                "replace": "replace",
                "skip": "skip",
            }
            mode = mode_map.get(merge_mode, "new")

            # Import
            result = portability.import_kb(zip_data, merge_mode=mode)

            if result["success"]:
                msg = f"""✅ Import successful!

Imported Articles: {len(result['imported_articles'])}
Imported Cases: {len(result['imported_cases'])}
Conflicts detected: {len(result['conflicts'])}"""
                if result['errors']:
                    msg += f"\n\nErrors: {len(result['errors'])}"
                    for error in result['errors'][:3]:
                        msg += f"\n- {error}"
            else:
                msg = f"❌ Import failed: {result.get('errors', ['Unknown error'])[0]}"

            return msg
        except Exception as e:
            return f"❌ Error: {str(e)}"

    def load_article_for_edit(evt: gr.SelectData):
        """Load selected article into editor."""
        if evt is None or evt.index is None:
            return None, "", "", "", "", ""

        # Get article ID from row
        articles = kb.list_articles()
        if evt.index[0] >= len(articles):
            return None, "", "", "", "", ""

        article = articles[evt.index[0]]
        if not article:
            return None, "", "", "", "", ""

        # Format revision history
        revisions = kb.get_revisions(article.id)
        rev_text = "Version history:\n"
        for rev in revisions:
            date_str = rev.get('created_at', 'N/A')
            author = rev.get('created_by', 'unknown')
            note = rev.get('change_note', '')
            rev_text += f"- v{rev.get('version')}: {date_str} by {author}\n"
            if note:
                rev_text += f"  Note: {note}\n"

        finding_codes = ", ".join(article.finding_codes) if article.finding_codes else ""
        tags_str = ", ".join(article.tags) if article.tags else ""

        return (
            article.id,
            article.title,
            article.summary or "",
            article.content,
            tags_str,
            finding_codes,
            rev_text if len(revisions) > 0 else "No revisions yet",
        )

    def save_article_handler(article_id, title, summary, content, tags_str, findings_str):
        """Save article changes."""
        if not article_id:
            return "⚠️ No article selected"
        if not title or not content:
            return "⚠️ Title and Content are required"

        try:
            tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []
            findings = [f.strip() for f in findings_str.split(",") if f.strip()] if findings_str else []

            success = kb.update_article(
                article_id=article_id,
                title=title,
                summary=summary,
                content=content,
                change_note="UI update"
            )

            if success:
                return "✅ Article saved successfully"
            else:
                return "❌ Failed to save article"
        except Exception as e:
            return f"❌ Error: {str(e)}"

    def delete_article_handler(article_id):
        """Delete article."""
        if not article_id:
            return "⚠️ No article selected"

        try:
            success = kb.delete_article(article_id)
            if success:
                return "✅ Article deleted"
            else:
                return "❌ Failed to delete article"
        except Exception as e:
            return f"❌ Error: {str(e)}"

    def load_case_for_edit(evt: gr.SelectData):
        """Load selected case into editor."""
        if evt is None or evt.index is None:
            return None, "", "", "", ""

        cases = kb.list_cases()
        if evt.index[0] >= len(cases):
            return None, "", "", "", ""

        case = cases[evt.index[0]]
        if not case:
            return None, "", "", "", ""

        # Get related articles
        related_data = []
        for article_id in case.related_article_ids:
            article = kb.get_article(article_id)
            if article:
                related_data.append([article.id, article.title])

        tags_str = ", ".join(case.tags) if case.tags else ""

        return (
            case.id,
            case.title,
            case.summary or "",
            case.content,
            tags_str,
            related_data if related_data else [],
        )

    def save_case_handler(case_id, title, summary, content, tags_str):
        """Save case changes."""
        if not case_id:
            return "⚠️ No case selected"
        if not title or not content:
            return "⚠️ Title and Content are required"

        try:
            tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []

            success = kb.update_case(
                case_id=case_id,
                title=title,
                summary=summary,
                content=content
            )

            if success:
                return "✅ Case saved successfully"
            else:
                return "❌ Failed to save case"
        except Exception as e:
            return f"❌ Error: {str(e)}"

    def delete_case_handler(case_id):
        """Delete case."""
        if not case_id:
            return "⚠️ No case selected"

        try:
            success = kb.delete_case(case_id)
            if success:
                return "✅ Case deleted"
            else:
                return "❌ Failed to delete case"
        except Exception as e:
            return f"❌ Error: {str(e)}"

    # Wire handlers
    search_btn.click(
        fn=perform_search,
        inputs=[search_query],
        outputs=[search_results_articles, search_results_cases],
    )

    # Article list selection - load into editor (from All Knowledge tab)
    articles_list.select(
        fn=load_article_for_edit,
        outputs=[article_id_edit, article_title_edit, article_summary_edit,
                 article_content_edit, article_tags_edit, article_findings_edit, article_history],
    )

    # Search results - load into editor (from Search Results tab)
    search_results_articles.select(
        fn=load_article_for_edit,
        outputs=[article_id_edit, article_title_edit, article_summary_edit,
                 article_content_edit, article_tags_edit, article_findings_edit, article_history],
    )

    # Save and delete article
    save_article_btn.click(
        fn=save_article_handler,
        inputs=[article_id_edit, article_title_edit, article_summary_edit,
                article_content_edit, article_tags_edit, article_findings_edit],
        outputs=[article_status],
    ).then(
        fn=refresh_all_knowledge,
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    delete_article_btn.click(
        fn=delete_article_handler,
        inputs=[article_id_edit],
        outputs=[article_status],
    ).then(
        fn=refresh_all_knowledge,
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    create_article_btn.click(
        fn=create_new_article,
        inputs=[new_article_title, new_article_tags, new_article_content],
        outputs=[create_article_status],
    ).then(
        fn=refresh_all_knowledge,
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    # Case list selection - load into editor (from All Knowledge tab)
    cases_list.select(
        fn=load_case_for_edit,
        outputs=[case_id_edit, case_title_edit, case_summary_edit,
                 case_content_edit, case_tags_edit, case_related_articles],
    )

    # Search results cases - load into editor (from Search Results tab)
    search_results_cases.select(
        fn=load_case_for_edit,
        outputs=[case_id_edit, case_title_edit, case_summary_edit,
                 case_content_edit, case_tags_edit, case_related_articles],
    )

    # Save and delete case
    save_case_btn.click(
        fn=save_case_handler,
        inputs=[case_id_edit, case_title_edit, case_summary_edit,
                case_content_edit, case_tags_edit],
        outputs=[case_status],
    ).then(
        fn=refresh_all_knowledge,
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    delete_case_btn.click(
        fn=delete_case_handler,
        inputs=[case_id_edit],
        outputs=[case_status],
    ).then(
        fn=refresh_all_knowledge,
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    create_case_btn.click(
        fn=create_new_case,
        inputs=[new_case_title, new_case_tags, new_case_content],
        outputs=[create_case_status],
    ).then(
        fn=refresh_all_knowledge,
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    # Export handlers
    export_all_btn.click(
        fn=export_full_kb,
        outputs=[export_status, export_file],
    )

    # Import handlers
    import_btn.click(
        fn=import_kb_from_file,
        inputs=[import_file, import_merge_mode],
        outputs=[import_status],
    ).then(
        fn=refresh_all_knowledge,
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    # Load data on tab open
    # Note: Gradio 4.x doesn't have easy "on tab open" events
    # We'll load on demo.launch() instead

    return (
        refresh_all_knowledge,
        articles_count,
        cases_count,
        articles_list,
        cases_list,
        search_results_articles,
        search_results_cases,
    )


def init_kb_data(refresh_fn):
    """Initialize KB data on startup."""
    refresh_fn()
