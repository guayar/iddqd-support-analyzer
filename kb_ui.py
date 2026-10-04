"""Knowledge Base UI for Gradio.

Builds the Knowledge Base tab with Articles, Cases, and Search.
"""

import gradio as gr
from typing import Optional, Tuple, List
import json
import pandas as pd

from analyzers.kb_actions import KnowledgeBaseActions
from kb_rendering import (
    render_articles_table,
    render_cases_table,
    render_search_articles_table,
    render_search_cases_table,
)


# Initialize KB at module level
kb = KnowledgeBaseActions()


def build_kb_tab() -> Tuple:
    """Build Knowledge Base tab for main UI.

    Returns:
        Tuple of Gradio components for state management
    """

    with gr.Tab("Knowledge Base"):
        # ========================
        # SELECTION STATE
        # ========================
        # Keep Article and Case selection completely independent
        selected_article_id = gr.State(None)
        selected_case_id = gr.State(None)

        # Store current search results for re-rendering with selection
        article_search_results = gr.State([])  # List of Article objects
        case_search_results = gr.State([])    # List of Case objects

        with gr.Column(elem_classes=["psa-shell"], scale=1.75):
            # Header
            gr.Markdown("""
            # Knowledge Base

            **Articles** — Reusable troubleshooting knowledge
            **Cases** — Previous investigations and findings

            Create Articles and Cases, then use the Search tab to find them.
            """)

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
                                headers=["Selected", "ID", "Title", "Updated", "Tags"],
                                interactive=False,
                                label="Articles",
                                elem_classes=["kb-dataframe"],
                                elem_id="kb-articles-list",
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
                                headers=["Selected", "ID", "Title", "Created", "Tags"],
                                interactive=False,
                                label="Cases",
                                elem_classes=["kb-dataframe"],
                                elem_id="kb-cases-list",
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

                    # article_history = gr.Textbox(
                    #     label="Revision History",
                    #     interactive=False,
                    #     lines=6,
                    # )

                    gr.Markdown("### Link Cases to This Article")
                    with gr.Row():
                        link_case_dropdown = gr.Dropdown(
                            label="Select Case to Link",
                            choices=[],
                            scale=3,
                        )
                        link_case_btn = gr.Button("🔗 Link", scale=1, variant="primary")

                    link_case_status = gr.Textbox(
                        label="Status",
                        interactive=False,
                        value="Ready to link cases",
                    )

                    article_related_cases = gr.Dataframe(
                        headers=["Case ID", "Title"],
                        interactive=False,
                        label="Related Cases",
                        wrap=False,
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

                    gr.Markdown("### Link Articles to This Case")
                    with gr.Row():
                        link_article_dropdown = gr.Dropdown(
                            label="Select Article to Link",
                            choices=[],
                            scale=3,
                        )
                        link_article_btn = gr.Button("🔗 Link", scale=1, variant="primary")

                    link_status = gr.Textbox(
                        label="Status",
                        interactive=False,
                        value="Ready to link articles",
                    )

                    case_related_articles = gr.Dataframe(
                        headers=["Article ID", "Title"],
                        interactive=False,
                        label="Related Articles",
                        wrap=False,
                    )

                    with gr.Row():
                        save_case_btn = gr.Button("💾 Save", variant="primary")
                        delete_case_btn = gr.Button("🗑️ Delete", variant="stop")

                # ========================
                # SEARCH
                # ========================
                with gr.Tab("Search"):
                    with gr.Row():
                        search_query = gr.Textbox(
                            label="Search Articles and Cases",
                            placeholder="jwt, deadlock, timeout, oauth...",
                            scale=4,
                        )
                        search_btn = gr.Button("🔍 Search", scale=1, variant="primary")

                    search_results_articles = gr.Dataframe(
                        headers=["Selected", "ID", "Title", "Summary"],
                        interactive=False,
                        label="Articles Found",
                        elem_classes=["kb-dataframe"],
                        elem_id="kb-search-articles",
                    )

                    search_results_cases = gr.Dataframe(
                        headers=["Selected", "ID", "Title", "Summary"],
                        interactive=False,
                        label="Cases Found",
                        elem_classes=["kb-dataframe"],
                        elem_id="kb-search-cases",
                    )

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

    def refresh_all_knowledge(
        selected_article_uuid=None,
        selected_case_uuid=None,
    ):
        """Refresh Articles and Cases lists (first 10 records) with current selection highlighting.

        Args:
            selected_article_uuid: Current selected Article UUID (from gr.State)
            selected_case_uuid: Current selected Case UUID (from gr.State)
        """
        all_articles = kb.list_articles()
        all_cases = kb.list_cases()

        articles = all_articles[:10]  # First 10 records
        cases = all_cases[:10]  # First 10 records

        total_articles = len(all_articles)
        total_cases = len(all_cases)

        articles_count_text = f"{len(articles)} of {total_articles}" if total_articles > 10 else f"{total_articles}"
        cases_count_text = f"{len(cases)} of {total_cases}" if total_cases > 10 else f"{total_cases}"

        # Use render helpers to get styled dataframes with selection highlighting
        articles_styled, _ = render_articles_table(articles, selected_article_uuid)
        cases_styled, _ = render_cases_table(cases, selected_case_uuid)

        return (
            articles_count_text,
            cases_count_text,
            articles_styled,
            cases_styled,
        )

    def perform_search(query, selected_article_uuid=None, selected_case_uuid=None):
        """Search KB and return styled dataframes with selection highlighting.

        Args:
            query: Search query string
            selected_article_uuid: Current selected Article UUID
            selected_case_uuid: Current selected Case UUID

        Returns:
            Tuple of (articles_styled, cases_styled, articles_list, cases_list)
        """
        if not query:
            empty_articles = pd.DataFrame(columns=["Selected", "ID", "Title", "Summary"])
            empty_cases = pd.DataFrame(columns=["Selected", "ID", "Title", "Summary"])
            return empty_articles, empty_cases, [], []

        try:
            result = kb.search(query, limit=10)
            articles = result["articles"]
            cases = result["cases"]

            print(f"Search query: '{query}'")
            print(f"Found {len(articles)} articles, {len(cases)} cases")

            # Use render helpers to get styled dataframes with selection highlighting
            articles_styled, _ = render_search_articles_table(articles, selected_article_uuid)
            cases_styled, _ = render_search_cases_table(cases, selected_case_uuid)

            return articles_styled, cases_styled, articles, cases
        except Exception as e:
            print(f"Search error: {e}")
            import traceback
            traceback.print_exc()
            empty_articles = pd.DataFrame(columns=["Selected", "ID", "Title", "Summary"])
            empty_cases = pd.DataFrame(columns=["Selected", "ID", "Title", "Summary"])
            return empty_articles, empty_cases, [], []

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
        """Load selected article into editor.

        Uses evt.row_value[1] (display ID at index 1) instead of row index
        to correctly handle search results. Index 0 is the selection marker.
        """
        if evt is None or evt.row_value is None or len(evt.row_value) < 2:
            return None, "", "", "", "", "", [], None

        # Extract display ID from second column (index 1, after selection marker at 0)
        display_id = evt.row_value[1]

        # Resolve display ID to actual article
        article = kb.get_article_by_display_id(display_id)
        if not article:
            return None, "", "", "", "", "", [], None

        print(f"[ARTICLE SELECT] display_id={display_id}, canonical_uuid={article.id}")

        finding_codes = ", ".join(article.finding_codes) if article.finding_codes else ""
        tags_str = ", ".join(article.tags) if article.tags else ""

        # Get related cases (cases that link to this article)
        related_data = []
        all_cases = kb.list_cases()
        for case in all_cases:
            if article.id in case.related_article_ids:
                related_data.append([case.display_id, case.title])

        # Return editor fields + state update (without revision history)
        return (
            article.display_id,
            article.title,
            article.summary or "",
            article.content,
            tags_str,
            finding_codes,
            related_data if related_data else [],
            article.id,  # Update selected_article_id state
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
        """Load selected case into editor.

        Uses evt.row_value[1] (display ID at index 1) instead of row index
        to correctly handle search results. Index 0 is the selection marker.
        """
        if evt is None or evt.row_value is None or len(evt.row_value) < 2:
            return None, "", "", "", "", [], None

        # Extract display ID from second column (index 1, after selection marker at 0)
        display_id = evt.row_value[1]

        # Resolve display ID to actual case
        case = kb.get_case_by_display_id(display_id)
        if not case:
            return None, "", "", "", "", [], None

        print(f"[CASE SELECT] display_id={display_id}, canonical_uuid={case.id}")

        # Get related articles (show display_id, not UUID)
        related_data = []
        for article_id in case.related_article_ids:
            article = kb.get_article(article_id)
            if article:
                related_data.append([article.display_id, article.title])

        tags_str = ", ".join(case.tags) if case.tags else ""

        return (
            case.display_id,
            case.title,
            case.summary or "",
            case.content,
            tags_str,
            related_data if related_data else [],
            case.id,  # Update selected_case_id state
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

    def populate_article_dropdown():
        """Populate dropdown with available articles."""
        articles = kb.list_articles()
        choices = [f"{a.display_id} — {a.title}" for a in articles]
        return gr.Dropdown(choices=choices, value=None)

    def link_article_to_case(selected_case_uuid, article_choice):
        """Link selected article to case."""
        if not selected_case_uuid:
            return "⚠️ No case selected", []
        if not article_choice:
            return "⚠️ No article selected", []

        try:
            # Extract display_id from choice (format: "AN00000001 — title")
            display_id = article_choice.split(" — ")[0]
            article = kb.get_article_by_display_id(display_id)
            if not article:
                return "❌ Article not found", []

            # Link article to case
            success = kb.link_case_to_article(selected_case_uuid, article.id)
            if success:
                # Reload case to show updated related articles
                case = kb.get_case(selected_case_uuid)
                related_data = []
                for article_id in case.related_article_ids:
                    art = kb.get_article(article_id)
                    if art:
                        related_data.append([art.display_id, art.title])
                return f"✅ Linked: {article.display_id}", related_data
            else:
                return "❌ Failed to link article", []
        except Exception as e:
            return f"❌ Error: {str(e)}", []

    def populate_case_dropdown():
        """Populate dropdown with available cases."""
        cases = kb.list_cases()
        choices = [f"{c.display_id} — {c.title}" for c in cases]
        return gr.Dropdown(choices=choices, value=None)

    def link_case_to_article(selected_article_uuid, case_choice):
        """Link selected case to article."""
        if not selected_article_uuid:
            return "⚠️ No article selected", []
        if not case_choice:
            return "⚠️ No case selected", []

        try:
            # Extract display_id from choice (format: "CN00000001 — title")
            display_id = case_choice.split(" — ")[0]
            case = kb.get_case_by_display_id(display_id)
            if not case:
                return "❌ Case not found", []

            # Link article to case (same as linking case to article)
            success = kb.link_case_to_article(case.id, selected_article_uuid)
            if success:
                # Get all cases related to this article
                all_cases = kb.list_cases()
                related_data = []
                for c in all_cases:
                    if selected_article_uuid in c.related_article_ids:
                        related_data.append([c.display_id, c.title])
                return f"✅ Linked: {case.display_id}", related_data
            else:
                return "❌ Failed to link case", []
        except Exception as e:
            return f"❌ Error: {str(e)}", []

    def refresh_articles_display_only(selected_article_uuid=None):
        """Refresh Articles table to show current selection highlighting.

        Args:
            selected_article_uuid: Current selected Article UUID (from gr.State)
        """
        all_articles = kb.list_articles()[:10]
        articles_styled, _ = render_articles_table(all_articles, selected_article_uuid)
        return articles_styled

    def refresh_cases_display_only(selected_case_uuid=None):
        """Refresh Cases table to show current selection highlighting.

        Args:
            selected_case_uuid: Current selected Case UUID (from gr.State)
        """
        all_cases = kb.list_cases()[:10]
        cases_styled, _ = render_cases_table(all_cases, selected_case_uuid)
        return cases_styled

    def refresh_search_articles_display(
        selected_article_uuid=None,
        search_results=None,
    ):
        """Refresh search results articles table with current selection.

        Args:
            selected_article_uuid: Current selected Article UUID
            search_results: List of Article objects from last search
        """
        if not search_results:
            search_results = []
        print(f"[RENDER SEARCH ARTICLES] selected_uuid={selected_article_uuid}, results_count={len(search_results)}")
        articles_styled, _ = render_search_articles_table(search_results, selected_article_uuid)
        return articles_styled

    def refresh_search_cases_display(
        selected_case_uuid=None,
        search_results=None,
    ):
        """Refresh search results cases table with current selection.

        Args:
            selected_case_uuid: Current selected Case UUID
            search_results: List of Case objects from last search
        """
        if not search_results:
            search_results = []
        cases_styled, _ = render_search_cases_table(search_results, selected_case_uuid)
        return cases_styled

    # Wire handlers

    # Search - capture results in state AND pass current selection for correct rendering
    search_btn.click(
        fn=perform_search,
        inputs=[search_query, selected_article_id, selected_case_id],
        outputs=[search_results_articles, search_results_cases, article_search_results, case_search_results],
    )

    # Article list selection - load into editor (from All Knowledge tab)
    articles_list.select(
        fn=load_article_for_edit,
        outputs=[article_id_edit, article_title_edit, article_summary_edit,
                 article_content_edit, article_tags_edit, article_findings_edit,
                 article_related_cases, selected_article_id],
    ).then(
        fn=refresh_articles_display_only,
        inputs=[selected_article_id],
        outputs=[articles_list],
    )

    # Search results articles - load into editor AND re-render search results with selection
    search_results_articles.select(
        fn=load_article_for_edit,
        outputs=[article_id_edit, article_title_edit, article_summary_edit,
                 article_content_edit, article_tags_edit, article_findings_edit,
                 article_related_cases, selected_article_id],
    ).then(
        fn=refresh_search_articles_display,
        inputs=[selected_article_id, article_search_results],
        outputs=[search_results_articles],
    ).then(
        fn=refresh_articles_display_only,
        inputs=[selected_article_id],
        outputs=[articles_list],
    )

    # Save and delete article
    save_article_btn.click(
        fn=save_article_handler,
        inputs=[selected_article_id, article_title_edit, article_summary_edit,
                article_content_edit, article_tags_edit, article_findings_edit],
        outputs=[article_status],
    ).then(
        fn=refresh_all_knowledge,
        inputs=[selected_article_id, selected_case_id],
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    delete_article_btn.click(
        fn=delete_article_handler,
        inputs=[selected_article_id],
        outputs=[article_status],
    ).then(
        fn=refresh_all_knowledge,
        inputs=[selected_case_id],  # Pass None for selected_article (will be cleared)
        outputs=[articles_count, cases_count, articles_list, cases_list],
    ).then(
        fn=lambda: (None, "", "", "", "", "", [], ""),
        outputs=[selected_article_id, article_id_edit, article_title_edit,
                article_summary_edit, article_content_edit, article_tags_edit, article_findings_edit, article_related_cases],
    )

    create_article_btn.click(
        fn=create_new_article,
        inputs=[new_article_title, new_article_tags, new_article_content],
        outputs=[create_article_status],
    ).then(
        fn=refresh_all_knowledge,
        inputs=[selected_article_id, selected_case_id],
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    # Case list selection - load into editor (from All Knowledge tab)
    cases_list.select(
        fn=load_case_for_edit,
        outputs=[case_id_edit, case_title_edit, case_summary_edit,
                 case_content_edit, case_tags_edit, case_related_articles, selected_case_id],
    ).then(
        fn=refresh_cases_display_only,
        inputs=[selected_case_id],
        outputs=[cases_list],
    ).then(
        fn=populate_article_dropdown,
        outputs=[link_article_dropdown],
    )

    # Search results cases - load into editor AND re-render search results with selection
    search_results_cases.select(
        fn=load_case_for_edit,
        outputs=[case_id_edit, case_title_edit, case_summary_edit,
                 case_content_edit, case_tags_edit, case_related_articles, selected_case_id],
    ).then(
        fn=refresh_search_cases_display,
        inputs=[selected_case_id, case_search_results],
        outputs=[search_results_cases],
    ).then(
        fn=refresh_cases_display_only,
        inputs=[selected_case_id],
        outputs=[cases_list],
    ).then(
        fn=populate_article_dropdown,
        outputs=[link_article_dropdown],
    )

    # Save and delete case
    save_case_btn.click(
        fn=save_case_handler,
        inputs=[selected_case_id, case_title_edit, case_summary_edit,
                case_content_edit, case_tags_edit],
        outputs=[case_status],
    ).then(
        fn=refresh_all_knowledge,
        inputs=[selected_article_id, selected_case_id],
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    delete_case_btn.click(
        fn=delete_case_handler,
        inputs=[selected_case_id],
        outputs=[case_status],
    ).then(
        fn=refresh_all_knowledge,
        inputs=[selected_article_id],  # Pass None for selected_case (will be cleared)
        outputs=[articles_count, cases_count, articles_list, cases_list],
    ).then(
        fn=lambda: (None, "", "", "", "", ""),
        outputs=[selected_case_id, case_id_edit, case_title_edit,
                case_summary_edit, case_content_edit, case_tags_edit],
    )

    create_case_btn.click(
        fn=create_new_case,
        inputs=[new_case_title, new_case_tags, new_case_content],
        outputs=[create_case_status],
    ).then(
        fn=refresh_all_knowledge,
        inputs=[selected_article_id, selected_case_id],
        outputs=[articles_count, cases_count, articles_list, cases_list],
    )

    # Link article to case
    link_article_btn.click(
        fn=link_article_to_case,
        inputs=[selected_case_id, link_article_dropdown],
        outputs=[link_status, case_related_articles],
    )

    # Link case to article
    link_case_btn.click(
        fn=link_case_to_article,
        inputs=[selected_article_id, link_case_dropdown],
        outputs=[link_case_status, article_related_cases],
    )

    # Populate case dropdown when article is loaded
    articles_list.select(
        fn=populate_case_dropdown,
        outputs=[link_case_dropdown],
    )

    search_results_articles.select(
        fn=populate_case_dropdown,
        outputs=[link_case_dropdown],
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
        inputs=[selected_article_id, selected_case_id],
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
        selected_article_id,
        selected_case_id,
        article_search_results,
        case_search_results,
    )


def init_kb_data(refresh_fn):
    """Initialize KB data on startup."""
    refresh_fn()
