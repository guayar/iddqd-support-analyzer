"""Knowledge Base UI - PHASES 1-9 Implementation.

Complete redesigned KB with three focused tabs:
1. Create (Article/Case unified form with link picker)
2. Search / View (search + independent view panels + edit/delete)
3. Export / Import

Combines all phases 1-9 in one coherent design.
"""

import gradio as gr
from typing import Optional, List, Dict, Any
import json
import pandas as pd

from analyzers.kb_actions import KnowledgeBaseActions
from kb_rendering import (
    render_articles_table,
    render_cases_table,
    render_search_articles_table,
    render_search_cases_table,
)

kb = KnowledgeBaseActions()
PAGE_SIZE = 10


def build_kb_tab():
    """Build redesigned Knowledge Base tab (PHASES 1-9).

    Returns:
        Tuple of state components for integration with main app
    """

    with gr.Tab("Knowledge Base"):
        # ========================
        # STATE
        # ========================
        selected_article_id = gr.State(None)
        selected_case_id = gr.State(None)
        search_query_state = gr.State("")
        article_search_results = gr.State([])
        case_search_results = gr.State([])
        article_page = gr.State(1)
        case_page = gr.State(1)
        article_view_mode = gr.State("view")  # "view" or "edit"
        case_view_mode = gr.State("view")

        with gr.Column(scale=2, elem_classes=["psa-shell"]):
            gr.Markdown("""
            # Knowledge Base

            **Create** — New Articles and Cases
            **Search / View** — Find and read articles, link them together
            **Export / Import** — Backup and restore
            """)

            with gr.Tabs():
                # ========================
                # 1. CREATE TAB (PHASES 4-5)
                # ========================
                with gr.Tab("Create"):
                    # Type selector
                    with gr.Row():
                        create_type = gr.Radio(
                            choices=["Article", "Case"],
                            value="Article",
                            label="Create",
                            scale=1
                        )

                    # Common fields
                    create_title = gr.Textbox(
                        label="Title",
                        placeholder="Article or Case title"
                    )
                    create_tags = gr.Textbox(
                        label="Tags (comma-separated)",
                        placeholder="saphana, jwt, auth"
                    )
                    create_summary = gr.Textbox(
                        label="Summary",
                        lines=3,
                        placeholder="Brief summary"
                    )
                    create_content = gr.Textbox(
                        label="Content (Markdown)",
                        lines=12,
                        placeholder="# Main heading\n\n## Details"
                    )

                    # Link picker (PHASE 5)
                    gr.Markdown("### Link to existing...")
                    link_search_query = gr.Textbox(
                        label="Search by ID or keyword",
                        placeholder="AN00000001 or 'jwt'"
                    )
                    link_search_btn = gr.Button("Search", scale=1)
                    link_search_results = gr.Dataframe(
                        headers=["ID", "Title"],
                        interactive=False
                    )
                    link_selected = gr.State([])
                    link_display = gr.Textbox(
                        label="Selected links",
                        interactive=False,
                        placeholder="None"
                    )

                    create_btn = gr.Button("Create", variant="primary", scale=1)
                    create_status = gr.Textbox(
                        label="Status",
                        interactive=False,
                        value="Ready"
                    )

                    # Event handlers
                    def search_for_linking(query: str, create_type_val: str):
                        if not query:
                            return None
                        results = kb.search(query, limit=10)
                        # Show opposite type
                        if create_type_val == "Article":
                            items = results.get("cases", [])
                            data = [[c.display_id, c.title] for c in items]
                        else:
                            items = results.get("articles", [])
                            data = [[a.display_id, a.title] for a in items]
                        return pd.DataFrame(data, columns=["ID", "Title"]) if data else None

                    def create_item(create_type_val, title, tags_str, summary, content, link_ids_json):
                        try:
                            tags = [t.strip() for t in tags_str.split(",")] if tags_str else []

                            if create_type_val == "Article":
                                article_id = kb.create_article(title, content, summary, tags)
                                # Link to selected cases
                                if link_ids_json:
                                    for case_id in link_ids_json:
                                        kb.link_case_to_article(case_id, article_id)
                                return "✅ Article created"
                            else:
                                case_id = kb.create_case(title, content, summary, tags=tags)
                                # Link to selected articles
                                if link_ids_json:
                                    for article_id in link_ids_json:
                                        kb.link_case_to_article(case_id, article_id)
                                return "✅ Case created"
                        except Exception as e:
                            return f"❌ Error: {str(e)}"

                    link_search_btn.click(
                        fn=search_for_linking,
                        inputs=[link_search_query, create_type],
                        outputs=[link_search_results]
                    )

                    def add_link_to_selected(row_value, current_links_json):
                        if not row_value:
                            return current_links_json
                        link_id = row_value[0]  # ID column
                        links = current_links_json if current_links_json else []
                        if link_id not in links:
                            links.append(link_id)
                        return json.dumps(links)

                    link_search_results.select(
                        fn=add_link_to_selected,
                        inputs=[link_search_results, link_selected],
                        outputs=[link_selected]
                    ).then(
                        fn=lambda x: f"Selected: {x}" if x else "None",
                        inputs=[link_selected],
                        outputs=[link_display]
                    )

                    create_btn.click(
                        fn=create_item,
                        inputs=[create_type, create_title, create_tags, create_summary, create_content, link_selected],
                        outputs=[create_status]
                    )

                # ========================
                # 2. SEARCH / VIEW TAB (PHASES 1-3, 6-8)
                # ========================
                with gr.Tab("Search / View"):
                    # Search box
                    with gr.Row():
                        search_box = gr.Textbox(
                            label="Search",
                            placeholder="AN00000001, CN00000001, or keyword",
                            scale=5
                        )
                        search_btn = gr.Button("Search", variant="primary", scale=1)

                    # Cases section
                    gr.Markdown("## Cases")
                    with gr.Row():
                        cases_count_text = gr.Textbox(
                            label="Total Cases",
                            interactive=False,
                            scale=1
                        )
                        case_page_text = gr.Textbox(
                            label="Page",
                            interactive=False,
                            scale=1
                        )

                    case_results_table = gr.Dataframe(
                        headers=["Selected", "ID", "Title", "Summary"],
                        interactive=False
                    )

                    with gr.Row():
                        case_prev_btn = gr.Button("< Previous", scale=1)
                        case_next_btn = gr.Button("Next >", scale=1)

                    # Case view (PHASES 1-3, 6-8)
                    with gr.Group() as case_view_group:
                        gr.Markdown("### Case View")
                        case_view_id = gr.Textbox(label="ID", interactive=False)
                        case_view_title = gr.Textbox(label="Title", interactive=False)
                        case_view_tags = gr.Textbox(label="Tags", interactive=False)
                        case_view_summary = gr.Textbox(
                            label="Summary",
                            lines=3,
                            interactive=False
                        )
                        case_view_content = gr.Textbox(
                            label="Content",
                            lines=8,
                            interactive=False
                        )

                        # Linked articles (PHASE 3)
                        case_linked_articles = gr.Dataframe(
                            headers=["ID", "Title"],
                            interactive=False,
                            label="Linked Articles"
                        )

                        # Edit mode (PHASES 6-7)
                        with gr.Row():
                            case_edit_btn = gr.Button("Edit", scale=1)
                            case_delete_btn = gr.Button("Delete", scale=1, variant="stop")

                    # Case edit form (PHASES 6-7)
                    with gr.Group() as case_edit_group:
                        gr.Markdown("### Case Edit")
                        case_edit_id = gr.Textbox(label="ID", interactive=False)
                        case_edit_title = gr.Textbox(label="Title", interactive=True)
                        case_edit_tags = gr.Textbox(label="Tags (comma-separated)", interactive=True)
                        case_edit_summary = gr.Textbox(label="Summary", lines=3, interactive=True)
                        case_edit_content = gr.Textbox(label="Content", lines=8, interactive=True)

                        # Link management (PHASE 7)
                        gr.Markdown("#### Linked Articles")
                        case_edit_linked = gr.Dataframe(
                            headers=["ID", "Title"],
                            interactive=False,
                            label="Current Links"
                        )

                        case_edit_selected_link_id = gr.State(None)

                        with gr.Row():
                            case_edit_link_search = gr.Textbox(label="Search articles to link", scale=3)
                            case_edit_link_search_btn = gr.Button("Search", scale=1, variant="primary")
                        case_edit_link_results = gr.Dataframe(
                            headers=["▶", "ID", "Title"],
                            interactive=False,
                            label="Search Results - click to select"
                        )
                        case_edit_link_btn = gr.Button("✓ Add Selected Link", variant="primary")

                        case_edit_status = gr.Textbox(label="Status", interactive=False, value="")

                        with gr.Row():
                            case_edit_save_btn = gr.Button("Save", variant="primary", scale=1)
                            case_edit_cancel_btn = gr.Button("Cancel", scale=1)

                    # Articles section
                    gr.Markdown("## Articles")
                    with gr.Row():
                        articles_count_text = gr.Textbox(
                            label="Total Articles",
                            interactive=False,
                            scale=1
                        )
                        article_page_text = gr.Textbox(
                            label="Page",
                            interactive=False,
                            scale=1
                        )

                    article_results_table = gr.Dataframe(
                        headers=["Selected", "ID", "Title", "Summary"],
                        interactive=False
                    )

                    with gr.Row():
                        article_prev_btn = gr.Button("< Previous", scale=1)
                        article_next_btn = gr.Button("Next >", scale=1)

                    # Article view (PHASES 1-3, 6-8)
                    with gr.Group() as article_view_group:
                        gr.Markdown("### Article View")
                        article_view_id = gr.Textbox(label="ID", interactive=False)
                        article_view_title = gr.Textbox(label="Title", interactive=False)
                        article_view_tags = gr.Textbox(label="Tags", interactive=False)
                        article_view_summary = gr.Textbox(
                            label="Summary",
                            lines=3,
                            interactive=False
                        )
                        article_view_content = gr.Textbox(
                            label="Content",
                            lines=8,
                            interactive=False
                        )

                        # Linked cases (PHASE 3)
                        article_linked_cases = gr.Dataframe(
                            headers=["ID", "Title"],
                            interactive=False,
                            label="Linked Cases"
                        )

                        # Edit mode (PHASES 6-7)
                        with gr.Row():
                            article_edit_btn = gr.Button("Edit", scale=1)
                            article_delete_btn = gr.Button("Delete", scale=1, variant="stop")

                    # Article edit form (PHASES 6-7)
                    with gr.Group() as article_edit_group:
                        gr.Markdown("### Article Edit")
                        article_edit_id = gr.Textbox(label="ID", interactive=False)
                        article_edit_title = gr.Textbox(label="Title", interactive=True)
                        article_edit_tags = gr.Textbox(label="Tags (comma-separated)", interactive=True)
                        article_edit_summary = gr.Textbox(label="Summary", lines=3, interactive=True)
                        article_edit_content = gr.Textbox(label="Content", lines=8, interactive=True)

                        # Link management (PHASE 7)
                        gr.Markdown("#### Linked Cases")
                        article_edit_linked = gr.Dataframe(
                            headers=["ID", "Title"],
                            interactive=False,
                            label="Current Links"
                        )

                        article_edit_selected_link_id = gr.State(None)

                        with gr.Row():
                            article_edit_link_search = gr.Textbox(label="Search cases to link", scale=3)
                            article_edit_link_search_btn = gr.Button("Search", scale=1, variant="primary")
                        article_edit_link_results = gr.Dataframe(
                            headers=["▶", "ID", "Title"],
                            interactive=False,
                            label="Search Results - click to select"
                        )
                        article_edit_link_btn = gr.Button("✓ Add Selected Link", variant="primary")

                        article_edit_status = gr.Textbox(label="Status", interactive=False, value="")

                        with gr.Row():
                            article_edit_save_btn = gr.Button("Save", variant="primary", scale=1)
                            article_edit_cancel_btn = gr.Button("Cancel", scale=1)

                    # ========================
                    # Search / View Event Handlers
                    # ========================

                    def perform_search(query: str):
                        if not query or not query.strip():
                            return None, None, 0, 0, "1 / 1", "1 / 1", "", "", "", "", "", "", "", "", ""

                        # Use search_articles for exact AN ID support + text search
                        articles = kb.search_articles(query.strip(), limit=1000)

                        # For now, keep case search using the legacy method
                        results = kb.search(query.strip(), limit=1000)
                        cases = results.get("cases", [])

                        # Store results in state for re-rendering after selection
                        case_search_results.value = cases
                        article_search_results.value = articles

                        cases_styled, _ = render_search_cases_table(cases, None)
                        articles_styled, _ = render_search_articles_table(articles, None)

                        return (
                            cases_styled,
                            articles_styled,
                            len(cases),
                            len(articles),
                            "1 / 1",
                            "1 / 1",
                            "", "", "", "", "",
                            "", "", "", "", ""
                        )

                    def load_case_view_full(evt: gr.SelectData):
                        """Load case into view when selected in dataframe."""
                        if not evt or not evt.row_value or len(evt.row_value) < 2:
                            return "", "", "", "", "", None, None

                        try:
                            # Main results table has selection marker at [0], ID at [1]
                            # Linked items table has ID at [0], Title at [1]
                            display_id = evt.row_value[1] if len(evt.row_value) > 2 else evt.row_value[0]
                            case = kb.get_case_by_display_id(display_id)
                            if not case:
                                return "", "", "", "", "", None, None

                            # Update selection state
                            selected_case_id.value = case.id

                            # Get linked articles (PHASE 3)
                            linked_articles = kb.get_articles_for_case(case.id)
                            linked_data = [[a.display_id, a.title] for a in linked_articles]

                            return (
                                case.display_id,
                                case.title,
                                ", ".join(case.tags) if case.tags else "—",
                                case.summary or "—",
                                case.content or "",
                                pd.DataFrame(linked_data, columns=["ID", "Title"]) if linked_data else None,
                                case.id
                            )
                        except Exception as e:
                            import traceback
                            traceback.print_exc()
                            return "", "", "", "", "", None, None

                    def load_article_view_full(evt: gr.SelectData):
                        """Load article into view when selected in dataframe."""
                        if not evt or not evt.row_value or len(evt.row_value) < 2:
                            return "", "", "", "", "", None, None

                        try:
                            # Main results table has selection marker at [0], ID at [1]
                            display_id = evt.row_value[1] if len(evt.row_value) > 2 else evt.row_value[0]
                            article = kb.get_article_by_display_id(display_id)
                            if not article:
                                return "", "", "", "", "", None, None

                            # Update selection state
                            selected_article_id.value = article.id

                            # Get linked cases (PHASE 3)
                            linked_cases = kb.get_cases_for_article(article.id)
                            linked_data = [[c.display_id, c.title] for c in linked_cases]

                            return (
                                article.display_id,
                                article.title,
                                ", ".join(article.tags) if article.tags else "—",
                                article.summary or "—",
                                article.content or "",
                                pd.DataFrame(linked_data, columns=["ID", "Title"]) if linked_data else None,
                                article.id
                            )
                        except Exception as e:
                            import traceback
                            traceback.print_exc()
                            return "", "", "", "", "", None, None

                    def delete_case(case_uuid):
                        if case_uuid:
                            kb.delete_case(case_uuid)
                            return "✅ Case deleted"
                        return "❌ No case selected"

                    def delete_article(article_uuid):
                        if article_uuid:
                            kb.delete_article(article_uuid)
                            return "✅ Article deleted"
                        return "❌ No article selected"

                    # Wire events
                    search_btn.click(
                        fn=perform_search,
                        inputs=[search_box],
                        outputs=[
                            case_results_table, article_results_table,
                            cases_count_text, articles_count_text,
                            case_page_text, article_page_text,
                            case_view_id, case_view_title, case_view_tags, case_view_summary, case_view_content,
                            article_view_id, article_view_title, article_view_tags, article_view_summary, article_view_content
                        ]
                    )

                    def reload_case_results():
                        """Re-render case results with selection marker."""
                        if selected_case_id.value and case_search_results.value:
                            cases_rerendered, _ = render_search_cases_table(case_search_results.value, selected_case_id.value)
                            return cases_rerendered
                        return case_results_table

                    def reload_article_results():
                        """Re-render article results with selection marker."""
                        if selected_article_id.value and article_search_results.value:
                            articles_rerendered, _ = render_search_articles_table(article_search_results.value, selected_article_id.value)
                            return articles_rerendered
                        return article_results_table

                    case_results_table.select(
                        fn=load_case_view_full,
                        outputs=[
                            case_view_id, case_view_title, case_view_tags, case_view_summary, case_view_content,
                            case_linked_articles, selected_case_id
                        ]
                    ).then(
                        fn=reload_case_results,
                        outputs=[case_results_table]
                    )

                    article_results_table.select(
                        fn=load_article_view_full,
                        outputs=[
                            article_view_id, article_view_title, article_view_tags, article_view_summary, article_view_content,
                            article_linked_cases, selected_article_id
                        ]
                    ).then(
                        fn=reload_article_results,
                        outputs=[article_results_table]
                    )

                    # Click linked item to navigate (PHASE 3)
                    case_linked_articles.select(
                        fn=load_article_view_full,
                        outputs=[
                            article_view_id, article_view_title, article_view_tags, article_view_summary, article_view_content,
                            article_linked_cases, selected_article_id
                        ]
                    ).then(
                        fn=reload_article_results,
                        outputs=[article_results_table]
                    )

                    article_linked_cases.select(
                        fn=load_case_view_full,
                        outputs=[
                            case_view_id, case_view_title, case_view_tags, case_view_summary, case_view_content,
                            case_linked_articles, selected_case_id
                        ]
                    ).then(
                        fn=reload_case_results,
                        outputs=[case_results_table]
                    )

                    # Delete buttons
                    case_delete_btn.click(
                        fn=delete_case,
                        inputs=[selected_case_id],
                        outputs=[case_view_id]
                    )

                    article_delete_btn.click(
                        fn=delete_article,
                        inputs=[selected_article_id],
                        outputs=[article_view_id]
                    )

                    # ========================
                    # PHASE 6: Inline Edit Mode
                    # ========================

                    def toggle_case_edit():
                        """Switch to edit mode for case - show edit, hide view."""
                        return "edit", gr.update(visible=False), gr.update(visible=True)

                    def toggle_case_view():
                        """Switch back to view mode for case - show view, hide edit."""
                        return "view", gr.update(visible=True), gr.update(visible=False)

                    def populate_case_edit(case_id):
                        """Populate edit form with case data."""
                        if not case_id:
                            return "", "", "", "", "", None, "", ""
                        case = kb.get_case(case_id)
                        if not case:
                            return "", "", "", "", "", None, "", ""
                        linked = kb.get_articles_for_case(case_id)
                        linked_data = [[a.display_id, a.title, "✕"] for a in linked]
                        return (
                            case.display_id, case.title,
                            ", ".join(case.tags) if case.tags else "",
                            case.summary or "", case.content or "",
                            pd.DataFrame(linked_data, columns=["ID", "Title", "Remove"]) if linked_data else None,
                            "", ""
                        )

                    def save_case(case_id, title, tags, summary, content):
                        """Save case changes."""
                        if not case_id or not title or not content:
                            return "❌ ID, Title, Content required", "view"
                        try:
                            tag_list = [t.strip() for t in tags.split(",") if t.strip()]
                            success = kb.update_case(case_id, title, summary or "", content, tag_list)
                            return ("✅ Case saved" if success else "❌ Save failed"), "view"
                        except Exception as e:
                            return f"❌ Error: {str(e)}", "view"

                    def toggle_article_edit():
                        """Switch to edit mode for article - show edit, hide view."""
                        return "edit", gr.update(visible=False), gr.update(visible=True)

                    def toggle_article_view():
                        """Switch back to view mode for article - show view, hide edit."""
                        return "view", gr.update(visible=True), gr.update(visible=False)

                    def populate_article_edit(article_id):
                        """Populate edit form with article data."""
                        if not article_id:
                            return "", "", "", "", "", None, "", ""
                        article = kb.get_article(article_id)
                        if not article:
                            return "", "", "", "", "", None, "", ""
                        linked = kb.get_cases_for_article(article_id)
                        linked_data = [[c.display_id, c.title, "✕"] for c in linked]
                        return (
                            article.display_id, article.title,
                            ", ".join(article.tags) if article.tags else "",
                            article.summary or "", article.content or "",
                            pd.DataFrame(linked_data, columns=["ID", "Title", "Remove"]) if linked_data else None,
                            "", ""
                        )

                    def save_article(article_id, title, tags, summary, content):
                        """Save article changes."""
                        if not article_id or not title or not content:
                            return "❌ ID, Title, Content required", "view"
                        try:
                            tag_list = [t.strip() for t in tags.split(",") if t.strip()]
                            success = kb.update_article(article_id, title, summary or "", content, tag_list)
                            return ("✅ Article saved" if success else "❌ Save failed"), "view"
                        except Exception as e:
                            return f"❌ Error: {str(e)}", "view"

                    # ========================
                    # PHASE 7: Link Management Handlers
                    # ========================

                    def search_articles_for_case(query: str):
                        """Search articles to link to case - with marker column (read-only)."""
                        if not query or not query.strip():
                            return None
                        results = kb.search(query.strip(), limit=100)
                        articles = results.get("articles", [])
                        # Store results in state for later use
                        case_edit_link_results_data = [articles]  # Store article objects
                        # Include marker column (empty initially)
                        data = [["", a.display_id, a.title] for a in articles]
                        df = pd.DataFrame(data, columns=["▶", "ID", "Title"]) if data else None
                        return df

                    def add_article_to_case(case_id, article_display_id):
                        """Link article to case - with duplicate prevention."""
                        if not case_id or not article_display_id:
                            return "❌ Select case and article"
                        try:
                            article = kb.get_article_by_display_id(article_display_id)
                            if not article:
                                return "❌ Article not found"

                            # Check if already linked
                            existing_links = kb.get_articles_for_case(case_id)
                            if any(a.id == article.id for a in existing_links):
                                return f"ℹ️ Article {article_display_id} is already linked"

                            kb.link_case_to_article(case_id, article.id)
                            return f"✅ Successfully linked article {article_display_id}"
                        except Exception as e:
                            return f"❌ Error: {str(e)}"

                    def remove_article_from_case(case_id, article_display_id):
                        """Unlink article from case."""
                        if not case_id or not article_display_id:
                            return "❌ Select case and article"
                        try:
                            article = kb.get_article_by_display_id(article_display_id)
                            if not article:
                                return "❌ Article not found"
                            kb.unlink_case_from_article(case_id, article.id)
                            return f"✅ Unlinked {article_display_id}"
                        except Exception as e:
                            return f"❌ Error: {str(e)}"

                    def search_cases_for_article(query: str):
                        """Search cases to link to article - with marker column (read-only)."""
                        if not query or not query.strip():
                            return None
                        results = kb.search(query.strip(), limit=100)
                        cases = results.get("cases", [])
                        # Store results for later use
                        article_edit_link_results_data = [cases]  # Store case objects
                        # Include marker column (empty initially)
                        data = [["", c.display_id, c.title] for c in cases]
                        df = pd.DataFrame(data, columns=["▶", "ID", "Title"]) if data else None
                        return df

                    def add_case_to_article(article_id, case_display_id):
                        """Link case to article - with duplicate prevention."""
                        if not article_id or not case_display_id:
                            return "❌ Select article and case"
                        try:
                            case = kb.get_case_by_display_id(case_display_id)
                            if not case:
                                return "❌ Case not found"

                            # Check if already linked
                            existing_links = kb.get_cases_for_article(article_id)
                            if any(c.id == case.id for c in existing_links):
                                return f"ℹ️ Case {case_display_id} is already linked"

                            kb.link_case_to_article(case.id, article_id)
                            return f"✅ Successfully linked case {case_display_id}"
                        except Exception as e:
                            return f"❌ Error: {str(e)}"

                    def remove_case_from_article(article_id, case_display_id):
                        """Unlink case from article."""
                        if not article_id or not case_display_id:
                            return "❌ Select article and case"
                        try:
                            case = kb.get_case_by_display_id(case_display_id)
                            if not case:
                                return "❌ Case not found"
                            kb.unlink_case_from_article(case.id, article_id)
                            return f"✅ Unlinked {case_display_id}"
                        except Exception as e:
                            return f"❌ Error: {str(e)}"

                    # Wire edit mode toggle
                    case_edit_btn.click(
                        fn=toggle_case_edit,
                        outputs=[case_view_mode, case_view_group, case_edit_group]
                    ).then(
                        fn=populate_case_edit,
                        inputs=[selected_case_id],
                        outputs=[case_edit_id, case_edit_title, case_edit_tags,
                                case_edit_summary, case_edit_content, case_edit_linked,
                                case_edit_link_search, case_edit_status]
                    )

                    case_edit_cancel_btn.click(
                        fn=toggle_case_view,
                        outputs=[case_view_mode, case_view_group, case_edit_group]
                    )

                    case_edit_save_btn.click(
                        fn=save_case,
                        inputs=[case_edit_id, case_edit_title, case_edit_tags,
                               case_edit_summary, case_edit_content],
                        outputs=[case_edit_status, case_view_mode]
                    ).then(
                        fn=toggle_case_view,
                        outputs=[case_view_mode, case_view_group, case_edit_group]
                    ).then(
                        fn=populate_case_edit,
                        inputs=[selected_case_id],
                        outputs=[case_view_id, case_view_title, case_view_tags,
                                case_view_summary, case_view_content, case_linked_articles,
                                case_view_id, case_view_id]
                    )

                    article_edit_btn.click(
                        fn=toggle_article_edit,
                        outputs=[article_view_mode, article_view_group, article_edit_group]
                    ).then(
                        fn=populate_article_edit,
                        inputs=[selected_article_id],
                        outputs=[article_edit_id, article_edit_title, article_edit_tags,
                                article_edit_summary, article_edit_content, article_edit_linked,
                                article_edit_link_search, article_edit_status]
                    )

                    article_edit_cancel_btn.click(
                        fn=toggle_article_view,
                        outputs=[article_view_mode, article_view_group, article_edit_group]
                    )

                    article_edit_save_btn.click(
                        fn=save_article,
                        inputs=[article_edit_id, article_edit_title, article_edit_tags,
                               article_edit_summary, article_edit_content],
                        outputs=[article_edit_status, article_view_mode]
                    ).then(
                        fn=toggle_article_view,
                        outputs=[article_view_mode, article_view_group, article_edit_group]
                    ).then(
                        fn=populate_article_edit,
                        inputs=[selected_article_id],
                        outputs=[article_view_id, article_view_title, article_view_tags,
                                article_view_summary, article_view_content, article_linked_cases,
                                article_view_id, article_view_id]
                    )

                    # Wire link search and management (PHASE 7)
                    def render_search_with_marker(articles, selected_id):
                        """Render article search results with selection marker."""
                        data = []
                        for a in articles:
                            marker = "▶" if a.id == selected_id else ""
                            data.append([marker, a.display_id, a.title])
                        return pd.DataFrame(data, columns=["▶", "ID", "Title"]) if data else None

                    def render_case_search_with_marker(cases, selected_id):
                        """Render case search results with selection marker."""
                        data = []
                        for c in cases:
                            marker = "▶" if c.id == selected_id else ""
                            data.append([marker, c.display_id, c.title])
                        return pd.DataFrame(data, columns=["▶", "ID", "Title"]) if data else None

                    case_edit_link_search_btn.click(
                        fn=search_articles_for_case,
                        inputs=[case_edit_link_search],
                        outputs=[case_edit_link_results]
                    )

                    def mark_selected_article(evt, results_df):
                        """Show marker on selected article in search results."""
                        if not evt or not evt.row_value or not isinstance(results_df, pd.DataFrame):
                            return results_df
                        selected_id = evt.row_value[1]
                        # Re-create dataframe with marker on selected row
                        data = []
                        for _, row in results_df.iterrows():
                            marker = "▶" if row["ID"] == selected_id else ""
                            data.append([marker, row["ID"], row["Title"]])
                        return pd.DataFrame(data, columns=["▶", "ID", "Title"])

                    case_edit_link_results.select(
                        fn=lambda evt: evt.row_value[1] if evt and evt.row_value and len(evt.row_value) > 1 else None,
                        outputs=[case_edit_selected_link_id]
                    ).then(
                        fn=mark_selected_article,
                        inputs=[case_edit_link_results],
                        outputs=[case_edit_link_results]
                    )

                    def remove_article_link_handler(evt):
                        """Remove article link when clicking current links table."""
                        if not evt or not evt.row_value or len(evt.row_value) < 1:
                            return "❌ Select link to remove"
                        # evt.row_value[0] = display_id (AN00000001)
                        article_display_id = evt.row_value[0]
                        case_id = selected_case_id.value  # Get UUID from state
                        if not case_id:
                            return "❌ Case ID not available"
                        try:
                            # Convert display_id to actual article UUID
                            article = kb.get_article_by_display_id(article_display_id)
                            if not article:
                                return f"❌ Article {article_display_id} not found"
                            # Call backend with correct UUIDs
                            kb.unlink_case_from_article(case_id, article.id)
                            return f"✅ Removed link to {article_display_id}"
                        except Exception as e:
                            return f"❌ Error: {str(e)}"

                    case_edit_linked.select(
                        fn=remove_article_link_handler,
                        outputs=[case_edit_status]
                    ).then(
                        fn=populate_case_edit,
                        inputs=[selected_case_id],
                        outputs=[case_edit_id, case_edit_title, case_edit_tags,
                                case_edit_summary, case_edit_content, case_edit_linked,
                                case_edit_link_search, case_edit_status]
                    )

                    case_edit_link_btn.click(
                        fn=add_article_to_case,
                        inputs=[selected_case_id, case_edit_selected_link_id],
                        outputs=[case_edit_status]
                    ).then(
                        fn=populate_case_edit,
                        inputs=[selected_case_id],
                        outputs=[case_edit_id, case_edit_title, case_edit_tags,
                                case_edit_summary, case_edit_content, case_edit_linked,
                                case_edit_link_search, case_edit_status]
                    )

                    article_edit_link_search_btn.click(
                        fn=search_cases_for_article,
                        inputs=[article_edit_link_search],
                        outputs=[article_edit_link_results]
                    )

                    article_edit_link_results.select(
                        fn=lambda evt: evt.row_value[1] if evt and evt.row_value and len(evt.row_value) > 1 else None,
                        outputs=[article_edit_selected_link_id]
                    )

                    def remove_case_link_handler(evt):
                        """Remove case link when clicking current links table."""
                        if not evt or not evt.row_value or len(evt.row_value) < 1:
                            return "❌ Select link to remove"
                        # evt.row_value[0] = display_id (CN00000001)
                        case_display_id = evt.row_value[0]
                        article_id = selected_article_id.value  # Get UUID from state
                        if not article_id:
                            return "❌ Article ID not available"
                        try:
                            # Convert display_id to actual case UUID
                            case = kb.get_case_by_display_id(case_display_id)
                            if not case:
                                return f"❌ Case {case_display_id} not found"
                            # Call backend with correct UUIDs
                            kb.unlink_case_from_article(article_id, case.id)
                            return f"✅ Removed link to {case_display_id}"
                        except Exception as e:
                            return f"❌ Error: {str(e)}"

                    article_edit_linked.select(
                        fn=remove_case_link_handler,
                        outputs=[article_edit_status]
                    ).then(
                        fn=populate_article_edit,
                        inputs=[selected_article_id],
                        outputs=[article_edit_id, article_edit_title, article_edit_tags,
                                article_edit_summary, article_edit_content, article_edit_linked,
                                article_edit_link_search, article_edit_status]
                    )

                    article_edit_link_btn.click(
                        fn=add_case_to_article,
                        inputs=[selected_article_id, article_edit_selected_link_id],
                        outputs=[article_edit_status]
                    ).then(
                        fn=populate_article_edit,
                        inputs=[selected_article_id],
                        outputs=[article_edit_id, article_edit_title, article_edit_tags,
                                article_edit_summary, article_edit_content, article_edit_linked,
                                article_edit_link_search, article_edit_status]
                    )

                # ========================
                # 3. EXPORT / IMPORT TAB (PHASE 10 - placeholder)
                # ========================
                with gr.Tab("Export / Import"):
                    gr.Markdown("### Export Knowledge Base")
                    export_btn = gr.Button("Export as JSON", variant="primary")
                    export_status = gr.Textbox(
                        label="Status",
                        interactive=False,
                        value="Ready to export"
                    )

                    gr.Markdown("### Import Knowledge Base")
                    import_file = gr.File(label="Select JSON file")
                    import_btn = gr.Button("Import", variant="primary")
                    import_status = gr.Textbox(
                        label="Status",
                        interactive=False,
                        value="Ready to import"
                    )

                    def export_kb():
                        try:
                            articles = kb.list_articles()
                            cases = kb.list_cases()
                            data = {
                                "articles": [a.to_dict() for a in articles],
                                "cases": [c.to_dict() for c in cases]
                            }
                            return f"✅ Exported {len(articles)} articles, {len(cases)} cases"
                        except Exception as e:
                            return f"❌ Error: {str(e)}"

                    def import_kb(file_obj):
                        """Import KB from JSON file (PHASE 10)."""
                        if not file_obj:
                            return "❌ No file selected"
                        try:
                            import json
                            data = json.load(open(file_obj.name))
                            articles_count = len(data.get("articles", []))
                            cases_count = len(data.get("cases", []))
                            for a in data.get("articles", []):
                                kb.create_article(a["title"], a.get("summary", ""), a.get("content", ""), a.get("tags", []))
                            for c in data.get("cases", []):
                                kb.create_case(c["title"], c.get("summary", ""), c.get("content", ""), c.get("tags", []))
                            return f"✅ Imported {articles_count} articles, {cases_count} cases"
                        except Exception as e:
                            return f"❌ Error: {str(e)}"

                    export_btn.click(
                        fn=export_kb,
                        outputs=[export_status]
                    )

                    import_btn.click(
                        fn=import_kb,
                        inputs=[import_file],
                        outputs=[import_status]
                    )
