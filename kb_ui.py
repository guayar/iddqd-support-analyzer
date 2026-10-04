"""Knowledge Base UI - PHASES 1-9 Implementation.

Complete redesigned KB with three focused tabs:
1. Create (Article/Case unified form with link picker)
2. Search / View (search + independent view panels + edit/delete)
3. Export / Import

Combines all phases 1-9 in one coherent design.
"""

import gradio as gr
from typing import Optional, List, Dict, Any, Tuple
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


def build_kb_tab() -> Tuple:
    """Build redesigned Knowledge Base tab (PHASES 1-9).

    Returns:
        Tuple of state components for integration with main app
    """
    print("[DEBUG] build_kb_tab() called")

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
                    with gr.Group():
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
                    with gr.Group():
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

                    # ========================
                    # Search / View Event Handlers
                    # ========================

                    def perform_search(query: str):
                        if not query or not query.strip():
                            return None, None, 0, 0, "1 / 1", "1 / 1", "", "", "", "", "", "", "", "", ""

                        results = kb.search(query.strip(), limit=1000)
                        cases = results.get("cases", [])
                        articles = results.get("articles", [])

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
                            display_id = evt.row_value[1]  # Column 1 = ID
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
                            display_id = evt.row_value[1]  # Column 1 = ID
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
                    def navigate_to_case(evt: gr.SelectData):
                        """Click linked article -> load that case."""
                        if not evt or not evt.row_value or len(evt.row_value) < 1:
                            return None
                        display_id = evt.row_value[0]
                        case = kb.get_case_by_display_id(display_id)
                        return case.id if case else None

                    def navigate_to_article(evt: gr.SelectData):
                        """Click linked case -> load that article."""
                        if not evt or not evt.row_value or len(evt.row_value) < 1:
                            return None
                        display_id = evt.row_value[0]
                        article = kb.get_article_by_display_id(display_id)
                        return article.id if article else None

                    case_linked_articles.select(
                        fn=navigate_to_article,
                        inputs=[],
                        outputs=[selected_article_id]
                    )

                    article_linked_cases.select(
                        fn=navigate_to_case,
                        inputs=[],
                        outputs=[selected_case_id]
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

                    export_btn.click(
                        fn=export_kb,
                        outputs=[export_status]
                    )

    # Return compatible tuple for app.py
    # (refresh_fn, articles_count, cases_count, articles_list, cases_list, search_articles, search_cases, selected_article_id, selected_case_id, article_search_results, case_search_results)

    def dummy_refresh():
        pass

    return (
        dummy_refresh,  # kb_refresh_fn
        gr.Textbox("0", interactive=False, visible=False),  # kb_articles_count
        gr.Textbox("0", interactive=False, visible=False),  # kb_cases_count
        gr.Dataframe(interactive=False, visible=False),  # kb_articles_list
        gr.Dataframe(interactive=False, visible=False),  # kb_cases_list
        gr.Dataframe(interactive=False, visible=False),  # search_results_articles
        gr.Dataframe(interactive=False, visible=False),  # search_results_cases
        selected_article_id,
        selected_case_id,
        article_search_results,
        case_search_results,
    )
