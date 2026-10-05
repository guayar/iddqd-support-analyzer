"""Articles-only Knowledge Base UI."""
import json
import uuid
from pathlib import Path

import gradio as gr

from analyzers.kb_actions import KnowledgeBaseActions
from kb_rendering import render_search_articles_table

kb = KnowledgeBaseActions()
PAGE_SIZE = 10


def build_kb_tab():
    with gr.Tab("Knowledge Base"):
        selected_article_id = gr.State(None)
        query_state = gr.State("")
        page_state = gr.State(1)
        article_view_mode = gr.State("view")
        with gr.Column(elem_classes=["psa-shell"]):
            gr.Markdown("# Knowledge Base\nCreate, find and edit Articles.")
            with gr.Tabs(elem_classes=["psa-kb-tabs"]):
                with gr.Tab("Create"):
                    create_title = gr.Textbox(label="Title")
                    create_tags = gr.Textbox(label="Tags (comma-separated)")
                    create_summary = gr.Textbox(label="Summary", lines=3)
                    create_content = gr.Textbox(label="Content (Markdown)", lines=8)
                    create_btn = gr.Button("Create Article", variant="primary")
                    create_status = gr.Textbox(label="Status", interactive=False)

                with gr.Tab("Search / View") as search_tab:
                    with gr.Row():
                        search_box = gr.Textbox(label="Search", placeholder="AN00000001 or keyword", scale=3)
                        search_btn = gr.Button("Search", variant="primary", scale=1)
                    with gr.Row():
                        count = gr.Textbox(label="Total Articles", interactive=False)
                        page_label = gr.Textbox(label="Page", interactive=False)
                    article_results_table = gr.Dataframe(
                        headers=["Selected", "ID", "Title", "Summary"],
                        interactive=False, column_count=(4, "fixed"), label="Articles")
                    with gr.Row():
                        prev_btn = gr.Button("< Previous")
                        next_btn = gr.Button("Next >")
                    with gr.Group() as article_view_group:
                        gr.Markdown("### Article View")
                        view_id = gr.Textbox(label="ID", interactive=False)
                        view_title = gr.Textbox(label="Title", interactive=False)
                        view_tags = gr.Textbox(label="Tags", interactive=False)
                        view_summary = gr.Textbox(label="Summary", lines=3, interactive=False)
                        view_content = gr.Textbox(label="Content", lines=8, interactive=False)
                        with gr.Row():
                            edit_btn = gr.Button("Edit")
                            delete_btn = gr.Button("Delete", variant="stop")
                    with gr.Group(visible=False) as article_edit_group:
                        gr.Markdown("### Article Edit")
                        edit_id = gr.Textbox(label="ID", interactive=False)
                        edit_title = gr.Textbox(label="Title")
                        edit_tags = gr.Textbox(label="Tags (comma-separated)")
                        edit_summary = gr.Textbox(label="Summary", lines=3)
                        edit_content = gr.Textbox(label="Content", lines=8)
                        with gr.Row():
                            save_btn = gr.Button("Save", variant="primary")
                            cancel_btn = gr.Button("Cancel")
                    status = gr.Textbox(label="Status", interactive=False)

                with gr.Tab("Export / Import"):
                    export_btn = gr.Button("Export as JSON", variant="primary")
                    export_file = gr.File(label="Download Articles", interactive=False, height=220)
                    export_status = gr.Textbox(label="Status", interactive=False)
                    import_file = gr.File(label="Select JSON file", file_types=[".json"], type="filepath", height=220)
                    import_btn = gr.Button("Import", variant="primary")
                    import_status = gr.Textbox(label="Status", interactive=False)

            view_fields = [view_id, view_title, view_tags, view_summary, view_content]
            edit_fields = [edit_id, edit_title, edit_tags, edit_summary, edit_content]
            mode_outputs = [article_view_mode, article_view_group, article_edit_group]

            def tags_from_text(text):
                return list(dict.fromkeys(tag.strip() for tag in (text or "").split(",") if tag.strip()))

            def article_fields(article_id):
                article = kb.get_article(article_id) if article_id else None
                if article is None:
                    return "", "", "", "", ""
                return article.display_id, article.title, ", ".join(article.tags), article.summary or "", article.content

            def toggle_article_view():
                return "view", gr.update(visible=True), gr.update(visible=False)

            def toggle_article_edit(article_id):
                if not article_id or kb.get_article(article_id) is None:
                    return (gr.skip(),) * 8 + ("❌ Select an Article",)
                return (*article_fields(article_id), "edit", gr.update(visible=False), gr.update(visible=True), "")

            def render_page(query, page, selected=None):
                query = (query or "").strip()
                articles = kb.search_articles(query, limit=10000) if query else kb.list_articles()
                pages = max(1, (len(articles) + PAGE_SIZE - 1) // PAGE_SIZE)
                page = max(1, min(page, pages))
                table = render_search_articles_table(articles[(page - 1) * PAGE_SIZE:page * PAGE_SIZE], selected)[0]
                return table, len(articles), f"{page} / {pages}", page

            def perform_search(query):
                return (*render_page(query, 1), (query or "").strip(), None,
                        *article_fields(None), *toggle_article_view(), "")

            def previous_page(query, page, selected):
                return render_page(query, page - 1, selected)

            def next_page(query, page, selected):
                return render_page(query, page + 1, selected)

            def reload_article_results(query, page, selected):
                return render_page(query, page, selected)

            def load_article_view_full(evt: gr.SelectData):
                if evt is None or not evt.row_value or len(evt.row_value) < 2:
                    return (gr.skip(),) * 9
                article = kb.get_article_by_display_id(evt.row_value[1])
                if article is None:
                    return (gr.skip(),) * 9
                return (*article_fields(article.id), article.id, *toggle_article_view())

            def create_article(title, tags, summary, content):
                if not (title or "").strip() or not (content or "").strip():
                    return "❌ Title and Content required"
                try:
                    article_id = kb.create_article(title=title.strip(), content=content,
                                                   summary=summary or "", tags=tags_from_text(tags))
                    return f"✅ Created {kb.get_article(article_id).display_id}"
                except Exception as exc:
                    return f"❌ Error: {exc}"

            def save_article(article_id, title, tags, summary, content):
                if not article_id or not (title or "").strip() or not (content or "").strip():
                    return (gr.skip(),) * 8 + ("❌ ID, Title and Content required",)
                try:
                    saved = kb.update_article(article_id, title=title.strip(), content=content,
                                              summary=summary or "", tags=tags_from_text(tags))
                    if not saved:
                        return (gr.skip(),) * 8 + ("❌ Article no longer exists",)
                    return (*article_fields(article_id), *toggle_article_view(), "✅ Article saved")
                except Exception as exc:
                    return (gr.skip(),) * 8 + (f"❌ Error: {exc}",)

            def delete_article(article_id):
                if not article_id or kb.get_article(article_id) is None:
                    return (gr.skip(),) * 9 + ("❌ Select an Article",)
                kb.delete_article(article_id)
                return (*article_fields(None), None, *toggle_article_view(), "✅ Article deleted")

            def export_kb():
                articles = []
                for article in kb.list_articles():
                    record = article.to_dict()
                    record.pop("related_article_ids", None)
                    articles.append(record)
                path = Path("output") / f"articles-{uuid.uuid4().hex}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({"articles": articles}, ensure_ascii=False, indent=2), encoding="utf-8")
                return str(path.resolve()), f"✅ Exported {len(articles)} Articles"

            def import_kb(file_path):
                if not file_path:
                    return "❌ Select a JSON file"
                try:
                    data = json.loads(Path(file_path).read_text(encoding="utf-8-sig"))
                    if not isinstance(data, dict) or "articles" not in data:
                        return "❌ Invalid Articles file"
                    articles = data["articles"]
                    if not isinstance(articles, list) or any(
                        not isinstance(a, dict) or not isinstance(a.get("title"), str)
                        or not a["title"].strip() or not isinstance(a.get("content"), str)
                        or not a["content"].strip() or not isinstance(a.get("tags", []), list)
                        or (a.get("summary") is not None and not isinstance(a["summary"], str))
                        or any(not isinstance(tag, str) for tag in a.get("tags", [])) for a in articles
                    ):
                        return "❌ Invalid Articles file"
                    kb.storage.import_articles(articles)
                    return f"✅ Imported {len(articles)} Articles"
                except Exception as exc:
                    return f"❌ Error: {exc}"

            list_inputs = [query_state, page_state, selected_article_id]
            list_outputs = [article_results_table, count, page_label, page_state]
            search_tab.select(reload_article_results, list_inputs, list_outputs)
            create_btn.click(create_article, [create_title, create_tags, create_summary, create_content], create_status).then(
                reload_article_results, list_inputs, list_outputs)
            search_btn.click(perform_search, search_box,
                             list_outputs + [query_state, selected_article_id] + view_fields + mode_outputs + [status])
            prev_btn.click(previous_page, list_inputs, list_outputs)
            next_btn.click(next_page, list_inputs, list_outputs)
            article_results_table.select(load_article_view_full,
                                         outputs=view_fields + [selected_article_id] + mode_outputs).then(
                reload_article_results, list_inputs, list_outputs)
            edit_btn.click(toggle_article_edit, selected_article_id, edit_fields + mode_outputs + [status])
            cancel_btn.click(toggle_article_view, outputs=mode_outputs)
            save_btn.click(save_article, [selected_article_id, edit_title, edit_tags, edit_summary, edit_content],
                           view_fields + mode_outputs + [status]).then(reload_article_results, list_inputs, list_outputs)
            delete_btn.click(delete_article, selected_article_id,
                             view_fields + [selected_article_id] + mode_outputs + [status]).then(
                reload_article_results, list_inputs, list_outputs)
            export_btn.click(export_kb, outputs=[export_file, export_status])
            import_btn.click(import_kb, import_file, import_status).then(reload_article_results, list_inputs, list_outputs)
