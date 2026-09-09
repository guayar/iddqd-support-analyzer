from __future__ import annotations

import html
import os

import gradio as gr

from actions import analyze as run_analyze
from actions import write_decoded_artifact_download
from config import APP_PORT, APP_TITLE, APP_VERSION, MAX_FILE_MB, OLLAMA_MODEL
from modules import (
    PLUGIN_ANONYMIZE,
    PLUGIN_ASSISTANT,
    PLUGIN_GENERAL_CHAT,
    RUNNING_PLUGINS,
    plugin_enabled,
    read_saved_plugins,
    restart_application,
    write_saved_plugins,
)
from uploads import InputError, should_clear_file_for_paste, should_clear_paste_for_file

DROP_HEIGHT = 220
CONTROL_HEIGHT = 128

ANONYMIZE_ON = plugin_enabled(PLUGIN_ANONYMIZE)
ASSISTANT_ON = plugin_enabled(PLUGIN_ASSISTANT)
GENERAL_CHAT_ON = plugin_enabled(PLUGIN_GENERAL_CHAT)

RESTART_HTML = (
    "<p class='psa-restart-warn'>Restart required for module changes to take effect.</p>"
    "<p>After restart the UI will disconnect — refresh the page.</p>"
)

CSS = """
.gradio-container {
    max-width: 1240px !important;
    margin: 0 auto !important;
    padding: 18px 28px 42px !important;
}
.wrap:has(.error),
.wrap:has(.validation-error) {
    display: none !important;
}
.psa-page,
#hero,
.psa-shell {
    width: 100% !important;
    max-width: 1180px !important;
    margin-left: auto !important;
    margin-right: auto !important;
}
#hero {
    margin: 0 auto 8px auto !important;
    padding: 0 !important;
}
.psa-shell {
    padding: 0 !important;
    background: transparent !important;
}
.psa-shell,
.psa-shell > div,
.psa-shell .block,
.psa-shell .form,
.psa-shell .panel,
.psa-shell .group,
.psa-shell .column,
.psa-shell .row,
.psa-chat,
.psa-chat .interface,
.psa-chat .column,
.psa-chat .block {
    width: 100% !important;
    max-width: 100% !important;
}
.psa-note {
    padding: 4px 0 10px 0 !important;
    margin: 0 !important;
    background: transparent !important;
    border: 0 !important;
}
#analysis-wrap {
    position: relative !important;
}
#copy-report-slot,
#copy-report-slot .html-container,
#copy-report-slot .prose,
#copy-report-slot .padded {
    height: 0 !important;
    min-height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
    border: 0 !important;
    background: transparent !important;
    overflow: visible !important;
}
.psa-copy-report {
    position: absolute !important;
    top: 10px !important;
    right: 12px !important;
    z-index: 5 !important;
    display: inline-flex !important;
    align-items: center !important;
    justify-content: center !important;
    width: 32px !important;
    height: 32px !important;
    padding: 0 !important;
    border: 1px solid var(--border-color-primary) !important;
    border-radius: 6px !important;
    background: var(--block-background-fill) !important;
    color: var(--body-text-color) !important;
    cursor: pointer !important;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.08) !important;
}
.psa-copy-report:hover {
    color: var(--body-text-color) !important;
    border-color: var(--color-accent) !important;
}
.psa-copy-report svg {
    width: 16px !important;
    height: 16px !important;
    display: block !important;
}
.psa-copy-report .psa-copy-check {
    display: none !important;
}
.psa-copy-report.is-copied .psa-copy-icon {
    display: none !important;
}
.psa-copy-report.is-copied .psa-copy-check {
    display: block !important;
    color: #16a34a !important;
}
#analysis {
    min-height: 210px !important;
    padding: 14px 48px 14px 16px !important;
    background: var(--block-background-fill) !important;
    color: var(--body-text-color) !important;
    border: 1px solid var(--border-color-primary) !important;
    border-radius: 8px !important;
    overflow: auto !important;
}
.psa-chat {
    display: flex !important;
    flex-direction: column !important;
    gap: 8px !important;
}
.psa-chat-tab .psa-note,
.psa-chat-tab .psa-assistant-controls,
.psa-chat-tab .psa-llm-meta {
    flex: 0 0 auto !important;
}
#assistant-chat,
#web-chat {
    height: min(32rem, calc(100dvh - 22rem)) !important;
    max-height: min(32rem, calc(100dvh - 22rem)) !important;
    min-height: 12rem !important;
    overflow: hidden !important;
}
#assistant-chat .bubble-wrap,
#web-chat .bubble-wrap {
    overflow-y: auto !important;
}
.psa-chat textarea {
    max-height: 6.5rem !important;
    overflow-y: auto !important;
    resize: none !important;
}
#paste-input textarea,
#anon-paste textarea {
    height: 198px !important;
    min-height: 198px !important;
    resize: none !important;
    background: var(--input-background-fill) !important;
    color: var(--body-text-color) !important;
}
#anon-preview textarea {
    height: 480px !important;
    min-height: 480px !important;
    background: var(--input-background-fill) !important;
    color: var(--body-text-color) !important;
}
.psa-shell .form,
.psa-shell .panel,
.psa-shell .group {
    background: transparent !important;
}
.psa-shell > div {
    background: transparent;
}
.psa-primary {
    min-height: 48px !important;
    width: 100% !important;
}
.psa-control {
    min-height: 128px !important;
}
.psa-mode {
    display: flex !important;
    flex-direction: column !important;
    align-items: center !important;
    justify-content: center !important;
    text-align: center !important;
}
.psa-mode [data-testid="block-info"] {
    display: block !important;
    width: 100% !important;
    text-align: center !important;
    margin: 0 0 8px 0 !important;
}
.psa-mode .wrap {
    display: flex !important;
    flex-wrap: wrap !important;
    gap: 8px !important;
    align-items: stretch !important;
    justify-content: center !important;
    width: 100% !important;
}
.psa-mode label {
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    gap: 8px !important;
    flex: 0 0 auto !important;
    min-height: 42px !important;
    margin: 0 !important;
    padding: 8px 12px !important;
    border: 1px solid var(--border-color-primary) !important;
    border-radius: 8px !important;
    background: var(--background-fill-primary) !important;
    color: var(--body-text-color) !important;
    font-size: 14px !important;
    font-weight: 500 !important;
    line-height: 1.2 !important;
    box-shadow: none !important;
    transform: none !important;
}
.psa-mode label > :where(*) + :where(*) {
    margin: 0 !important;
}
.psa-mode label.selected {
    background: var(--color-accent-soft, #fff4eb) !important;
    border-color: var(--color-accent) !important;
    color: inherit !important;
}
.psa-mode input[type="radio"] {
    appearance: none !important;
    -webkit-appearance: none !important;
    width: 16px !important;
    height: 16px !important;
    min-width: 16px !important;
    min-height: 16px !important;
    margin: 0 !important;
    padding: 0 !important;
    flex-shrink: 0 !important;
    border: 2px solid var(--border-color-primary) !important;
    border-radius: 50% !important;
    background: var(--input-background-fill) !important;
    background-image: none !important;
    box-shadow: none !important;
    position: relative !important;
}
.psa-mode input[type="radio"]:checked {
    border-color: var(--color-accent) !important;
    background-color: var(--input-background-fill) !important;
    background-image: none !important;
}
.psa-mode input[type="radio"]:checked::after {
    content: "" !important;
    width: 8px !important;
    height: 8px !important;
    border-radius: 50% !important;
    background: var(--color-accent) !important;
    position: absolute !important;
    top: 50% !important;
    left: 50% !important;
    transform: translate(-50%, -50%) !important;
}
.psa-restart-warn {
    color: var(--error-text-color, #b91c1c) !important;
    font-weight: 600 !important;
}
.psa-assistant-controls {
    gap: 8px !important;
}
.psa-context {
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    flex-wrap: wrap !important;
    gap: 10px 18px !important;
    margin: 6px 0 2px 0 !important;
    font-size: 16px !important;
    font-weight: 500 !important;
    line-height: 1.3 !important;
}
.psa-context-status {
    display: inline-flex !important;
    align-items: center !important;
    gap: 10px !important;
}
.psa-context-light {
    width: 12px !important;
    height: 12px !important;
    border-radius: 50% !important;
    flex-shrink: 0 !important;
}
.psa-model {
    font-size: 13px !important;
    font-weight: 400 !important;
    color: #6b7280 !important;
    line-height: 1.3 !important;
}
.psa-llm-meta {
    margin: 0 0 4px 0 !important;
    text-align: center !important;
}
.psa-context-off {
    background: #9ca3af !important;
}
.psa-context-on {
    background: #16a34a !important;
}
""" + f"""
footer button.settings::before {{
    content: "v{APP_VERSION} · ";
    font-weight: 400;
    opacity: 0.85;
}}
"""


COPY_REPORT_JS = """
() => {
  if (window.__psaCopyReportBound) return;
  window.__psaCopyReportBound = true;
  document.addEventListener("click", async (event) => {
    const btn = event.target && event.target.closest && event.target.closest("#psa-copy-report");
    if (!btn) return;
    event.preventDefault();
    const root = document.querySelector("#analysis");
    const text = ((root && root.innerText) || "").trim();
    if (!text) return;
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (e) {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      try { ok = document.execCommand("copy"); } catch (e2) { ok = false; }
      document.body.removeChild(ta);
    }
    if (!ok) return;
    btn.classList.add("is-copied");
    btn.setAttribute("aria-label", "Copied");
    window.setTimeout(() => {
      btn.classList.remove("is-copied");
      btn.setAttribute("aria-label", "Copy report");
    }, 1500);
  });
}
"""

COPY_REPORT_HTML = """
<button type="button" id="psa-copy-report" class="psa-copy-report" title="Copy report" aria-label="Copy report">
  <svg class="psa-copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <rect x="9" y="9" width="13" height="13" rx="2"></rect>
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
  </svg>
  <svg class="psa-copy-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M20 6 9 17l-5-5"></path>
  </svg>
</button>
"""


def _hero_text() -> str:
    extras = []
    if ANONYMIZE_ON:
        extras.append("optional log anonymizer")
    if ASSISTANT_ON:
        extras.append("optional local assistant")
    if GENERAL_CHAT_ON:
        extras.append("separate web-enabled general chat")
    extra = (" · " + " · ".join(extras)) if extras else ""
    return (
        "# IDDQD Support Analyzer\n"
        f"**Local SAML + `*.log` analysis{extra}**"
    )


def _model_hint(extra: str = "") -> str:
    suffix = f" · {html.escape(extra)}" if extra else ""
    return f"<span class='psa-model'>Model: {html.escape(OLLAMA_MODEL)}{suffix}</span>"


def _context_badge(attached) -> str:
    on = bool(attached)
    state = "on" if on else "off"
    label = "Analysis context attached" if on else "No analysis context attached"
    return (
        f"<p class='psa-context'>"
        f"<span class='psa-context-status'>"
        f"<span class='psa-context-light psa-context-{state}' aria-hidden='true'></span>"
        f"{label}</span>"
        f"{_model_hint()}</p>"
    )


def _restart_notice(saved: tuple[str, ...]) -> str:
    if set(saved) == set(RUNNING_PLUGINS):
        return ""
    return RESTART_HTML


def _ui_error(message: str):
    raise gr.Error(message, duration=8, print_exception=False)


def analyze(files, pasted, mode, signing_cert_file=None):
    try:
        markdown, raw_json, result = run_analyze(files, pasted, mode, signing_cert_file)
    except InputError as e:
        _ui_error(str(e))
    return markdown, raw_json, result, write_decoded_artifact_download(result)


def send_to_assistant(latest_analysis):
    from chats import empty_assistant_history

    if not latest_analysis:
        _ui_error("Analyze a log or SAML tracer first.")
    return latest_analysis, _context_badge(latest_analysis), empty_assistant_history()


def analyze_with_assistant(files, pasted, mode, signing_cert_file=None):
    markdown, raw_json, result, download = analyze(files, pasted, mode, signing_cert_file)
    ctx, badge, history = send_to_assistant(result)
    return markdown, raw_json, result, download, ctx, badge, history


def clear_assistant_context():
    from chats import empty_assistant_history
    from vision import SCOPE_ASSISTANT, clear_vision_cache

    clear_vision_cache(SCOPE_ASSISTANT)
    return None, _context_badge(None), empty_assistant_history()


def anonymize(file, pasted):
    from actions import anonymize as run_anonymize

    try:
        return run_anonymize(file, pasted)
    except InputError as e:
        _ui_error(str(e))


def _anon_file_chosen(file):
    return "" if should_clear_paste_for_file(file) else gr.update()


def _anon_text_chosen(text):
    return None if should_clear_file_for_paste(text) else gr.update()


def save_modules(anonymize_on: bool, assistant_on: bool, general_chat_on: bool):
    saved = write_saved_plugins(
        ([PLUGIN_ANONYMIZE] if anonymize_on else [])
        + ([PLUGIN_ASSISTANT] if assistant_on else [])
        + ([PLUGIN_GENERAL_CHAT] if general_chat_on else [])
    )
    return _restart_notice(saved)


def restart_clicked():
    restart_application()


with gr.Blocks(title=APP_TITLE, delete_cache=(3600, 3600)) as demo:
    analysis_state = gr.State(None)
    assistant_context = gr.State(None)
    with gr.Column(elem_classes=["psa-page"]):
        gr.Markdown(_hero_text(), elem_id="hero")

        with gr.Tabs():
            with gr.Tab("Analyze"):
                with gr.Column(elem_classes=["psa-shell"]):
                    with gr.Row(equal_height=True):
                        files = gr.File(
                            label="Upload SAML tracer / metadata XML / HAR / *.log",
                            file_count="multiple",
                            height=DROP_HEIGHT,
                            scale=1,
                        )
                        pasted = gr.Textbox(
                            label="or paste SAML / log text",
                            lines=9,
                            placeholder="Paste SAML tracer, metadata XML, Base64 SAMLRequest/SAMLResponse, Assertion, stack trace or *.log fragment…",
                            scale=1,
                            elem_id="paste-input",
                        )

                    with gr.Row(equal_height=True):
                        signing_cert = gr.File(
                            label="Signing certificate (optional) — X.509 .pem / .crt / .cer",
                            file_count="single",
                            file_types=[".pem", ".crt", ".cer"],
                            height=CONTROL_HEIGHT,
                            scale=1,
                            elem_classes=["psa-control"],
                        )
                        mode = gr.Radio(
                            ["Auto-detect", "SAML", "Log"],
                            value="Auto-detect",
                            label="Analyzer",
                            scale=1,
                            elem_classes=["psa-control", "psa-mode"],
                        )

                    run = gr.Button("Analyze", variant="primary", elem_classes=["psa-primary"])

                    gr.Markdown(
                        "Standalone certificate upload is used only for SAML XML Signature verification. "
                        "Upload the **public X.509 certificate**; private keys are not required or accepted.",
                        elem_classes=["psa-note"],
                    )

                    with gr.Column(elem_id="analysis-wrap"):
                        gr.HTML(COPY_REPORT_HTML, elem_id="copy-report-slot")
                        report = gr.Markdown(elem_id="analysis")
                    decoded_download = gr.File(label="Decoded SAML artifacts", interactive=False)

                    with gr.Accordion("Structured analyzer output (JSON)", open=False):
                        raw = gr.Code(label="JSON", language="json")

            if ANONYMIZE_ON:
                with gr.Tab("Anonymize log"):
                    with gr.Column(elem_classes=["psa-shell"]):
                        gr.Markdown(
                            "### Local log anonymizer\n"
                            "Creates a shareable pseudonymized copy while preserving timestamps, error codes and stack-trace "
                            "structure. A residual leak scan runs on the output. The mapping stays local and is not embedded in the output file.",
                            elem_classes=["psa-note"],
                        )
                        with gr.Row(equal_height=True):
                            anon_file = gr.File(
                                label="Drop a log/text file",
                                file_count="single",
                                height=DROP_HEIGHT,
                                scale=1,
                            )
                            anon_pasted = gr.Textbox(
                                label="or paste text",
                                lines=9,
                                placeholder="Paste a log fragment…",
                                scale=1,
                                elem_id="anon-paste",
                            )

                        anon_run = gr.Button("Anonymize", variant="primary", elem_classes=["psa-primary"])
                        anon_summary = gr.Markdown()
                        anon_preview = gr.Textbox(
                            label="Anonymized preview",
                            lines=18,
                            elem_id="anon-preview",
                        )
                        anon_download = gr.File(label="Download anonymized copy", interactive=False)
                        anon_decoded_download = gr.File(
                            label="Original decoded SAML (contains source data — do not share)",
                            interactive=False,
                        )
                        anon_xml_download = gr.File(
                            label="Anonymized SAML XML (after transform, before re-encode)",
                            interactive=False,
                        )

                        with gr.Accordion("Local replacement map — do NOT share this with the anonymized log", open=False):
                            anon_mapping = gr.Code(label="Mapping JSON", language="json")

                        anon_file.change(_anon_file_chosen, inputs=anon_file, outputs=anon_pasted)
                        anon_pasted.change(_anon_text_chosen, inputs=anon_pasted, outputs=anon_file)
                        anon_run.click(
                            anonymize,
                            inputs=[anon_file, anon_pasted],
                            outputs=[
                                anon_summary,
                                anon_preview,
                                anon_mapping,
                                anon_download,
                                anon_decoded_download,
                                anon_xml_download,
                            ],
                        )

            if ASSISTANT_ON:
                from chats import assistant_chat

                with gr.Tab("Assistant"):
                    with gr.Column(elem_classes=["psa-shell", "psa-chat-tab"]):
                        gr.Markdown(
                            "### Local Assistant\n"
                            "Everything in this tab stays between the browser, this application, local OCR and the local Ollama model. "
                            "**No web search.** Attach PNG/JPEG/WEBP screenshots (terminals, stack traces, admin consoles). "
                            "The latest Analyze result is available here automatically. "
                            "**Clear analysis context** removes it and resets this chat. "
                            "General Chat never receives that report, screenshots or OCR.",
                            elem_classes=["psa-note"],
                        )
                        with gr.Column(elem_classes=["psa-assistant-controls"]):
                            context_badge = gr.HTML(_context_badge(None))
                            clear_ctx = gr.Button("Clear analysis context")
                        with gr.Column(elem_classes=["psa-chat"]):
                            assistant_chatbot = gr.Chatbot(
                                height="min(32rem, calc(100dvh - 22rem))",
                                resizable=False,
                                label="Chat",
                                elem_id="assistant-chat",
                            )
                            gr.ChatInterface(
                                fn=assistant_chat,
                                multimodal=True,
                                chatbot=assistant_chatbot,
                                textbox=gr.MultimodalTextbox(
                                    file_count="multiple",
                                    file_types=[".png", ".jpg", ".jpeg", ".webp"],
                                    sources=["upload"],
                                    placeholder="Ask a question or attach a local screenshot…",
                                    max_plain_text_length=20000,
                                ),
                                additional_inputs=[assistant_context],
                                save_history=False,
                                fill_height=False,
                            )
                        clear_ctx.click(
                            clear_assistant_context,
                            inputs=[],
                            outputs=[assistant_context, context_badge, assistant_chatbot],
                        )

            if GENERAL_CHAT_ON:
                from chats import web_chat

                with gr.Tab("General Chat"):
                    with gr.Column(elem_classes=["psa-shell", "psa-chat-tab"]):
                        gr.Markdown(
                            "### Web-enabled General Chat\n"
                            "This tab is a **separate module**. It may send **text search queries** to public search providers "
                            "(Google, Brave, DuckDuckGo, Wikipedia and others; see `WEB_SEARCH_BACKEND`). "
                            "Attach a local PNG/JPEG/WEBP (for example a product photo): pixels stay on this machine. "
                            "It receives **no Analyzer or Assistant context, screenshots or OCR**. "
                            "Do not paste customer logs, credentials or other sensitive data here; use **Assistant** for that.",
                            elem_classes=["psa-note"],
                        )
                        with gr.Column(elem_classes=["psa-chat"]):
                            gr.HTML(
                                f"<p class='psa-llm-meta'>{_model_hint('Web search enabled')}</p>"
                            )
                            web_chatbot = gr.Chatbot(
                                height="min(32rem, calc(100dvh - 22rem))",
                                resizable=False,
                                label="Chat",
                                elem_id="web-chat",
                            )
                            gr.ChatInterface(
                                fn=web_chat,
                                multimodal=True,
                                chatbot=web_chatbot,
                                textbox=gr.MultimodalTextbox(
                                    file_count="multiple",
                                    file_types=[".png", ".jpg", ".jpeg", ".webp"],
                                    sources=["upload"],
                                    placeholder="Ask a public question or attach a local product photo…",
                                    max_plain_text_length=20000,
                                ),
                                save_history=False,
                                fill_height=False,
                            )

            with gr.Tab("Config"):
                with gr.Column(elem_classes=["psa-shell"]):
                    gr.Markdown(
                        "### Modules\n"
                        "Analyze and Config are always available. Optional modules load only after **Restart application** and a browser refresh. "
                        "Default UI: Analyze + Config. No optional modules are enabled by default.",
                        elem_classes=["psa-note"],
                    )
                    saved = read_saved_plugins()
                    anon_box = gr.Checkbox(
                        label="Anonymize",
                        info="Local log and SAML pseudonymization. No language model.",
                        value=PLUGIN_ANONYMIZE in saved,
                    )
                    assistant_box = gr.Checkbox(
                        label="Assistant",
                        info="Requires local Ollama. Sees the latest Analyze result and local screenshots. No web search.",
                        value=PLUGIN_ASSISTANT in saved,
                    )
                    general_chat_box = gr.Checkbox(
                        label="General Chat",
                        info="Requires local Ollama. Public web search. Optional local images stay on this tab; only text queries leave the machine. Never receives Analyzer or Assistant material.",
                        value=PLUGIN_GENERAL_CHAT in saved,
                    )
                    restart_md = gr.Markdown(_restart_notice(saved))
                    restart_btn = gr.Button("Restart application", variant="primary", elem_classes=["psa-primary"])
                    anon_box.change(
                        save_modules,
                        inputs=[anon_box, assistant_box, general_chat_box],
                        outputs=[restart_md],
                    )
                    assistant_box.change(
                        save_modules,
                        inputs=[anon_box, assistant_box, general_chat_box],
                        outputs=[restart_md],
                    )
                    general_chat_box.change(
                        save_modules,
                        inputs=[anon_box, assistant_box, general_chat_box],
                        outputs=[restart_md],
                    )
                    restart_btn.click(restart_clicked)

            if ASSISTANT_ON:
                run.click(
                    analyze_with_assistant,
                    inputs=[files, pasted, mode, signing_cert],
                    outputs=[report, raw, analysis_state, decoded_download, assistant_context, context_badge, assistant_chatbot],
                )
            else:
                run.click(analyze, inputs=[files, pasted, mode, signing_cert], outputs=[report, raw, analysis_state, decoded_download])

            demo.load(fn=None, js=COPY_REPORT_JS)


if __name__ == "__main__":
    auth = None
    if os.getenv("BASIC_AUTH_USER") and os.getenv("BASIC_AUTH_PASS"):
        auth = (os.environ["BASIC_AUTH_USER"], os.environ["BASIC_AUTH_PASS"])
    demo.launch(
        server_name="127.0.0.1",
        server_port=APP_PORT,
        auth=auth,
        show_error=False,
        footer_links=["settings"],
        css=CSS,
        max_file_size=f"{MAX_FILE_MB}mb",
    )
