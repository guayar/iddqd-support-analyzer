from __future__ import annotations

import os

import gradio as gr

from actions import analyze as run_analyze
from config import APP_PORT, APP_TITLE, APP_VERSION, MAX_FILE_MB
from modules import (
    PLUGIN_ANONYMIZE,
    PLUGIN_LLM,
    RUNNING_PLUGINS,
    plugin_enabled,
    read_saved_plugins,
    restart_application,
    write_saved_plugins,
)
from uploads import InputError

DROP_HEIGHT = 220
CHAT_HEIGHT = 480
CONTROL_HEIGHT = 128

ANONYMIZE_ON = plugin_enabled(PLUGIN_ANONYMIZE)
LLM_ON = plugin_enabled(PLUGIN_LLM)

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
.psa-chat {
    width: 100% !important;
    max-width: 100% !important;
}
.psa-note {
    padding: 4px 0 10px 0 !important;
    margin: 0 !important;
    background: transparent !important;
    border: 0 !important;
}
#analysis {
    min-height: 210px !important;
    padding: 14px 16px !important;
    background: white !important;
    border: 1px solid var(--border-color-primary) !important;
    border-radius: 8px !important;
    overflow: auto !important;
}
#assistant-chat,
#web-chat {
    height: 480px !important;
    min-height: 480px !important;
}
#paste-input textarea,
#anon-paste textarea {
    height: 198px !important;
    min-height: 198px !important;
    resize: none !important;
    background: white !important;
}
#anon-preview textarea {
    height: 480px !important;
    min-height: 480px !important;
    background: white !important;
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
    background: white !important;
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
    border: 2px solid #9ca3af !important;
    border-radius: 50% !important;
    background: white !important;
    background-image: none !important;
    box-shadow: none !important;
    position: relative !important;
}
.psa-mode input[type="radio"]:checked {
    border-color: var(--color-accent) !important;
    background-color: white !important;
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
    color: #b91c1c !important;
    font-weight: 600 !important;
}
""" + f"""
footer button.settings::before {{
    content: "v{APP_VERSION} · ";
    font-weight: 400;
    opacity: 0.85;
}}
"""


def _hero_text() -> str:
    extras = []
    if ANONYMIZE_ON:
        extras.append("optional log anonymizer")
    if LLM_ON:
        extras.append("optional local assistant")
        extras.append("separate web-enabled general chat")
    extra = (" · " + " · ".join(extras)) if extras else ""
    return (
        "# IDDQD Support Analyzer\n"
        f"**Local SAML + `*.log` analysis{extra}**"
    )


def _context_badge(result, detached: bool) -> str:
    if result and not detached:
        return "Analysis context attached"
    return "No analysis context attached"


def _restart_notice(saved: tuple[str, ...]) -> str:
    if set(saved) == set(RUNNING_PLUGINS):
        return ""
    return RESTART_HTML


def analyze(files, pasted, mode, signing_cert_file=None):
    try:
        md, raw, result = run_analyze(files, pasted, mode, signing_cert_file)
    except InputError as e:
        raise gr.Error(str(e)) from e
    if LLM_ON:
        return md, raw, result, False, _context_badge(result, False)
    return md, raw, result


def anonymize(file, pasted):
    from actions import anonymize as run_anonymize

    try:
        return run_anonymize(file, pasted)
    except InputError as e:
        raise gr.Error(str(e)) from e


def save_modules(anonymize_on: bool, llm_on: bool):
    saved = write_saved_plugins(
        ([PLUGIN_ANONYMIZE] if anonymize_on else []) + ([PLUGIN_LLM] if llm_on else [])
    )
    return _restart_notice(saved)


def restart_clicked():
    restart_application()


def clear_assistant_context(analysis_state):
    return True, _context_badge(analysis_state, True)


with gr.Blocks(title=APP_TITLE, delete_cache=(3600, 3600)) as demo:
    analysis_state = gr.State(None)
    assistant_detached = gr.State(False)
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

                    report = gr.Markdown(elem_id="analysis")

                    with gr.Accordion("Structured analyzer output (JSON)", open=False):
                        raw = gr.Code(label="JSON", language="json")

                    if not LLM_ON:
                        run.click(analyze, inputs=[files, pasted, mode, signing_cert], outputs=[report, raw, analysis_state])

            if ANONYMIZE_ON:
                with gr.Tab("Anonymize log"):
                    with gr.Column(elem_classes=["psa-shell"]):
                        gr.Markdown(
                            "### Local log anonymizer\n"
                            "Creates a shareable pseudonymized copy while preserving timestamps, error codes and stack-trace "
                            "structure. The mapping stays local and is not embedded in the output file.",
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

                        with gr.Accordion("Local replacement map — do NOT share this with the anonymized log", open=False):
                            anon_mapping = gr.Code(label="Mapping JSON", language="json")

                        anon_run.click(
                            anonymize,
                            inputs=[anon_file, anon_pasted],
                            outputs=[anon_summary, anon_preview, anon_mapping, anon_download],
                        )

            if LLM_ON:
                from chats import assistant_chat, web_chat

                with gr.Tab("Assistant"):
                    with gr.Column(elem_classes=["psa-shell"]):
                        gr.Markdown(
                            "### Local Assistant\n"
                            "Everything in this tab stays between the browser, this application and the local Ollama model. "
                            "**No web search.** The current Analyze report is attached automatically; use **Clear analysis context** "
                            "to chat without it. Do not paste secrets into General Chat.",
                            elem_classes=["psa-note"],
                        )
                        assistant_mode = gr.Radio(
                            ["General", "Support Mail", "Code"],
                            value="General",
                            label="Mode",
                        )
                        context_badge = gr.Markdown(_context_badge(None, False))
                        clear_ctx = gr.Button("Clear analysis context")
                        with gr.Column(elem_classes=["psa-chat"]):
                            assistant_chatbot = gr.Chatbot(height=CHAT_HEIGHT, label="Chat", elem_id="assistant-chat")
                            gr.ChatInterface(
                                fn=assistant_chat,
                                chatbot=assistant_chatbot,
                                additional_inputs=[assistant_mode, analysis_state, assistant_detached],
                                save_history=False,
                            )
                        clear_ctx.click(clear_assistant_context, inputs=[analysis_state], outputs=[assistant_detached, context_badge])
                        run.click(
                            analyze,
                            inputs=[files, pasted, mode, signing_cert],
                            outputs=[report, raw, analysis_state, assistant_detached, context_badge],
                        )

                with gr.Tab("General Chat"):
                    with gr.Column(elem_classes=["psa-shell"]):
                        gr.Markdown(
                            "### Web-enabled General Chat\n"
                            "This tab is deliberately separate. It may send **search queries** to public search providers. "
                            "It receives **no Analyzer or Assistant context**. Do not paste customer logs, credentials or other "
                            "sensitive data here; use **Assistant** for that.",
                            elem_classes=["psa-note"],
                        )
                        with gr.Column(elem_classes=["psa-chat"]):
                            web_chatbot = gr.Chatbot(height=CHAT_HEIGHT, label="Chat", elem_id="web-chat")
                            gr.ChatInterface(fn=web_chat, chatbot=web_chatbot, save_history=False)

            with gr.Tab("Config"):
                with gr.Column(elem_classes=["psa-shell"]):
                    gr.Markdown(
                        "### Modules\n"
                        "Analyze is always available. Optional modules load only after **Restart application** and a browser refresh. "
                        "Default is Analyze only.",
                        elem_classes=["psa-note"],
                    )
                    saved = read_saved_plugins()
                    anon_box = gr.Checkbox(
                        label="Anonymize",
                        info="Local log and SAML pseudonymization. No language model.",
                        value=PLUGIN_ANONYMIZE in saved,
                    )
                    llm_box = gr.Checkbox(
                        label="Assistant and General Chat",
                        info="Requires local Ollama. Assistant can read the Analyze report. General Chat can use the web and never receives that report.",
                        value=PLUGIN_LLM in saved,
                    )
                    restart_md = gr.Markdown(_restart_notice(saved))
                    restart_btn = gr.Button("Restart application", variant="primary", elem_classes=["psa-primary"])
                    anon_box.change(save_modules, inputs=[anon_box, llm_box], outputs=[restart_md])
                    llm_box.change(save_modules, inputs=[anon_box, llm_box], outputs=[restart_md])
                    restart_btn.click(restart_clicked)


if __name__ == "__main__":
    auth = None
    if os.getenv("BASIC_AUTH_USER") and os.getenv("BASIC_AUTH_PASS"):
        auth = (os.environ["BASIC_AUTH_USER"], os.environ["BASIC_AUTH_PASS"])
    demo.launch(
        server_name="127.0.0.1",
        server_port=APP_PORT,
        auth=auth,
        show_error=True,
        footer_links=["settings"],
        css=CSS,
        max_file_size=f"{MAX_FILE_MB}mb",
    )
