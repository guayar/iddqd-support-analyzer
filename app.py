from __future__ import annotations

import os

import gradio as gr

from actions import analyze as run_analyze
from actions import anonymize as run_anonymize
from chats import analysis_chat, assistant_chat, web_chat
from config import APP_PORT, APP_TITLE, MAX_FILE_MB
from uploads import InputError

CSS = """
.gradio-container {
    max-width: 1240px !important;
    margin: 0 auto !important;
    padding: 18px 28px 42px !important;
}
#hero {
    max-width: 1180px !important;
    margin: 0 auto 8px auto !important;
    padding: 0 !important;
}
.psa-shell {
    width: 100% !important;
    max-width: 1180px !important;
    margin: 0 auto !important;
    padding: 0 !important;
    background: transparent !important;
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
#analysis-chat, #assistant-chat, #web-chat {
    min-height: 500px !important;
}
#anon-preview textarea, #paste-input textarea, #anon-paste textarea {
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
"""


def analyze(files, pasted, mode, signing_cert_file=None):
    try:
        return run_analyze(files, pasted, mode, signing_cert_file)
    except InputError as e:
        raise gr.Error(str(e)) from e


def anonymize(file, pasted):
    try:
        return run_anonymize(file, pasted)
    except InputError as e:
        raise gr.Error(str(e)) from e


with gr.Blocks(title=APP_TITLE, delete_cache=(3600, 3600)) as demo:
    state = gr.State(None)
    gr.Markdown(
        "# IDDQD Support Analyzer\n"
        "**Local SAML + `*.log` analysis · private local assistant · separate web-enabled general chat · log anonymizer**",
        elem_id="hero",
    )

    with gr.Tabs():
        with gr.Tab("Analyze"):
            with gr.Column(elem_classes=["psa-shell"]):
                with gr.Row(equal_height=True):
                    files = gr.File(
                        label="Upload SAML tracer / metadata XML / HAR / *.log",
                        file_count="multiple",
                        height=235,
                        scale=1,
                    )
                    pasted = gr.Textbox(
                        label="or paste SAML / log text",
                        lines=10,
                        placeholder="Paste SAML tracer, metadata XML, Base64 SAMLRequest/SAMLResponse, Assertion, stack trace or *.log fragment…",
                        scale=1,
                        elem_id="paste-input",
                    )

                with gr.Row(equal_height=True):
                    signing_cert = gr.File(
                        label="Signing certificate (optional) — X.509 .pem / .crt / .cer",
                        file_count="single",
                        file_types=[".pem", ".crt", ".cer"],
                        height=110,
                        scale=2,
                    )
                    mode = gr.Radio(
                        ["Auto-detect", "SAML", "Log"],
                        value="Auto-detect",
                        label="Analyzer",
                        scale=3,
                    )
                    run = gr.Button("Analyze", variant="primary", scale=1, min_width=180)

                gr.Markdown(
                    "Standalone certificate upload is used only for SAML XML Signature verification. "
                    "Upload the **public X.509 certificate**; private keys are not required or accepted.",
                    elem_classes=["psa-note"],
                )

                report = gr.Markdown(elem_id="analysis")

                with gr.Accordion("Structured analyzer output (JSON)", open=False):
                    raw = gr.Code(label="JSON", language="json")

                gr.Markdown(
                    "### Ask about this analysis\n"
                    "Examples: **napisz maila do supportu po angielsku**, **zrób raport techniczny**, "
                    "**który błąd jest root cause?**, **porównaj metadata/ACS/Audience/Destination/Issuer**"
                )
                analysis_chatbot = gr.Chatbot(height=500, label="Chat", elem_id="analysis-chat")
                gr.ChatInterface(
                    fn=analysis_chat,
                    chatbot=analysis_chatbot,
                    additional_inputs=[state],
                    save_history=False,
                )
                run.click(analyze, inputs=[files, pasted, mode, signing_cert], outputs=[report, raw, state])

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
                        height=235,
                        scale=1,
                    )
                    anon_pasted = gr.Textbox(
                        label="or paste text",
                        lines=10,
                        placeholder="Paste a log fragment…",
                        scale=1,
                        elem_id="anon-paste",
                    )

                anon_run = gr.Button("Anonymize", variant="primary")
                anon_summary = gr.Markdown()
                anon_preview = gr.Textbox(
                    label="Anonymized preview",
                    lines=20,
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
        with gr.Tab("Assistant"):
            with gr.Column(elem_classes=["psa-shell"]):
                gr.Markdown(
                    "### 🔒 Local Assistant\n"
                    "Everything in this tab stays between the browser, this application and the local Ollama model. "
                    "**No web search.** Use it for sensitive analysis, support mail and coding.",
                    elem_classes=["psa-note"],
                )
                assistant_mode = gr.Radio(
                    ["General", "Support Mail", "Code"],
                    value="General",
                    label="Mode",
                )
                assistant_chatbot = gr.Chatbot(height=500, label="Chat", elem_id="assistant-chat")
                gr.ChatInterface(
                    fn=assistant_chat,
                    chatbot=assistant_chatbot,
                    additional_inputs=[assistant_mode],
                    save_history=False,
                )

        with gr.Tab("General Chat 🌐"):
            with gr.Column(elem_classes=["psa-shell"]):
                gr.Markdown(
                    "### 🌐 Web-enabled General Chat\n"
                    "This tab is deliberately separate. It may send **search queries** to public search providers. "
                    "It receives **no Analyzer or Assistant context**. Do not paste customer logs, credentials or other "
                    "sensitive data here; use **Assistant** for that.",
                    elem_classes=["psa-note"],
                )
                web_chatbot = gr.Chatbot(height=500, label="Chat", elem_id="web-chat")
                gr.ChatInterface(fn=web_chat, chatbot=web_chatbot, save_history=False)


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
