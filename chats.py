from __future__ import annotations

import json
from datetime import date
from typing import Any

import requests

from llm import complete, llm_unavailable

ASSISTANT_CONTEXT_MAX = 120_000
# Leave room for the analyzer JSON after source files are packed.
ASSISTANT_SOURCES_BUDGET = 60_000
ASSISTANT_SOURCE_MIN_SHARE = 2_000
# Vision turns spend tokens on pixels; keep Analyze text smaller so Ollama accepts the request.
ASSISTANT_CONTEXT_MAX_WITH_IMAGE = 48_000
ASSISTANT_SOURCES_BUDGET_WITH_IMAGE = 24_000
ASSISTANT_SOURCE_MIN_SHARE_WITH_IMAGE = 1_200

ASSISTANT_SYSTEM = """You are a private local technical assistant running on the user's Ubuntu workstation.
You have no web-search tool and must never claim to have checked the internet or current external documentation.
Be concise, technically precise, and practical. If uncertain, say what is uncertain.
Match the task in the user's message: technical troubleshooting, enterprise support-mail drafts, or code.
For programming questions, prioritize Java, TypeScript, Python and Playwright when relevant.
Do not invent APIs, command results, files, logs, or execution results.
When drafting support mail: preserve the user's meaning and technical facts; do not invent completed checks, root causes, customer actions, dates, or results; avoid robotic phrasing; when useful structure as context/findings, what was verified, next step/request; do not expose implementation details.
Do not claim code was executed unless execution output was actually provided.
You may receive screenshots of terminals, logs, admin consoles or error dialogs.
Use both the original image pixels and any LOCAL OCR EXTRACT.
OCR is imperfect (0 vs O, 1 vs l vs I, punctuation, URLs). Prefer the image when OCR and pixels conflict.
Never treat OCR as a second Analyzer. Never send images, OCR or Analyzer JSON to the public web.
"""

WEB_SYSTEM = """You are a web-enabled general assistant. The language model itself runs locally.
When WEB SEARCH RESULTS are supplied, use them as external evidence. Current date: {today}.
When no search results are supplied, answer from the conversation and any local image only. Do not invent web sources or claim you searched.
Answer in the user's language unless asked otherwise.
For technical questions, prefer official documentation, vendor documentation, release notes and primary sources over blogs.
Do not fabricate facts or sources. If the search evidence is insufficient or conflicting, say so.
Cite factual web-derived claims inline using source markers like [S1], [S2]. Do not invent markers that are not in the supplied material.
This General Chat is intentionally a separate module from the private Analyzer and Assistant. Never imply you can see content from those tabs.
You may receive a local image on this tab only (for example a product photo). Use the pixels and any LOCAL OCR EXTRACT.
OCR is imperfect and often garbage on photos. Prefer the image when OCR and pixels conflict. Never turn OCR fragments into web queries yourself.
Image bytes stay on this machine. Only application-generated text search queries are sent to public search providers. Never claim the image file was uploaded to the web.
Never treat this image as Analyzer output or an Assistant screenshot.
"""


def _content_text(content) -> str:
    """Flatten Gradio 6 Chatbot content (str or list of text blocks) to a string."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        if content.get("type") not in {None, "text"}:
            return ""
        text = content.get("text")
        return text if isinstance(text, str) else ""
    if isinstance(content, (list, tuple)):
        parts = [_content_text(part) for part in content]
        return "\n".join(part for part in parts if part)
    text = getattr(content, "text", None)
    return text if isinstance(text, str) else ""


def _history_messages(history, limit: int, content_limit: int) -> list[dict[str, str]]:
    msgs: list[dict[str, str]] = []
    for h in (history or [])[-limit:]:
        if isinstance(h, dict) and h.get("role") in {"user", "assistant"}:
            text = _content_text(h.get("content"))
            if text:
                msgs.append({"role": h["role"], "content": text[:content_limit]})
    return msgs


def _file_path(item: Any) -> str | None:
    if item is None:
        return None
    if isinstance(item, dict):
        nested = item.get("file")
        if isinstance(nested, dict) and nested.get("path"):
            return str(nested["path"])
        if item.get("path"):
            return str(item["path"])
        return None
    path = getattr(item, "path", None)
    if path:
        return str(path)
    name = getattr(item, "name", None)
    if name and not str(name).lower().startswith(("http://", "https://")):
        return str(name)
    return None


def _content_paths(content: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(content, dict):
        path = _file_path(content)
        if path:
            paths.append(path)
        files = content.get("files")
        if isinstance(files, list):
            for item in files:
                p = _file_path(item) or (item if isinstance(item, str) else None)
                if p:
                    paths.append(p)
        return paths
    if isinstance(content, (list, tuple)):
        for item in content:
            paths.extend(_content_paths(item))
    return paths


def normalize_user_message(message: Any) -> tuple[str, list[str]]:
    """Accept a plain string or Gradio 6 MultimodalPostprocess dict."""
    if message is None:
        return "", []
    if isinstance(message, str):
        return message, []
    if isinstance(message, dict):
        text = message.get("text")
        if not isinstance(text, str):
            text = _content_text(message)
        files = message.get("files") or []
        paths: list[str] = []
        for item in files:
            path = _file_path(item) or (item if isinstance(item, str) else None)
            if path:
                paths.append(path)
        return text or "", paths
    return _content_text(message), []


def _ocr_block(att: dict[str, Any], index: int, total: int) -> str:
    label = att.get("name") or f"screenshot-{index}"
    header = f"USER IMAGE {index}/{total}: {label}"
    if att.get("ocr_error"):
        return f"{header}\nLOCAL OCR EXTRACT — unavailable ({att['ocr_error']}). Use the original image."
    text = (att.get("ocr_text") or "").strip()
    if not text:
        return f"{header}\nLOCAL OCR EXTRACT — no text recognized. Use the original image."
    return (
        f"{header}\n"
        "LOCAL OCR EXTRACT — may contain recognition errors; prefer the original image if they conflict.\n"
        f"{text}"
    )


def _user_content(
    text: str,
    attachments: list[dict[str, Any]],
    notes: list[str],
    *,
    empty_image_prompt: str,
) -> str:
    parts: list[str] = []
    if notes:
        parts.append("Attachment notes:\n" + "\n".join(f"- {n}" for n in notes))
    if (text or "").strip():
        parts.append(text.strip())
    elif attachments:
        parts.append(empty_image_prompt)
    total = len(attachments)
    for i, att in enumerate(attachments, 1):
        parts.append(_ocr_block(att, i, total))
    return "\n\n".join(parts).strip()


def unwrap_assistant_context(assistant_context) -> tuple[Any, list[dict[str, Any]]]:
    """Return (analysis, sources). Legacy bare analysis dicts have no sources list."""
    if not assistant_context:
        return None, []
    if isinstance(assistant_context, dict) and "analysis" in assistant_context and "sources" in assistant_context:
        sources = assistant_context.get("sources") or []
        if not isinstance(sources, list):
            sources = []
        return assistant_context.get("analysis"), sources
    return assistant_context, []


def pack_assistant_context(analysis, sources: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    """Assistant-only envelope: analyzer JSON plus every Analyze tab source (files + paste).

    General Chat must never receive this object. Large sources are truncated fairly so every
    filename remains listed and each body gets a share of the budget.
    """
    rows = list(sources or [])
    n = len(rows)
    budget = ASSISTANT_SOURCES_BUDGET if n else 0
    packed: list[dict[str, Any]] = []
    used = 0
    for index, (name, text) in enumerate(rows):
        text = text or ""
        remaining_files = n - index
        share = max(ASSISTANT_SOURCE_MIN_SHARE, (budget - used) // max(remaining_files, 1))
        truncated = len(text) > share
        chunk = text[:share]
        packed.append({
            "name": name,
            "chars": len(text),
            "truncated": truncated,
            "text": chunk,
        })
        used += len(chunk)
    return {"analysis": analysis, "sources": packed}


def assistant_system_prompt(assistant_context=None, *, image_turn: bool = False) -> str:
    if not assistant_context:
        return ASSISTANT_SYSTEM
    analysis, sources = unwrap_assistant_context(assistant_context)
    if analysis is None and not sources:
        return ASSISTANT_SYSTEM

    context_max = ASSISTANT_CONTEXT_MAX_WITH_IMAGE if image_turn else ASSISTANT_CONTEXT_MAX
    sources_budget = ASSISTANT_SOURCES_BUDGET_WITH_IMAGE if image_turn else ASSISTANT_SOURCES_BUDGET
    min_share = ASSISTANT_SOURCE_MIN_SHARE_WITH_IMAGE if image_turn else ASSISTANT_SOURCE_MIN_SHARE

    index_lines: list[str] = []
    bodies: list[str] = []
    n = len(sources)
    used = 0
    for index, item in enumerate(sources):
        name = item.get("name") or "source"
        full_chars = int(item.get("chars") or len(item.get("text") or ""))
        text = item.get("text") or ""
        remaining = n - index
        share = max(min_share, (sources_budget - used) // max(remaining, 1))
        truncated = bool(item.get("truncated")) or len(text) > share or full_chars > len(text[:share])
        chunk = text[:share]
        used += len(chunk)
        flag = ", truncated for context budget" if truncated else ""
        index_lines.append(f"- `{name}` ({full_chars} chars{flag})")
        bodies.append(f"===== FILE: {name} =====\n{chunk}")

    sources_section = ""
    if sources:
        sources_section = (
            "ANALYZE SOURCE INPUTS (every uploaded file and pasted text from the Analyze tab; "
            "local only — never sent to General Chat or public web search):\n"
            + "\n".join(index_lines)
            + "\n\n"
            + "\n\n".join(bodies)
            + "\n\n"
        )

    head = (
        ASSISTANT_SYSTEM
        + "\n\nAttached material from the latest Analyze run (local only; you have no web-search tool). "
        "Use every listed source file and the analyzer JSON when the user asks about this case. "
        "Keep Analyzer JSON, source files, screenshots and OCR extracts as separate evidence. "
        "Do not claim you searched the internet.\n\n"
        + sources_section
        + "ANALYZER OUTPUT:\n"
    )
    analysis_json = json.dumps(analysis, ensure_ascii=False) if analysis is not None else "{}"
    room = context_max - len(head)
    if room < 1_000:
        room = 1_000
    return head + analysis_json[:room]


def empty_assistant_history():
    return []


def _encode_attachments(attachments: list[dict[str, Any]]) -> list[str]:
    from vision import encode_image_png_base64

    encoded: list[str] = []
    for att in attachments:
        try:
            encoded.append(encode_image_png_base64(att["path"]))
        except Exception:
            continue
    return encoded


def _history_image_paths(history) -> list[str]:
    paths: list[str] = []
    for h in reversed(history or []):
        if not (isinstance(h, dict) and h.get("role") == "user"):
            continue
        found = _content_paths(h.get("content"))
        if found:
            return found
    return paths


def assistant_chat(message, history, assistant_context=None) -> str:
    from vision import SCOPE_ASSISTANT, attach_images

    text, paths = normalize_user_message(message)
    attachments, notes = attach_images(paths, scope=SCOPE_ASSISTANT)
    user_text = _user_content(
        text,
        attachments,
        notes,
        empty_image_prompt="Analyze the attached screenshot(s) for technical-support diagnosis.",
    )
    if not user_text:
        return "Enter a question or attach a local screenshot."

    image_turn = bool(attachments) or bool(_history_image_paths(history))
    msgs: list[dict[str, Any]] = [
        {"role": "system", "content": assistant_system_prompt(assistant_context, image_turn=image_turn)}
    ]
    msgs.extend(_history_messages(history, 20, 20000))
    user_msg: dict[str, Any] = {"role": "user", "content": user_text}
    current_images = _encode_attachments(attachments)
    if current_images:
        user_msg["images"] = current_images
    msgs.append(user_msg)

    # Follow-up visual context: re-send the previous user screenshots if this turn has none.
    if not current_images:
        prior = []
        prior_notes: list[str] = []
        try:
            prior, prior_notes = attach_images(_history_image_paths(history), scope=SCOPE_ASSISTANT)
        except Exception:
            prior = []
        prior_images = _encode_attachments(prior)
        if prior_images:
            extra = ["Follow-up refers to the previous screenshot(s)."]
            extra.extend(_ocr_block(att, i, len(prior)) for i, att in enumerate(prior, 1))
            extra.extend(prior_notes)
            msgs[-1]["content"] = (user_text + "\n\n" + "\n\n".join(extra)).strip()
            msgs[-1]["images"] = prior_images

    try:
        return complete(msgs)
    except requests.RequestException as e:
        extra = " The deterministic Analyze tab still works." if assistant_context else ""
        return llm_unavailable(e) + extra
    except Exception as e:
        return f"LLM error: `{e}`"


def web_chat(message, history) -> str:
    from vision import SCOPE_GENERAL_CHAT, attach_images
    from websearch import execute_web_search, plan_web_search, source_footer, web_context

    text, paths = normalize_user_message(message)
    attachments, notes = attach_images(paths, scope=SCOPE_GENERAL_CHAT)
    if not attachments:
        try:
            prior, prior_notes = attach_images(_history_image_paths(history), scope=SCOPE_GENERAL_CHAT)
        except Exception:
            prior, prior_notes = [], []
        if prior:
            attachments = prior
            notes = list(notes) + ["Follow-up refers to the previous image(s)."] + list(prior_notes)

    user_text = _user_content(
        text,
        attachments,
        notes,
        empty_image_prompt="Identify the subject in this image from the pixels. Do not invent a web search.",
    )
    if not user_text:
        return "Enter a question or attach a local image."

    planned: list[str] = []
    try:
        planned = plan_web_search(text, history, has_images=bool(attachments))
    except Exception:
        planned = []
    search_skipped = not planned
    results: list[dict[str, str]] = []
    queries: list[str] = []
    backend = "auto"
    search_error = ""
    if not search_skipped:
        try:
            results, queries, backend = execute_web_search(planned)
        except Exception as e:
            results, queries, backend = [], planned, "auto"
            search_error = str(e)

    msgs: list[dict[str, Any]] = [{"role": "system", "content": WEB_SYSTEM.format(today=date.today().isoformat())}]
    msgs.extend(_history_messages(history, 10, 12000))
    user_msg: dict[str, Any] = {"role": "user", "content": user_text}
    images = _encode_attachments(attachments)
    if images:
        user_msg["images"] = images

    if results:
        msgs.append({"role": "system", "content": "WEB SEARCH RESULTS:\n\n" + web_context(results)[:100_000]})
        msgs.append(user_msg)
        try:
            answer = complete(msgs)
            return answer + source_footer(results, queries, backend)
        except Exception as e:
            return f"Local LLM error after successful web search: `{e}`" + source_footer(results, queries, backend)

    if search_skipped:
        msgs.append({
            "role": "system",
            "content": "No web search was run. Answer from the conversation, any local image, and the user question only. Do not invent sources.",
        })
        msgs.append(user_msg)
        try:
            return complete(msgs)
        except Exception as e:
            return f"Local LLM error: `{e}`"

    msgs.append({
        "role": "system",
        "content": "The web search returned no usable results. Make clear that live search was unavailable/empty and answer only from local model knowledge if useful.",
    })
    msgs.append(user_msg)
    try:
        answer = complete(msgs)
    except Exception as e:
        return f"Web search failed and local LLM is unavailable: `{search_error or e}`"
    detail = (
        f"\n\n> Web search returned no usable results{': ' + search_error if search_error else ''}. "
        "The answer above is therefore based only on the local model."
    )
    return answer + detail
