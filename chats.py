from __future__ import annotations

import json
from datetime import date
from typing import Any

import requests

from llm import complete, llm_unavailable

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


def assistant_system_prompt(assistant_context=None) -> str:
    if not assistant_context:
        return ASSISTANT_SYSTEM
    compact = json.dumps(assistant_context, ensure_ascii=False)[:120_000]
    return (
        ASSISTANT_SYSTEM
        + "\n\nAttached analyzer JSON from the latest Analyze run "
        "(local only; you have no web-search tool). Use it when the user asks about this case. "
        "Keep Analyzer JSON, screenshots and OCR extracts as separate evidence. "
        "Do not claim you searched the internet.\n\n"
        "ANALYZER OUTPUT:\n"
        + compact
    )


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

    msgs: list[dict[str, Any]] = [{"role": "system", "content": assistant_system_prompt(assistant_context)}]
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
