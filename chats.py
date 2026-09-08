from __future__ import annotations

import json
from datetime import date

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
"""

WEB_SYSTEM = """You are a web-enabled general assistant. The language model itself runs locally, but for this chat the application deliberately searches the public web.
Use the supplied search results as external evidence. Current date: {today}.
Answer in the user's language unless asked otherwise.
For technical questions, prefer official documentation, vendor documentation, release notes and primary sources over blogs.
Do not fabricate facts or sources. If the search evidence is insufficient or conflicting, say so.
Cite factual web-derived claims inline using source markers like [S1], [S2]. Do not invent markers that are not in the supplied material.
This General Chat is intentionally separate from the private Analyzer/Assistant. Never imply you can see content from those tabs.
"""


def _history_messages(history, limit: int, content_limit: int) -> list[dict[str, str]]:
    msgs: list[dict[str, str]] = []
    for h in (history or [])[-limit:]:
        if isinstance(h, dict) and h.get("role") in {"user", "assistant"}:
            c = h.get("content")
            if isinstance(c, str):
                msgs.append({"role": h["role"], "content": c[:content_limit]})
    return msgs


def assistant_system_prompt(assistant_context=None) -> str:
    if not assistant_context:
        return ASSISTANT_SYSTEM
    compact = json.dumps(assistant_context, ensure_ascii=False)[:120_000]
    return (
        ASSISTANT_SYSTEM
        + "\n\nAttached analyzer JSON from the latest Analyze run "
        "(local only; you have no web-search tool). Use it when the user asks about this case. "
        "Do not claim you searched the internet.\n\n"
        "ANALYZER OUTPUT:\n"
        + compact
    )


def empty_assistant_history():
    return []


def assistant_chat(message, history, assistant_context=None) -> str:
    msgs = [{"role": "system", "content": assistant_system_prompt(assistant_context)}]
    msgs.extend(_history_messages(history, 20, 20000))
    msgs.append({"role": "user", "content": message})
    try:
        return complete(msgs)
    except requests.RequestException as e:
        extra = " The deterministic Analyze tab still works." if assistant_context else ""
        return llm_unavailable(e) + extra
    except Exception as e:
        return f"LLM error: `{e}`"


def web_chat(message, history) -> str:
    from websearch import source_footer, web_context, web_search
    if not (message or "").strip():
        return "Enter a question to search."
    try:
        results, queries = web_search(message, history)
    except Exception as e:
        results, queries = [], [message]
        search_error = str(e)
    else:
        search_error = ""

    msgs = [{"role": "system", "content": WEB_SYSTEM.format(today=date.today().isoformat())}]
    msgs.extend(_history_messages(history, 10, 12000))

    if results:
        msgs.append({"role": "system", "content": "WEB SEARCH RESULTS:\n\n" + web_context(results)[:100_000]})
        msgs.append({"role": "user", "content": message})
        try:
            answer = complete(msgs)
            return answer + source_footer(results, queries)
        except Exception as e:
            return f"Local LLM error after successful web search: `{e}`" + source_footer(results, queries)

    msgs.append({
        "role": "system",
        "content": "The web search returned no usable results. Make clear that live search was unavailable/empty and answer only from local model knowledge if useful.",
    })
    msgs.append({"role": "user", "content": message})
    try:
        answer = complete(msgs)
    except Exception as e:
        return f"Web search failed and local LLM is unavailable: `{search_error or e}`"
    detail = (
        f"\n\n> Web search returned no usable results{': ' + search_error if search_error else ''}. "
        "The answer above is therefore based only on the local model."
    )
    return answer + detail
