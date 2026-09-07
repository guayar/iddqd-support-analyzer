from __future__ import annotations

import json
from datetime import date

import requests

from llm import complete, llm_unavailable
from websearch import source_footer, web_context, web_search

ANALYSIS_SYSTEM = """You are a senior enterprise support/escalation engineer assistant running LOCALLY.
You receive deterministic analyzer output generated from customer-provided material.
Never invent values, completed checks, root causes, dates, error codes, or customer actions.
Clearly distinguish observed facts from hypotheses and recommendations.
If asked for an email, write concise, natural professional English suitable for enterprise support. Do not expose internal notes or implementation details.
If asked for a report, produce a structured technical report with: Scope, Time range (if available), Findings, Error groups/codes, Caused-by chains, Assessment, Recommended next checks.
For SAML, preserve exact URLs/Entity IDs/Audience/Destination/Recipient values and explicitly call out MATCH/MISMATCH/UNKNOWN checks.
The system has no web-search tool. Do not claim to have checked external documentation.
"""

GENERAL_SYSTEM = """You are a private local technical assistant running on the user's Ubuntu workstation.
You have no web-search tool and must never claim to have checked the internet or current external documentation.
Be concise, technically precise, and practical. If uncertain, say what is uncertain.
For programming questions, prioritize Java, TypeScript, Python and Playwright when relevant.
Do not invent APIs, command results, files, logs, or execution results.
"""

MAIL_SYSTEM = """You are a senior enterprise technical support writing assistant running LOCALLY.
Turn rough notes, Polish/English drafts, or technical findings into concise, natural professional English.
Preserve the user's meaning and technical facts. Do not invent completed checks, root causes, customer actions, dates, or results.
Avoid robotic phrasing and unnecessary corporate filler.
When useful, structure the message as: context/findings, what was verified, next step/request.
Do not expose implementation details.
"""

CODE_SYSTEM = """You are a senior software engineering assistant running LOCALLY.
Primary stack: Java, TypeScript, Python and Playwright.
Help write, review, debug and explain code. Prefer production-quality, readable solutions and point out assumptions.
Do not claim code was executed unless execution output was actually provided.
You have no web-search tool, so do not claim to have checked current documentation. If an API/version detail may have changed, flag it.
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


def analysis_chat(message, history, analysis_state) -> str:
    if not analysis_state:
        return "Najpierw wrzuć plik/SAML tracer i kliknij **Analyze**."
    compact = json.dumps(analysis_state, ensure_ascii=False)[:120_000]
    msgs = [{"role": "system", "content": ANALYSIS_SYSTEM + "\n\nANALYZER OUTPUT:\n" + compact}]
    msgs.extend(_history_messages(history, 12, 12000))
    msgs.append({"role": "user", "content": message})
    try:
        return complete(msgs)
    except requests.RequestException as e:
        return llm_unavailable(e, analyzer_still_works=True)
    except Exception as e:
        return f"LLM error: `{e}`"


def assistant_chat(message, history, mode) -> str:
    systems = {
        "General": GENERAL_SYSTEM,
        "Support Mail": MAIL_SYSTEM,
        "Code": CODE_SYSTEM,
    }
    msgs = [{"role": "system", "content": systems.get(mode, GENERAL_SYSTEM)}]
    msgs.extend(_history_messages(history, 20, 20000))
    msgs.append({"role": "user", "content": message})
    try:
        return complete(msgs)
    except requests.RequestException as e:
        return llm_unavailable(e)
    except Exception as e:
        return f"LLM error: `{e}`"


def web_chat(message, history) -> str:
    if not (message or "").strip():
        return "Wpisz pytanie do wyszukania."
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
