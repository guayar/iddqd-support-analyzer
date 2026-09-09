from __future__ import annotations

import json

from ddgs import DDGS

from chats import _content_text
from config import WEB_FETCH_CHARS, WEB_FETCH_RESULTS, WEB_SEARCH_BACKEND, WEB_SEARCH_REGION, WEB_SEARCH_RESULTS
from llm import complete

# Text engines supported by ddgs 9.x. "auto"/"all" use every engine in this set.
TEXT_SEARCH_BACKENDS = (
    "brave",
    "duckduckgo",
    "google",
    "grokipedia",
    "mojeek",
    "startpage",
    "wikipedia",
    "yahoo",
)
_BACKEND_ALIASES = {
    "ddg": "duckduckgo",
    "duck": "duckduckgo",
    "wiki": "wikipedia",
}


def history_text(history, limit: int = 6) -> str:
    items = []
    for h in (history or [])[-limit:]:
        if not (isinstance(h, dict) and h.get("role") in {"user", "assistant"}):
            continue
        text = _content_text(h.get("content"))
        if text:
            items.append(f"{h['role'].upper()}: {text[:2500]}")
    return "\n".join(items)


def _loads_json(raw: str):
    text = (raw or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


def resolve_search_backend(raw: str | None = None) -> str:
    """Return a ddgs backend string: 'auto' or a comma-separated known engine list."""
    text = (raw if raw is not None else WEB_SEARCH_BACKEND).strip().lower()
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if not parts or "auto" in parts or "all" in parts:
        return "auto"
    ordered: list[str] = []
    for part in parts:
        name = _BACKEND_ALIASES.get(part, part)
        if name in TEXT_SEARCH_BACKENDS and name not in ordered:
            ordered.append(name)
    return ",".join(ordered) if ordered else "auto"


def plan_web_search(message: str, history, *, has_images: bool = False) -> list[str]:
    """Local-by-default. Returns 1–3 minimal queries, or [] to stay local. Never sends OCR/images."""
    request = (message or "").strip()
    if not request and has_images:
        request = "(no text; user attached a local image)"
    if not request:
        return []
    prompt = f"""Decide whether this General Chat turn needs a live public web search.
Default: do NOT search. Answer from the local model, the conversation, and any attached image.
Search only if the user asked to look something up online, or the task clearly needs current/external public information (latest version, current price, public documentation, whether a product/release exists). If the recent conversation is already a web-research thread and this is a follow-up, search remains appropriate.
Do not search to describe or identify an attached image, explain code, rewrite text, or reason over supplied local evidence.
Attached images are not a reason to search. You are not given OCR, screenshots, logs, or Analyzer JSON — never invent queries from those.
If search is true, queries must be 1 to 3 short strings using only terms present in the user request or recent chat text. No emails, internal hostnames, stack traces, or pasted log bodies.

Attached local images this turn: {"yes" if has_images else "no"}

RECENT CONTEXT:
{history_text(history) or "(none)"}

LATEST REQUEST:
{request}

Return ONLY JSON: {{"search": false}} or {{"search": true, "queries": ["short query"]}}
"""
    try:
        raw = complete(
            [
                {"role": "system", "content": "You decide whether to search the public web. Local by default. JSON only."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
        )
        parsed = _loads_json(raw)
        if not isinstance(parsed, dict) or parsed.get("search") is not True:
            return []
        queries: list[str] = []
        for item in parsed.get("queries") or []:
            query = " ".join(str(item).split())
            if query and len(query) <= 200:
                queries.append(query)
        return queries[:3]
    except Exception:
        return []


def search_queries(message: str, history) -> list[str]:
    """Queries only when a web search is actually planned. Empty means stay local."""
    return plan_web_search(message, history)


def execute_web_search(queries: list[str]) -> tuple[list[dict[str, str]], list[str], str]:
    backend = resolve_search_backend()
    merged: list[dict[str, str]] = []
    seen: set[str] = set()
    ddgs = DDGS(timeout=10)
    used = [q for q in queries if str(q).strip()][:3]

    for query in used:
        try:
            results = ddgs.text(
                query,
                region=WEB_SEARCH_REGION,
                safesearch="moderate",
                max_results=WEB_SEARCH_RESULTS,
                backend=backend,
            )
        except Exception:
            results = []
        for item in results or []:
            url = str(item.get("href") or item.get("url") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            merged.append({
                "title": str(item.get("title") or url).strip(),
                "url": url,
                "snippet": str(item.get("body") or item.get("snippet") or "").strip(),
                "content": "",
            })
            if len(merged) >= WEB_SEARCH_RESULTS:
                break
        if len(merged) >= WEB_SEARCH_RESULTS:
            break

    for item in merged[:WEB_FETCH_RESULTS]:
        try:
            extracted = ddgs.extract(item["url"], fmt="text_plain")
            content = extracted.get("content", "") if isinstance(extracted, dict) else ""
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            item["content"] = str(content)[:WEB_FETCH_CHARS]
        except Exception:
            item["content"] = ""

    return merged, used, backend


def web_search(message: str, history, *, has_images: bool = False) -> tuple[list[dict[str, str]], list[str], str]:
    queries = plan_web_search(message, history, has_images=has_images)
    if not queries:
        return [], [], resolve_search_backend()
    return execute_web_search(queries)


def web_context(results: list[dict[str, str]]) -> str:
    blocks = []
    for idx, item in enumerate(results, 1):
        blocks.append(
            f"[S{idx}] {item['title']}\nURL: {item['url']}\n"
            f"SEARCH SNIPPET: {item['snippet']}\n"
            f"PAGE CONTENT:\n{item.get('content') or '(page not fetched; use snippet only)'}"
        )
    return "\n\n---\n\n".join(blocks)


def source_footer(results: list[dict[str, str]], queries: list[str], backend: str | None = None) -> str:
    lines = ["\n\n---\n**Web sources used by this chat**"]
    for idx, item in enumerate(results, 1):
        safe_title = item["title"].replace("[", "\\[").replace("]", "\\]")
        lines.append(f"- [S{idx}] [{safe_title}]({item['url']})")
    if backend:
        engines = TEXT_SEARCH_BACKENDS if backend in {"auto", "all"} else tuple(x for x in backend.split(",") if x)
        lines.append("\nSearch engines: " + ", ".join(f"`{name}`" for name in engines))
    if queries:
        lines.append(
            "\n<details><summary>Search queries sent to the web</summary>\n\n"
            + "\n".join(f"- `{q}`" for q in queries)
            + "\n</details>"
        )
    return "\n".join(lines)
