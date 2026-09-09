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


def search_queries(message: str, history) -> list[str]:
    """Ask the local model for focused search queries. Only the resulting query strings leave the machine."""
    prompt = f"""Create 1 to 3 concise web-search queries for the user's latest request.
Preserve important product names, versions, error codes and technical terms. Prefer English queries for technical documentation when useful.
For a follow-up question, use the short conversation context to make the query self-contained.
Return ONLY a JSON array of strings, no markdown.

RECENT CONTEXT:
{history_text(history)}

LATEST REQUEST:
{message}
"""
    try:
        raw = complete(
            [{"role": "system", "content": "You generate precise web search queries."}, {"role": "user", "content": prompt}],
            temperature=0.0,
        ).strip()
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.lower().startswith("json"):
                raw = raw[4:].strip()
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            queries = [str(x).strip() for x in parsed if str(x).strip()]
            if queries:
                return queries[:3]
    except Exception:
        pass
    return [message.strip()]


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


def web_search(message: str, history) -> tuple[list[dict[str, str]], list[str], str]:
    queries = search_queries(message, history)
    backend = resolve_search_backend()
    merged: list[dict[str, str]] = []
    seen: set[str] = set()
    ddgs = DDGS(timeout=10)

    for query in queries:
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

    return merged, queries, backend


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
