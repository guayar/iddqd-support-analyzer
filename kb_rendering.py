"""Knowledge Base rendering helpers for styled dataframes.

Uses pandas.Styler to highlight selected rows persistently,
without custom JavaScript or DOM manipulation.
"""

import pandas as pd
from typing import Optional, List, Any, Tuple
from analyzers.kb_models import Article, Case


def render_articles_table(
    articles: List[Article],
    selected_article_uuid: Optional[str] = None
) -> Tuple[Any, dict]:
    """Render Articles table with selection marker and styling.

    Columns:
    - Selected: "▶" if selected, else ""
    - ID: Display ID (AN00000001)
    - Title: Article title
    - Updated: Last update date
    - Tags: Comma-separated tags

    Args:
        articles: List of Article objects
        selected_article_uuid: Canonical UUID of selected article

    Returns:
        Tuple of (styled DataFrame, uuid_map dict for reference)
    """
    if not articles:
        df = pd.DataFrame(columns=["Selected", "ID", "Title", "Updated", "Tags"])
        return df, {}

    data = []
    uuid_map = {}
    for article in articles:
        is_selected = article.id == selected_article_uuid
        data.append([
            "▶" if is_selected else "",
            article.display_id,
            article.title,
            article.updated_at.strftime("%Y-%m-%d") if article.updated_at else "—",
            ", ".join(article.tags) if article.tags else "—",
        ])
        uuid_map[article.display_id] = article.id

    df = pd.DataFrame(data, columns=["Selected", "ID", "Title", "Updated", "Tags"])

    # Apply styling: highlight entire row if this article is selected
    def style_selected_row(row):
        display_id = row["ID"]
        if uuid_map.get(display_id) == selected_article_uuid:
            return ["background-color: rgba(59, 130, 246, 0.15); font-weight: 600;"] * len(row)
        return [""] * len(row)

    styled = df.style.apply(style_selected_row, axis=1)
    return styled, uuid_map


def render_cases_table(
    cases: List[Case],
    selected_case_uuid: Optional[str] = None
) -> Tuple[Any, dict]:
    """Render Cases table with selection marker and styling.

    Columns:
    - Selected: "▶" if selected, else ""
    - ID: Display ID (CN00000001)
    - Title: Case title
    - Created: Creation date
    - Tags: Comma-separated tags

    Args:
        cases: List of Case objects
        selected_case_uuid: Canonical UUID of selected case

    Returns:
        Tuple of (styled DataFrame, uuid_map dict)
    """
    if not cases:
        df = pd.DataFrame(columns=["Selected", "ID", "Title", "Created", "Tags"])
        return df, {}

    data = []
    uuid_map = {}
    for case in cases:
        is_selected = case.id == selected_case_uuid
        data.append([
            "▶" if is_selected else "",
            case.display_id,
            case.title,
            case.created_at.strftime("%Y-%m-%d") if case.created_at else "—",
            ", ".join(case.tags) if case.tags else "—",
        ])
        uuid_map[case.display_id] = case.id

    df = pd.DataFrame(data, columns=["Selected", "ID", "Title", "Created", "Tags"])

    def style_selected_row(row):
        display_id = row["ID"]
        if uuid_map.get(display_id) == selected_case_uuid:
            return ["background-color: rgba(59, 130, 246, 0.15); font-weight: 600;"] * len(row)
        return [""] * len(row)

    styled = df.style.apply(style_selected_row, axis=1)
    return styled, uuid_map


def render_search_articles_table(
    articles: List[Article],
    selected_article_uuid: Optional[str] = None
) -> Tuple[Any, dict]:
    """Render search results for Articles.

    Columns:
    - Selected: "▶" if selected
    - ID: Display ID (AN00000001)
    - Title: Article title
    - Summary: Summary or first 100 chars of content

    Args:
        articles: List of Article objects
        selected_article_uuid: Canonical UUID of selected article

    Returns:
        Tuple of (styled DataFrame, uuid_map dict)
    """
    if not articles:
        df = pd.DataFrame(columns=["Selected", "ID", "Title", "Summary"])
        return df, {}

    data = []
    uuid_map = {}
    for article in articles:
        is_selected = article.id == selected_article_uuid
        summary = article.summary or (
            article.content[:100] + "..." if len(article.content) > 100 else article.content
        )
        data.append([
            "▶" if is_selected else "",
            article.display_id,
            article.title,
            summary,
        ])
        uuid_map[article.display_id] = article.id

    df = pd.DataFrame(data, columns=["Selected", "ID", "Title", "Summary"])

    def style_selected_row(row):
        display_id = row["ID"]
        if uuid_map.get(display_id) == selected_article_uuid:
            return ["background-color: rgba(59, 130, 246, 0.15); font-weight: 600;"] * len(row)
        return [""] * len(row)

    styled = df.style.apply(style_selected_row, axis=1)
    return styled, uuid_map


def render_search_cases_table(
    cases: List[Case],
    selected_case_uuid: Optional[str] = None
) -> Tuple[Any, dict]:
    """Render search results for Cases.

    Columns:
    - Selected: "▶" if selected
    - ID: Display ID (CN00000001)
    - Title: Case title
    - Summary: Summary or first 100 chars of content

    Args:
        cases: List of Case objects
        selected_case_uuid: Canonical UUID of selected case

    Returns:
        Tuple of (styled DataFrame, uuid_map dict)
    """
    if not cases:
        df = pd.DataFrame(columns=["Selected", "ID", "Title", "Summary"])
        return df, {}

    data = []
    uuid_map = {}
    for case in cases:
        is_selected = case.id == selected_case_uuid
        summary = case.summary or (
            case.content[:100] + "..." if len(case.content) > 100 else case.content
        )
        data.append([
            "▶" if is_selected else "",
            case.display_id,
            case.title,
            summary,
        ])
        uuid_map[case.display_id] = case.id

    df = pd.DataFrame(data, columns=["Selected", "ID", "Title", "Summary"])

    def style_selected_row(row):
        display_id = row["ID"]
        if uuid_map.get(display_id) == selected_case_uuid:
            return ["background-color: rgba(59, 130, 246, 0.15); font-weight: 600;"] * len(row)
        return [""] * len(row)

    styled = df.style.apply(style_selected_row, axis=1)
    return styled, uuid_map
