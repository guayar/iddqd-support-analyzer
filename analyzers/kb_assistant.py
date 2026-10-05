"""Knowledge Base context provider for Assistant.

Generates KB context for Ollama Assistant to use in system prompt.
"""

from typing import Dict, List, Any, Optional
from .kb_actions import KnowledgeBaseActions
from .kb_models import Article


class KBAssistantContext:
    """Generate KB context for Assistant."""

    def __init__(self, kb_path: str = "data/iddqd_kb.db"):
        """Initialize.

        Args:
            kb_path: Path to KB database
        """
        self.kb = KnowledgeBaseActions(kb_path)

    def get_kb_context(
        self,
        findings: Optional[List[Dict[str, Any]]] = None,
        findings_by_code: bool = True,
    ) -> str:
        """Generate KB context for Assistant prompt.

        Args:
            findings: Optional list of Analyze findings
            findings_by_code: If True, search by finding codes; if False, search by kind

        Returns:
            Formatted KB context as string
        """
        if not findings:
            return self._get_general_kb_summary()

        # Find related Articles based on findings
        related_articles = set()

        for finding in findings:
            # By finding code
            if findings_by_code:
                finding_code = finding.get("finding_code") or f"{finding.get('category', '')}_{finding.get('kind', '')}"
                articles = self.kb.search_by_finding(finding_code)
                related_articles.update([a.id for a in articles])

            # By keyword search on kind
            kind = finding.get("kind", "")
            if kind:
                results = self.kb.search(kind, limit=3)
                related_articles.update([a.id for a in results["articles"]])

        # Format output
        context_lines = ["## Relevant Knowledge Base\n"]

        if not related_articles:
            context_lines.append("No directly matching Articles found.\n")
            return "".join(context_lines)

        # Format Articles
        if related_articles:
            context_lines.append("### Related Articles\n")
            for article_id in sorted(related_articles)[:5]:  # Limit to 5
                article = self.kb.get_article(article_id)
                if article:
                    context_lines.append(f"**{article.title}**\n")
                    if article.summary:
                        context_lines.append(f"{article.summary}\n")
                    context_lines.append("\n")

        return "".join(context_lines)

    def _get_general_kb_summary(self) -> str:
        """Get summary of entire KB."""
        articles = self.kb.list_articles()

        lines = [
            "## Knowledge Base Available\n",
            f"**{len(articles)} Articles**\n\n",
        ]

        # Top articles
        if articles:
            lines.append("### Top Articles\n")
            for article in articles[:5]:
                lines.append(f"- {article.title}\n")
            lines.append("\n")

        lines.append(
            "Use these Articles to inform your analysis and suggestions.\n"
        )

        return "".join(lines)

    def get_assistant_system_prompt_fragment(
        self, findings: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """Get system prompt fragment for Assistant.

        Args:
            findings: Optional findings from Analyze

        Returns:
            System prompt fragment to inject into Assistant prompt
        """
        kb_context = self.get_kb_context(findings)

        return f"""
## Knowledge Base Access

You have access to a local Knowledge Base with Articles from previous investigations.

{kb_context}

### How to Use KB

- **Articles** are reusable troubleshooting knowledge about specific problems or patterns
- Use KB content to inform your analysis and provide context
- Always distinguish between:
  - **Observed evidence** (from the Analyze findings)
  - **KB suggestions** (from relevant Articles)
  - **Your interpretation** (your analysis combining both)
- If findings match a KB Article, explain how and what that Article recommends
- Never present KB content as proven facts if Analyze findings contradict them
- Suggest creating new Articles if you identify useful patterns

### Important

- KB context is for **guidance** only, not **proof**
- Always prioritize Analyze findings (deterministic) over heuristic patterns
- When KB suggests something, verify it against the actual evidence
"""

    def save_article_from_analysis(
        self,
        title: str,
        findings: List[Dict[str, Any]],
        summary: Optional[str] = None,
        content: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Save current analysis as a KB Article.

        Args:
            title: Article title
            findings: List of Analyze findings
            summary: Optional summary
            content: Optional Markdown content
            tags: Optional tags

        Returns:
            Article ID
        """
        if not content:
            # Auto-generate from findings
            lines = ["# Investigation\n"]

            if summary:
                lines.append(f"**Summary**: {summary}\n\n")

            lines.append("## Findings\n")
            for finding in findings:
                kind = finding.get("kind", "Unknown")
                category = finding.get("category", "unknown")
                level = finding.get("level", "INFO")
                signature = finding.get("signature", "No description")

                lines.append(f"### {category.replace('_', ' ').title()}: {kind}\n")
                lines.append(f"**Level**: {level}\n")
                lines.append(f"{signature}\n\n")

            content = "".join(lines)

        return self.kb.create_article(title=title, content=content, summary=summary, tags=tags)

    # Legacy callers also save an Article; no Case records are recreated.
    save_case_from_analysis = save_article_from_analysis
