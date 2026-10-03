"""Knowledge Base context provider for Assistant.

Generates KB context for Ollama Assistant to use in system prompt.
"""

from typing import Dict, List, Any, Optional
from .kb_actions import KnowledgeBaseActions
from .kb_models import Article, Case


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
        related_cases_ids = set()

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
                related_cases_ids.update([c.id for c in results["cases"]])

        # Format output
        context_lines = ["## Relevant Knowledge Base\n"]

        if not related_articles and not related_cases_ids:
            context_lines.append("No directly matching Articles or Cases found.\n")
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

        # Format Cases
        if related_cases_ids:
            context_lines.append("### Related Cases\n")
            for case_id in sorted(related_cases_ids)[:3]:  # Limit to 3
                case = self.kb.get_case(case_id)
                if case:
                    context_lines.append(f"**{case.title}**\n")
                    if case.summary:
                        context_lines.append(f"{case.summary}\n")
                    context_lines.append("\n")

        return "".join(context_lines)

    def _get_general_kb_summary(self) -> str:
        """Get summary of entire KB."""
        articles = self.kb.list_articles()
        cases = self.kb.list_cases()

        lines = [
            "## Knowledge Base Available\n",
            f"**{len(articles)} Articles** | **{len(cases)} Cases**\n\n",
        ]

        # Top articles
        if articles:
            lines.append("### Top Articles\n")
            for article in articles[:5]:
                lines.append(f"- {article.title}\n")
            lines.append("\n")

        # Recent cases
        if cases:
            lines.append("### Recent Cases\n")
            for case in cases[:5]:
                lines.append(f"- {case.title}\n")
            lines.append("\n")

        lines.append(
            "Use these Articles and Cases to inform your analysis and suggestions.\n"
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

You have access to a local Knowledge Base with Articles and Cases from previous investigations.

{kb_context}

### How to Use KB

- **Articles** are reusable troubleshooting knowledge about specific problems or patterns
- **Cases** are records of previous incidents and how they were resolved
- Use KB content to inform your analysis and provide context
- Always distinguish between:
  - **Observed evidence** (from the Analyze findings)
  - **KB suggestions** (from relevant Articles/Cases)
  - **Your interpretation** (your analysis combining both)
- If findings match a KB Article or Case, explain how and what that Article/Case recommends
- Never present KB content as proven facts if Analyze findings contradict them
- Suggest creating new Articles or Cases if you identify useful patterns

### Important

- KB context is for **guidance** only, not **proof**
- Always prioritize Analyze findings (deterministic) over heuristic patterns
- When KB suggests something, verify it against the actual evidence
"""

    def save_case_from_analysis(
        self,
        title: str,
        findings: List[Dict[str, Any]],
        summary: Optional[str] = None,
        content: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        """Save current analysis as KB Case.

        Args:
            title: Case title
            findings: List of Analyze findings
            summary: Optional summary
            content: Optional Markdown content
            tags: Optional tags

        Returns:
            Case ID
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

        return self.kb.create_case_from_analysis(
            findings=findings,
            title=title,
            summary=summary,
            content=content,
        )
