"""Slack export - sends findings as rich messages."""

from __future__ import annotations

import json
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

from .base import BaseExporter


class SlackExporter(BaseExporter):
    """Export findings to Slack via webhooks."""

    def __init__(self, webhook_url: str, channel: str | None = None, **kwargs: Any):
        """Initialize Slack exporter.

        Args:
            webhook_url: Slack incoming webhook URL
            channel: Optional channel override (e.g., #alerts)
        """
        super().__init__(webhook_url, **kwargs)
        self.channel = channel

    def export(self, findings: list[dict[str, Any]]) -> str:
        """Convert findings to Slack message format.

        Args:
            findings: List of finding dicts

        Returns:
            JSON string for Slack API
        """
        if not findings:
            return "{}"

        # Group by level for better visualization
        by_level = {}
        for finding in findings:
            level = finding.get("level", "INFO")
            if level not in by_level:
                by_level[level] = []
            by_level[level].append(finding)

        # Build message
        blocks = []

        # Header
        total = sum(len(f) for f in by_level.values())
        blocks.append(
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔍 IDDQD Analysis: {total} Findings",
                },
            }
        )

        # Findings by level
        level_order = ["CRITICAL", "ERROR", "WARN", "INFO"]
        for level in level_order:
            if level not in by_level:
                continue

            level_findings = by_level[level]
            icon = {"CRITICAL": "🔴", "ERROR": "🟠", "WARN": "🟡", "INFO": "🔵"}.get(
                level, "⚪"
            )

            # Section for this level
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{icon} *{level}* ({len(level_findings)} findings)",
                    },
                }
            )

            # Add up to 5 findings per level
            for finding in level_findings[:5]:
                sig = finding.get("signature", "Unknown")
                kind = finding.get("kind", "unknown")
                count = finding.get("count", 0)

                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"• *{sig}*\n  Category: `{kind}` | Count: {count}",
                        },
                    }
                )

            # Show if more exist
            if len(level_findings) > 5:
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"  ... and {len(level_findings) - 5} more",
                        },
                    }
                )

        # Footer
        blocks.append(
            {
                "type": "divider",
            }
        )

        payload = {"blocks": blocks}
        if self.channel:
            payload["channel"] = self.channel

        return json.dumps(payload)

    def send(self, findings: list[dict[str, Any]]) -> bool:
        """Send findings to Slack.

        Args:
            findings: List of findings

        Returns:
            True if successful
        """
        try:
            payload = self.export(findings).encode("utf-8")

            req = Request(
                self.endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
            )

            with urlopen(req, timeout=30) as response:
                return response.status == 200

        except (URLError, TimeoutError, Exception) as e:
            print(f"Error sending to Slack: {e}")
            return False
