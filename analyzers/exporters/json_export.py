"""JSON export format."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseExporter


class JsonExporter(BaseExporter):
    """Export findings as JSON."""

    def export(self, findings: list[dict[str, Any]]) -> str:
        """Convert findings to JSON.

        Args:
            findings: List of finding dicts

        Returns:
            JSON string
        """
        output = {
            "findings": findings,
            "count": len(findings),
            "format": "json",
        }
        return json.dumps(output, indent=2, default=str)

    def send(self, findings: list[dict[str, Any]]) -> bool:
        """JSON export is local-only, always succeeds.

        Args:
            findings: List of findings

        Returns:
            Always True
        """
        return True


class JsonlExporter(BaseExporter):
    """Export findings as JSON Lines (one per line)."""

    def export(self, findings: list[dict[str, Any]]) -> str:
        """Convert findings to JSONL.

        Args:
            findings: List of finding dicts

        Returns:
            JSONL string (one finding per line)
        """
        lines = [json.dumps(f, default=str) for f in findings]
        return "\n".join(lines) + "\n"

    def send(self, findings: list[dict[str, Any]]) -> bool:
        """JSONL export is local-only, always succeeds.

        Args:
            findings: List of findings

        Returns:
            Always True
        """
        return True
