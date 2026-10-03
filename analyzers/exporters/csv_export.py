"""CSV export format (for Excel, etc)."""

from __future__ import annotations

import csv
import io
from typing import Any

from .base import BaseExporter


class CsvExporter(BaseExporter):
    """Export findings as CSV."""

    def export(self, findings: list[dict[str, Any]]) -> str:
        """Convert findings to CSV.

        Args:
            findings: List of finding dicts

        Returns:
            CSV string
        """
        if not findings:
            return ""

        output = io.StringIO()

        # Collect all possible keys
        all_keys = set()
        for finding in findings:
            all_keys.update(finding.keys())

        # Sort keys: put important ones first
        priority_keys = [
            "signature",
            "level",
            "category",
            "kind",
            "count",
            "first_line",
            "sample",
        ]
        header = [k for k in priority_keys if k in all_keys]
        header.extend(sorted(all_keys - set(header)))

        writer = csv.DictWriter(output, fieldnames=header, extrasaction="ignore")
        writer.writeheader()

        # Flatten complex fields for CSV
        for finding in findings:
            row = finding.copy()
            # Flatten nested structures
            if "codes" in row and isinstance(row["codes"], dict):
                row["codes"] = ",".join(f"{k}:{v}" for k, v in row["codes"].items())
            if "variations" in row and isinstance(row["variations"], list):
                row["variations"] = ";".join(
                    f"{v.get('kind')}({v.get('count')})" for v in row["variations"]
                )
            if "causes" in row and isinstance(row["causes"], list):
                row["causes"] = ";".join(row["causes"][:3])
            writer.writerow(row)

        return output.getvalue()

    def send(self, findings: list[dict[str, Any]]) -> bool:
        """CSV export is local-only, always succeeds.

        Args:
            findings: List of findings

        Returns:
            Always True
        """
        return True
