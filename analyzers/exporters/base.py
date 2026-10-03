"""Base exporter interface for all export formats."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseExporter(ABC):
    """Base class for all exporters."""

    def __init__(self, endpoint: str | None = None, **kwargs: Any):
        """Initialize exporter.

        Args:
            endpoint: Destination URL/endpoint
            **kwargs: Format-specific options
        """
        self.endpoint = endpoint
        self.kwargs = kwargs

    @abstractmethod
    def export(self, findings: list[dict[str, Any]]) -> str | bytes:
        """Convert findings to export format.

        Args:
            findings: List of finding dicts from analyzers

        Returns:
            Formatted output (string or bytes)
        """
        ...

    @abstractmethod
    def send(self, findings: list[dict[str, Any]]) -> bool:
        """Send findings to destination.

        Args:
            findings: List of findings

        Returns:
            True if successful
        """
        ...

    def batch_export(
        self, findings: list[dict[str, Any]], batch_size: int = 100
    ) -> list[str | bytes]:
        """Export findings in batches.

        Args:
            findings: List of findings
            batch_size: Maximum findings per batch

        Returns:
            List of formatted batches
        """
        batches = []
        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            batches.append(self.export(batch))
        return batches
