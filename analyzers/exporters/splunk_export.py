"""Splunk HEC (HTTP Event Collector) export."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

from .base import BaseExporter


class SplunkExporter(BaseExporter):
    """Export findings to Splunk HEC endpoint."""

    def __init__(
        self,
        endpoint: str,
        hec_token: str,
        source: str = "iddqd-analyzer",
        sourcetype: str = "json",
        index: str = "main",
        **kwargs: Any,
    ):
        """Initialize Splunk exporter.

        Args:
            endpoint: Splunk HEC URL (e.g., https://splunk.example.com:8088)
            hec_token: HEC authentication token
            source: Log source name
            sourcetype: Splunk source type
            index: Destination index
        """
        super().__init__(endpoint, **kwargs)
        self.hec_token = hec_token
        self.source = source
        self.sourcetype = sourcetype
        self.index = index

    def export(self, findings: list[dict[str, Any]]) -> str:
        """Convert findings to Splunk HEC format.

        Args:
            findings: List of finding dicts

        Returns:
            Newline-delimited HEC events
        """
        events = []
        for finding in findings:
            hec_event = {
                "time": time.time(),
                "source": self.source,
                "sourcetype": self.sourcetype,
                "index": self.index,
                "event": finding,
            }
            events.append(json.dumps(hec_event))

        return "\n".join(events) + "\n"

    def send(self, findings: list[dict[str, Any]]) -> bool:
        """Send findings to Splunk HEC.

        Args:
            findings: List of findings

        Returns:
            True if successful
        """
        try:
            payload = self.export(findings).encode("utf-8")

            url = f"{self.endpoint}/services/collector"
            req = Request(
                url,
                data=payload,
                headers={
                    "Authorization": f"Splunk {self.hec_token}",
                    "Content-Type": "application/json",
                },
            )

            with urlopen(req, timeout=30) as response:
                return response.status == 200

        except (URLError, TimeoutError, Exception) as e:
            print(f"Error sending to Splunk: {e}")
            return False
