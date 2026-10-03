"""ELK/Elasticsearch export."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

from .base import BaseExporter


class ElkExporter(BaseExporter):
    """Export findings to Elasticsearch (ELK)."""

    def __init__(
        self,
        endpoint: str,
        index: str = "iddqd-findings",
        username: str | None = None,
        password: str | None = None,
        **kwargs: Any,
    ):
        """Initialize ELK exporter.

        Args:
            endpoint: Elasticsearch endpoint (e.g., http://localhost:9200)
            index: Index name pattern (e.g., iddqd-findings-{date})
            username: Optional basic auth username
            password: Optional basic auth password
        """
        super().__init__(endpoint, **kwargs)
        self.index = index
        self.username = username
        self.password = password

    def export(self, findings: list[dict[str, Any]]) -> str:
        """Convert findings to Elasticsearch bulk format.

        Args:
            findings: List of finding dicts

        Returns:
            Newline-delimited bulk API format
        """
        lines = []

        for finding in findings:
            # Bulk API requires metadata line + data line
            metadata = {
                "index": {
                    "_index": self.index,
                    "_type": "_doc",
                }
            }
            lines.append(json.dumps(metadata))

            # Add timestamp if not present
            if "@timestamp" not in finding:
                finding_copy = finding.copy()
                finding_copy["@timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                finding_copy = finding

            lines.append(json.dumps(finding_copy))

        return "\n".join(lines) + "\n"

    def send(self, findings: list[dict[str, Any]]) -> bool:
        """Send findings to Elasticsearch.

        Args:
            findings: List of findings

        Returns:
            True if successful
        """
        try:
            payload = self.export(findings).encode("utf-8")

            url = f"{self.endpoint}/_bulk"
            headers = {"Content-Type": "application/x-ndjson"}

            # Add basic auth if provided
            if self.username and self.password:
                import base64

                credentials = base64.b64encode(
                    f"{self.username}:{self.password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {credentials}"

            req = Request(url, data=payload, headers=headers)

            with urlopen(req, timeout=30) as response:
                if response.status == 200:
                    # Check for errors in bulk response
                    body = response.read().decode()
                    result = json.loads(body)
                    return not result.get("errors", False)
                return False

        except (URLError, TimeoutError, Exception) as e:
            print(f"Error sending to Elasticsearch: {e}")
            return False
