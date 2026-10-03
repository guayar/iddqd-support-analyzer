"""Graylog GELF (Graylog Extended Log Format) export."""

from __future__ import annotations

import json
import time
import socket
from typing import Any

from .base import BaseExporter


class GraylogExporter(BaseExporter):
    """Export findings to Graylog via GELF protocol."""

    def __init__(
        self,
        endpoint: str,
        port: int = 12201,
        protocol: str = "udp",
        facility: str = "iddqd-analyzer",
        **kwargs: Any,
    ):
        """Initialize Graylog exporter.

        Args:
            endpoint: Graylog server hostname/IP
            port: GELF UDP port (default 12201)
            protocol: udp or tcp
            facility: Log facility name
        """
        super().__init__(endpoint, **kwargs)
        self.port = port
        self.protocol = protocol
        self.facility = facility

    def export(self, findings: list[dict[str, Any]]) -> str:
        """Convert findings to GELF format.

        Args:
            findings: List of finding dicts

        Returns:
            Newline-delimited GELF messages
        """
        messages = []

        for finding in findings:
            gelf_msg = {
                "version": "1.1",
                "host": "iddqd-analyzer",
                "timestamp": time.time(),
                "level": self._map_level_to_syslog(finding.get("level", "INFO")),
                "short_message": finding.get("signature", "Unknown finding"),
                "facility": self.facility,
                "_finding_kind": finding.get("kind"),
                "_finding_category": finding.get("category"),
                "_finding_count": finding.get("count"),
                "_finding_level": finding.get("level"),
                "_first_line": finding.get("first_line"),
            }

            # Add optional fields
            if finding.get("sample"):
                gelf_msg["_sample"] = finding["sample"]
            if finding.get("root_cause"):
                gelf_msg["_root_cause"] = finding["root_cause"]
            if finding.get("top_exception"):
                gelf_msg["_top_exception"] = finding["top_exception"]

            messages.append(json.dumps(gelf_msg))

        return "\n".join(messages) + "\n"

    @staticmethod
    def _map_level_to_syslog(level: str) -> int:
        """Map IDDQD levels to syslog levels.

        Args:
            level: CRITICAL|ERROR|WARN|INFO

        Returns:
            Syslog level (0-7)
        """
        mapping = {
            "CRITICAL": 2,  # syslog CRITICAL
            "ERROR": 3,  # syslog ERROR
            "WARN": 4,  # syslog WARNING
            "INFO": 6,  # syslog INFO
        }
        return mapping.get(level, 6)

    def send(self, findings: list[dict[str, Any]]) -> bool:
        """Send findings to Graylog via GELF.

        Args:
            findings: List of findings

        Returns:
            True if successful
        """
        try:
            payload = self.export(findings).encode("utf-8")

            if self.protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(payload, (self.endpoint, self.port))
                sock.close()
            elif self.protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.endpoint, self.port))
                sock.sendall(payload)
                sock.close()
            else:
                return False

            return True

        except (socket.error, OSError, Exception) as e:
            print(f"Error sending to Graylog: {e}")
            return False
