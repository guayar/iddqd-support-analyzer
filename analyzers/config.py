"""Configuration system for v0.21.0.

Supports:
  - Custom pattern injection
  - Correlation window configuration
  - Analyzer enabling/disabling
  - Export format selection
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from pathlib import Path


@dataclass
class CustomPattern:
    """Single custom detection pattern."""

    name: str
    pattern: str
    level: str  # CRITICAL|ERROR|WARN|INFO
    category: str
    kind: str
    action: Optional[str] = None  # e.g., 'page_oncall', 'slack'

    def compile(self) -> re.Pattern:
        """Compile regex pattern."""
        try:
            return re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            raise ValueError(f"Invalid regex for pattern '{self.name}': {e}")


@dataclass
class AnalyzerConfig:
    """Configuration for a single analyzer."""

    enabled: bool = True
    correlation_window_seconds: int = 1800  # 30 minutes default
    custom_patterns: list[CustomPattern] = field(default_factory=list)


@dataclass
class Config:
    """Master configuration object."""

    # Global settings
    enabled_analyzers: list[str] = field(
        default_factory=lambda: [
            "ssh",
            "nginx",
            "oauth2",
            "docker",
            "postgresql",
            "ldap",
            "ssh_keys",
            "html",
            "jwt",
            "api_performance",
            "test_lifecycle",
            "mfa",
            "permissions",
            "service_comms",
            "database",
            "message_queue",
            "browser",
            "visual",
            "user_journey",
            "error_impact",
        ]
    )

    # Per-analyzer settings
    analyzers: dict[str, AnalyzerConfig] = field(default_factory=dict)

    # Deduplication settings
    deduplicate_findings: bool = True
    dedup_window_seconds: int = 300  # 5 minutes

    # Streaming settings
    stream_output_buffer_seconds: int = 10
    stream_max_findings_per_batch: int = 50

    def __post_init__(self):
        """Initialize per-analyzer configs."""
        for analyzer_name in self.enabled_analyzers:
            if analyzer_name not in self.analyzers:
                self.analyzers[analyzer_name] = AnalyzerConfig()

    @staticmethod
    def from_file(path: str | Path) -> Config:
        """Load configuration from JSON file."""
        with open(path) as f:
            data = json.load(f)
        return Config.from_dict(data)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Config:
        """Load configuration from dict."""
        config = Config()

        # Override enabled analyzers
        if "enabled_analyzers" in data:
            config.enabled_analyzers = data["enabled_analyzers"]

        # Set per-analyzer settings
        if "analyzers" in data:
            for name, ana_config in data["analyzers"].items():
                if isinstance(ana_config, dict):
                    config.analyzers[name] = AnalyzerConfig(
                        enabled=ana_config.get("enabled", True),
                        correlation_window_seconds=ana_config.get(
                            "correlation_window_seconds", 1800
                        ),
                        custom_patterns=[
                            CustomPattern(**p) for p in ana_config.get("custom_patterns", [])
                        ],
                    )

        # Set deduplication settings
        if "deduplicate_findings" in data:
            config.deduplicate_findings = data["deduplicate_findings"]
        if "dedup_window_seconds" in data:
            config.dedup_window_seconds = data["dedup_window_seconds"]

        # Set streaming settings
        if "stream_output_buffer_seconds" in data:
            config.stream_output_buffer_seconds = data["stream_output_buffer_seconds"]
        if "stream_max_findings_per_batch" in data:
            config.stream_max_findings_per_batch = data["stream_max_findings_per_batch"]

        return config

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict (for JSON serialization)."""
        return asdict(self)

    def to_json(self, pretty: bool = True) -> str:
        """Convert to JSON string."""
        data = self.to_dict()
        # Remove AnalyzerConfig dataclass conversion complexities
        return json.dumps(data, indent=2 if pretty else None, default=str)

    def save(self, path: str | Path) -> None:
        """Save configuration to file."""
        with open(path, "w") as f:
            f.write(self.to_json(pretty=True))


# ─── DEFAULT CONFIGURATIONS ──────────────────────────────────────────────

def default_config() -> Config:
    """Get default production configuration."""
    return Config()


def example_config_with_custom_patterns() -> Config:
    """Example config showing custom pattern injection."""
    config = Config()

    # Add custom pattern for user app
    config.analyzers["ssh"].custom_patterns = [
        CustomPattern(
            name="my_app_error",
            pattern=r"ERROR.*my_service.*(\w+)",
            level="ERROR",
            category="custom",
            kind="my_app_error",
            action="slack",
        )
    ]

    # Configure different time windows
    config.analyzers["ssh"].correlation_window_seconds = 15 * 60  # 15 min for fast attacks
    config.analyzers["postgresql"].correlation_window_seconds = 60 * 60  # 1 hour for slow degradation
    config.analyzers["permissions"].correlation_window_seconds = 24 * 60 * 60  # 24 hours for audits

    return config


def example_minimal_config() -> Config:
    """Minimal config - only SSH analyzer."""
    config = Config(enabled_analyzers=["ssh"])
    return config
