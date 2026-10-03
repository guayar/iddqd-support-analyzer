"""Tests for v0.21.0 configuration system."""

import json
import tempfile
from pathlib import Path

from analyzers.config import Config, CustomPattern, AnalyzerConfig, ExportConfig


def test_default_config():
    """Test default configuration."""
    config = Config()
    assert config.enabled_analyzers
    assert "ssh" in config.enabled_analyzers
    assert config.deduplicate_findings is True


def test_config_from_dict():
    """Test loading config from dict."""
    data = {
        "enabled_analyzers": ["ssh", "nginx"],
        "deduplicate_findings": False,
        "dedup_window_seconds": 600,
    }
    config = Config.from_dict(data)

    assert config.enabled_analyzers == ["ssh", "nginx"]
    assert config.deduplicate_findings is False
    assert config.dedup_window_seconds == 600


def test_config_custom_patterns():
    """Test custom pattern injection."""
    pattern = CustomPattern(
        name="my_error",
        pattern=r"ERROR.*critical",
        level="CRITICAL",
        category="custom",
        kind="my_error",
    )
    assert pattern.name == "my_error"
    assert pattern.level == "CRITICAL"

    # Compile and test
    regex = pattern.compile()
    assert regex.search("ERROR this is critical")
    assert not regex.search("warning message")


def test_config_correlation_windows():
    """Test configurable correlation windows."""
    config = Config()

    # Set different windows per analyzer
    config.analyzers["ssh"].correlation_window_seconds = 15 * 60  # 15 min
    config.analyzers["postgresql"].correlation_window_seconds = 60 * 60  # 1 hour
    config.analyzers["permissions"].correlation_window_seconds = 24 * 60 * 60  # 24 hours

    assert config.analyzers["ssh"].correlation_window_seconds == 900
    assert config.analyzers["postgresql"].correlation_window_seconds == 3600
    assert config.analyzers["permissions"].correlation_window_seconds == 86400


def test_config_export_formats():
    """Test export format configuration."""
    config = Config()
    config.exports = [
        ExportConfig(format="slack", webhook_url="https://hooks.slack.com/..."),
        ExportConfig(format="splunk", endpoint="https://splunk.example.com", api_key="token123"),
    ]

    assert len(config.exports) == 2
    assert config.exports[0].format == "slack"
    assert config.exports[1].format == "splunk"


def test_config_save_load():
    """Test saving and loading config from file."""
    config = Config()
    config.deduplicate_findings = False
    config.dedup_window_seconds = 600

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "config.json"

        # Save
        config.save(path)
        assert path.exists()

        # Load
        loaded = Config.from_file(path)
        assert loaded.deduplicate_findings is False
        assert loaded.dedup_window_seconds == 600


def test_config_to_json():
    """Test JSON serialization."""
    config = Config()
    json_str = config.to_json(pretty=False)

    assert isinstance(json_str, str)
    assert "enabled_analyzers" in json_str

    # Verify it's valid JSON
    data = json.loads(json_str)
    assert "enabled_analyzers" in data


if __name__ == "__main__":
    test_default_config()
    test_config_from_dict()
    test_config_custom_patterns()
    test_config_correlation_windows()
    test_config_export_formats()
    test_config_save_load()
    test_config_to_json()
    print("✓ All config tests passed!")
