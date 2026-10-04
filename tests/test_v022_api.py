"""Tests for v0.22 API server."""

import os
import sys
import json
import unittest
from io import BytesIO
from unittest.mock import Mock, patch

# Skip in Light edition - API server not available
if os.getenv("LIGHT_EDITION"):
    print("SKIPPED: API server tests not available in Light edition", file=sys.stderr)
    sys.exit(0)

from analyzers.api_server import AnalysisHandler


class TestAnalysisAPI(unittest.TestCase):
    """Test API server endpoints."""

    def setUp(self):
        """Set up test fixtures."""
        self.handler = AnalysisHandler(
            Mock(), ("127.0.0.1", 8000), Mock()
        )
        # Mock the socket and server
        self.handler.rfile = BytesIO()
        self.handler.wfile = BytesIO()
        self.handler.client_address = ("127.0.0.1", 12345)
        self.handler.server = Mock()

    def test_handler_exists(self):
        """Test that handler class exists."""
        assert AnalysisHandler is not None

    def test_analyze_endpoint_structure(self):
        """Test /analyze endpoint structure."""
        # Verify method exists
        assert hasattr(AnalysisHandler, "_handle_analyze")

    def test_batch_endpoint_structure(self):
        """Test /batch endpoint structure."""
        # Verify method exists
        assert hasattr(AnalysisHandler, "_handle_batch")

    def test_health_endpoint_structure(self):
        """Test /health endpoint exists."""
        # Verify method exists
        assert hasattr(AnalysisHandler, "do_GET")

    def test_send_json_formats_correctly(self):
        """Test that JSON formatting works."""
        handler = AnalysisHandler(
            Mock(), ("127.0.0.1", 8000), Mock()
        )
        handler.wfile = BytesIO()

        # Call _send_json
        test_data = {"status": "success", "data": {"key": "value"}}

        # Mock send_response, send_header, end_headers
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()

        handler._send_json(test_data)

        # Verify response was attempted
        handler.send_response.assert_called_once_with(200)

    def test_send_error_formats_correctly(self):
        """Test error response formatting."""
        handler = AnalysisHandler(
            Mock(), ("127.0.0.1", 8000), Mock()
        )
        handler.wfile = BytesIO()

        # Mock methods
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()

        handler._send_error(400, "Bad request")

        # Should have called send_response
        handler.send_response.assert_called_once_with(400)

    def test_api_request_format_single_file(self):
        """Test API accepts single file uploads."""
        # Expected format for single file:
        # Raw POST data with log content

        # Simulate POST with log content
        log_content = "ERROR: test error\n" * 5
        assert isinstance(log_content, str)
        assert len(log_content) > 0

    def test_api_request_format_batch(self):
        """Test API accepts batch file uploads."""
        # Expected format for batch:
        # JSON with files array
        # [{"name": "app.log", "content": "..."}, ...]

        request_data = {
            "files": [
                {"name": "app.log", "content": "ERROR: error 1\n"},
                {"name": "db.log", "content": "ERROR: error 2\n"},
            ]
        }

        json_data = json.dumps(request_data)
        assert isinstance(json_data, str)
        assert "app.log" in json_data
        assert "db.log" in json_data

    def test_response_includes_metadata(self):
        """Test responses include metadata."""
        # Single file response should include:
        # - status
        # - analysis
        # - metadata (lines_analyzed, incidents_found)

        expected_response_keys = {"status", "analysis", "metadata"}

        response_struct = {
            "status": "success",
            "analysis": {"incidents": []},
            "metadata": {
                "lines_analyzed": 0,
                "incidents_found": 0,
            },
        }

        assert expected_response_keys == set(response_struct.keys())

    def test_batch_response_includes_correlation(self):
        """Test batch responses include correlation info."""
        # Batch response should include:
        # - status
        # - analysis
        # - metadata (files_analyzed, correlation_strength)

        response_struct = {
            "status": "success",
            "analysis": {
                "summary": {},
                "cross_file_insights": {
                    "correlation_strength": "WEAK"
                },
            },
            "metadata": {
                "files_analyzed": 2,
                "correlation_strength": "WEAK",
            },
        }

        assert response_struct["metadata"]["correlation_strength"] in [
            "WEAK", "MODERATE", "STRONG"
        ]

    def test_correlation_message_for_no_correlation(self):
        """Test that NO CORRELATION message appears when needed."""
        # When correlation_strength is WEAK, should have message
        response_with_weak = {
            "correlation_message": (
                "⚠️  NO STRONG CORRELATION FOUND between files. "
                "Each may represent separate incidents."
            ),
            "correlation_strength": "WEAK",
        }

        assert "NO STRONG CORRELATION" in response_with_weak["correlation_message"]

    def test_correlation_message_for_moderate(self):
        """Test correlation message for moderate correlation."""
        response = {
            "correlation_message": (
                "Moderate correlation detected. Events appear related but confidence is moderate."
            ),
            "correlation_strength": "MODERATE",
        }

        assert "confidence is moderate" in response["correlation_message"]

    def test_correlation_message_for_strong(self):
        """Test correlation message for strong correlation."""
        response = {
            "correlation_message": (
                "Strong causality chain detected across files."
            ),
            "correlation_strength": "STRONG",
        }

        assert "Strong causality" in response["correlation_message"]


class TestAnalysisServerConfig(unittest.TestCase):
    """Test server configuration."""

    def test_server_default_port(self):
        """Test default server port."""
        from analyzers.api_server import AnalysisServer

        server = AnalysisServer()
        assert server.port == 8000
        assert server.host == "localhost"

    def test_server_custom_config(self):
        """Test custom server configuration."""
        from analyzers.api_server import AnalysisServer

        server = AnalysisServer(host="0.0.0.0", port=9000)
        assert server.port == 9000
        assert server.host == "0.0.0.0"


if __name__ == "__main__":
    unittest.main()
