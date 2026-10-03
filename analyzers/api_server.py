"""API server for v0.22 - HTTP endpoint for log analysis.

Endpoints:
  POST /analyze - Upload and analyze log file(s)
  GET /incidents - Query analysis results
  POST /batch - Analyze multiple files
"""

from __future__ import annotations

import json
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Any

from .logs import analyze_log_text
from .multi_file_analyzer import MultiFileAnalyzer


class AnalysisHandler(BaseHTTPRequestHandler):
    """HTTP request handler for analysis API."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default logging."""
        pass

    def do_POST(self) -> None:
        """Handle POST requests."""
        if self.path == "/analyze":
            self._handle_analyze()
        elif self.path == "/batch":
            self._handle_batch()
        else:
            self._send_error(404, "Endpoint not found")

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == "/health":
            self._send_json({"status": "healthy"})
        elif self.path.startswith("/incidents"):
            self._handle_get_incidents()
        else:
            self._send_error(404, "Endpoint not found")

    def _handle_analyze(self) -> None:
        """Handle single file analysis."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_error(400, "No content provided")
                return

            # Read log content
            body = self.rfile.read(content_length)
            log_text = body.decode("utf-8", errors="replace")

            # Analyze
            result = analyze_log_text(log_text)

            # Format response
            response = {
                "status": "success",
                "analysis": result,
                "metadata": {
                    "lines_analyzed": result.get("line_count", 0),
                    "incidents_found": len(result.get("incidents", [])),
                },
            }

            self._send_json(response)

        except Exception as e:
            self._send_error(500, f"Analysis failed: {str(e)}")

    def _handle_batch(self) -> None:
        """Handle multi-file analysis."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_error(400, "No content provided")
                return

            # Parse JSON request with file contents
            body = self.rfile.read(content_length)
            request_data = json.loads(body.decode("utf-8"))

            if "files" not in request_data or not request_data["files"]:
                self._send_error(400, "No files provided in request")
                return

            # Prepare file dict
            file_contents = {}
            for file_entry in request_data["files"]:
                if isinstance(file_entry, dict):
                    # Format: {"name": "app.log", "content": "log text"}
                    name = file_entry.get("name", f"file_{len(file_contents)}")
                    content = file_entry.get("content", "")
                    file_contents[name] = content

            if not file_contents:
                self._send_error(400, "No valid files in request")
                return

            # Analyze multiple files
            analyzer = MultiFileAnalyzer()
            result = analyzer.analyze_files(file_contents)

            # Enhance response with correlation status
            correlation_strength = result.get("cross_file_insights", {}).get(
                "correlation_strength", "UNKNOWN"
            )
            if correlation_strength == "WEAK":
                result["correlation_message"] = (
                    "⚠️  NO STRONG CORRELATION FOUND between files. "
                    "Each may represent separate incidents."
                )
            elif correlation_strength == "MODERATE":
                result["correlation_message"] = (
                    "Moderate correlation detected. Events appear related but confidence is moderate."
                )
            elif correlation_strength == "STRONG":
                result["correlation_message"] = (
                    "Strong causality chain detected across files."
                )

            response = {
                "status": "success",
                "analysis": result,
                "metadata": {
                    "files_analyzed": len(file_contents),
                    "total_lines": result["summary"]["total_lines_analyzed"],
                    "root_cause_incidents": result["summary"]["root_cause_incidents"],
                    "correlation_strength": correlation_strength,
                },
            }

            self._send_json(response)

        except json.JSONDecodeError:
            self._send_error(400, "Invalid JSON in request")
        except Exception as e:
            self._send_error(500, f"Batch analysis failed: {str(e)}")

    def _handle_get_incidents(self) -> None:
        """Handle incidents query (stub - would need state management)."""
        response = {
            "message": "Use POST /analyze or POST /batch to get analysis results",
            "endpoints": {
                "POST /analyze": "Upload single log file (raw text)",
                "POST /batch": "Upload multiple files (JSON format)",
                "GET /health": "Check server health",
            },
        }
        self._send_json(response)

    def _send_json(self, data: dict[str, Any]) -> None:
        """Send JSON response."""
        response_text = json.dumps(data, indent=2, default=str)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_text)))
        self.end_headers()
        self.wfile.write(response_text.encode("utf-8"))

    def _send_error(self, code: int, message: str) -> None:
        """Send error response."""
        error_response = {"status": "error", "message": message}
        response_text = json.dumps(error_response, indent=2)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_text)))
        self.end_headers()
        self.wfile.write(response_text.encode("utf-8"))


class AnalysisServer:
    """API server for log analysis."""

    def __init__(self, host: str = "localhost", port: int = 8000):
        """Initialize server.

        Args:
            host: Server host (default localhost)
            port: Server port (default 8000)
        """
        self.host = host
        self.port = port
        self.server = None

    def start(self) -> None:
        """Start the server."""
        address = (self.host, self.port)
        self.server = HTTPServer(address, AnalysisHandler)
        print(f"🚀 IDDQD Analysis Server running on {self.host}:{self.port}")
        print()
        print("📝 Endpoints:")
        print(f"   POST http://{self.host}:{self.port}/analyze")
        print(f"   POST http://{self.host}:{self.port}/batch")
        print(f"   GET  http://{self.host}:{self.port}/health")
        print()
        print("Examples:")
        print(f"   curl -X POST http://{self.host}:{self.port}/analyze --data @app.log")
        print()

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            print("\n✅ Server stopped")

    def stop(self) -> None:
        """Stop the server."""
        if self.server:
            self.server.shutdown()


def run_server(host: str = "localhost", port: int = 8000) -> None:
    """Run analysis server.

    Args:
        host: Server host
        port: Server port
    """
    server = AnalysisServer(host, port)
    server.start()


if __name__ == "__main__":
    import sys

    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000

    run_server(host, port)
