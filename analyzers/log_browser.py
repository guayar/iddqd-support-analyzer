"""Browser/E2E logs: Selenium/Playwright failures, JS errors, timeouts."""
from __future__ import annotations
import collections, re
from typing import Any

ELEMENT_NOT_FOUND_RE = re.compile(r'(?:element|selector).*?(?:not.*?found|timeout|stale)', re.IGNORECASE)
JS_ERROR_RE = re.compile(r'(?:javascript|js).*?(?:error|undefined|exception)', re.IGNORECASE)
SCREENSHOT_RE = re.compile(r'(?:screenshot|capture).*?(?:saved|taken|failure)', re.IGNORECASE)

class BrowserCorrelator:
    def __init__(self):
        self.element_failures: int = 0
        self.js_errors: int = 0
        self.screenshots: int = 0
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.first_error_line: int = 0
        self.total_lines = 0

    def hint(self, line: str) -> bool:
        return any(kw in line.lower() for kw in ['element', 'javascript', 'browser', 'selenium', 'playwright', 'js_error'])

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if not self.hint(line): return
        if any(kw in line.lower() for kw in ['error', 'fail', 'timeout']):
            if self.first_error_line == 0: self.first_error_line = idx
        
        if ELEMENT_NOT_FOUND_RE.search(line): self.findings['element_failure'] += 1; self.element_failures += 1
        if JS_ERROR_RE.search(line): self.findings['js_error'] += 1; self.js_errors += 1
        if SCREENSHOT_RE.search(line): self.findings['screenshot'] += 1; self.screenshots += 1

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        findings = []
        first_line = self.first_error_line if self.first_error_line > 0 else 0
        
        if self.findings['element_failure'] > 0:
            findings.append({'signature': f"Element not found ({self.element_failures})", 'count': self.element_failures, 'level': 'ERROR', 'category': 'browser', 'kind': 'element_failure', 'first_line': first_line, 'codes': {}})
        if self.findings['js_error'] > 0:
            findings.append({'signature': f"JS errors ({self.js_errors})", 'count': self.js_errors, 'level': 'ERROR', 'category': 'browser', 'kind': 'js_error', 'first_line': first_line, 'codes': {}})
        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return self.findings['element_failure'] + self.findings['js_error']

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if ELEMENT_NOT_FOUND_RE.search(line): return 'ERROR', 'e2e', 'element_failure'
        if JS_ERROR_RE.search(line): return 'ERROR', 'e2e', 'js_error'
        return None

    def finding_component(self, line: str) -> str | None:
        if ELEMENT_NOT_FOUND_RE.search(line): return 'Element not found'
        if JS_ERROR_RE.search(line): return 'JS error'
        return None

    def context_pid(self, line: str) -> str | None:
        return None
