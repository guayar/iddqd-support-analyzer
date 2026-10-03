"""Message queue monitoring: Delivery failures, DLQ, ordering, lag."""
from __future__ import annotations
import collections, re
from typing import Any

DELIVERY_FAIL_RE = re.compile(r'(?:message|event).*?(?:fail|error|rejected)', re.IGNORECASE)
DLQ_RE = re.compile(r'(?:dlq|dead.*?letter|dead.*?queue)', re.IGNORECASE)
LAG_RE = re.compile(r'(?:lag|consumer.*?lag)[:\s=]*(\d+)', re.IGNORECASE)
ORDER_VIOLATION_RE = re.compile(r'(?:order|sequence).*?(?:violation|wrong)', re.IGNORECASE)

class MessageQueueCorrelator:
    def __init__(self):
        self.delivery_failures: int = 0
        self.dlq_messages: int = 0
        self.order_violations: int = 0
        self.max_lag: int = 0
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.first_error_line: int = 0
        self.total_lines = 0

    def hint(self, line: str) -> bool:
        return any(kw in line.lower() for kw in ['message', 'queue', 'event', 'dlq', 'kafka', 'rabbit'])

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if not self.hint(line): return
        if any(kw in line.lower() for kw in ['fail', 'error', 'violation']):
            if self.first_error_line == 0: self.first_error_line = idx
        
        if DELIVERY_FAIL_RE.search(line): self.findings['delivery_failure'] += 1; self.delivery_failures += 1
        if DLQ_RE.search(line): self.findings['dlq'] += 1; self.dlq_messages += 1
        if ORDER_VIOLATION_RE.search(line): self.findings['order_violation'] += 1; self.order_violations += 1
        if m := LAG_RE.search(line): self.max_lag = max(self.max_lag, int(m.group(1)))

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        findings = []
        first_line = self.first_error_line if self.first_error_line > 0 else 0
        
        if self.findings['delivery_failure'] > 0:
            findings.append({'signature': f"Message delivery failures ({self.delivery_failures})", 'count': self.delivery_failures, 'level': 'ERROR', 'category': 'messaging', 'kind': 'delivery_failure', 'first_line': first_line, 'codes': {}})
        if self.findings['dlq'] > 0:
            findings.append({'signature': f"DLQ messages ({self.dlq_messages})", 'count': self.dlq_messages, 'level': 'ERROR', 'category': 'messaging', 'kind': 'dlq', 'first_line': first_line, 'codes': {}})
        if self.max_lag > 0:
            findings.append({'signature': f"Consumer lag: {self.max_lag}s", 'count': 1, 'level': 'WARN', 'category': 'messaging', 'kind': 'consumer_lag', 'first_line': first_line, 'codes': {}})
        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return self.findings['delivery_failure'] + self.findings['dlq']

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if DELIVERY_FAIL_RE.search(line): return 'ERROR', 'msg', 'delivery_fail'
        if DLQ_RE.search(line): return 'ERROR', 'msg', 'dlq'
        return None

    def finding_component(self, line: str) -> str | None:
        if DELIVERY_FAIL_RE.search(line): return 'Message delivery failed'
        return None

    def context_pid(self, line: str) -> str | None:
        return None
