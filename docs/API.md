# LogFamily Protocol API Reference

## Overview

The IDDQD Support Analyzer uses a **LogFamily protocol** - a 7-method interface that all log analyzers implement. This enables modular, independent analysis of different log types with automatic correlation.

## LogFamily Protocol

Every analyzer must implement these 7 methods:

```python
class LogFamily(Protocol):
    """Stateful log analyzer correlator."""
    
    def hint(self, line: str) -> bool:
        """Quick check: might this line be for my analyzer?"""
        ...
    
    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        """Process one line of the log."""
        ...
    
    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings after all lines processed."""
        ...
    
    def overflow_unique(self) -> int:
        """Return count of unique items tracked (for memory management)."""
        ...
    
    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        """Return (level, category, kind) for incident reporting."""
        ...
    
    def finding_component(self, line: str) -> str | None:
        """Extract meaningful error message from line."""
        ...
    
    def context_pid(self, line: str) -> str | None:
        """Extract correlation ID (PID, user, IP, etc)."""
        ...
```

## Method Details

### `hint(line: str) -> bool`

**Purpose**: Fast pre-filter to decide if this line might be relevant.

**Rules**:
- Must be FAST (O(1) substring/prefix check)
- Return `False` if definitely not your log type
- Return `True` if possibly relevant

**Example**:
```python
def hint(self, line: str) -> bool:
    return any(kw in line.lower() for kw in [
        'error', 'jwt', 'signature', 'token'
    ])
```

### `on_line(idx: int, line: str, stamp: str | None) -> None`

**Purpose**: Process one line of the log.

**Parameters**:
- `idx`: Line number (0-indexed) for sorting/tracking
- `line`: The log line text
- `stamp`: Parsed timestamp (if available), else None

**Rules**:
- Called once per line (after hint() returns True)
- Must update internal state (findings, counts, etc)
- Must be deterministic (same input → same state)
- Never throw exceptions

**Example**:
```python
def on_line(self, idx: int, line: str, stamp: str | None) -> None:
    self.total_lines += 1
    
    match = JWT_SIGNATURE_FAIL_RE.search(line)
    if match:
        self.findings['signature_failure'] += 1
        self.signature_failures.append({
            'line_idx': idx,
            'kid': match.group('kid'),
        })
```

### `flush() -> tuple[list[dict[str, Any]], int]`

**Purpose**: Emit final findings after all lines processed.

**Returns**:
- List of incident dictionaries (findings)
- Total line count processed

**Finding Dictionary Structure**:
```python
{
    'signature': str,           # One-liner: "JWT failures (2 events)"
    'count': int,               # Total occurrences
    'level': str,               # CRITICAL|ERROR|WARN|INFO
    'category': str,            # security|performance|reliability|etc
    'kind': str,                # signature_failure|timeout|etc
    'first_line': int,          # Line index for sorting
    'root_cause': Optional[str],
    'top_exception': Optional[str],
    'causes': list,
    'exception_chain': list,
    'exit_code': Optional[int],
    'codes': dict,              # Vendor codes
    'sample': str,              # Example log excerpt
    # ... analyzer-specific fields
}
```

**Example**:
```python
def flush(self) -> tuple[list[dict[str, Any]], int]:
    findings = []
    
    if self.findings['signature_failure'] > 0:
        findings.append({
            'signature': f"JWT signature failures ({self.findings['signature_failure']})",
            'count': self.findings['signature_failure'],
            'level': 'CRITICAL',
            'category': 'security-token',
            'kind': 'signature_failure',
            'first_line': self.first_error_line or 0,
            'codes': {},
            'sample': self.signature_failures[0]['line'],
        })
    
    return findings, self.total_lines
```

### `overflow_unique() -> int`

**Purpose**: Track unique items for memory management.

**Usage**: 
- Returns count of unique tracked entities (IPs, users, keys, etc)
- Used by correlator cap in logs.py
- Helps detect when memory management is needed

**Example**:
```python
def overflow_unique(self) -> int:
    return len(self.tokens_seen) + len(self.key_ids)
```

### `line_rule(line: str) -> tuple[str, str, str] | None`

**Purpose**: Fast severity classification for line-level reporting.

**Returns**: `(level, category, kind)` or `None`

**Levels**: `CRITICAL`, `ERROR`, `WARN`, `INFO`

**Example**:
```python
def line_rule(self, line: str) -> tuple[str, str, str] | None:
    if JWT_SIGNATURE_FAIL_RE.search(line):
        return 'CRITICAL', 'token', 'signature_validation_fail'
    if JWT_EXPIRED_RE.search(line):
        return 'WARN', 'token', 'token_expired'
    return None
```

### `finding_component(line: str) -> str | None`

**Purpose**: Extract meaningful component/message for logging.

**Returns**: Human-readable error message or `None`

**Example**:
```python
def finding_component(self, line: str) -> str | None:
    if JWT_SIGNATURE_FAIL_RE.search(line):
        return 'JWT signature validation failed'
    if JWT_EXPIRED_RE.search(line):
        return 'JWT token expired'
    return None
```

### `context_pid(line: str) -> str | None`

**Purpose**: Extract correlation ID for grouping events.

**Returns**: 
- User ID, IP address, PID, session ID, or any correlation ID
- First 16 chars (for memory efficiency)
- `None` if N/A

**Example**:
```python
def context_pid(self, line: str) -> str | None:
    kid_match = JWT_KEY_ID_RE.search(line)
    if kid_match:
        return kid_match.group(1)[:16]
    
    user_match = USER_RE.search(line)
    if user_match:
        return user_match.group(1)[:16]
    
    return None
```

## Integration

### 1. Create Analyzer

```python
# analyzers/log_example.py
from __future__ import annotations
import re, collections
from typing import Any

PATTERN_RE = re.compile(r'error: (\w+)', re.IGNORECASE)

class ExampleCorrelator:
    def __init__(self):
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.first_error_line: int = 0
        self.total_lines = 0
    
    def hint(self, line: str) -> bool:
        return 'error' in line.lower()
    
    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if PATTERN_RE.search(line):
            self.findings['error'] += 1
            if self.first_error_line == 0:
                self.first_error_line = idx
    
    def flush(self) -> tuple[list[dict[str, Any]], int]:
        findings = []
        if self.findings['error'] > 0:
            findings.append({
                'signature': f"Example errors ({self.findings['error']})",
                'count': self.findings['error'],
                'level': 'ERROR',
                'category': 'example',
                'kind': 'error',
                'first_line': self.first_error_line,
                'codes': {},
            })
        return findings, self.total_lines
    
    def overflow_unique(self) -> int:
        return 1
    
    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if PATTERN_RE.search(line):
            return 'ERROR', 'example', 'error'
        return None
    
    def finding_component(self, line: str) -> str | None:
        if PATTERN_RE.search(line):
            return 'Example error detected'
        return None
    
    def context_pid(self, line: str) -> str | None:
        return None
```

### 2. Register in logs.py

```python
# analyzers/logs.py
from .log_example import ExampleCorrelator

LINE_FAMILY_TYPES: tuple[type[LogFamily], ...] = (
    # ... existing analyzers ...
    ExampleCorrelator,
)
```

### 3. Write Tests

```python
# tests/test_log_example.py
from analyzers.logs import analyze_log_text

def test_example_error():
    log = 'error: critical_issue detected'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1

if __name__ == "__main__":
    test_example_error()
    print("✓ Example tests OK")
```

## Performance Guidelines

- **hint()**: Must be <100ns per call (use simple substring checks)
- **on_line()**: Should be <1µs per call
- **Total**: <1s per 1MB (5000 lines)

## Error Handling

- **Never throw** exceptions in on_line() or flush()
- **Gracefully handle** malformed log lines
- **Skip silently** if pattern doesn't match

## Best Practices

1. **Use compiled regexes** at module level (not in on_line)
2. **Track first_error_line** for sorting findings
3. **Group related findings** in flush() (don't over-fragment)
4. **Use defaultdict** for flexible state tracking
5. **Set first_line to 0** if no errors found
6. **Return (level, category, kind)** as strings, not enums
7. **Keep sample text short** (<100 chars)
8. **Document patterns** with examples in docstrings

## Example: Full Minimal Analyzer

```python
# 50 lines minimum template
class MinimalCorrelator:
    def __init__(self):
        self.count = 0
        self.first_error_line = 0
        self.total_lines = 0
    
    def hint(self, line: str) -> bool:
        return 'keyword' in line.lower()
    
    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if 'keyword' in line.lower():
            self.count += 1
            if self.first_error_line == 0:
                self.first_error_line = idx
    
    def flush(self) -> tuple[list[dict[str, Any]], int]:
        if self.count > 0:
            return [{
                'signature': f"Keywords found ({self.count})",
                'count': self.count,
                'level': 'INFO',
                'category': 'custom',
                'kind': 'keyword',
                'first_line': self.first_error_line,
                'codes': {},
            }], self.total_lines
        return [], self.total_lines
    
    def overflow_unique(self) -> int:
        return 0
    
    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if 'keyword' in line.lower():
            return 'INFO', 'custom', 'keyword'
        return None
    
    def finding_component(self, line: str) -> str | None:
        return 'Keyword found' if 'keyword' in line.lower() else None
    
    def context_pid(self, line: str) -> str | None:
        return None
```

---

**API Version**: 1.0
**Analyzer Count**: 20
**Supported**: Python 3.9+
