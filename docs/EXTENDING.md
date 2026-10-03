# Extending IDDQD Support Analyzer

## Quick Start: Add New Analyzer in 5 Minutes

### Step 1: Create Analyzer File

```bash
cat > analyzers/log_myservice.py << 'PYTHON'
"""My service log analyzer."""
from __future__ import annotations
import re, collections
from typing import Any

MY_ERROR_RE = re.compile(r'error.*?(\w+)', re.IGNORECASE)

class MyServiceCorrelator:
    def __init__(self):
        self.errors: int = 0
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.first_error_line: int = 0
        self.total_lines = 0
    
    def hint(self, line: str) -> bool:
        return 'myservice' in line.lower() or 'error' in line.lower()
    
    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if not self.hint(line): return
        
        if MY_ERROR_RE.search(line):
            self.findings['error'] += 1
            self.errors += 1
            if self.first_error_line == 0:
                self.first_error_line = idx
    
    def flush(self) -> tuple[list[dict[str, Any]], int]:
        findings = []
        if self.findings['error'] > 0:
            findings.append({
                'signature': f"MyService errors ({self.errors})",
                'count': self.errors,
                'level': 'ERROR',
                'category': 'myservice',
                'kind': 'error',
                'first_line': self.first_error_line or 0,
                'codes': {},
            })
        return findings, self.total_lines
    
    def overflow_unique(self) -> int:
        return 1
    
    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if MY_ERROR_RE.search(line):
            return 'ERROR', 'myservice', 'error'
        return None
    
    def finding_component(self, line: str) -> str | None:
        if MY_ERROR_RE.search(line):
            return 'MyService error'
        return None
    
    def context_pid(self, line: str) -> str | None:
        return None
PYTHON
```

### Step 2: Register in logs.py

```bash
cd analyzers
# Add to logs.py imports
sed -i '/from .log_error_impact import/a from .log_myservice import MyServiceCorrelator' logs.py

# Add to LINE_FAMILY_TYPES tuple
sed -i '/ErrorImpactCorrelator,/a \    MyServiceCorrelator,' logs.py
```

### Step 3: Write Tests

```bash
cat > tests/test_log_myservice.py << 'PYTHON'
from analyzers.logs import analyze_log_text

def test_myservice_error():
    log = 'ERROR: myservice failed: connection_timeout'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1

if __name__ == "__main__":
    test_myservice_error()
    print("✓ MyService tests OK")
PYTHON
```

### Step 4: Test It

```bash
cd /repo
PYTHONPATH=. python tests/test_log_myservice.py
```

Done! ✅

---

## Checklist for New Analyzer

- [ ] Create `analyzers/log_NAME.py` with class `NAMECorrelator`
- [ ] Implement all 7 methods (see API.md)
- [ ] Use meaningful regex patterns (module-level)
- [ ] Track `first_error_line` for sorting
- [ ] Create `tests/test_log_NAME.py` with 5+ tests
- [ ] Register in `analyzers/logs.py`
- [ ] Run tests: `PYTHONPATH=. python tests/test_log_NAME.py`
- [ ] Test integration: `PYTHONPATH=. python -c "from analyzers.logs import analyze_log_text; print(analyze_log_text('your test log'))"`
- [ ] Update README with new analyzer
- [ ] Commit with message: `Add NAMECorrelator for X detection`

---

## Template: Full Minimal Analyzer (Copy & Modify)

```python
"""My analyzer - detect X in logs."""
from __future__ import annotations

import collections
import re
from typing import Any

# Patterns
PATTERN_A_RE = re.compile(r'pattern_a', re.IGNORECASE)
PATTERN_B_RE = re.compile(r'pattern_b', re.IGNORECASE)


class MyCorrelator:
    """Correlate events from my logs."""

    def __init__(self):
        self.events_a: int = 0
        self.events_b: int = 0
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.first_error_line: int = 0
        self.total_lines = 0

    def hint(self, line: str) -> bool:
        return any(kw in line.lower() for kw in ['keyword1', 'keyword2'])

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1
        if not self.hint(line):
            return

        if PATTERN_A_RE.search(line):
            self.findings['event_a'] += 1
            self.events_a += 1
            if self.first_error_line == 0:
                self.first_error_line = idx

        if PATTERN_B_RE.search(line):
            self.findings['event_b'] += 1
            self.events_b += 1

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        findings = []

        if self.findings['event_a'] > 0:
            findings.append({
                'signature': f"Event A ({self.events_a})",
                'count': self.events_a,
                'level': 'WARN',
                'category': 'mycategory',
                'kind': 'event_a',
                'first_line': self.first_error_line or 0,
                'codes': {},
            })

        if self.findings['event_b'] > 0:
            findings.append({
                'signature': f"Event B ({self.events_b})",
                'count': self.events_b,
                'level': 'INFO',
                'category': 'mycategory',
                'kind': 'event_b',
                'first_line': self.first_error_line or 0,
                'codes': {},
            })

        return findings, self.total_lines

    def overflow_unique(self) -> int:
        return max(self.events_a, self.events_b)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if PATTERN_A_RE.search(line):
            return 'WARN', 'my', 'event_a'
        if PATTERN_B_RE.search(line):
            return 'INFO', 'my', 'event_b'
        return None

    def finding_component(self, line: str) -> str | None:
        if PATTERN_A_RE.search(line):
            return 'Event A detected'
        if PATTERN_B_RE.search(line):
            return 'Event B detected'
        return None

    def context_pid(self, line: str) -> str | None:
        # Extract ID for correlation, or return None
        return None
```

---

## Common Patterns

### User/IP Extraction
```python
USER_RE = re.compile(r'(?:user|username|uid)[:\s=]*([^,\s;]+)', re.IGNORECASE)
IP_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

def extract_user(line: str) -> str | None:
    m = USER_RE.search(line)
    return m.group(1) if m else None
```

### Duration Extraction
```python
DURATION_RE = re.compile(r'(?:duration|took|elapsed)[:\s=]*(\d+)\s*(?:ms|s|minutes?)', re.IGNORECASE)

def extract_duration_ms(line: str) -> int | None:
    m = DURATION_RE.search(line)
    if m:
        val = int(m.group(1))
        # Convert seconds to ms if needed
        if 's' in m.group(0).lower() and 'ms' not in m.group(0).lower():
            val *= 1000
        return val
    return None
```

### Error Level Detection
```python
LEVEL_RE = re.compile(r'(?:CRITICAL|ERROR|WARN|INFO)', re.IGNORECASE)

def get_level(line: str) -> str | None:
    m = LEVEL_RE.search(line)
    return m.group(0).upper() if m else None
```

---

## Testing Checklist

```bash
# 1. Unit tests
PYTHONPATH=. python tests/test_log_myservice.py

# 2. Integration test
PYTHONPATH=. python -c "
from analyzers.logs import analyze_log_text
log = 'ERROR: myservice something'
r = analyze_log_text(log)
print(f'Lines: {r[\"line_count\"]}')
print(f'Incidents: {len(r[\"incidents\"])}')
assert r['line_count'] >= 1
print('✓ Integration OK')
"

# 3. Edge cases
PYTHONPATH=. python -c "
from analyzers.logs import analyze_log_text
r = analyze_log_text('')  # Empty
r = analyze_log_text('no match')  # No match
r = analyze_log_text('ERROR\n' * 1000)  # Large
print('✓ Edge cases OK')
"
```

---

## v0.20.0 Feature Additions

The following have been documented but can be added in v0.21.0:

- **Correlation Window**: Extend from 30min to configurable duration
- **Custom Patterns**: Allow users to inject custom regex patterns
- **Filter API**: Filter findings by level, category, time range
- **Export Formats**: JSON, CSV, Splunk, ELK formatters

---

## Getting Help

1. Check `docs/API.md` for LogFamily protocol
2. Check `docs/EXAMPLES.md` for real scenarios
3. Check `docs/ARCHITECTURE.md` for system design
4. Look at existing analyzers in `analyzers/log_*.py`
5. Read docstrings in your analyzer
6. Run with `PYTHONPATH=. python -c "from analyzers import log_xyz; help(log_xyz.XYZCorrelator)"`

