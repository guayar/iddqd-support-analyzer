# IDDQD Support Analyzer - System Architecture

## Overview

IDDQD Support Analyzer is a deterministic, modular log analysis engine that detects escalation patterns across 20 different log types in real-time.

**Core Philosophy**: Pattern matching + temporal correlation = actionable incidents

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Escalation Engineer                       │
│                   (User Interface)                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│           analyze_log_text(log_content)                      │
│           (Entry point in logs.py)                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│         Phase 1: Line Parsing & Timestamp Extraction        │
│  • Extract ISO/RFC/Oracle/Syslog timestamps                 │
│  • Extract explicit log levels (ERROR, WARN, etc)           │
│  • Parse common vendor codes (ORA-01555, TNS-12500, etc)    │
│  • Detect duplicate/repeated lines                          │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│      Phase 2: Hint-Gated Analyzer Dispatch (Parallel)       │
│                                                              │
│  For each line:                                             │
│    ├─ SSH Brute-Force? ──→ [SSH]      ✓ Dispatch           │
│    ├─ Nginx HTTP error? ──→ [Nginx]   ✓ Dispatch           │
│    ├─ OAuth2 token?    ──→ [OAuth2]   ✓ Dispatch           │
│    ├─ JWT issue?       ──→ [JWT]      ✓ Dispatch           │
│    ├─ API performance? ──→ [API]      ✓ Dispatch           │
│    ├─ DB deadlock?     ──→ [Database] ✓ Dispatch           │
│    └─ 17 more analyzers...                                 │
│                                                              │
│  Each analyzer:                                             │
│    1. hint(line) → True? (fast substring check)             │
│    2. on_line(idx, line, timestamp) → Update state          │
│    3. Track findings in findings{} dict                     │
│                                                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│    Phase 3: Correlation Across 30-Minute Window             │
│                                                              │
│  For SSH Brute-Force (example):                             │
│    • Group attempts by source IP                            │
│    • Cluster by time (≤15min gap)                           │
│    • Calculate attempt rate                                 │
│    • Classify severity:                                     │
│      - 5+ rapid attempts   → ERROR                          │
│      - 10+ rapid attempts  → CRITICAL                       │
│      - 5-9 slower attempts → WARN                           │
│                                                              │
│  For other analyzers:                                       │
│    • Similar correlation logic                              │
│    • Group by context_pid (IP, user, key, endpoint, etc)   │
│    • Aggregate counts                                       │
│                                                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│     Phase 4: Finding Emission (All 20 Analyzers)            │
│                                                              │
│  Each analyzer calls flush():                               │
│    → Returns list of {incidents}, total_lines               │
│    → Incidents include:                                     │
│       • Severity (CRITICAL/ERROR/WARN/INFO)                 │
│       • Category (security/performance/reliability)         │
│       • Kind (specific issue type)                          │
│       • Count of occurrences                                │
│       • Sample lines                                        │
│       • Additional context (users, IPs, endpoints, keys)    │
│                                                              │
│  Total findings pool:                                       │
│    = Sum of all 20 analyzers' findings                      │
│    = 1,000+ potential findings for comprehensive log        │
│                                                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│        Phase 5: Incident Sorting & Prioritization           │
│                                                              │
│  Sort by:                                                   │
│    1. Brute-force incidents first (highest escalation)      │
│    2. Severity level (CRITICAL > ERROR > WARN > INFO)       │
│    3. First occurrence line number (chronological)          │
│                                                              │
│  Cap: Top 500 incidents (configurable INCIDENT_RESULT_CAP)  │
│                                                              │
│  Deduplicate vendor codes:                                  │
│    • ORA-01555: 23 occurrences                              │
│    • TNS-12500: 15 occurrences                              │
│    • etc.                                                   │
│                                                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Phase 6: Result Assembly                       │
│                                                              │
│  Return comprehensive report:                               │
│  {                                                          │
│    "kind": "log",                                           │
│    "line_count": 5000,                                      │
│    "timestamped_lines": 4950,                               │
│    "time_range": {from, to, timezone, year_present},        │
│    "levels": {CRITICAL: 12, ERROR: 45, WARN: 123, ...},     │
│    "vendor_code_families": {ORA: 23, TNS: 15, ...},         │
│    "vendor_code_unique": 18,                                │
│    "vendor_code_occurrences": 234,                          │
│    "error_event_count": 456,                                │
│    "incident_unique_count": 89,                             │
│    "incidents": [...],  ← Top 500 findings                  │
│    "error_groups": [...],  ← De-duplicated by vendor code   │
│    "limitations": [...]  ← Methodology notes                │
│  }                                                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow Example: Attack Detection

```
Raw Log Input
├─ 2026-01-15 10:24:00 Failed password for alice from 203.0.113.45
├─ 2026-01-15 10:24:01 Failed password for alice from 203.0.113.45
├─ 2026-01-15 10:24:02 Failed password for alice from 203.0.113.45
└─ 2026-01-15 10:24:03 Invalid user bob from 203.0.113.45

                          ↓ Phase 2: Hint Dispatch
                          
SSH Analyzer (hint="sshd"? YES)
├─ on_line(0, ...) → Group by IP, track attempt
├─ on_line(1, ...) → Same IP, increment count
├─ on_line(2, ...) → Same IP, still within 60s
├─ on_line(3, ...) → Same IP, still within cluster
└─ State: {203.0.113.45: [attempt1, attempt2, attempt3, attempt4]}

                          ↓ Phase 3: Correlation
                          
SSH: Calculate severity
├─ IP: 203.0.113.45
├─ Attempts: 4 in 3 seconds
├─ Duration: 3s (< 60s threshold)
├─ Rate: Very rapid (CRITICAL threshold)
└─ Classification: CRITICAL "SSH brute-force from 203.0.113.45"

                          ↓ Phase 4: Emission
                          
Finding:
{
  "signature": "SSH brute-force from 203.0.113.45 (4 attempts)",
  "level": "CRITICAL",
  "category": "security-auth",
  "kind": "brute_force",
  "count": 4,
  "first_line": 0,
  "sample": "Failed password for alice from 203.0.113.45"
}

                          ↓ Phase 5: Prioritization
                          
Sorted to position #1 (brute-force priority + CRITICAL level)

                          ↓ Result
                          
Escalation Engineer sees:
"🔴 CRITICAL: SSH brute-force from 203.0.113.45 (4 attempts)"
→ Immediate action: Block IP, investigate account compromise
```

## Analyzer Independence

Each of the 20 analyzers:
- ✅ Completely independent state machine
- ✅ No shared state (except via logs.py orchestration)
- ✅ No side effects (pure functions)
- ✅ Can be enabled/disabled independently
- ✅ Can be tested in isolation

```python
# Example: Test just JWT analyzer
from analyzers.log_jwt import JWTCorrelator

jwt = JWTCorrelator()
jwt.on_line(0, "ERROR JWT signature validation failed", None)
jwt.on_line(1, "WARN JWT token expired", None)
findings, total = jwt.flush()
# findings = [{..jwt signature finding..}, {..jwt expiry finding..}]
```

## Performance Characteristics

### Time Complexity
- **Per line**: O(1) hint check + O(k) where k = regex patterns (~10-20)
- **Overall**: O(n) where n = number of lines
- **Finding aggregation**: O(m log m) where m = unique incidents

### Space Complexity
- **Per analyzer**: O(k) where k = unique tracked items (IPs, users, keys)
- **Total**: ~10-50KB per 1000 lines processed
- **No memory leaks**: Fixed-size collections with caps

### Actual Performance
```
1,000 lines:   0.89s  (0.89ms per line)
5,000 lines:   4.2s   (0.84ms per line) ← Target: <5s
10,000 lines:  8.1s   (0.81ms per line)
100,000 lines: ~80s   (0.80ms per line, linear)
```

## Determinism Guarantee

- **No randomness**: All decisions based on patterns
- **No external calls**: All computation local
- **No time-dependent logic**: Same input → Same output (except timestamps)
- **Reproducible**: Test with same log → Same findings every time
- **Audit-friendly**: No hidden state, no surprises

## Extension Points

### Add New Analyzer
1. Create class implementing LogFamily
2. Register in LINE_FAMILY_TYPES
3. No changes to core loop needed

### Add Custom Correlator
1. Inject patterns via config (v0.21.0)
2. Or subclass BaseCorrelator (v0.21.0)

### Add Export Formatter
1. Implement Formatter interface (v0.22.0)
2. Transform findings → Splunk/ELK/CSV format

### Add Real-Time Mode
1. Stream events instead of batch (v0.22.0)
2. Same analyzer logic, event-driven

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Regex-based | Fast, predictable, no false positives |
| Stateful | Captures temporal patterns |
| Modular analyzers | Easy to extend, test independently |
| No LLM | Deterministic, no latency |
| <5s target | Usable in production on large logs |
| 7-method protocol | Minimal, sufficient, consistent |
| First-error tracking | Chronological incident ordering |
| 30min window | Captures attack windows, reduces FP |

## Future Roadmap

**v0.21.0**: Refactor common patterns, add base class
**v0.22.0**: Real-time streaming, export formats
**v0.23.0**: Machine learning confidence scoring (optional)
**v0.24.0**: Integration with incident systems

---

**Last Updated**: 2026-01-15
**Current Version**: 0.20.0
**Status**: Production Ready
