# Knowledge Base Design for IDDQD Support Analyzer

**Status**: DESIGN ONLY (v0.22) - Implementation planned for v0.23+

## Purpose

The Knowledge Base (KB) extends IDDQD's deterministic analysis with curated, human-verified patterns and rules for specific environments, systems, and incident types.

## Design Principles

### 1. **Deterministic + Human Review = Trustworthy**

- KB rules are written by humans (operators, SREs, domain experts)
- Each rule is tagged with: author, creation date, last verified date, verification cadence
- Rules are NOT learned from data (no ML, no autonomous updates)
- All rules can be audited: source, confidence, when last verified

### 2. **Environment-Specific**

KB is per-environment:
- Production vs staging vs development
- Different services have different normal patterns
- Rules capture environment-specific baselines
- Example: "In prod, 3+ 5xx errors in 30s is critical. In staging, 50+ is normal."

### 3. **Layered Confidence**

Each rule has explicit confidence level:

- **VERIFIED** (high confidence): Tested by human, known root cause
- **PATTERN** (medium confidence): Observed multiple times, pattern seems stable
- **HYPOTHESIS** (low confidence): Proposed by system, needs verification
- **DEPRECATED** (not used): Previously used, now outdated

### 4. **Actionable + Safe**

- Rules suggest investigation steps, not automated actions
- No auto-remediation (operator always reviews before acting)
- Rules marked BLOCKED if too risky or context-dependent
- Rules include prerequisite checks (e.g., "only applies if feature X enabled")

## Rule Structure

### Basic Rule

```json
{
  "rule_id": "kb_pg_deadlock_cascade_001",
  "title": "PostgreSQL deadlock cascade pattern",
  "confidence": "VERIFIED",
  "environment": "production",
  "created_by": "alice@company.com",
  "created_date": "2026-09-15",
  "last_verified": "2026-10-03",
  "verification_cadence": "quarterly",
  
  "description": "When PostgreSQL reports deadlock, connection pool exhaustion follows within 2-5 seconds, causing HTTP 503 timeouts.",
  
  "triggers": [
    {
      "analyzer": "postgresql",
      "kind": "deadlock",
      "count_threshold": 1,
      "time_window_seconds": 5
    }
  ],
  
  "expected_cascade": [
    {
      "analyzer": "postgresql",
      "kind": "connection_pool_exhausted",
      "time_after_trigger_seconds": "2-5",
      "confidence": 0.95
    },
    {
      "analyzer": "nginx",
      "kind": "http_503",
      "time_after_trigger_seconds": "3-7",
      "confidence": 0.90
    }
  ],
  
  "investigation_steps": [
    "Check postgres slow query log for the blocking query",
    "Identify which connections are blocked",
    "Check application connection pool settings",
    "Review recent schema changes or query plan changes",
    "Look for foreign key lock contention"
  ],
  
  "typical_root_causes": [
    "Foreign key constraint check during bulk insert",
    "Two transactions updating same rows in different order",
    "Long-running background job holding lock"
  ],
  
  "remediation_options": [
    {
      "option": "Kill blocking query",
      "manual_only": true,
      "prerequisite": "Operator verification",
      "risk": "Query interrupted mid-operation"
    },
    {
      "option": "Restart application to reset pool",
      "manual_only": true,
      "prerequisite": "Traffic drained",
      "risk": "Brief service disruption"
    }
  ],
  
  "false_positive_risk": "MEDIUM - deadlock without cascade can occur, check pool size before escalating",
  
  "related_rules": [
    "kb_pg_connection_pool_001",
    "kb_nginx_503_001"
  ]
}
```

### Rule Components

#### triggers
- **What must be observed** to activate this rule
- Multiple analyzers can trigger the same rule
- Includes count and time-window thresholds

#### expected_cascade
- **What typically follows** the trigger
- Time deltas between events
- Pattern-match strength (0.0-1.0), NOT probability

#### investigation_steps
- **Ordered list of manual checks** an operator should do
- Specific to this pattern
- Links to logs, metrics, dashboards

#### typical_root_causes
- **Why this cascade usually happens**
- Human-written explanations
- Helps operator understand what to look for

#### remediation_options
- **What an operator can try** to mitigate
- Always manual (no auto-execution)
- Prerequisites and risks explicitly stated

#### false_positive_risk
- **When this rule misfires**
- How to distinguish true vs false positives
- Confidence adjustment needed

## KB Query API (Future v0.23)

```python
from analyzers.kb import KnowledgeBase

kb = KnowledgeBase.load("production")

# Find rules triggered by these findings
triggered_rules = kb.find_triggered_rules(findings)

# Get investigation steps for first rule
if triggered_rules:
    rule = triggered_rules[0]
    print(rule.investigation_steps)
    print(rule.typical_root_causes)
```

## KB Storage

### Option 1: JSON Files (v0.23 likely)

```
kb/
  production/
    postgresql/
      deadlock_cascade_001.json
      connection_pool_001.json
    nginx/
      high_error_rate_001.json
    cross_service/
      db_timeout_cascade_001.json
  staging/
    ...
  index.json (manifest)
```

### Option 2: YAML (more human-readable)

```yaml
# kb/production/postgresql/deadlock_cascade.yaml
rule_id: kb_pg_deadlock_cascade_001
title: PostgreSQL deadlock cascade pattern
confidence: VERIFIED
...
```

### Option 3: Database (for large KB)

- PostgreSQL table for rules + versions
- Git-like history (who changed what, when, why)
- Audit trail for compliance

## KB Lifecycle

### Creation

1. Operator observes incident pattern
2. Manually writes rule (or AI generates draft for review)
3. Rule is HYPOTHESIS until verified
4. Operator documents evidence/verification

### Verification

1. Rule tested against historical incidents
2. False positive rate measured
3. Investigation steps validated by domain expert
4. Confidence upgraded to PATTERN or VERIFIED

### Maintenance

- Rules reviewed quarterly (verification_cadence)
- Marked DEPRECATED if no longer relevant
- Updated when environment changes
- Version history kept

### Integration with Analysis

- Analyzer generates findings
- KB queries: "Are these findings triggered by any rule?"
- If yes: show rule's investigation steps, root causes, remediation
- If no: operator reports pattern, KB rule can be created

## KB Validation

Each rule must:

✅ Have clear triggers (measurable)
✅ Have documented cascade (what typically follows)
✅ Have investigation steps (actionable)
✅ Have typical root causes (educational)
✅ Have false positive guidance (prevent noise)
✅ Be verified by human before VERIFIED status
✅ Have verification date and cadence

## Security Considerations

- Rules can contain sensitive patterns (e.g., PII, internal service names)
- KB files are local (not shared externally)
- Rules should NOT contain: passwords, secrets, customer data
- Audit trail: who created/modified rules and when

## Future Enhancements (v0.24+)

1. **KB Learning**: Operator feedback improves confidence scores
2. **Cross-Environment Rules**: Share non-sensitive patterns across environments
3. **ML Validation**: ML can help find new patterns, humans verify before KB inclusion
4. **Automation Bridge**: KB can recommend safe automated actions (with approval)
5. **Team Collaboration**: KB shared across team, rules improved collectively

## KB vs Experiment Features

| Aspect | KB Rules | Experimental (v0.22) |
|--------|----------|----------------------|
| Verification | Human-verified | Heuristic patterns only |
| Confidence | VERIFIED/PATTERN/HYPOTHESIS | Pattern-match weight |
| Causality | Proven by human | Temporal proximity only |
| Actionability | Specific investigation steps | Generic hints |
| Trust | High (human-vetted) | Low (unvalidated) |
| Update | Manual, versioned | Auto (pattern-based) |

## Example KB Rules (Future)

See [KB_EXAMPLES.md](KB_EXAMPLES.md) for concrete examples:
- Database deadlock cascade
- Memory leak leading to OOM
- Network partition causing split-brain
- Authentication service outage cascades
