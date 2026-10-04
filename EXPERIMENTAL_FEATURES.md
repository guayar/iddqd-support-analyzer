# Experimental Features

IDDQD Support Analyzer includes several EXPERIMENTAL features that are not production-grade diagnostic tools but may be useful for investigation hints.

## Knowledge Base (KB) - Under Development

### Status: EXPERIMENTAL / UNDER DEVELOPMENT

The Knowledge Base (create/edit/delete Articles and Cases, full-text search, export/import) is currently under active development and has known limitations.

### Known Issues

- **Search**: Full-text search may not return results in all cases; fallback substring search is available
- **Persistence**: Articles and cases may not persist across browser refreshes in all scenarios
- **UI**: Layout and interaction patterns are being refined
- **Export/Import**: ZIP export/import functionality is functional but format may change

### What It Does

- Create and edit **Articles**: reusable troubleshooting knowledge linked to finding codes
- Create and edit **Cases**: individual investigation records with snapshots and findings
- **Full-text search** with SQLite FTS5 (with substring fallback)
- **Tag support** for organizing content
- **Export/Import** as ZIP for backup and sharing
- **No LLM required** — works in Light Edition

### What It's NOT

❌ Not suitable for production knowledge management  
❌ Not guaranteed to persist across deployments  
❌ Not a replacement for static documentation  
❌ Search reliability not guaranteed  

### Intended Use

- Local reference during troubleshooting sessions
- Testing the concept before deploying to permanent KB
- Temporary notes linked to Analyze findings
- Backup/sharing articles and cases as ZIP

### Future Improvements

- Robust persistence layer
- Reliable full-text search
- Browser storage state management
- Export to Markdown / static HTML
- Integration with Analyze findings

---

## Correlation and Root-Cause Hints (v0.21+)

### Status: EXPERIMENTAL

These features provide heuristic suggestions about possible relationships between findings. They are **NOT** proven diagnoses and require human judgment to interpret.

### What They Are

**Temporal Correlation**: Shows when events occur close together in time
- Based on parsing log timestamps
- If no timestamps exist: marked as UNKNOWN (not invented)

**Pattern Matching**: Detects known sequences (e.g., "database deadlock often leads to connection exhaustion")
- Strengths like 0.95 indicate "this pattern has been observed before"
- These are NOT statistical probabilities or causal proofs
- Only indicates pattern similarity, not causation

**Multi-file Analysis**: Groups related findings across different log files
- Only if real timestamps allow cross-file comparison
- Otherwise: ordered within each file separately, cross-file ordering marked UNKNOWN

### What They Are NOT

❌ **Not deterministic validation** - no guarantee of correctness  
❌ **Not root-cause analysis** - correlation ≠ causation  
❌ **Not probabilistic** - confidence scores are heuristic weights, not probabilities  
❌ **Not overriding** - never changes Analyze findings or severity  
❌ **Not diagnostic conclusions** - for hints only  

### Output Format

Experimental features are clearly marked:

```
⚠️  EXPERIMENTAL FEATURE
This output shows possible patterns and correlations.
It is NOT a proven diagnosis.
Interpretation requires human judgment.

Known pattern: MATCHED
Pattern-match strength: 0.95
(Pattern-match strength is NOT a probability)

Temporal relationship: OBSERVED

Possible chain:
Database deadlock → Connection exhaustion → API timeout

Causality: NOT ESTABLISHED
Root cause: UNKNOWN
```

### How to Interpret

✅ **Good use**:
- "Show me what I should investigate next"
- "Are these events likely related?"
- "What patterns might explain this?"

❌ **Bad use**:
- "Tell me the root cause with 95% confidence"
- "Automatically escalate this to engineering"
- "Use this to override human judgment"

### Limitations

1. **No synthetic timestamps**: If a log entry has no timestamp, it is NOT given a fake one. Temporal relationships requiring timestamps are marked UNKNOWN instead.

2. **No cross-file causality**: Line numbers from different files have no chronological relationship. Cross-file ordering is only valid if real timestamps exist.

3. **Pattern match ≠ causation**: Just because "deadlock often leads to timeout" does not mean that the observed deadlock caused the observed timeout. Alternative explanations exist.

4. **Earliest event ≠ root cause**: The first event in a sequence is not automatically the root cause. The earliest observed symptom may itself be caused by something else not captured in the logs.

5. **Heuristic weights only**: Confidence numbers (0.95, 0.90, 0.85) are pattern-match weights. They indicate familiarity with a pattern, not statistical confidence in a conclusion.

### Future Improvements

- Better timestamp handling across different formats
- ML-based confidence scoring (future v0.23+)
- Causality validation with stronger evidence
- Integration with Knowledge Base for context

### Feedback

These experimental features are under active development. If you have feedback on their usefulness or accuracy, please report it.
