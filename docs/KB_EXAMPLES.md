# Knowledge Base Examples

These examples show what KB rules will look like when implemented in v0.23+.

All examples are **DOCUMENTATION ONLY** - these rules do not yet exist in the system.

## Example 1: PostgreSQL Deadlock Cascade

```json
{
  "rule_id": "kb_pg_deadlock_cascade_001",
  "title": "PostgreSQL deadlock → connection pool exhaustion → HTTP 503",
  "confidence": "VERIFIED",
  "environment": "production",
  "created_by": "alice@company.com",
  "created_date": "2026-09-15",
  "last_verified": "2026-10-03",
  "verification_cadence": "quarterly",
  
  "description": "When PostgreSQL detects a deadlock (two transactions waiting on each other), the database cancels one transaction with error. If the application doesn't handle this gracefully, connection pool exhaustion follows within 2-5 seconds as waiting clients retry. This cascades to HTTP 503 errors in Nginx when all connections are consumed.",
  
  "triggers": [
    {
      "analyzer": "postgresql",
      "kind": "deadlock_detected",
      "count_threshold": 1,
      "time_window_seconds": 5
    }
  ],
  
  "expected_cascade": [
    {
      "analyzer": "postgresql",
      "kind": "connection_pool_exhausted",
      "time_after_trigger_seconds": "2-5",
      "pattern_match_strength": 0.95,
      "note": "Connection pool exhaustion happens as retries accumulate"
    },
    {
      "analyzer": "postgresql",
      "kind": "max_connections_exceeded",
      "time_after_trigger_seconds": "3-6",
      "pattern_match_strength": 0.92
    },
    {
      "analyzer": "nginx",
      "kind": "upstream_connect_timeout",
      "time_after_trigger_seconds": "4-8",
      "pattern_match_strength": 0.90
    },
    {
      "analyzer": "nginx",
      "kind": "http_503",
      "time_after_trigger_seconds": "5-10",
      "pattern_match_strength": 0.88
    }
  ],
  
  "investigation_steps": [
    "Check postgres.log for 'deadlock detected' message and identify the two conflicting queries",
    "Look at the time the deadlock was detected (should match the 503 error spike time)",
    "Run 'SELECT * FROM pg_stat_activity' equivalent to see connection state",
    "Check application logs for connection pool errors (look for 'timeout waiting for connection' or 'no available connections')",
    "Review the two queries involved - deadlock usually means lock order is inconsistent",
    "Check recent schema changes or index changes that might have affected query plan",
    "Look for Foreign Key constraints on both tables - common deadlock cause"
  ],
  
  "typical_root_causes": [
    "Two concurrent transactions acquiring locks on same rows in different order",
    "Foreign key constraint checking during multi-table update",
    "Implicit locks from index maintenance during bulk insert",
    "Application connection pool too small for current load",
    "Query plan change due to new statistics or missing index"
  ],
  
  "prerequisite_checks": [
    "PostgreSQL version >= 10",
    "Connection pooling enabled (not direct connections)",
    "idle_in_transaction_session_timeout configured"
  ],
  
  "remediation_options": [
    {
      "option": "Kill blocking query manually",
      "manual_only": true,
      "prerequisite": "Operator has kill permission on pg_terminate_backend()",
      "risk": "Query interrupted mid-operation; data consistency verified",
      "steps": [
        "Identify PID of blocking query from pg_stat_activity",
        "SELECT pg_terminate_backend(pid);",
        "Monitor for immediate recovery or continued 503s"
      ]
    },
    {
      "option": "Increase application connection pool size",
      "manual_only": true,
      "prerequisite": "Operator access to application config",
      "risk": "Higher resource usage; may mask the root cause",
      "steps": [
        "Increase max_pool_size by 20-30%",
        "Rolling deploy with zero-downtime restart",
        "Monitor pool utilization - should stay <80%"
      ]
    },
    {
      "option": "Increase PostgreSQL max_connections",
      "manual_only": true,
      "prerequisite": "Database admin access, server resources available",
      "risk": "Temporary fix; deadlock root cause still present",
      "steps": [
        "PostgreSQL restart required (not hot-reload)",
        "Plan during maintenance window",
        "Monitor shared_buffers usage"
      ]
    }
  ],
  
  "false_positive_guidance": "MEDIUM RISK - Not all deadlocks cause connection exhaustion. Check if: (1) application has connection pooling, (2) errors are actually connection timeouts, (3) pool size is adequate for current load.",
  
  "related_rules": [
    "kb_pg_connection_pool_001",
    "kb_pg_lock_contention_001",
    "kb_nginx_503_cascade_001"
  ],
  
  "references": [
    "PostgreSQL docs: Chapter 14 - Locking",
    "PgBouncer docs: Connection pooling best practices",
    "Company incident #2847: deadlock cascade during bulk import"
  ],
  
  "test_cases": [
    {
      "description": "Real deadlock, small pool",
      "expected_result": "Rule triggers, suggests pool increase"
    },
    {
      "description": "Lock timeout (not deadlock)",
      "expected_result": "Rule should NOT trigger"
    },
    {
      "description": "Single 503 error (no deadlock)",
      "expected_result": "Rule should NOT trigger"
    }
  ]
}
```

---

## Example 2: Memory Leak Leading to OOM Kill

```json
{
  "rule_id": "kb_docker_memory_leak_oom_001",
  "title": "Gradual memory increase → OOM kill → container restart",
  "confidence": "PATTERN",
  "environment": "production",
  "created_by": "bob@company.com",
  "created_date": "2026-08-20",
  "last_verified": "2026-10-01",
  "verification_cadence": "monthly",
  
  "description": "Memory usage gradually increases over hours/days (classic memory leak pattern). When container hits memory limit, Linux OOM killer terminates the process. Docker then restarts the container. This creates a sawtooth pattern in memory graphs and periodic brief outages.",
  
  "triggers": [
    {
      "analyzer": "docker",
      "kind": "container_oom_killed",
      "count_threshold": 1
    }
  ],
  
  "expected_cascade": [
    {
      "analyzer": "docker",
      "kind": "container_restart",
      "time_after_trigger_seconds": "1-3",
      "pattern_match_strength": 0.98
    },
    {
      "analyzer": "nginx",
      "kind": "upstream_unavailable",
      "time_after_trigger_seconds": "2-5",
      "pattern_match_strength": 0.95
    },
    {
      "analyzer": "application",
      "kind": "startup_error",
      "time_after_trigger_seconds": "3-8",
      "pattern_match_strength": 0.90
    }
  ],
  
  "investigation_steps": [
    "Plot container memory usage over last 7 days - look for sawtooth pattern",
    "Note times of container restarts - should align with OOM kills",
    "Check application logs between restarts - look for memory allocation errors",
    "Identify what changed in last version before memory leak started",
    "Look for common leak patterns: unclosed database connections, unbounded caches, event listeners",
    "Review heap dumps (if Java) or memory profiler output for v0.23+",
    "Check if issue is load-dependent or time-dependent"
  ],
  
  "typical_root_causes": [
    "Unclosed database connections accumulating in pool",
    "Cache without TTL or eviction policy growing unbounded",
    "Event listeners not unregistered on object cleanup",
    "Circular references preventing garbage collection (Java)",
    "Memory leaks in native libraries (C extensions)",
    "Goroutines spawned without cleanup (Go)",
    "Temporary buffers not freed (any language)"
  ],
  
  "prerequisite_checks": [
    "Container memory limit is set (not unlimited)",
    "OOM killer logs available in Docker/Kubernetes logs",
    "Application supports memory profiling in v0.23+"
  ],
  
  "remediation_options": [
    {
      "option": "Increase container memory limit (temporary)",
      "manual_only": true,
      "prerequisite": "Operator has deployment permissions",
      "risk": "Masks the root cause; eventual out-of-memory still occurs",
      "steps": [
        "Increase memory limit by 50%",
        "Deploy and monitor - should reduce restart frequency",
        "Schedule engineering work to find actual leak"
      ]
    },
    {
      "option": "Switch to regular restarts (temporary mitigation)",
      "manual_only": true,
      "prerequisite": "Low-impact service or maintenance window",
      "risk": "Brief service disruption every N hours",
      "steps": [
        "Add restart cron job or sidecar that restarts every 4 hours",
        "Reduces impact of emergency OOM kill",
        "Provides time for engineering to locate leak"
      ]
    },
    {
      "option": "Deploy memory profiler version (v0.23+)",
      "manual_only": true,
      "prerequisite": "Profiler version built and tested",
      "risk": "5-10% performance overhead during profiling",
      "steps": [
        "Deploy profiler-enabled build to staging",
        "Reproduce memory leak",
        "Analyze heap dump or profiler output",
        "Identify leak source"
      ]
    }
  ],
  
  "false_positive_guidance": "LOW RISK - OOM kill is definitive. However, distinguish from: (1) legitimate growth as traffic increases, (2) normal Java GC pauses, (3) swap usage (not same as OOM).",
  
  "monitoring_recommendations": [
    "Graph memory usage over time with 1-hour granularity",
    "Alert on memory growth rate > 50MB/hour sustained",
    "Alert on OOM kills (should be rare or never)",
    "For Java: enable GC logging, monitor Full GC frequency"
  ]
}
```

---

## Example 3: Authentication Service Outage Cascades

```json
{
  "rule_id": "kb_auth_outage_cascade_001",
  "title": "Auth service down → all login attempts fail → high error rate",
  "confidence": "VERIFIED",
  "environment": "production",
  
  "triggers": [
    {
      "analyzer": "oauth2",
      "kind": "auth_service_unavailable",
      "count_threshold": 1
    }
  ],
  
  "expected_cascade": [
    {
      "analyzer": "oauth2",
      "kind": "token_validation_timeout",
      "time_after_trigger_seconds": "1-5",
      "pattern_match_strength": 0.95
    },
    {
      "analyzer": "nginx",
      "kind": "auth_failure_spike",
      "time_after_trigger_seconds": "2-10",
      "pattern_match_strength": 0.90
    },
    {
      "analyzer": "application",
      "kind": "access_denied",
      "time_after_trigger_seconds": "3-15",
      "pattern_match_strength": 0.88
    }
  ],
  
  "investigation_steps": [
    "Check auth service health: is it responding to health checks?",
    "Check auth service logs for startup errors or crashes",
    "Check if auth service upgrade happened recently",
    "Verify network connectivity to auth service (DNS, firewall)",
    "Check certificate expiration if using mTLS",
    "Look for dependent service outages (database, cache that auth uses)",
    "Check for recent config changes in auth service"
  ],
  
  "typical_root_causes": [
    "Auth service deployment failed to start",
    "Database connection string incorrect in new config",
    "Certificate expired or misconfigured",
    "Dependency (Redis, etc) that auth uses is down",
    "Network issue (firewall, DNS, load balancer)",
    "Memory/resource exhaustion in auth service",
    "Recent code push with bug"
  ]
}
```

---

## Future KB Capabilities (v0.24+)

When KB is implemented, IDDQD will:

1. **Match findings to KB rules** automatically
2. **Show investigation steps** from rules when incidents detected
3. **Suggest root causes** based on pattern history
4. **Track rule accuracy** - operator feedback improves scores
5. **Recommend safe mitigations** - automation with approval gates

Example usage:

```
FINDINGS:
  🔴 PostgreSQL: deadlock detected
  🔴 PostgreSQL: connection pool exhausted
  🔴 Nginx: HTTP 503 spike

MATCHED KB RULES:
  Rule: kb_pg_deadlock_cascade_001 (VERIFIED)
  Pattern match strength: 0.92

  Investigation steps:
  1. Check postgres.log for conflicting queries
  2. Identify lock order issue
  3. Review foreign key constraints
  
  Typical root causes:
  - Foreign key constraint during bulk insert
  - Lock order inconsistency between transactions
  
  Safe remediation:
  - Kill blocking query (manual - needs DBA approval)
  - Increase connection pool (temporary - needs engineering fix)
```

## Migrating from Experimental to KB

When an experimental correlation pattern (v0.22) becomes reliable:

1. Operator documents the pattern in detail
2. Rule is created with HYPOTHESIS confidence
3. Rule tested against 3+ historical incidents
4. Confidence upgraded to PATTERN
5. Operator verifies quarterly
6. After 2 quarters: VERIFIED status
7. Rule becomes trusted KB recommendation

This ensures KB rules are **proven before used**, unlike experimental patterns which are **untested heuristics**.
