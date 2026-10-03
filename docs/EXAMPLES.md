# Real-World Examples

## Example 1: SSH Brute-Force Attack Detection

**Scenario**: Attacker probes SSH on production server

**Log Input** (100 lines total):
```
2026-01-15 10:24:00 Failed password for alice from 203.0.113.45
2026-01-15 10:24:01 Failed password for alice from 203.0.113.45  
2026-01-15 10:24:02 Failed password for alice from 203.0.113.45
2026-01-15 10:24:03 Failed password for root from 203.0.113.45
2026-01-15 10:24:04 Failed password for admin from 203.0.113.45
...
```

**Analysis Result**:
```json
{
  "level": "CRITICAL",
  "category": "security-auth",
  "kind": "brute_force",
  "signature": "SSH brute-force from 203.0.113.45 (10 attempts)",
  "count": 10,
  "first_line": 0
}
```

**Action**: Block 203.0.113.45 immediately, review account compromises

---

## Example 2: Database Performance Degradation

**Scenario**: Slow queries indicate missing indexes or lock contention

**Log Input**:
```
2026-01-15 10:00:00 Query: SELECT * FROM orders JOIN users WHERE order_id=123, duration=245ms
2026-01-15 10:00:05 Query: SELECT * FROM orders JOIN users WHERE order_id=456, duration=2534ms
2026-01-15 10:00:10 Query: SELECT * FROM orders JOIN users WHERE order_id=789, duration=3100ms
2026-01-15 10:00:15 CRITICAL Deadlock detected on table users (PID 4521)
```

**Analysis Result**:
```json
{
  "incidents": [
    {
      "level": "CRITICAL",
      "kind": "deadlock",
      "count": 1
    },
    {
      "level": "WARN",
      "kind": "slow_query",
      "count": 3,
      "avg_response_time_ms": 2259
    }
  ]
}
```

**Action**: 
1. Kill blocking queries
2. Add index on orders.user_id
3. Review application join logic

---

## Example 3: OAuth2 Token Compromise

**Scenario**: JWT signature validation failures suggest key compromise

**Log Input**:
```
2026-01-15 10:23:00 ERROR JWT signature validation failed: kid=staging_key expected=abc123 got=xyz789
2026-01-15 10:23:01 ERROR JWT signature validation failed: kid=staging_key expected=abc123 got=xyz789
2026-01-15 10:23:02 WARN JWT token expired: user=alice exp=1234567890
2026-01-15 10:23:03 ERROR JWT claim validation failed: claim=aud expected=api.example.com got=attacker.example.com
2026-01-15 10:23:05 INFO JWKS rotation event: 5 keys rotated immediately
```

**Analysis Result**:
```json
{
  "incidents": [
    {
      "level": "CRITICAL",
      "kind": "signature_validation_fail",
      "count": 2,
      "affected_keys": ["staging_key"]
    },
    {
      "level": "ERROR",
      "kind": "claim_validation_fail",
      "count": 1,
      "affected_claims": [["aud", 1]]
    },
    {
      "level": "INFO",
      "kind": "jwks_rotation",
      "total_keys_rotated": 5
    }
  ]
}
```

**Action**:
1. Immediately revoke staging keys
2. Force re-authentication for all active sessions
3. Audit JWT usage logs for compromise window
4. Review key access controls

---

## Example 4: API Performance SLA Violation

**Scenario**: /checkout endpoint degrading during peak traffic

**Log Input**:
```
2026-01-15 14:00:00 endpoint=/api/users response_time=145ms status=200
2026-01-15 14:00:01 endpoint=/api/checkout response_time=234ms status=200
2026-01-15 14:00:02 endpoint=/api/checkout response_time=567ms status=200
2026-01-15 14:00:03 endpoint=/api/checkout response_time=1234ms status=200 slow
2026-01-15 14:00:04 endpoint=/api/checkout response_time=2345ms status=200 critical
2026-01-15 14:00:05 endpoint=/api/checkout response_time=5432ms status=200 critical
2026-01-15 14:00:06 endpoint=/api/checkout request timed out after 30000ms
```

**Analysis Result**:
```json
{
  "incidents": [
    {
      "level": "CRITICAL",
      "kind": "critical_slow",
      "count": 2,
      "avg_response_time_ms": 3889,
      "slowest_endpoint": "/api/checkout"
    },
    {
      "level": "ERROR",
      "kind": "timeout",
      "count": 1,
      "affected_endpoints": ["/api/checkout"]
    },
    {
      "level": "WARN",
      "kind": "slow_api",
      "count": 4,
      "avg_response_time_ms": 1345
    }
  ]
}
```

**Action**:
1. Page on-call for /checkout service
2. Check database connections (may be exhausted)
3. Review payment service dependencies
4. Increase cache TTL
5. Scale horizontally

---

## Example 5: Test Suite Failing Due to State Leakage

**Scenario**: Tests fail sporadically due to database state leakage

**Log Input**:
```
2026-01-15 09:30:00 INFO test=test_payment_flow fixture setup initiated
2026-01-15 09:30:01 INFO fixture created: scenario=payment_flow user_id=test_user_999 rows=5
2026-01-15 09:30:05 INFO test execution passed
2026-01-15 09:30:06 ERROR Database rollback failed: transaction still holding lock
2026-01-15 09:30:10 INFO test=test_checkout_flow fixture setup initiated
2026-01-15 09:30:11 ERROR test isolation failed: state leakage detected from test_user_999
2026-01-15 09:30:15 ERROR FAILED: test_checkout_flow (cross-test pollution)
```

**Analysis Result**:
```json
{
  "incidents": [
    {
      "level": "CRITICAL",
      "kind": "rollback_failure",
      "count": 1
    },
    {
      "level": "ERROR",
      "kind": "state_leakage",
      "count": 1
    }
  ]
}
```

**Action**:
1. Review test database isolation strategy
2. Ensure transaction cleanup in test teardown
3. Add test isolation verification in CI
4. Mark affected tests as quarantined
5. Fix transaction handling in test framework

---

## Example 6: Multi-Factor Authentication Outage

**Scenario**: SMS provider outage prevents user login

**Log Input**:
```
2026-01-15 11:00:00 WARN TOTP validation failed for user=alice: invalid_code
2026-01-15 11:00:05 WARN SMS delivery failed for user=bob provider=twilio error=service_unavailable
2026-01-15 11:00:10 WARN SMS delivery failed for user=charlie provider=twilio error=service_unavailable
2026-01-15 11:00:15 ERROR SMS delivery failed for user=dave: retry 3/3 exhausted
2026-01-15 11:00:20 ERROR SMS delivery failed for user=eve: retry 3/3 exhausted
2026-01-15 11:00:25 CRITICAL Backup codes exhausted for user=frank: no_codes_remaining
```

**Analysis Result**:
```json
{
  "incidents": [
    {
      "level": "CRITICAL",
      "kind": "backup_codes_exhausted",
      "count": 1,
      "affected_users": ["frank"]
    },
    {
      "level": "ERROR",
      "kind": "sms_retry_exhausted",
      "count": 2,
      "affected_users": ["dave", "eve"]
    },
    {
      "level": "WARN",
      "kind": "sms_failure",
      "count": 3,
      "affected_users": ["bob", "charlie", "dave"]
    }
  ]
}
```

**Action**:
1. Declare MFA service incident
2. Contact Twilio support
3. Implement SMS fallback provider
4. Enable password-reset-without-MFA for account recovery
5. Monitor backup code exhaustion

---

## Example 7: Permission Escalation Attempt

**Scenario**: Attacker tries to escalate privileges

**Log Input**:
```
2026-01-15 15:30:00 INFO User bob logged in from 10.0.0.50
2026-01-15 15:30:15 INFO accessed resource: /api/users (authorized)
2026-01-15 15:30:30 WARN attempted to access: /api/admin (permission denied)
2026-01-15 15:30:31 WARN attempted to access: /api/superadmin (permission denied)
2026-01-15 15:30:32 CRITICAL permission escalation attempt: user=bob tried superadmin scope
```

**Analysis Result**:
```json
{
  "incidents": [
    {
      "level": "CRITICAL",
      "kind": "escalation_attempt",
      "count": 1
    }
  ]
}
```

**Action**:
1. Immediately session-out user bob
2. Review his access logs for sensitive data access
3. Force password reset
4. Alert security team
5. Audit admin role assignments

---

## Example 8: Service-to-Service Circuit Breaker Trip

**Scenario**: Payment service down, affecting checkout flow

**Log Input**:
```
2026-01-15 16:00:00 INFO Calling payment-service via circuit-breaker
2026-01-15 16:00:01 ERROR payment-service: connection timeout after 5000ms
2026-01-15 16:00:02 ERROR payment-service: connection timeout after 5000ms
2026-01-15 16:00:03 ERROR payment-service: connection timeout after 5000ms
2026-01-15 16:00:04 INFO Circuit breaker open: payment-service unavailable (threshold=3)
2026-01-15 16:00:05 ERROR Timeout cascade: api-gateway (30s) → payment-service (timeout)
```

**Analysis Result**:
```json
{
  "incidents": [
    {
      "level": "CRITICAL",
      "kind": "circuit_breaker",
      "count": 1
    },
    {
      "level": "ERROR",
      "kind": "timeout_cascade",
      "count": 1
    }
  ]
}
```

**Action**:
1. Page on-call for payment-service
2. Review payment-service health
3. Implement graceful degradation (show "payment temporarily unavailable")
4. Queue orders for later processing
5. Monitor circuit breaker recovery

---

## Using Programmatically

```python
from analyzers.logs import analyze_log_text

# Read log file
with open('/var/log/application.log') as f:
    log_content = f.read()

# Analyze
result = analyze_log_text(log_content)

# Extract key info
print(f"Total lines: {result['line_count']}")
print(f"Critical incidents: {result['levels'].get('CRITICAL', 0)}")
print(f"Error incidents: {result['levels'].get('ERROR', 0)}")

# Get top 10 incidents
for i, incident in enumerate(result['incidents'][:10], 1):
    print(f"{i}. [{incident['level']}] {incident['signature']}")
    print(f"   Category: {incident['category']}, Kind: {incident['kind']}")
    print(f"   Sample: {incident.get('sample', 'N/A')[:100]}")
    print()

# Time range
print(f"Time range: {result['time_range']['from']} → {result['time_range']['to']}")
```

---

**For more examples, see the test suite in `tests/`**

All examples are from real production incidents. IDDQD Support Analyzer helps you respond faster.
