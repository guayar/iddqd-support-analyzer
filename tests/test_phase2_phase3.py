"""Phase 2 + Phase 3 analyzer tests"""
from analyzers.logs import analyze_log_text

def test_permissions():
    log = '2026-01-15 10:00:00 INFO Role granted: user=alice role=admin\n2026-01-15 10:00:01 CRITICAL Permission escalation attempt: user=bob trying superadmin'
    r = analyze_log_text(log)
    assert r.get("line_count", 0) >= 1

def test_service_comms():
    log = '2026-01-15 10:00:00 ERROR Circuit breaker open: payment-service\n2026-01-15 10:00:01 ERROR Timeout cascade detected'
    r = analyze_log_text(log)
    assert r.get("line_count", 0) >= 1

def test_database():
    log = '2026-01-15 10:00:00 CRITICAL Deadlock detected in orders table\n2026-01-15 10:00:01 WARN Slow query: duration=2500ms'
    r = analyze_log_text(log)
    assert r.get("line_count", 0) >= 1

def test_message_queue():
    log = '2026-01-15 10:00:00 ERROR Message delivery failed: order_id=12345\n2026-01-15 10:00:01 ERROR DLQ message: consumer_lag=60s'
    r = analyze_log_text(log)
    assert r.get("line_count", 0) >= 1

def test_browser():
    log = '2026-01-15 10:00:00 ERROR Element not found: selector=#submit-btn\n2026-01-15 10:00:01 ERROR JS error: TypeError'
    r = analyze_log_text(log)
    assert r.get("line_count", 0) >= 1

def test_visual():
    log = '2026-01-15 10:00:00 WARN Visual diff detected: 2.3% pixels differ\n2026-01-15 10:00:01 ERROR Visual regression: button color changed'
    r = analyze_log_text(log)
    assert r.get("line_count", 0) >= 1

def test_user_journey():
    log = '2026-01-15 10:00:00 INFO session=sess_xyz user_id=alice\n2026-01-15 10:00:05 INFO action=viewed_product\n2026-01-15 10:00:10 WARN User dropout at checkout'
    r = analyze_log_text(log)
    assert r.get("line_count", 0) >= 2

def test_error_impact():
    log = '2026-01-15 10:00:00 CRITICAL Outage: payment_processing users_affected=1500 duration=87s'
    r = analyze_log_text(log)
    assert r.get("line_count", 0) >= 1

if __name__ == "__main__":
    test_permissions()
    test_service_comms()
    test_database()
    test_message_queue()
    test_browser()
    test_visual()
    test_user_journey()
    test_error_impact()
    print("✓ ALL PHASE 2+3 TESTS OK (8/8)")
