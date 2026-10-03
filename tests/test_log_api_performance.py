"""API performance log analyzer tests."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_api_slow_response():
    """API slow response (>1s)."""
    log = 'INFO: endpoint=/api/users response_time=1234ms status=200'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_api_critical_slow_response():
    """API critical slow response (>5s)."""
    log = 'ERROR: endpoint=/api/heavy-report response_time=6789ms status=200 duration=6.789s'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_api_timeout():
    """API timeout detected."""
    log = '2026-01-15 10:00:00 ERROR endpoint=/api/checkout request timed out after 30000ms'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_api_rate_limit():
    """API rate limit (429)."""
    log = '2026-01-15 10:00:01 WARN endpoint=/api/search status=429 rate_limit exceeded threshold=100 requests/minute'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_api_multiple_slow_endpoints():
    """Multiple slow responses from different endpoints."""
    text = (
        'endpoint=/api/users response_time=1500ms status=200\n'
        'endpoint=/api/orders response_time=2000ms status=200\n'
        'endpoint=/api/payments response_time=1800ms status=200\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_api_performance_degradation():
    """Performance degradation over time."""
    text = (
        'timestamp=2026-01-15T10:00:00Z endpoint=/api/users response_time=500ms\n'
        'timestamp=2026-01-15T10:00:05Z endpoint=/api/users response_time=800ms\n'
        'timestamp=2026-01-15T10:00:10Z endpoint=/api/users response_time=1200ms\n'
        'timestamp=2026-01-15T10:00:15Z endpoint=/api/users response_time=3000ms\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 3


def test_api_percentile_tracking():
    """API response time percentile tracking."""
    log = 'endpoint=/api/search p95=1234ms p99=2500ms avg=800ms'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_api_post_slow():
    """Slow POST request."""
    log = 'method=POST endpoint=/api/data response_time=5500ms status=201 duration_ms=5500'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_api_delete_timeout():
    """DELETE request timeout."""
    log = 'method=DELETE endpoint=/api/resource/123 timeout after 30000ms max_wait=30000'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_api_concurrent_surge():
    """Multiple concurrent slow requests (surge)."""
    lines = [
        f'endpoint=/api/report response_time={1000 + (i*100)}ms status=200'
        for i in range(20)
    ]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r.get("line_count", 0) >= 10


def test_api_throttled_responses():
    """API throttled responses (429)."""
    lines = [
        f'endpoint=/api/bulk-action status=429 retry_after=60' if i % 5 == 0
        else f'endpoint=/api/bulk-action status=200'
        for i in range(50)
    ]
    r = analyze_log_text("\n".join(lines) + "\n")
    assert r.get("line_count", 0) >= 30


def test_api_endpoint_specific_slowdown():
    """One endpoint slow, others normal."""
    text = (
        'endpoint=/api/fast response_time=100ms\n'
        'endpoint=/api/fast response_time=150ms\n'
        'endpoint=/api/slow response_time=4500ms\n'
        'endpoint=/api/fast response_time=120ms\n'
        'endpoint=/api/slow response_time=5200ms\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 3


if __name__ == "__main__":
    test_api_slow_response()
    test_api_critical_slow_response()
    test_api_timeout()
    test_api_rate_limit()
    test_api_multiple_slow_endpoints()
    test_api_performance_degradation()
    test_api_percentile_tracking()
    test_api_post_slow()
    test_api_delete_timeout()
    test_api_concurrent_surge()
    test_api_throttled_responses()
    test_api_endpoint_specific_slowdown()
    print("✓ API PERFORMANCE LOG TESTS OK")
