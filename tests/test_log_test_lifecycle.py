"""Test fixture lifecycle analyzer tests."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_test_setup_teardown():
    """Test setup and successful teardown."""
    text = (
        'INFO: test_payment_flow setup started\n'
        'INFO: fixture created: scenario=payment_flow user_id=test_user_123\n'
        'INFO: test_payment_flow teardown completed duration=234ms\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_database_rollback_failure():
    """Database rollback failure (CRITICAL)."""
    log = '2026-01-15 10:00:00 ERROR Database transaction rollback failed: transaction still holding lock after 30s timeout'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_test_data_cleanup_failure():
    """Test data cleanup failure (ERROR)."""
    log = '2026-01-15 10:00:01 ERROR cleanup failed: table=orders rows=500 not deleted failed_constraint'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_orphaned_test_data():
    """Orphaned test data detection (WARN)."""
    log = '2026-01-15 10:00:02 WARN orphaned test data found: table=users rows=25 from_tests=3'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_state_leakage():
    """Test state leakage between tests (ERROR)."""
    log = '2026-01-15 10:00:03 ERROR test isolation failed: state leakage detected from test_user_456'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_mock_service_unavailable():
    """Mock service unavailable (ERROR)."""
    log = '2026-01-15 10:00:04 ERROR Mock service payment_gateway_mock unavailable: connection refused'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_fixture_lifecycle_full():
    """Full test lifecycle: setup, execution, cleanup."""
    text = (
        'INFO: test=checkout_flow fixture setup initiated\n'
        'INFO: fixture created: scenario=payment_flow user_id=test_user_999\n'
        'INFO: test execution duration=1500ms\n'
        'INFO: test teardown starting cleanup for 3 tables\n'
        'INFO: cleanup completed successfully\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 3


def test_multiple_cleanup_failures():
    """Multiple table cleanup failures."""
    text = (
        '2026-01-15 10:00:00 ERROR cleanup failed: table=orders rows=100\n'
        '2026-01-15 10:00:01 ERROR cleanup failed: table=payments rows=50\n'
        '2026-01-15 10:00:02 ERROR cleanup failed: table=users rows=25\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_cascade_state_leakage():
    """Cascading state leakage across test suite."""
    text = (
        'INFO: test_user_123 state modified\n'
        'ERROR: test isolation failed: state leakage detected\n'
        'ERROR: test isolation failed: cross-test pollution from test_previous_test\n'
        'CRITICAL: Database rollback failed: transaction hold\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


if __name__ == "__main__":
    test_test_setup_teardown()
    test_database_rollback_failure()
    test_test_data_cleanup_failure()
    test_orphaned_test_data()
    test_state_leakage()
    test_mock_service_unavailable()
    test_fixture_lifecycle_full()
    test_multiple_cleanup_failures()
    test_cascade_state_leakage()
    print("✓ TEST LIFECYCLE LOG TESTS OK")
