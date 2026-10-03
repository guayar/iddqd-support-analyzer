"""PostgreSQL log analyzer tests."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_deadlock_detected():
    """Concurrent transaction deadlock."""
    log = '2026-01-15 10:23:45 ERROR deadlock detected: Process 1234 waiting for ShareLock'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_statement_timeout():
    """Query exceeded timeout."""
    log = '2026-01-15 10:24:00 ERROR statement timeout: Query exceeded 300000ms'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_lock_timeout():
    """Lock acquisition timeout."""
    log = '2026-01-15 10:25:00 ERROR lock timeout waiting for lock'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_too_many_connections():
    """Connection pool exhausted."""
    log = '2026-01-15 10:26:00 FATAL too many connections for role "app_user"'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_authentication_failed():
    """Invalid credentials."""
    log = '2026-01-15 10:27:00 ERROR authentication failed: user=john password authentication failed'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_permission_denied():
    """Role lacks permissions."""
    log = '2026-01-15 10:28:00 ERROR permission denied for schema public user=readonly_user'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_disk_full():
    """No space left on device."""
    log = '2026-01-15 10:29:00 PANIC could not write to file: No space left on device'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_slow_query_duration():
    """Query with high duration."""
    log = '2026-01-15 10:30:00 LOG statement: SELECT * FROM big_table duration: 5432.123 ms'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_multiple_deadlocks():
    """Repeated deadlock pattern."""
    text = (
        '2026-01-15 10:31:00 ERROR deadlock detected: Process 1234\n'
        '2026-01-15 10:31:05 ERROR deadlock detected: Process 5678\n'
        '2026-01-15 10:31:10 ERROR deadlock detected: Process 9012\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_connection_issues_cascade():
    """Multiple connection errors."""
    text = (
        '2026-01-15 10:32:00 ERROR authentication failed: user=app1 database=prod\n'
        '2026-01-15 10:32:01 ERROR authentication failed: user=app1 database=prod\n'
        '2026-01-15 10:32:02 FATAL too many connections\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_healthy_database():
    """Normal DB operation."""
    log = '2026-01-15 10:33:00 LOG database system is ready to accept connections'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


if __name__ == "__main__":
    test_deadlock_detected()
    test_statement_timeout()
    test_lock_timeout()
    test_too_many_connections()
    test_authentication_failed()
    test_permission_denied()
    test_disk_full()
    test_slow_query_duration()
    test_multiple_deadlocks()
    test_connection_issues_cascade()
    test_healthy_database()
    print("LOG POSTGRESQL TESTS OK")
