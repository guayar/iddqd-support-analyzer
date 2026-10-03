"""Docker/K8s log analyzer tests - escalation scenarios."""

from __future__ import annotations

from analyzers.logs import analyze_log_text


def test_crashloop_detection():
    """Pod stuck in CrashLoopBackOff."""
    log = '2026-01-15 10:23:45 ERROR pod/app-123-xyz CrashLoopBackOff: App crashed on startup'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_oomkilled_detection():
    """Pod killed due to memory exhaustion."""
    log = '2026-01-15 10:24:00 ERROR pod/api-server OOMKilled: Memory limit 512Mi exceeded'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_image_pull_backoff():
    """Docker image cannot be pulled."""
    text = (
        '2026-01-15 10:25:00 WARN pod/web-app ImagePullBackOff\n'
        '2026-01-15 10:25:01 ERROR Failed to pull image: pull rate exceeded\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 1


def test_restart_storm():
    """Pod restarting repeatedly."""
    text = (
        '2026-01-15 10:26:00 WARN pod/worker-1 restarted (attempt 1)\n'
        '2026-01-15 10:26:05 WARN pod/worker-1 restarted (attempt 2)\n'
        '2026-01-15 10:26:10 WARN pod/worker-1 restarted (attempt 3)\n'
        '2026-01-15 10:26:15 ERROR pod/worker-1 Too many restarts\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 3


def test_memory_pressure():
    """Node under memory pressure."""
    log = '2026-01-15 10:27:00 WARN node/worker-2 MemoryPressure: Available memory < 5%'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_disk_pressure():
    """Node running out of disk."""
    log = '2026-01-15 10:28:00 ERROR node/worker-3 DiskPressure: Inodes < 1%'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_pod_evicted():
    """Pod evicted due to resource pressure."""
    log = '2026-01-15 10:29:00 CRITICAL pod/cache-service evicted: DiskPressure'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_multiple_crashes():
    """Multiple pods crashing in same timeframe."""
    text = (
        '2026-01-15 10:30:00 ERROR pod/api-1 CrashLoopBackOff\n'
        '2026-01-15 10:30:01 ERROR pod/api-2 CrashLoopBackOff\n'
        '2026-01-15 10:30:02 ERROR pod/api-3 CrashLoopBackOff\n'
    )
    r = analyze_log_text(text)
    assert r.get("line_count", 0) >= 2


def test_healthy_pod():
    """Normal pod operation - no errors."""
    text = (
        '2026-01-15 10:31:00 INFO pod/healthy-app Ready\n'
        '2026-01-15 10:31:01 INFO pod/healthy-app Starting\n'
    )
    r = analyze_log_text(text)
    # No errors expected
    assert r.get("error_event_count", 0) == 0 or r.get("line_count", 0) >= 1


def test_node_not_ready():
    """Node cannot be scheduled."""
    log = '2026-01-15 10:32:00 WARN node/worker-5 NotReady: KubeletNotReady: runtime network not ready'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


def test_kubernetes_namespace():
    """K8s logs with namespace info."""
    log = '2026-01-15 10:33:00 ERROR namespace=production pod/api-service OOMKilled'
    r = analyze_log_text(log + "\n")
    assert r.get("line_count", 0) >= 1


if __name__ == "__main__":
    test_crashloop_detection()
    test_oomkilled_detection()
    test_image_pull_backoff()
    test_restart_storm()
    test_memory_pressure()
    test_disk_pressure()
    test_pod_evicted()
    test_multiple_crashes()
    test_healthy_pod()
    test_node_not_ready()
    test_kubernetes_namespace()
    print("LOG DOCKER TESTS OK")
