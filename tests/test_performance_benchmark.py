"""Performance benchmarking for log analyzers - real-world large logs."""

from __future__ import annotations

import time
from analyzers.logs import analyze_log_text


def generate_nginx_logs(count: int) -> str:
    """Generate realistic Nginx logs."""
    lines = []
    for i in range(count):
        status = [200, 200, 200, 404, 403, 500, 502][i % 7]
        ip = f"192.168.{(i // 256) % 256}.{i % 256}"
        method = ["GET", "POST", "PUT"][i % 3]
        path = ["/api/users", "/admin", "/api/data", "/index.html"][i % 4]
        lines.append(
            f'{ip} - - [15/Oct/2026:10:{(i % 60):02d}:{(i % 60):02d} +0000] "{method} {path} HTTP/1.1" {status} {512 + i % 4096} "-" "Chrome/90"'
        )
    return "\n".join(lines) + "\n"


def generate_postgresql_logs(count: int) -> str:
    """Generate realistic PostgreSQL logs."""
    lines = []
    for i in range(count):
        if i % 50 == 0:
            lines.append("2026-10-15 10:23:45 ERROR deadlock detected")
        elif i % 100 == 0:
            lines.append(f"2026-10-15 10:24:00 ERROR statement timeout duration: {1000 + i % 5000}.123 ms")
        elif i % 200 == 0:
            lines.append("2026-10-15 10:25:00 FATAL too many connections for role app_user")
        else:
            lines.append(
                f"2026-10-15 10:{(i // 60) % 60:02d}:{i % 60:02d} LOG statement: SELECT * FROM table_{i % 10} rows={100 + i % 1000}"
            )
    return "\n".join(lines) + "\n"


def generate_docker_logs(count: int) -> str:
    """Generate realistic Docker logs."""
    lines = []
    for i in range(count):
        if i % 30 == 0:
            lines.append(f"2026-10-15 10:23:{i % 60:02d} WARN pod/app-{i % 10} restarted (attempt {i % 5})")
        elif i % 50 == 0:
            lines.append(f"2026-10-15 10:24:{i % 60:02d} CRITICAL pod/cache OOMKilled: Memory limit exceeded")
        else:
            lines.append(f"2026-10-15 10:25:{i % 60:02d} INFO container/service-{i % 20} running")
    return "\n".join(lines) + "\n"


def generate_ldap_logs(count: int) -> str:
    """Generate realistic LDAP logs."""
    lines = []
    for i in range(count):
        user = f"user{i % 100}"
        if i % 20 == 0:
            lines.append(f"2026-10-15 10:23:{i % 60:02d} ERROR bind failed for user={user} invalid credentials")
        elif i % 100 == 0:
            lines.append(f"2026-10-15 10:24:{i % 60:02d} CRITICAL account locked for account={user}")
        else:
            lines.append(f"2026-10-15 10:25:{i % 60:02d} INFO authentication for user={user} successful")
    return "\n".join(lines) + "\n"


def test_nginx_performance_1mb():
    """Benchmark: 1MB Nginx log (~10k lines)."""
    log_text = generate_nginx_logs(10000)

    start = time.time()
    result = analyze_log_text(log_text)
    elapsed = time.time() - start

    size_mb = len(log_text.encode()) / (1024 * 1024)
    print(f"\nNginx 1MB: {elapsed:.2f}s ({size_mb:.1f}MB, {len(log_text.splitlines())} lines)")
    print(f"  Speed: {len(log_text.splitlines()) / elapsed:.0f} lines/sec")
    assert elapsed < 5.0  # Should complete in < 5 seconds


def test_postgresql_performance_1mb():
    """Benchmark: 1MB PostgreSQL log (~10k lines)."""
    log_text = generate_postgresql_logs(10000)

    start = time.time()
    result = analyze_log_text(log_text)
    elapsed = time.time() - start

    size_mb = len(log_text.encode()) / (1024 * 1024)
    print(f"\nPostgreSQL 1MB: {elapsed:.2f}s ({size_mb:.1f}MB, {len(log_text.splitlines())} lines)")
    print(f"  Speed: {len(log_text.splitlines()) / elapsed:.0f} lines/sec")
    assert elapsed < 5.0


def test_docker_performance_1mb():
    """Benchmark: 1MB Docker log (~10k lines)."""
    log_text = generate_docker_logs(10000)

    start = time.time()
    result = analyze_log_text(log_text)
    elapsed = time.time() - start

    size_mb = len(log_text.encode()) / (1024 * 1024)
    print(f"\nDocker 1MB: {elapsed:.2f}s ({size_mb:.1f}MB, {len(log_text.splitlines())} lines)")
    print(f"  Speed: {len(log_text.splitlines()) / elapsed:.0f} lines/sec")
    assert elapsed < 5.0


def test_ldap_performance_1mb():
    """Benchmark: 1MB LDAP log (~10k lines)."""
    log_text = generate_ldap_logs(10000)

    start = time.time()
    result = analyze_log_text(log_text)
    elapsed = time.time() - start

    size_mb = len(log_text.encode()) / (1024 * 1024)
    print(f"\nLDAP 1MB: {elapsed:.2f}s ({size_mb:.1f}MB, {len(log_text.splitlines())} lines)")
    print(f"  Speed: {len(log_text.splitlines()) / elapsed:.0f} lines/sec")
    assert elapsed < 5.0


def test_mixed_logs_performance_1mb():
    """Benchmark: Mixed log types."""
    logs = [
        generate_nginx_logs(2500),
        generate_postgresql_logs(2500),
        generate_docker_logs(2500),
        generate_ldap_logs(2500),
    ]
    log_text = "".join(logs)

    start = time.time()
    result = analyze_log_text(log_text)
    elapsed = time.time() - start

    size_mb = len(log_text.encode()) / (1024 * 1024)
    print(f"\nMixed 1MB: {elapsed:.2f}s ({size_mb:.1f}MB, {len(log_text.splitlines())} lines)")
    print(f"  Speed: {len(log_text.splitlines()) / elapsed:.0f} lines/sec")
    assert elapsed < 5.0


if __name__ == "__main__":
    test_nginx_performance_1mb()
    test_postgresql_performance_1mb()
    test_docker_performance_1mb()
    test_ldap_performance_1mb()
    test_mixed_logs_performance_1mb()
    print("\n✓ ALL BENCHMARKS PASSED (<5s per 1MB)")
