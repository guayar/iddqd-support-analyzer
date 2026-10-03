"""Docker/Kubernetes log correlator: CrashLoopBackOff, restart storms, OOMKilled.

Real escalation scenarios:
- Pod restart loop (app crashing repeatedly)
- OOMKilled (memory pressure, memory leak)
- Image pull errors (registry down or auth failure)
- Node pressure (CPU/disk exhaustion)
- CrashLoopBackOff (app bug or config issue)
"""

from __future__ import annotations

import collections
import json
import re
from typing import Any

# Docker/K8s log formats
DOCKER_JSON_RE = re.compile(r'^\s*\{.*"log":\s*"([^"]*)"', re.MULTILINE)
DOCKER_TIME_RE = re.compile(r'"time":\s*"([^"]+)"')
DOCKER_STREAM_RE = re.compile(r'"stream":\s*"(stdout|stderr)"')

# Kubernetes patterns
K8S_TIMESTAMP_RE = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
K8S_POD_RE = re.compile(r'\bpod/([a-z0-9\-]+)')
K8S_NAMESPACE_RE = re.compile(r'namespace=([a-z0-9\-]+)', re.I)
K8S_CONTAINER_RE = re.compile(r'container=([a-z0-9\-]+)', re.I)

# Real escalation keywords
CRASH_KEYWORDS = [
    'CrashLoopBackOff',
    'Terminated',
    'Exit code',
    'fatal',
    'panic',
    'segmentation fault',
]

OOM_KEYWORDS = [
    'OOMKilled',
    'Out of memory',
    'Memory limit exceeded',
    'Cannot allocate',
]

PULL_ERROR_KEYWORDS = [
    'ImagePullBackOff',
    'pull rate exceeded',
    'unauthorized',
    'manifest not found',
    'connection refused',
]

RESTART_KEYWORDS = [
    'restart',
    'restarted',
    'rebooted',
    'bouncing',
    'respawning',
]

PRESSURE_KEYWORDS = [
    'MemoryPressure',
    'DiskPressure',
    'PIDPressure',
    'NotReady',
    'evicted',
]

LEVEL_KEYWORDS = {
    'ERROR': re.compile(r'\b(ERROR|FATAL|CRITICAL|PANIC|EXCEPTION)\b', re.I),
    'WARN': re.compile(r'\b(WARN|WARNING|DEPRECAT)\b', re.I),
    'INFO': re.compile(r'\b(INFO|NOTICE)\b', re.I),
}


def docker_log_hint(line: str) -> bool:
    """Cheap check: Docker/K8s keywords."""
    return any(kw in line.lower() for kw in [
        'docker', 'container', 'pod', 'kubernetes', 'k8s', 'replica',
        'crashloop', 'oomkilled', 'imagepull', 'namespace='
    ])


class DockerCorrelator:
    """Correlate container/pod lifecycle events."""

    def __init__(self):
        # Pod tracking
        self.pods: dict[str, dict[str, Any]] = {}
        self.containers: dict[str, dict[str, Any]] = {}

        # Issue tracking
        self.crash_events: list[dict[str, Any]] = []
        self.oom_events: list[dict[str, Any]] = []
        self.pull_errors: list[dict[str, Any]] = []
        self.restart_storms: dict[str, int] = collections.defaultdict(int)

        # Severity
        self.findings: dict[str, int] = collections.defaultdict(int)
        self.finding_details: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

        self.total_lines = 0
        self.docker_lines = 0

    def hint(self, line: str) -> bool:
        return docker_log_hint(line)

    def on_line(self, idx: int, line: str, stamp: str | None) -> None:
        self.total_lines += 1

        if not docker_log_hint(line):
            return

        self.docker_lines += 1

        # Extract identifiers
        pod_match = K8S_POD_RE.search(line)
        pod_name = pod_match.group(1) if pod_match else None

        container_match = K8S_CONTAINER_RE.search(line)
        container_name = container_match.group(1) if container_match else None

        namespace_match = K8S_NAMESPACE_RE.search(line)
        namespace = namespace_match.group(1) if namespace_match else None

        # CrashLoopBackOff detection (CRITICAL)
        if 'CrashLoopBackOff' in line or 'crashloop' in line.lower():
            self.findings['crashloop'] += 1
            self.crash_events.append({
                'line_idx': idx,
                'pod': pod_name,
                'container': container_name,
                'namespace': namespace,
            })
            self.finding_details['crashloop'].append({
                'line_idx': idx,
                'pod': pod_name,
            })

        # OOMKilled detection (CRITICAL)
        if any(kw in line for kw in OOM_KEYWORDS):
            self.findings['oomkilled'] += 1
            self.oom_events.append({
                'line_idx': idx,
                'pod': pod_name,
                'container': container_name,
            })
            self.finding_details['oomkilled'].append({
                'line_idx': idx,
                'pod': pod_name,
            })

        # ImagePullBackOff detection (ERROR)
        if any(kw in line for kw in PULL_ERROR_KEYWORDS):
            self.findings['image_pull_error'] += 1
            self.pull_errors.append({
                'line_idx': idx,
                'pod': pod_name,
                'reason': 'pull_error' if 'pull' in line.lower() else 'registry_error',
            })
            self.finding_details['image_pull_error'].append({
                'line_idx': idx,
                'pod': pod_name,
            })

        # Restart storm detection (WARN)
        if pod_name:
            for kw in RESTART_KEYWORDS:
                if kw in line.lower():
                    self.restart_storms[pod_name] += 1
                    break

        # Node pressure detection (WARN)
        if any(kw in line for kw in PRESSURE_KEYWORDS):
            self.findings['node_pressure'] += 1
            self.finding_details['node_pressure'].append({
                'line_idx': idx,
                'issue': 'memory' if 'memory' in line.lower() else 'disk' if 'disk' in line.lower() else 'other',
            })

        # Crash detection (ERROR)
        if any(kw in line for kw in CRASH_KEYWORDS):
            self.findings['crash'] += 1
            self.crash_events.append({
                'line_idx': idx,
                'pod': pod_name,
            })

    def flush(self) -> tuple[list[dict[str, Any]], int]:
        """Emit findings."""
        findings = []

        # CrashLoopBackOff (CRITICAL)
        if self.findings['crashloop'] > 0:
            findings.append({
                'level': 'CRITICAL',
                'category': 'container',
                'kind': 'crashloop',
                'count': self.findings['crashloop'],
                'affected_pods': list(set(e['pod'] for e in self.crash_events if e.get('pod'))),
                'remediation': 'Check application logs for errors; verify config/env vars',
            })

        # OOMKilled (CRITICAL)
        if self.findings['oomkilled'] > 0:
            findings.append({
                'level': 'CRITICAL',
                'category': 'resource',
                'kind': 'oomkilled',
                'count': self.findings['oomkilled'],
                'affected_pods': list(set(e['pod'] for e in self.oom_events if e.get('pod'))),
                'remediation': 'Increase memory limits or find memory leak',
            })

        # Image Pull Error (ERROR)
        if self.findings['image_pull_error'] > 0:
            findings.append({
                'level': 'ERROR',
                'category': 'image',
                'kind': 'image_pull_error',
                'count': self.findings['image_pull_error'],
                'remediation': 'Check registry connectivity, credentials, or image existence',
            })

        # Restart Storm (WARN)
        if self.restart_storms:
            for pod, count in self.restart_storms.items():
                if count >= 3:
                    findings.append({
                        'level': 'WARN',
                        'category': 'lifecycle',
                        'kind': 'restart_storm',
                        'pod': pod,
                        'restart_count': count,
                    })

        # Node Pressure (WARN)
        if self.findings['node_pressure'] > 0:
            findings.append({
                'level': 'WARN',
                'category': 'node',
                'kind': 'node_pressure',
                'count': self.findings['node_pressure'],
                'remediation': 'Check node resources (CPU, memory, disk)',
            })

        return findings, len(findings)

    def overflow_unique(self) -> int:
        return len(self.pods) + len(self.containers)

    def line_rule(self, line: str) -> tuple[str, str, str] | None:
        if 'CrashLoopBackOff' in line or 'OOMKilled' in line:
            return 'CRITICAL', 'container', 'lifecycle_error'
        if 'ImagePullBackOff' in line:
            return 'ERROR', 'image', 'pull_error'
        if any(kw in line for kw in PRESSURE_KEYWORDS):
            return 'WARN', 'node', 'pressure'
        return None

    def finding_component(self, line: str) -> str | None:
        if 'CrashLoopBackOff' in line:
            return 'Container crash loop detected'
        if 'OOMKilled' in line:
            return 'Pod killed due to memory exhaustion'
        if 'ImagePullBackOff' in line:
            return 'Image pull failure'
        return None

    def context_pid(self, line: str) -> str | None:
        pod_match = K8S_POD_RE.search(line)
        return pod_match.group(1)[:16] if pod_match else None
