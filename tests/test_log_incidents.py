from __future__ import annotations

from pathlib import Path

from analyzers.logs import analyze_log_text, parse_java_exception_chain
from reporting import render_log_report

TEST_A = """2026-06-16T13:34:08.229+05:30 ERROR 29224 --- [CRT-Backend] [main] o.s.boot.SpringApplication : Application run failed

org.springframework.context.ApplicationContextException: Unable to start web server
    at example.A(A.java:1)
Caused by: org.springframework.boot.web.server.WebServerException: Unable to start embedded Tomcat
    at example.B(B.java:2)
Caused by: org.springframework.beans.factory.BeanCreationException: Error creating bean with name 'jwtUtil'
    at example.C(C.java:3)
Caused by: java.lang.IllegalArgumentException: Could not resolve placeholder 'jwt.secret' in value "${jwt.secret}"
    at example.D(D.java:4)
"""

a = analyze_log_text(TEST_A, "nested.log")
assert a["error_event_count"] == 1
assert len(a["error_groups"]) == 1
g = a["error_groups"][0]
assert g["exception_chain"] == [
    "org.springframework.context.ApplicationContextException",
    "org.springframework.boot.web.server.WebServerException",
    "org.springframework.beans.factory.BeanCreationException",
    "java.lang.IllegalArgumentException",
]
assert len(g["exception_chain"]) == 4
assert g["root_cause"].startswith("java.lang.IllegalArgumentException")
assert "jwt.secret" in g["root_cause"]
assert "Caused by:" in g["sample"]
assert g["sample"].count("Caused by:") == 3
md = render_log_report(a)
assert "## Incidents" in md
assert "Caused by: not explicitly present" not in md
assert "<details>" in md
assert "<summary>Relevant log</summary>" in md
assert "**Caused by (3)**" in md
assert "1. `org.springframework.boot.web.server.WebServerException:" in md
assert "3. `java.lang.IllegalArgumentException: Could not resolve placeholder 'jwt.secret'" in md
assert "starting ApplicationContext" not in g["signature"]

TEST_B = "Error starting ApplicationContext. To display the condition evaluation report re-run your application with 'debug' enabled.\n"
b = analyze_log_text(TEST_B)
assert b["error_event_count"] == 0
assert b["error_groups"] == []
assert "ERROR" not in b["levels"]
b_md = render_log_report(b)
assert "starting ApplicationContext" not in b_md

TEST_C = """[ERROR] Failed to execute goal org.springframework.boot:spring-boot-maven-plugin:3.2.0:run: Process terminated with exit code: 1
[ERROR]
[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
[ERROR] Re-run Maven using the -X switch to enable full debug logging.
[ERROR] For more information about the errors and possible solutions, please read the following articles:
[ERROR] [Help 1] http://cwiki.apache.org/confluence/display/MAVEN/MojoExecutionException
"""
c = analyze_log_text(TEST_C)
assert c["error_event_count"] == 1
assert len(c["error_groups"]) == 1
cg = c["error_groups"][0]
assert "Failed to execute goal" in cg["signature"]
assert cg["exit_code"] == 1
assert cg["signature"] not in {"]", "[", ":", "-", ""}
assert "To see the full stack trace" in cg["sample"]
assert "MojoExecutionException" in cg["sample"]
assert not any(x["signature"].strip() in {"]", "["} for x in c["error_groups"])
assert not any(x["signature"].startswith("] ") for x in c["error_groups"])

TEST_D = TEST_A.replace("    at example.C(C.java:3)\n", "    at example.C(C.java:3)\n    ... 54 common frames omitted\n")
d = analyze_log_text(TEST_D)
assert d["error_event_count"] == 1
assert "... 54 common frames omitted" in d["error_groups"][0]["sample"]
chain = parse_java_exception_chain(TEST_D.splitlines())
assert len(chain["exception_chain"]) == 4
assert chain["root_cause"].startswith("java.lang.IllegalArgumentException")

# Banner from uploads must not become an error incident.
banner = analyze_log_text("\n===== FILE: error.txt =====\n2026-09-07 10:00:00 INFO started\n")
assert banner["error_event_count"] == 0

sample = Path("/home/sututrang/Downloads/error.txt")
if sample.is_file():
    spring = analyze_log_text(sample.read_text(encoding="utf-8"), "error.txt")
    titles = [g["signature"] for g in spring["error_groups"]]
    assert not any(t.strip() in {"]", "[", ":", "-"} for t in titles)
    assert not any(t.startswith("starting ApplicationContext") for t in titles)
    assert not any(t.startswith("] ") for t in titles)
    caused_only = [g for g in spring["error_groups"] if g["signature"].startswith("Caused by:")]
    assert caused_only == []
    chains = [g for g in spring["error_groups"] if len(g.get("exception_chain") or []) >= 4]
    assert chains, titles
    assert any("IllegalArgumentException" in (g.get("root_cause") or "") for g in spring["error_groups"])
    assert any("Failed to execute goal" in g["signature"] for g in spring["error_groups"])
    assert spring["error_event_count"] <= 4
    assert len(spring["error_groups"]) <= 4

print("LOG INCIDENT TESTS OK")
