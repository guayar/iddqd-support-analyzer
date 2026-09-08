from __future__ import annotations

from analyzers.anonymizer import anonymize_text, scan_residual_leaks
from reporting import render_anonymize_summary

# Clean replacement: residual scan should be quiet.
clean = anonymize_text("user 10.1.2.3 failed alice@example.com Authorization: Bearer tok_abc")
assert "10.1.2.3" not in clean["text"]
assert "alice@example.com" not in clean["text"]
assert clean["residual_count"] == 0
assert clean["residual_findings"] == []
md = render_anonymize_summary(clean)
assert "## Residual leaks" in md
assert "No leftover" in md

# Unknown SAML child text is not in the structural walker — residual must flag it.
leaky = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.example.com/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.example.com/entity</saml:Issuer><saml:Advice><ext:Note xmlns:ext="urn:example:ext">leak@customer.test</ext:Note></saml:Advice></saml:Assertion></samlp:Response>"""
leaky_out = anonymize_text(leaky)
assert leaky_out["structured_saml_payloads_anonymized"] == 1
assert any(h["kind"] == "EMAIL" and "leak@customer.test" in h["value"] for h in leaky_out["residual_findings"])
assert "Residual scan found" in " ".join(leaky_out["limitations"])
assert "❌" in render_anonymize_summary(leaky_out)

# Windows profile path is replaced, not left as a residual user folder.
win = anonymize_text(r"ERROR in C:\Users\jsmith\app.log")
assert r"C:\Users\jsmith" not in win["text"]
assert "USER_001" in win["text"]
assert not any(h["kind"] == "USER" and h["value"] == "jsmith" for h in win["residual_findings"])

# jwt.secret= values are treated as secrets.
prop = anonymize_text("jwt.secret=super-secret-value")
assert "super-secret-value" not in prop["text"]

# Java stack frames, logger abbreviations, filenames and :: are not domains/IPs.
stack = """2026-06-16T13:34:08.229+05:30 ERROR o.s.boot.SpringApplication : Application run failed
	at org.springframework.boot.SpringApplication.run(SpringApplication.java:323) ~[spring-boot-3.2.0.jar:3.2.0]
Caused by: java.lang.IllegalArgumentException: Could not resolve placeholder 'jwt.secret' in value "${jwt.secret}"
[INFO] from pom.xml
[ERROR] [Help 1] http://cwiki.apache.org/confluence/display/MAVEN/MojoExecutionException
::
"""
st = anonymize_text(stack)
assert "SpringApplication.java" in st["text"]
assert "spring-boot-3.2.0.jar" in st["text"]
assert "o.s.boot.SpringApplication" in st["text"]
assert "jwt.secret" in st["text"]
assert "pom.xml" in st["text"]
assert "cwiki.apache.org" in st["text"]
assert "::" in st["text"]
assert not any(
    row["original"].endswith((".java", ".jar", ".class", ".xml")) or row["original"] in {"jwt.secret", "::", "pom.xml"}
    for row in st["mapping"]
)
assert "api.customer.example.com" not in anonymize_text("https://api.customer.example.com/login")["text"]

# Residual scanner itself ignores placeholders and OASIS/W3C URIs.
hits = scan_residual_leaks("EMAIL_001 and https://www.w3.org/2000/09/xmldsig# and java.lang.RuntimeException")
assert hits == []

print("ANONYMIZER RESIDUAL TESTS OK")
