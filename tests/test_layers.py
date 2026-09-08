from pathlib import Path
import base64

from actions import analyze, anonymize
from config import APP_VERSION
from llm import endpoint_is_local
from reporting import render_anonymize_summary, render_log_report, render_saml_report
from uploads import InputError

md, raw, result = analyze(None, "2026-09-07 10:00:00 ERROR boom HTTP 500", "Auto-detect")
assert "# Log analysis" in md
assert result["error_event_count"] == 1
assert '"error_event_count"' in raw

empty_failed = False
try:
    analyze(None, "   ", "Auto-detect")
except InputError:
    empty_failed = True
assert empty_failed

saml = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.example/sso" AssertionConsumerServiceURL="https://sp.example/acs"><saml:Issuer>https://sp.example/entity</saml:Issuer></samlp:AuthnRequest>'
md, _raw, result = analyze(None, saml, "Auto-detect")
assert "# SAML / SSO analysis" in md
assert "## AuthnRequest" in md
assert result["summary"]["authn_requests"] == 1
assert render_saml_report(result).startswith("# SAML / SSO analysis")

declared_resp = '<?xml version="1.0"?>\r\n<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.example/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>'
md, _raw, result = analyze(None, base64.b64encode(declared_resp.encode()).decode(), "Auto-detect")
assert result["kind"] == "saml"
assert result["summary"]["responses"] == 1
assert "# SAML / SSO analysis" in md

log_report = render_log_report({
    "filename": "app.log",
    "line_count": 2,
    "time_range": {"from": None, "to": None},
    "levels": {"ERROR": 1},
    "error_codes": {},
    "error_groups": [],
    "error_event_count": 0,
})
assert "**File:** `app.log`" in log_report
assert "❌ **ERROR:** 1" in log_report
assert "No explicit ERROR/FATAL/SEVERE/CRITICAL events detected." in log_report

summary = render_anonymize_summary({"counts": {"IP": 1}, "replacements": 1})
assert "**IP:** 1" in summary

anon_md, anon_text, mapping, out_path = anonymize(None, "user 10.1.2.3 failed")
assert "10.1.2.3" not in anon_text
assert Path(out_path).read_text(encoding="utf-8") == anon_text
assert "IP_001" in anon_text
assert '"mapping"' in mapping

assert endpoint_is_local("http://127.0.0.1:11434")
assert endpoint_is_local("http://localhost:11434")
assert not endpoint_is_local("https://api.openai.com")
assert not endpoint_is_local("not-a-url")

assert APP_VERSION == Path("VERSION").read_text(encoding="utf-8").strip()
assert APP_VERSION

print("LAYER TESTS OK")
