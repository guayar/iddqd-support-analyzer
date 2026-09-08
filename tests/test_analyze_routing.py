from __future__ import annotations

import tempfile
from pathlib import Path

from actions import analyze
from uploads import InputError

LOG = """2026-09-07 10:00:00 INFO started
2026-09-07 10:01:00 ERROR boom HTTP 500
"""

REQUEST = '''<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.example/sso" AssertionConsumerServiceURL="https://sp.example/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://sp.example/entity</saml:Issuer></samlp:AuthnRequest>'''

RESPONSE = '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" InResponseTo="_req1" Destination="https://sp.example/acs" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.example/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>'''

SP_METADATA = '''<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example/entity"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example/acs" index="0" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>'''

IDP_METADATA = '''<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>'''


def _file(name: str, content: str) -> str:
    path = Path(tempfile.mkdtemp()) / name
    path.write_text(content, encoding="utf-8")
    return str(path)


# 1. log-only Auto-detect
md, raw, result = analyze(None, LOG, "Auto-detect")
assert result["kind"] == "log"
assert result["error_event_count"] == 1
assert "# Log analysis" in md
assert "kind" in raw

# 2. SAML-only Auto-detect
md, _raw, result = analyze(None, REQUEST, "Auto-detect")
assert result["kind"] == "saml"
assert result["summary"]["authn_requests"] == 1
assert "# SAML / SSO analysis" in md

# 3. multiple SAML artifacts still correlate together
req_f = _file("authn.xml", REQUEST)
resp_f = _file("response.xml", RESPONSE)
sp_f = _file("sp.xml", SP_METADATA)
idp_f = _file("idp.xml", IDP_METADATA)
md, _raw, result = analyze([req_f, resp_f, sp_f, idp_f], "", "Auto-detect")
assert result["kind"] == "saml"
assert result["documents_found"] >= 4
statuses = {c["check"]: c["status"] for c in result["checks"]}
assert statuses["AuthnRequest ACS vs Response Destination"] == "MATCH"
assert statuses["SP metadata #1 entityID vs AuthnRequest Issuer"] == "MATCH"
assert statuses["IdP metadata #1 entityID vs Response Issuer"] == "MATCH"

# 4. log + SAML mixed upload
log_f = _file("error.log", LOG)
trace_f = _file("trace.xml", RESPONSE)
md, raw, result = analyze([log_f, trace_f], "", "Auto-detect")
assert result["kind"] == "mixed"
assert result["log"]["kind"] == "log"
assert result["saml"]["kind"] == "saml"
assert result["log"]["error_event_count"] == 1
assert result["saml"]["summary"]["responses"] == 1
assert result["log"]["filename"] == "error.log"
assert {a["name"]: a["kind"] for a in result["artifacts"]} == {"error.log": "Log", "trace.xml": "SAML"}
assert "# Analysis" in md
assert "## SAML analysis" in md
assert "## Log analysis" in md
assert '"kind": "mixed"' in raw
assert "HTTP 500" in result["log"]["incidents"][0]["signature"] or result["log"]["error_event_count"] == 1

# 5. SAML metadata + log
md, _raw, result = analyze([_file("sp-metadata.xml", SP_METADATA), log_f], "", "Auto-detect")
assert result["kind"] == "mixed"
assert result["saml"]["summary"]["metadata_entities"] == 1
assert result["log"]["error_event_count"] == 1

# 6. explicit SAML mode with multiple artifacts (including a log) stays one SAML run
md, _raw, result = analyze([log_f, req_f, resp_f], "", "SAML")
assert result["kind"] == "saml"
assert "log" not in result
assert result["summary"]["authn_requests"] == 1
assert result["summary"]["responses"] == 1
assert "# SAML / SSO analysis" in md

# 7. explicit Log mode
md, _raw, result = analyze([log_f], "", "Log")
assert result["kind"] == "log"
assert result["error_event_count"] == 1
md, _raw, result = analyze([trace_f], "", "Log")
assert result["kind"] == "log"

# 8. pasted input remains compatible
md, _raw, result = analyze(None, LOG, "Auto-detect")
assert result["kind"] == "log"
md, _raw, result = analyze(None, REQUEST + "\n" + RESPONSE, "Auto-detect")
assert result["kind"] == "saml"
assert result["summary"]["authn_requests"] == 1
assert result["summary"]["responses"] == 1

empty_failed = False
try:
    analyze(None, "  ", "Auto-detect")
except InputError:
    empty_failed = True
assert empty_failed

print("ANALYZE ROUTING TESTS OK")
