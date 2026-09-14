from __future__ import annotations

import json
import urllib.parse
import zlib
import base64

from analyzers.saml import (
    _extract_candidates,
    _parse_xml_detailed,
    analyze_saml_input,
    _local,
)

PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"

AUTHN = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    f'<saml2p:AuthnRequest xmlns:saml2p="{PROTOCOL_NS}" '
    f'xmlns:saml2="{ASSERTION_NS}" ID="_req1" Version="2.0" '
    'IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.example/sso" '
    'AssertionConsumerServiceURL="https://sp.example/acs">'
    "<saml2:Issuer>https://sp.example/entity</saml2:Issuer>"
    "</saml2p:AuthnRequest>"
)
RESPONSE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    f'<saml2p:Response xmlns:saml2p="{PROTOCOL_NS}" '
    f'xmlns:saml2="{ASSERTION_NS}" ID="_resp1" Version="2.0" '
    'InResponseTo="_req1" Destination="https://sp.example/acs" '
    'IssueInstant="2026-09-07T08:00:01Z">'
    "<saml2:Issuer>https://idp.example/entity</saml2:Issuer>"
    "<saml2p:Status><saml2p:StatusCode "
    'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status>'
    '<saml2:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">'
    "<saml2:Issuer>https://idp.example/entity</saml2:Issuer>"
    "<saml2:Subject><saml2:NameID>alice@example.com</saml2:NameID></saml2:Subject>"
    "</saml2:Assertion></saml2p:Response>"
)
MALFORMED = (
    f'<saml2p:Response xmlns:saml2p="{PROTOCOL_NS}" ID="_r" Version="2.0" '
    'IssueInstant="2026-09-07T08:00:00Z"><saml2p:Status></saml2p:Response>'
)


def _ns(tag: str) -> str:
    if tag.startswith("{"):
        return tag[1:].split("}", 1)[0]
    return ""


def _redirect_b64(xml: str) -> str:
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(xml.encode()) + compressor.flush()
    return urllib.parse.quote_plus(base64.b64encode(deflated).decode())


def _tracer_export() -> str:
    return json.dumps(
        [
            {
                "method": "GET",
                "url": "https://idp.example/sso?SAMLRequest=" + _redirect_b64(AUTHN),
                "saml": AUTHN,
                "get": {"SAMLRequest": _redirect_b64(AUTHN)},
            },
            {
                "method": "POST",
                "url": "https://sp.example/acs",
                "saml": RESPONSE,
                "postData": {"SAMLResponse": base64.b64encode(RESPONSE.encode()).decode()},
            },
        ]
    )


def test_json_export_contains_escaped_quotes():
    raw = _tracer_export()
    assert 'AssertionConsumerServiceURL=\\"' in raw


def test_saml_tracer_json_does_not_parse_escaped_markup():
    raw = _tracer_export()
    assert "embedded AuthnRequest" not in {source for _xml, source in _extract_candidates(raw)}
    assert "embedded Response" not in {source for _xml, source in _extract_candidates(raw)}
    assert "embedded Assertion" not in {source for _xml, source in _extract_candidates(raw)}

    result = analyze_saml_input(raw)
    codes = {f["code"] for f in result["findings"]}
    assert "XML_NOT_WELL_FORMED" not in codes

    types = {d["type"] for d in result["documents"]}
    assert "AuthnRequest" in types
    assert "Response" in types
    assert result["summary"]["standalone_assertions"] == 0
    resp = next(d for d in result["documents"] if d["type"] == "Response")
    assert len(resp["assertions"]) == 1

    parsed: dict[str, object] = {}
    for candidate, _source in _extract_candidates(raw):
        root, err = _parse_xml_detailed(candidate)
        if root is None:
            assert err is None
            continue
        loc = _local(root.tag)
        parsed[loc] = root
        if loc == "Response":
            assertions = root.findall(f"{{{ASSERTION_NS}}}Assertion")
            assert len(assertions) == 1
            assert _ns(assertions[0].tag) == ASSERTION_NS
    assert _ns(parsed["AuthnRequest"].tag) == PROTOCOL_NS
    assert _ns(parsed["Response"].tag) == PROTOCOL_NS


def test_saml_tracer_prefers_decoded_saml_over_transport_duplicate():
    raw = _tracer_export()
    result = analyze_saml_input(raw)
    assert result["summary"]["authn_requests"] == 1
    assert result["summary"]["responses"] == 1


def test_json_string_with_malformed_xml_still_reports_parse_error():
    raw = json.dumps(
        [
            {
                "method": "POST",
                "url": "https://sp.example/acs",
                "saml": MALFORMED,
            }
        ]
    )
    result = analyze_saml_input(raw)
    findings = [f for f in result["findings"] if f["code"] == "XML_NOT_WELL_FORMED"]
    assert findings
    assert any("SAML-tracer saml" in f.get("scope", "") for f in findings)
    assert not any("embedded" in f.get("scope", "").lower() for f in findings)


if __name__ == "__main__":
    test_json_export_contains_escaped_quotes()
    test_saml_tracer_json_does_not_parse_escaped_markup()
    test_saml_tracer_prefers_decoded_saml_over_transport_duplicate()
    test_json_string_with_malformed_xml_still_reports_parse_error()
    print("SAML TRACER JSON TESTS OK")
