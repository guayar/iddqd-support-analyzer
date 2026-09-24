from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from unittest.mock import patch

from analyzers.saml import analyze_saml_input
from reporting import render_saml_report

ACS_URL = "https://172.16.217.82:8083/SecureSphere/login/saml2/sso/Imperva-DAM-UAT"
NB = "2026-09-24T04:59:21.000Z"
NOA = "2026-09-24T05:11:21.000Z"
ACS_DATE = "Thu, 24 Sep 2026 05:01:22 GMT"
ANALYZER_NOW = datetime(2026, 9, 24, 8, 49, 43, tzinfo=timezone.utc)
HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

RESPONSE = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
    f'InResponseTo="_req1" Destination="{ACS_URL}" IssueInstant="2026-09-24T05:01:00Z">'
    "<saml:Issuer>https://idp.example/hysecure</saml:Issuer>"
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-24T05:01:00Z">'
    "<saml:Issuer>https://idp.example/hysecure</saml:Issuer>"
    "<saml:Subject>"
    '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">K16177</saml:NameID>'
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
    f'<saml:SubjectConfirmationData Recipient="{ACS_URL}" InResponseTo="_req1" '
    f'NotOnOrAfter="{NOA}"/></saml:SubjectConfirmation></saml:Subject>'
    f'<saml:Conditions NotBefore="{NB}" NotOnOrAfter="{NOA}">'
    "<saml:AudienceRestriction>"
    "<saml:Audience>https://sp.example/imperva</saml:Audience>"
    "</saml:AudienceRestriction></saml:Conditions>"
    '<saml:AuthnStatement AuthnInstant="2026-09-24T05:00:50Z" SessionIndex="sess1">'
    "<saml:AuthnContext><saml:AuthnContextClassRef>"
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
    "</saml:Assertion></samlp:Response>"
)


def _tracer_export() -> str:
    return json.dumps(
        [
            {
                "method": "POST",
                "url": ACS_URL,
                "status": 401,
                "saml": RESPONSE,
                "postData": {"SAMLResponse": base64.b64encode(RESPONSE.encode()).decode()},
                "responseHeaders": [
                    {"name": "Date", "value": ACS_DATE},
                    {"name": "Content-Type", "value": "text/html"},
                ],
            }
        ]
    )


def test_incident_trace_uses_acs_date_not_analyzer_runtime():
    raw = _tracer_export()
    with patch("analyzers.saml_validation._now_utc", return_value=ANALYZER_NOW), patch(
        "config.SAML_CLOCK_SKEW_SECONDS", 120
    ):
        result = analyze_saml_input(raw)
    codes = {f["code"] for f in result["findings"]}
    assert "ASSERTION_EXPIRED" not in codes
    assert "BEARER_CONFIRMATION_EXPIRED" not in codes
    assert "ASSERTION_EXPIRED_IF_REPLAYED_NOW" in codes
    assert "BEARER_CONFIRMATION_EXPIRED_IF_REPLAYED_NOW" in codes

    timing = (result.get("validation_context") or {}).get("timing") or {}
    assert timing.get("mode") == "incident_trace"
    assert timing.get("validation_time") == "2026-09-24T05:01:22Z"
    assert timing.get("validation_time_source") == "acs_response_date"
    assert timing.get("valid_at_observed_time") is True
    assert timing.get("expired_at_analyzer_runtime") is True

    transport = result.get("transport") or {}
    assert transport.get("response_http_method") == "POST"
    assert transport.get("response_binding") == HTTP_POST
    assert transport.get("response_post_target") == ACS_URL

    report = render_saml_report(result)
    assert "Timing valid at observed ACS POST time" in report
    assert "Response HTTP method: `POST`" in report or "Response HTTP method:** `POST`" in report or "**Response HTTP method:** `POST`" in report
    assert ACS_URL in report
    assert "Standards/profile validation:** ❌ 2 error" not in report


def test_incident_trace_without_event_time_is_info_not_error():
    raw = json.dumps(
        [
            {
                "method": "POST",
                "url": ACS_URL,
                "status": 401,
                "saml": RESPONSE,
                "postData": {"SAMLResponse": base64.b64encode(RESPONSE.encode()).decode()},
            }
        ]
    )
    with patch("analyzers.saml_validation._now_utc", return_value=ANALYZER_NOW), patch(
        "config.SAML_CLOCK_SKEW_SECONDS", 120
    ):
        result = analyze_saml_input(raw)
    codes = {f["code"] for f in result["findings"]}
    assert "ASSERTION_EXPIRED" not in codes
    assert "BEARER_CONFIRMATION_EXPIRED" not in codes
    assert "ASSERTION_VALIDITY_TIME_UNKNOWN" in codes
    assert "BEARER_CONFIRMATION_VALIDITY_TIME_UNKNOWN" in codes


def test_raw_xml_still_uses_replay_now():
    with patch("analyzers.saml_validation._now_utc", return_value=ANALYZER_NOW), patch(
        "config.SAML_CLOCK_SKEW_SECONDS", 120
    ):
        result = analyze_saml_input(RESPONSE)
    codes = {f["code"] for f in result["findings"]}
    assert "ASSERTION_EXPIRED" in codes
    assert "BEARER_CONFIRMATION_EXPIRED" in codes
    timing = (result.get("validation_context") or {}).get("timing") or {}
    assert timing.get("mode") == "replay_now"


if __name__ == "__main__":
    test_incident_trace_uses_acs_date_not_analyzer_runtime()
    test_incident_trace_without_event_time_is_info_not_error()
    test_raw_xml_still_uses_replay_now()
    print("SAML INCIDENT TIMING TESTS OK")
