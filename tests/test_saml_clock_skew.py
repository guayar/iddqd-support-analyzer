from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

from analyzers.saml import analyze_saml_input
from analyzers.saml_validation import instant_expired, instant_not_yet_valid

NOW = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)

RESPONSE = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
    'InResponseTo="_req1" Destination="https://sp.example/acs" IssueInstant="2026-09-07T08:00:01Z">'
    '<saml:Issuer>https://idp.example/entity</saml:Issuer>'
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">'
    '<saml:Issuer>https://idp.example/entity</saml:Issuer>'
    '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
    "alice@example.com</saml:NameID>"
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
    '<saml:SubjectConfirmationData Recipient="https://sp.example/acs" InResponseTo="_req1" '
    'NotOnOrAfter="{noa}"/></saml:SubjectConfirmation></saml:Subject>'
    '<saml:Conditions NotBefore="{nb}" NotOnOrAfter="{noa}">'
    "<saml:AudienceRestriction><saml:Audience>https://sp.example/entity</saml:Audience>"
    "</saml:AudienceRestriction></saml:Conditions>"
    '<saml:AuthnStatement AuthnInstant="2026-09-07T08:00:00Z" SessionIndex="abc">'
    "<saml:AuthnContext><saml:AuthnContextClassRef>"
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
    "</saml:Assertion></samlp:Response>"
)


def _codes(xml: str) -> set[str]:
    with patch("analyzers.saml_validation._now_utc", return_value=NOW):
        return {f["code"] for f in analyze_saml_input(xml)["findings"]}


def _xml(*, nb: str, noa: str) -> str:
    return RESPONSE.format(nb=nb, noa=noa)


def test_helpers_match_sp_style_window():
    nb = datetime(2026, 9, 10, 12, 0, 30, tzinfo=timezone.utc)
    noa = datetime(2026, 9, 10, 11, 59, 30, tzinfo=timezone.utc)
    with patch("config.SAML_CLOCK_SKEW_SECONDS", 120):
        assert instant_not_yet_valid(NOW, nb) is False
        assert instant_expired(NOW, noa) is False
    with patch("config.SAML_CLOCK_SKEW_SECONDS", 0):
        assert instant_not_yet_valid(NOW, nb) is True
        assert instant_expired(NOW, noa) is True


def test_default_skew_tolerates_30s_expiry():
    xml = _xml(nb="2026-09-10T11:00:00Z", noa="2026-09-10T11:59:30Z")
    with patch("config.SAML_CLOCK_SKEW_SECONDS", 120):
        codes = _codes(xml)
    assert "ASSERTION_EXPIRED" not in codes
    assert "BEARER_CONFIRMATION_EXPIRED" not in codes


def test_zero_skew_flags_30s_expiry():
    xml = _xml(nb="2026-09-10T11:00:00Z", noa="2026-09-10T11:59:30Z")
    with patch("config.SAML_CLOCK_SKEW_SECONDS", 0):
        codes = _codes(xml)
    assert "ASSERTION_EXPIRED" in codes
    assert "BEARER_CONFIRMATION_EXPIRED" in codes


def test_default_skew_tolerates_30s_not_before():
    xml = _xml(nb="2026-09-10T12:00:30Z", noa="2026-09-10T13:00:00Z")
    with patch("config.SAML_CLOCK_SKEW_SECONDS", 120):
        codes = _codes(xml)
    assert "ASSERTION_NOT_YET_VALID" not in codes


def test_zero_skew_flags_30s_not_before():
    xml = _xml(nb="2026-09-10T12:00:30Z", noa="2026-09-10T13:00:00Z")
    with patch("config.SAML_CLOCK_SKEW_SECONDS", 0):
        codes = _codes(xml)
    assert "ASSERTION_NOT_YET_VALID" in codes


def test_hours_old_still_expires_with_default_skew():
    xml = _xml(nb="2026-09-10T08:00:00Z", noa="2026-09-10T09:00:00Z")
    with patch("config.SAML_CLOCK_SKEW_SECONDS", 120):
        codes = _codes(xml)
    assert "ASSERTION_EXPIRED" in codes
    assert "BEARER_CONFIRMATION_EXPIRED" in codes


if __name__ == "__main__":
    test_helpers_match_sp_style_window()
    test_default_skew_tolerates_30s_expiry()
    test_zero_skew_flags_30s_expiry()
    test_default_skew_tolerates_30s_not_before()
    test_zero_skew_flags_30s_not_before()
    test_hours_old_still_expires_with_default_skew()
    print("SAML CLOCK SKEW TESTS OK")
