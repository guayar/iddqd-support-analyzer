from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from config import parse_saml_clock_skew_seconds
from analyzers.saml import analyze_saml_input
from analyzers.saml_validation import instant_expired, instant_not_yet_valid, instant_on_or_after

NOW = datetime(2026, 9, 10, 12, 0, 0, tzinfo=timezone.utc)
TZ = timezone.utc


def _iso(dt: datetime) -> str:
    return dt.astimezone(TZ).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    '<saml:AuthnStatement AuthnInstant="2026-09-07T08:00:00Z" SessionIndex="abc"{session}>'
    "<saml:AuthnContext><saml:AuthnContextClassRef>"
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    "</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>"
    "</saml:Assertion></samlp:Response>"
)

SP_METADATA = (
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="https://sp.example/entity" validUntil="{vu}">'
    '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
    'AuthnRequestsSigned="false" WantAssertionsSigned="false">'
    "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
    '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
    'Location="https://sp.example/acs" index="0" isDefault="true"/>'
    "</md:SPSSODescriptor></md:EntityDescriptor>"
)


ASSISTED = "accepted within configured"


def _analyze(xml: str, *, now: datetime = NOW, skew: int = 120) -> dict:
    with patch("analyzers.saml_validation._now_utc", return_value=now), patch("config.SAML_CLOCK_SKEW_SECONDS", skew):
        return analyze_saml_input(xml)


def _codes(xml: str, *, now: datetime = NOW, skew: int | None = None) -> set[str]:
    kwargs = {"now": now}
    if skew is not None:
        kwargs["skew"] = skew
    return {f["code"] for f in _analyze(xml, **kwargs)["findings"]}


def _time_row(result: dict, name: str) -> dict:
    rows = [c for c in result["checks"] if c.get("check") == name]
    assert len(rows) == 1, [c.get("check") for c in result["checks"]]
    return rows[0]


def _xml(*, nb: datetime, noa: datetime, session_noa: datetime | None = None) -> str:
    session = f' SessionNotOnOrAfter="{_iso(session_noa)}"' if session_noa else ""
    return RESPONSE.format(nb=_iso(nb), noa=_iso(noa), session=session)


def _wide_open(*, noa: datetime) -> str:
    return _xml(nb=NOW - timedelta(hours=6), noa=noa)


def test_not_before_helper_minus_zero_plus_one():
    """Valid when now >= NotBefore − S. Equal to the lower edge is in-window."""
    not_before = NOW
    for skew in (0, 1, 120):
        edge = not_before - timedelta(seconds=skew)
        with patch("config.SAML_CLOCK_SKEW_SECONDS", skew):
            assert instant_not_yet_valid(edge - timedelta(seconds=1), not_before) is True, skew
            assert instant_not_yet_valid(edge, not_before) is False, skew
            assert instant_not_yet_valid(edge + timedelta(seconds=1), not_before) is False, skew


def test_not_on_or_after_helper_minus_zero_plus_one():
    """Expired when now >= NotOnOrAfter + S. Equal to the upper edge is expired."""
    not_on_or_after = NOW
    for skew in (0, 1, 120):
        edge = not_on_or_after + timedelta(seconds=skew)
        with patch("config.SAML_CLOCK_SKEW_SECONDS", skew):
            assert instant_expired(edge - timedelta(seconds=1), not_on_or_after) is False, skew
            assert instant_expired(edge, not_on_or_after) is True, skew
            assert instant_expired(edge + timedelta(seconds=1), not_on_or_after) is True, skew


def test_zero_skew_equals_raw_timestamps():
    with patch("config.SAML_CLOCK_SKEW_SECONDS", 0):
        assert instant_not_yet_valid(NOW, NOW) is False
        assert instant_not_yet_valid(NOW - timedelta(seconds=1), NOW) is True
        assert instant_expired(NOW, NOW) is True
        assert instant_expired(NOW - timedelta(seconds=1), NOW) is False


def test_instant_on_or_after_ignores_configured_skew():
    with patch("config.SAML_CLOCK_SKEW_SECONDS", 120):
        assert instant_on_or_after(NOW - timedelta(seconds=1), NOW) is False
        assert instant_on_or_after(NOW, NOW) is True
        assert instant_on_or_after(NOW + timedelta(seconds=1), NOW) is True
        assert instant_expired(NOW + timedelta(seconds=30), NOW) is False


def test_assertion_not_before_xml_minus_zero_plus_one():
    not_before = NOW
    far_noa = NOW + timedelta(hours=6)
    for skew in (0, 1, 120):
        edge = not_before - timedelta(seconds=skew)
        with patch("config.SAML_CLOCK_SKEW_SECONDS", skew):
            too_early = _xml(nb=not_before, noa=far_noa)
            codes_m1 = _codes(too_early, now=edge - timedelta(seconds=1), skew=skew)
            codes_0 = _codes(too_early, now=edge, skew=skew)
            codes_p1 = _codes(too_early, now=edge + timedelta(seconds=1), skew=skew)
        assert "ASSERTION_NOT_YET_VALID" in codes_m1, skew
        assert "ASSERTION_NOT_YET_VALID" not in codes_0, skew
        assert "ASSERTION_NOT_YET_VALID" not in codes_p1, skew
        assert "ASSERTION_EXPIRED" not in codes_m1 | codes_0 | codes_p1


def test_assertion_and_bearer_expiry_xml_minus_zero_plus_one():
    not_on_or_after = NOW
    for skew in (0, 1, 120):
        edge = not_on_or_after + timedelta(seconds=skew)
        xml = _wide_open(noa=not_on_or_after)
        with patch("config.SAML_CLOCK_SKEW_SECONDS", skew):
            codes_m1 = _codes(xml, now=edge - timedelta(seconds=1), skew=skew)
            codes_0 = _codes(xml, now=edge, skew=skew)
            codes_p1 = _codes(xml, now=edge + timedelta(seconds=1), skew=skew)
        for code in ("ASSERTION_EXPIRED", "BEARER_CONFIRMATION_EXPIRED"):
            assert code not in codes_m1, (skew, code)
            assert code in codes_0, (skew, code)
            assert code in codes_p1, (skew, code)


def test_session_expiry_is_strict_regardless_of_skew():
    session_noa = NOW
    xml = _xml(
        nb=NOW - timedelta(hours=6),
        noa=NOW + timedelta(hours=6),
        session_noa=session_noa,
    )
    for skew in (0, 120):
        with patch("config.SAML_CLOCK_SKEW_SECONDS", skew):
            codes_m1 = _codes(xml, now=session_noa - timedelta(seconds=1), skew=skew)
            codes_0 = _codes(xml, now=session_noa, skew=skew)
            codes_p1 = _codes(xml, now=session_noa + timedelta(seconds=1), skew=skew)
            codes_plus_30 = _codes(xml, now=session_noa + timedelta(seconds=30), skew=skew)
        assert "SESSION_NOTONORAFTER_EXPIRED" not in codes_m1, skew
        assert "SESSION_NOTONORAFTER_EXPIRED" in codes_0, skew
        assert "SESSION_NOTONORAFTER_EXPIRED" in codes_p1, skew
        assert "SESSION_NOTONORAFTER_EXPIRED" in codes_plus_30, skew
        assert "ASSERTION_EXPIRED" not in codes_m1 | codes_0 | codes_p1 | codes_plus_30


def test_metadata_expiry_is_strict_regardless_of_skew():
    live = _wide_open(noa=NOW + timedelta(hours=6))
    vu = NOW
    bundle = live + "\n\n" + SP_METADATA.format(vu=_iso(vu))
    for skew in (0, 120):
        with patch("config.SAML_CLOCK_SKEW_SECONDS", skew):
            codes_m1 = _codes(bundle, now=vu - timedelta(seconds=1), skew=skew)
            codes_0 = _codes(bundle, now=vu, skew=skew)
            codes_plus_30 = _codes(bundle, now=vu + timedelta(seconds=30), skew=skew)
        assert "METADATA_EXPIRED" not in codes_m1, skew
        assert "METADATA_EXPIRED" in codes_0, skew
        assert "METADATA_EXPIRED" in codes_plus_30, skew


def test_hours_old_still_expires_with_default_skew():
    xml = _xml(nb=NOW - timedelta(hours=4), noa=NOW - timedelta(hours=3))
    with patch("config.SAML_CLOCK_SKEW_SECONDS", 120):
        codes = _codes(xml, now=NOW, skew=120)
    assert "ASSERTION_EXPIRED" in codes
    assert "BEARER_CONFIRMATION_EXPIRED" in codes


def test_bearer_notbefore_forbidden_regardless_of_skew():
    xml = _wide_open(noa=NOW + timedelta(hours=6)).replace(
        '<saml:SubjectConfirmationData Recipient="https://sp.example/acs" InResponseTo="_req1" NotOnOrAfter=',
        '<saml:SubjectConfirmationData Recipient="https://sp.example/acs" InResponseTo="_req1" '
        'NotBefore="2026-09-10T11:59:00Z" NotOnOrAfter=',
    )
    result = _analyze(xml, now=NOW, skew=120)
    codes = {f["code"] for f in result["findings"]}
    assert "BEARER_NOTBEFORE_FORBIDDEN" in codes
    assert not any("NotBefore" in (c.get("check") or "") and "SubjectConfirmation" in (c.get("check") or "") for c in result["checks"])
    assert not any(
        ASSISTED in (c.get("note") or "") and "NotBefore" in (c.get("check") or "") and "SubjectConfirmation" in (c.get("check") or "")
        for c in result["checks"]
    )


def test_skew_assisted_match_distinct_from_strict_match():
    xml = _wide_open(noa=NOW - timedelta(seconds=30))
    assisted = _analyze(xml, now=NOW, skew=120)
    codes = {f["code"] for f in assisted["findings"]}
    assert "ASSERTION_EXPIRED" not in codes
    assert "BEARER_CONFIRMATION_EXPIRED" not in codes
    for name in ("Assertion Conditions NotOnOrAfter", "SubjectConfirmation #1 NotOnOrAfter"):
        row = _time_row(assisted, name)
        assert row["status"] == "MATCH"
        assert "30s" in row["note"]
        assert "120s" in row["note"]
        assert ASSISTED in row["note"]
    nb_row = _time_row(assisted, "Assertion Conditions NotBefore")
    assert nb_row["status"] == "MATCH"
    assert ASSISTED not in (nb_row.get("note") or "")

    strict_ok = _analyze(_wide_open(noa=NOW + timedelta(hours=6)), now=NOW, skew=120)
    for name in ("Assertion Conditions NotOnOrAfter", "SubjectConfirmation #1 NotOnOrAfter", "Assertion Conditions NotBefore"):
        row = _time_row(strict_ok, name)
        assert row["status"] == "MATCH"
        assert ASSISTED not in (row.get("note") or "")

    too_early = _xml(nb=NOW + timedelta(seconds=30), noa=NOW + timedelta(hours=6))
    early = _analyze(too_early, now=NOW, skew=120)
    assert "ASSERTION_NOT_YET_VALID" not in {f["code"] for f in early["findings"]}
    nb = _time_row(early, "Assertion Conditions NotBefore")
    assert nb["status"] == "MATCH"
    assert "30s" in nb["note"]
    assert ASSISTED in nb["note"]


def test_zero_skew_still_errors_30s_past_notonorafter():
    xml = _wide_open(noa=NOW - timedelta(seconds=30))
    codes = _codes(xml, now=NOW, skew=0)
    assert "ASSERTION_EXPIRED" in codes
    assert "BEARER_CONFIRMATION_EXPIRED" in codes
    result = _analyze(xml, now=NOW, skew=0)
    for name in ("Assertion Conditions NotOnOrAfter", "SubjectConfirmation #1 NotOnOrAfter"):
        row = _time_row(result, name)
        assert row["status"] == "MISMATCH"
        assert ASSISTED not in (row.get("note") or "")


def test_parse_saml_clock_skew_seconds_rejects_invalid():
    assert parse_saml_clock_skew_seconds("0") == 0
    assert parse_saml_clock_skew_seconds("120") == 120
    for raw in ("-1", "-120", "abc", "", "12.5", "1e2"):
        try:
            parse_saml_clock_skew_seconds(raw)
        except ValueError:
            continue
        raise AssertionError(raw)


if __name__ == "__main__":
    test_not_before_helper_minus_zero_plus_one()
    test_not_on_or_after_helper_minus_zero_plus_one()
    test_zero_skew_equals_raw_timestamps()
    test_assertion_not_before_xml_minus_zero_plus_one()
    test_assertion_and_bearer_expiry_xml_minus_zero_plus_one()
    test_instant_on_or_after_ignores_configured_skew()
    test_session_expiry_is_strict_regardless_of_skew()
    test_metadata_expiry_is_strict_regardless_of_skew()
    test_hours_old_still_expires_with_default_skew()
    test_bearer_notbefore_forbidden_regardless_of_skew()
    test_skew_assisted_match_distinct_from_strict_match()
    test_zero_skew_still_errors_30s_past_notonorafter()
    test_parse_saml_clock_skew_seconds_rejects_invalid()
    print("SAML CLOCK SKEW TESTS OK")
