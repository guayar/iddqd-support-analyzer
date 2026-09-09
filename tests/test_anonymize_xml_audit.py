import base64
import urllib.parse
import zipfile
import zlib
from pathlib import Path

from actions import anonymize
from analyzers.anonymizer import anonymize_text


RESPONSE = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
    'Destination="https://sp.customer.example.com/acs" IssueInstant="2026-09-07T08:00:01Z">'
    '<saml:Issuer>https://idp.customer.example.com/entity</saml:Issuer>'
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">'
    '<saml:Issuer>https://idp.customer.example.com/entity</saml:Issuer>'
    '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
    "alice.smith@customer.example.com</saml:NameID></saml:Subject>"
    "</saml:Assertion></samlp:Response>"
)
REQUEST = (
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" '
    'IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.customer.example.com/sso" '
    'AssertionConsumerServiceURL="https://sp.customer.example.com/acs">'
    '<saml:Issuer>https://sp.customer.example.com/entity</saml:Issuer></samlp:AuthnRequest>'
)


def test_base64_keeps_exact_decoded_xml():
    raw_b64 = base64.b64encode(RESPONSE.encode()).decode()
    result = anonymize_text(raw_b64, source_name="trace.txt")
    arts = result["xml_audit_artifacts"]
    assert len(arts) == 1
    item = arts[0]
    assert item["decoded_xml"] == RESPONSE
    assert item["decoded_export_name"] == "trace.response_01.decoded.xml"
    assert item["anonymized_export_name"] == "trace.response_01.anonymized.xml"
    assert "alice.smith@customer.example.com" in item["decoded_xml"]
    assert "alice.smith@customer.example.com" not in item["anonymized_xml"]
    assert "EMAIL_" in item["anonymized_xml"]
    assert "alice.smith@customer.example.com" not in result["text"]


def test_redirect_deflate_audit():
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(REQUEST.encode()) + compressor.flush()
    redirect_b64 = base64.b64encode(deflated).decode()
    pasted = "SAMLRequest=" + urllib.parse.quote_plus(redirect_b64)
    result = anonymize_text(pasted, source_name="pasted-log.txt")
    item = result["xml_audit_artifacts"][0]
    assert item["decoded_xml"] == REQUEST
    assert item["transport"] == "DEFLATE_BASE64"
    assert item["decoded_export_name"].startswith("pasted.authnrequest_01.")
    assert "sp.customer.example.com" in item["decoded_xml"]
    assert "sp.customer.example.com" not in item["anonymized_xml"]


def test_two_payloads_zip_and_names():
    b64_resp = base64.b64encode(RESPONSE.encode()).decode()
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(REQUEST.encode()) + compressor.flush()
    b64_req = urllib.parse.quote_plus(base64.b64encode(deflated).decode())
    text = f"SAMLRequest={b64_req}&SAMLResponse={b64_resp}"
    _summary, _out, _mapping, _full, decoded_path, xml_path = anonymize(None, text)
    assert decoded_path and xml_path
    decoded = Path(decoded_path)
    assert decoded.suffix == ".zip" or decoded.name.endswith(".zip") or "SENSITIVE" in decoded.name or decoded.name.endswith(".xml")
    if decoded.suffix == ".zip" or decoded.name.endswith(".zip"):
        with zipfile.ZipFile(decoded) as zf:
            names = sorted(zf.namelist())
            assert any(n.endswith(".decoded.xml") for n in names)
            assert len(names) == 2
            bodies = [zf.read(n).decode("utf-8") for n in names]
            assert any("alice.smith@customer.example.com" in b for b in bodies)
            assert any("AuthnRequest" in b for b in bodies)
        with zipfile.ZipFile(xml_path) as zf:
            bodies = [zf.read(n).decode("utf-8") for n in zf.namelist()]
            assert all("alice.smith@customer.example.com" not in b for b in bodies)
    else:
        raise AssertionError("two payloads should zip")


def test_raw_xml_paste():
    result = anonymize_text(RESPONSE, source_name="resp.xml")
    item = result["xml_audit_artifacts"][0]
    assert item["decoded_xml"] == RESPONSE
    assert item["transport"] == "raw XML"
    assert item["decoded_export_name"] == "resp.response_01.decoded.xml"


def test_non_saml_base64_has_no_audit():
    unrelated = base64.b64encode(("not-saml-data-" * 20).encode()).decode()
    result = anonymize_text(unrelated)
    assert result["xml_audit_artifacts"] == []
    assert result["text"] == unrelated


if __name__ == "__main__":
    test_base64_keeps_exact_decoded_xml()
    test_redirect_deflate_audit()
    test_two_payloads_zip_and_names()
    test_raw_xml_paste()
    test_non_saml_base64_has_no_audit()
    print("ANONYMIZE XML AUDIT TESTS OK")
