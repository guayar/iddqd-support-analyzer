import base64
import tempfile
import urllib.parse
import zlib
from pathlib import Path

from lxml import etree

from analyzers.saml import analyze_saml_input
from analyzers.saml_signature import _parse_lxml_documents
from analyzers.xml_safe import decompress_limited, lxml_fromstring


REQUEST = '''<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.example/sso" AssertionConsumerServiceURL="https://sp.example/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://sp.example/entity</saml:Issuer></samlp:AuthnRequest>'''


def test_decompress_rejects_oversize_output():
    payload = b"A" * 8000
    compressed = zlib.compress(payload)
    try:
        decompress_limited(compressed, zlib.MAX_WBITS, max_length=1024)
    except ValueError as exc:
        assert "size limit" in str(exc)
    else:
        raise AssertionError("oversize inflate must be rejected")


def test_decompress_accepts_small_raw_deflate():
    compressor = zlib.compressobj(wbits=-15)
    raw = compressor.compress(REQUEST.encode()) + compressor.flush()
    out = decompress_limited(raw, -15, max_length=64 * 1024)
    assert out.decode("utf-8") == REQUEST


def test_redirect_deflate_still_decodes():
    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(REQUEST.encode()) + compressor.flush()
    redir = urllib.parse.quote_plus(base64.b64encode(deflated).decode())
    result = analyze_saml_input("SAMLRequest=" + redir)
    assert result["summary"]["authn_requests"] == 1


def test_lxml_does_not_expand_internal_entities():
    xml = """<!DOCTYPE Response [
      <!ENTITY xxe "PWNED_ENTITY">
    ]>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_xxe" Version="2.0" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>&xxe;</saml:Issuer></samlp:Response>"""
    objects, _meta = _parse_lxml_documents(xml)
    blob = "".join(etree.tostring(root, encoding="unicode") for root in objects.values())
    assert "PWNED_ENTITY" not in blob


def test_lxml_does_not_read_external_entity_file():
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "secret.txt"
        path.write_text("SECRET_FILE_CONTENT", encoding="utf-8")
        xml = f"""<!DOCTYPE Response [
          <!ENTITY xxe SYSTEM "{path.as_uri()}">
        ]>
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_xxe" Version="2.0" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>&xxe;</saml:Issuer></samlp:Response>"""
        objects, _meta = _parse_lxml_documents(xml)
        blob = "".join(etree.tostring(root, encoding="unicode") for root in objects.values())
        assert "SECRET_FILE_CONTENT" not in blob
        try:
            root = lxml_fromstring(xml)
        except Exception:
            return
        assert "SECRET_FILE_CONTENT" not in etree.tostring(root, encoding="unicode")


if __name__ == "__main__":
    test_decompress_rejects_oversize_output()
    test_decompress_accepts_small_raw_deflate()
    test_redirect_deflate_still_decodes()
    test_lxml_does_not_expand_internal_entities()
    test_lxml_does_not_read_external_entity_file()
    print("INPUT HARDENING TESTS OK")
