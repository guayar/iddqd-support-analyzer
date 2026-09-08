from __future__ import annotations

import base64
import tempfile
import urllib.parse
import zipfile
import zlib
from pathlib import Path

from actions import analyze, decoded_artifacts_from_result, write_decoded_artifact_download
from analyzers.saml import collect_decoded_artifacts

REQUEST = (
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" '
    'IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.example/sso" '
    'AssertionConsumerServiceURL="https://sp.example/acs" '
    'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
    '<saml:Issuer>https://sp.example/entity</saml:Issuer></samlp:AuthnRequest>'
)
RESPONSE = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
    'InResponseTo="_req1" Destination="https://sp.example/acs" '
    'IssueInstant="2026-09-07T08:00:01Z">'
    '<saml:Issuer>https://idp.example/entity</saml:Issuer>'
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">'
    '<saml:Issuer>https://idp.example/entity</saml:Issuer>'
    '<saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>'
    '</saml:Assertion></samlp:Response>'
)
RESPONSE_2 = RESPONSE.replace("_resp1", "_resp2").replace("_a1", "_a2")


def _file(name: str, content: str) -> str:
    path = Path(tempfile.mkdtemp()) / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_plain_xml_is_not_a_decoded_export():
    assert collect_decoded_artifacts(REQUEST, "authn.xml") == []
    assert collect_decoded_artifacts(RESPONSE, "resp.xml") == []


def test_whole_file_base64_response_keeps_raw_xml():
    payload = '<?xml version="1.0"?>\r\n' + RESPONSE
    b64 = base64.b64encode(payload.encode()).decode()
    items = collect_decoded_artifacts(b64, "trace.txt")
    assert len(items) == 1
    assert items[0]["document_type"] == "Response"
    assert items[0]["xml"] == payload
    assert "Base64" in items[0]["encoding"]
    md, _raw, result = analyze(None, b64, "SAML")
    arts = result["decoded_artifacts"]
    assert arts[0]["export_name"] == "pasted.response_01.xml"
    assert arts[0]["xml"] == payload
    assert "## Decoded artifacts" in md
    path = Path(write_decoded_artifact_download(result))
    assert path.name == "pasted.response_01.xml"
    assert path.read_bytes() == payload.encode("utf-8")


def test_tracer_field_and_redirect_request():
    b64 = base64.b64encode(RESPONSE.encode()).decode()
    tracer = f"SAMLResponse={b64}\n"
    items = collect_decoded_artifacts(tracer, "trace.txt")
    assert len(items) == 1
    assert items[0]["xml"] == RESPONSE

    compressor = zlib.compressobj(wbits=-15)
    deflated = compressor.compress(REQUEST.encode()) + compressor.flush()
    redir = urllib.parse.quote_plus(base64.b64encode(deflated).decode())
    req_items = collect_decoded_artifacts(f"SAMLRequest={redir}&RelayState=abc", "trace.txt")
    assert len(req_items) == 1
    assert req_items[0]["document_type"] == "AuthnRequest"
    assert "DEFLATE" in req_items[0]["encoding"]
    assert req_items[0]["xml"] == REQUEST


def test_two_responses_in_one_tracer_stay_separate():
    t = (
        f"SAMLResponse={base64.b64encode(RESPONSE.encode()).decode()}\n"
        f"SAMLResponse={base64.b64encode(RESPONSE_2.encode()).decode()}\n"
    )
    path = _file("trace.txt", t)
    _md, _raw, result = analyze([path], "", "SAML")
    arts = result["decoded_artifacts"]
    assert [a["export_name"] for a in arts] == ["trace.response_01.xml", "trace.response_02.xml"]
    assert {a["xml"] for a in arts} == {RESPONSE, RESPONSE_2}
    assert all(a["source_name"] == "trace.txt" for a in arts)
    zpath = Path(write_decoded_artifact_download(result))
    assert zpath.suffix == ".zip"
    with zipfile.ZipFile(zpath) as zf:
        names = set(zf.namelist())
        assert names == {"trace.response_01.xml", "trace.response_02.xml"}
        bodies = {zf.read(n).decode("utf-8") for n in names}
        assert bodies == {RESPONSE, RESPONSE_2}


def test_duplicate_payload_exported_once():
    b64 = base64.b64encode(RESPONSE.encode()).decode()
    items = collect_decoded_artifacts(f"SAMLResponse={b64}\nSAMLResponse={b64}\n", "trace.txt")
    assert len(items) == 1


def test_bad_base64_and_non_saml_xml_are_not_exported():
    assert collect_decoded_artifacts("SAMLResponse=!!!not-base64!!!", "t.txt") == []
    other = base64.b64encode(b"<note>hello</note>").decode()
    assert collect_decoded_artifacts(other, "t.txt") == []


def test_nested_assertion_in_plain_response_is_not_exported():
    assert collect_decoded_artifacts(RESPONSE, "resp.xml") == []


def test_mixed_log_and_encoded_saml_lineage():
    log = "2026-09-07 10:00:00 ERROR boom HTTP 500\n"
    b64 = base64.b64encode(RESPONSE.encode()).decode()
    _md, _raw, result = analyze(
        [_file("error.log", log), _file("trace.txt", f"SAMLResponse={b64}\n")],
        "",
        "Auto-detect",
    )
    assert result["kind"] == "mixed"
    arts = decoded_artifacts_from_result(result)
    assert len(arts) == 1
    assert arts[0]["source_name"] == "trace.txt"
    assert arts[0]["export_name"] == "trace.response_01.xml"


def test_log_only_has_no_download():
    md, _raw, result = analyze(None, "2026-09-07 10:00:00 ERROR boom HTTP 500\n", "Auto-detect")
    assert result["kind"] == "log"
    assert write_decoded_artifact_download(result) is None
    assert "Decoded artifacts" not in md


if __name__ == "__main__":
    test_plain_xml_is_not_a_decoded_export()
    test_whole_file_base64_response_keeps_raw_xml()
    test_tracer_field_and_redirect_request()
    test_two_responses_in_one_tracer_stay_separate()
    test_duplicate_payload_exported_once()
    test_bad_base64_and_non_saml_xml_are_not_exported()
    test_nested_assertion_in_plain_response_is_not_exported()
    test_mixed_log_and_encoded_saml_lineage()
    test_log_only_has_no_download()
    print("DECODED SAML EXPORT TESTS OK")
