from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, methods

from analyzers import analyze_saml_input
from reporting import render_saml_report


PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

REQUEST = (
    f'<samlp:AuthnRequest xmlns:samlp="{PROTOCOL_NS}" xmlns:saml="{ASSERTION_NS}" '
    'ID="_req1" Version="2.0" IssueInstant="2026-09-07T08:00:00Z" '
    'Destination="https://idp.example/sso" AssertionConsumerServiceURL="https://sp.example/acs" '
    f'ProtocolBinding="{HTTP_POST}">'
    "<saml:Issuer>https://sp.example/entity</saml:Issuer>"
    "</samlp:AuthnRequest>"
)
RESPONSE = (
    f'<samlp:Response xmlns:samlp="{PROTOCOL_NS}" xmlns:saml="{ASSERTION_NS}" '
    'ID="_resp1" Version="2.0" InResponseTo="_req1" Destination="https://sp.example/acs" '
    'IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.example/entity</saml:Issuer>'
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">'
    "<saml:Issuer>https://idp.example/entity</saml:Issuer>"
    "<saml:Subject><saml:NameID>alice@example.com</saml:NameID>"
    f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
    '<saml:SubjectConfirmationData Recipient="https://sp.example/acs" InResponseTo="_req1" '
    'NotOnOrAfter="2099-09-07T08:05:00Z"/></saml:SubjectConfirmation></saml:Subject>'
    '<saml:Conditions NotBefore="2026-09-07T07:59:00Z" NotOnOrAfter="2099-09-07T08:05:00Z">'
    "<saml:AudienceRestriction><saml:Audience>https://sp.example/entity</saml:Audience></saml:AudienceRestriction>"
    "</saml:Conditions></saml:Assertion></samlp:Response>"
)
SIGNED_RESPONSE_TEMPLATE = (
    f'<samlp:Response xmlns:samlp="{PROTOCOL_NS}" xmlns:saml="{ASSERTION_NS}" '
    'ID="_resp-signed" Version="2.0" Destination="https://sp.example/acs" '
    'IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.example/entity</saml:Issuer>'
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    "</samlp:Response>"
)
SP_METADATA = (
    f'<md:EntityDescriptor xmlns:md="{MD_NS}" entityID="https://sp.example/entity">'
    f'<md:SPSSODescriptor protocolSupportEnumeration="{PROTOCOL_NS}" AuthnRequestsSigned="false" WantAssertionsSigned="false">'
    f'<md:AssertionConsumerService Binding="{HTTP_POST}" Location="https://sp.example/acs" index="0" isDefault="true"/>'
    "</md:SPSSODescriptor></md:EntityDescriptor>"
)


def _codes(result: dict) -> set[str]:
    return {f["code"] for f in result["findings"]}


def make_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Test IdP")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def sign_response(key, cert, xml: str = SIGNED_RESPONSE_TEMPLATE):
    root = etree.fromstring(xml.encode())
    signed = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    ).sign(root, key=key, cert=cert.public_bytes(serialization.Encoding.PEM), reference_uri="#_resp-signed")
    return etree.tostring(signed, encoding="unicode")


def _cert_b64(cert) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def idp_metadata(*, entity="https://idp.example/entity", keys=None, sso=None):
    keys = keys or []
    sso = sso or [(HTTP_REDIRECT, "https://idp.example/sso")]
    key_xml = []
    for use, cert in keys:
        use_attr = f' use="{use}"' if use else ""
        key_xml.append(
            f'<md:KeyDescriptor{use_attr}><ds:KeyInfo><ds:X509Data>'
            f"<ds:X509Certificate>{_cert_b64(cert)}</ds:X509Certificate>"
            f"</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        )
    sso_xml = "".join(f'<md:SingleSignOnService Binding="{b}" Location="{loc}"/>' for b, loc in sso)
    return (
        f'<md:EntityDescriptor xmlns:md="{MD_NS}" xmlns:ds="{DS_NS}" entityID="{entity}">'
        f'<md:IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL_NS}">'
        + "".join(key_xml)
        + sso_xml
        + "</md:IDPSSODescriptor></md:EntityDescriptor>"
    )


def sp_metadata(*, entity="https://sp.example/entity", acs=None, want_assertions=False):
    acs = acs or [(HTTP_POST, "https://sp.example/acs", "0", "true")]
    acs_xml = "".join(
        f'<md:AssertionConsumerService Binding="{binding}" Location="{loc}" index="{idx}" isDefault="{default}"/>'
        for binding, loc, idx, default in acs
    )
    want = "true" if want_assertions else "false"
    return (
        f'<md:EntityDescriptor xmlns:md="{MD_NS}" entityID="{entity}">'
        f'<md:SPSSODescriptor protocolSupportEnumeration="{PROTOCOL_NS}" '
        f'AuthnRequestsSigned="false" WantAssertionsSigned="{want}">'
        + acs_xml
        + "</md:SPSSODescriptor></md:EntityDescriptor>"
    )


def test_trace_only_signature_trust_not_evaluated():
    key, cert = make_cert()
    signed = sign_response(key, cert)
    result = analyze_saml_input(signed)
    codes = _codes(result)
    assert "RESPONSE_XML_SIGNATURE_VALID" in codes
    assert "RESPONSE_SIGNER_TRUST_NOT_EVALUATED" in codes
    assert "RESPONSE_SIGNING_KEY_NOT_IN_IDP_METADATA" not in codes
    assert "RESPONSE_XML_SIGNATURE_VALID_EMBEDDED_CERT_ONLY" not in codes
    assert "VALID_EMBEDDED_CERT_UNTRUSTED" not in codes
    resp = next(d for d in result["documents"] if d["type"] == "Response")
    assert resp["signature"]["crypto_verification"] == "XML_SIGNATURE_VALID_WITH_EMBEDDED_CERT"
    ctx = result["validation_context"]
    assert ctx["idp_metadata"]["supplied"] is False
    assert ctx["sp_metadata"]["supplied"] is False
    report = render_saml_report(result)
    assert "not supplied" in report
    assert "untrusted" not in report.lower() or "not evaluated" in report.lower()


def test_matching_idp_metadata_signing_key():
    key, cert = make_cert()
    signed = sign_response(key, cert)
    result = analyze_saml_input(signed, idp_metadata=idp_metadata(keys=[("signing", cert)]))
    codes = _codes(result)
    assert "RESPONSE_SIGNING_KEY_MATCHES_IDP_METADATA" in codes
    assert "RESPONSE_SIGNER_TRUST_NOT_EVALUATED" not in codes
    assert next(d for d in result["documents"] if d["type"] == "Response")["signature"]["crypto_verification"] == "VALID_TRUSTED_METADATA"


def test_nonmatching_idp_metadata_signing_key():
    key, cert = make_cert()
    _other_key, other = make_cert()
    signed = sign_response(key, cert)
    result = analyze_saml_input(signed, idp_metadata=idp_metadata(keys=[("signing", other)]))
    codes = _codes(result)
    assert "RESPONSE_XML_SIGNATURE_VALID" in codes
    assert "RESPONSE_SIGNING_KEY_NOT_IN_IDP_METADATA" in codes
    assert "RESPONSE_XML_SIGNATURE_INVALID" not in codes
    finding = next(f for f in result["findings"] if f["code"] == "RESPONSE_SIGNING_KEY_NOT_IN_IDP_METADATA")
    assert finding["severity"] == "ERROR"
    assert finding["observed"]
    assert finding["expected"]


def test_rollover_second_signing_certificate():
    key, cert = make_cert()
    _old_key, old = make_cert()
    signed = sign_response(key, cert)
    md = idp_metadata(keys=[("signing", old), ("signing", cert)])
    result = analyze_saml_input(signed, idp_metadata=md)
    assert "RESPONSE_SIGNING_KEY_MATCHES_IDP_METADATA" in _codes(result)


def test_keydescriptor_use_signing_and_unspecified():
    key, cert = make_cert()
    signed = sign_response(key, cert)
    signing = analyze_saml_input(signed, idp_metadata=idp_metadata(keys=[("signing", cert)]))
    unspecified = analyze_saml_input(signed, idp_metadata=idp_metadata(keys=[("", cert)]))
    assert "RESPONSE_SIGNING_KEY_MATCHES_IDP_METADATA" in _codes(signing)
    assert "RESPONSE_SIGNING_KEY_MATCHES_IDP_METADATA" in _codes(unspecified)

    _enc_key, enc = make_cert()
    encryption_only = analyze_saml_input(signed, idp_metadata=idp_metadata(keys=[("encryption", enc)]))
    assert "RESPONSE_SIGNING_KEY_NOT_IN_IDP_METADATA" in _codes(encryption_only)


def test_matching_sp_metadata_checks():
    result = analyze_saml_input("\n".join([REQUEST, RESPONSE]), sp_metadata=SP_METADATA)
    codes = _codes(result)
    assert "AUTHNREQUEST_ISSUER_MATCHES_SP_ENTITY_ID" in codes
    assert "AUTHNREQUEST_ACS_MATCHES_SP_METADATA" in codes
    assert "RESPONSE_DESTINATION_MATCHES_SP_ACS" in codes
    assert "ASSERTION_AUDIENCE_MATCHES_SP_ENTITY_ID" in codes
    assert "SUBJECT_RECIPIENT_MATCHES_SP_ACS" in codes
    assert "AUTHNREQUEST_ISSUER_SP_ENTITYID_MISMATCH" not in codes


def test_sp_metadata_mismatch_evidence():
    bad = RESPONSE.replace("https://sp.example/entity</saml:Audience>", "https://wrong.example/entity</saml:Audience>")
    result = analyze_saml_input("\n".join([REQUEST, bad]), sp_metadata=SP_METADATA)
    finding = next(f for f in result["findings"] if f["code"] == "AUDIENCE_SP_ENTITYID_MISMATCH")
    assert finding["severity"] == "ERROR"
    assert "https://wrong.example/entity" in str(finding["observed"])
    assert "https://sp.example/entity" in str(finding["expected"])


def test_both_metadata_cross_party():
    result = analyze_saml_input(
        "\n".join([REQUEST, RESPONSE]),
        idp_metadata=idp_metadata(),
        sp_metadata=SP_METADATA,
    )
    codes = _codes(result)
    assert "AUTHNREQUEST_DESTINATION_MATCHES_IDP_SSO" in codes
    assert "RESPONSE_ISSUER_MATCHES_IDP_ENTITY_ID" in codes
    assert "ASSERTION_ISSUER_MATCHES_IDP_ENTITY_ID" in codes
    assert "AUTHNREQUEST_ISSUER_MATCHES_SP_ENTITY_ID" in codes
    assert "SUBJECT_RECIPIENT_MATCHES_SP_ACS" in codes


def test_neither_metadata_trace_only_unchanged():
    result = analyze_saml_input("\n".join([REQUEST, RESPONSE]))
    codes = _codes(result)
    assert "AUTHNREQUEST_ISSUER_MATCHES_SP_ENTITY_ID" not in codes
    assert "RESPONSE_ISSUER_MATCHES_IDP_ENTITY_ID" not in codes
    assert "AUTHNREQUEST_ISSUER_SP_ENTITYID_MISMATCH" not in codes
    assert any(c["status"] == "MATCH" for c in result["checks"] if "InResponseTo" in c["check"])


def test_entities_descriptor_selects_by_issuer():
    other = idp_metadata(entity="https://other.example/idp")
    matching = idp_metadata()
    bundle = (
        f'<md:EntitiesDescriptor xmlns:md="{MD_NS}">'
        + other.replace(f' xmlns:md="{MD_NS}" xmlns:ds="{DS_NS}"', "")
        + matching.replace(f' xmlns:md="{MD_NS}" xmlns:ds="{DS_NS}"', "")
        + "</md:EntitiesDescriptor>"
    )
    # Rebuild a well-namespaced EntitiesDescriptor.
    bundle = (
        f'<md:EntitiesDescriptor xmlns:md="{MD_NS}" xmlns:ds="{DS_NS}">'
        f'<md:EntityDescriptor entityID="https://other.example/idp">'
        f'<md:IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL_NS}">'
        f'<md:SingleSignOnService Binding="{HTTP_REDIRECT}" Location="https://other.example/sso"/>'
        "</md:IDPSSODescriptor></md:EntityDescriptor>"
        f'<md:EntityDescriptor entityID="https://idp.example/entity">'
        f'<md:IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL_NS}">'
        f'<md:SingleSignOnService Binding="{HTTP_REDIRECT}" Location="https://idp.example/sso"/>'
        "</md:IDPSSODescriptor></md:EntityDescriptor></md:EntitiesDescriptor>"
    )
    result = analyze_saml_input("\n".join([REQUEST, RESPONSE]), idp_metadata=bundle)
    ctx = result["validation_context"]["idp_metadata"]
    assert ctx["selected_entity_id"] == "https://idp.example/entity"
    assert "RESPONSE_ISSUER_MATCHES_IDP_ENTITY_ID" in _codes(result)
    assert "METADATA_ENTITY_AMBIGUOUS" not in _codes(result)


def test_ambiguous_entity_is_not_guessed():
    response = RESPONSE.replace("https://idp.example/entity</saml:Issuer>", "https://idp-a.example/entity</saml:Issuer>", 1)
    # Assertion issuer left as idp.example → two different issuer hints.
    bundle = (
        f'<md:EntitiesDescriptor xmlns:md="{MD_NS}">'
        f'<md:EntityDescriptor entityID="https://idp-a.example/entity">'
        f'<md:IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL_NS}">'
        f'<md:SingleSignOnService Binding="{HTTP_REDIRECT}" Location="https://idp-a.example/sso"/>'
        "</md:IDPSSODescriptor></md:EntityDescriptor>"
        f'<md:EntityDescriptor entityID="https://idp.example/entity">'
        f'<md:IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL_NS}">'
        f'<md:SingleSignOnService Binding="{HTTP_REDIRECT}" Location="https://idp.example/sso"/>'
        "</md:IDPSSODescriptor></md:EntityDescriptor></md:EntitiesDescriptor>"
    )
    result = analyze_saml_input(response, idp_metadata=bundle)
    codes = _codes(result)
    assert "METADATA_ENTITY_AMBIGUOUS" in codes
    assert "RESPONSE_ISSUER_MATCHES_IDP_ENTITY_ID" not in codes
    assert "AUTHNREQUEST_DESTINATION_MATCHES_IDP_SSO" not in codes


def test_multiple_acs_endpoints():
    md = sp_metadata(
        acs=[
            (HTTP_POST, "https://sp.example/acs-old", "0", "false"),
            (HTTP_POST, "https://sp.example/acs", "1", "true"),
        ]
    )
    result = analyze_saml_input("\n".join([REQUEST, RESPONSE]), sp_metadata=md)
    assert "AUTHNREQUEST_ACS_MATCHES_SP_METADATA" in _codes(result)
    assert "RESPONSE_DESTINATION_MATCHES_SP_ACS" in _codes(result)


def test_binding_aware_idp_sso():
    md = idp_metadata(
        sso=[
            (HTTP_REDIRECT, "https://idp.example/sso"),
            (HTTP_POST, "https://idp.example/sso-post"),
        ]
    )
    result = analyze_saml_input("\n".join([REQUEST, RESPONSE]), idp_metadata=md)
    assert "AUTHNREQUEST_DESTINATION_MATCHES_IDP_SSO" in _codes(result)

    wrong_dest = REQUEST.replace("https://idp.example/sso", "https://idp.example/sso-post")
    result_redirect = analyze_saml_input(
        "https://idp.example/sso?SAMLRequest=abc\n" + wrong_dest,
        idp_metadata=md,
    )
    assert result_redirect["transport"]["request_binding"] == HTTP_REDIRECT
    assert "AUTHNREQUEST_DESTINATION_IDP_SSO_MISMATCH" in _codes(result_redirect)


def test_malformed_metadata_does_not_crash_trace():
    result = analyze_saml_input(RESPONSE, idp_metadata="<not-xml")
    codes = _codes(result)
    assert "METADATA_PARSE_FAILED" in codes
    assert result["summary"]["responses"] == 1
    assert "RESPONSE_SIGNING_KEY_NOT_IN_IDP_METADATA" not in codes


def test_wrong_role_slot():
    result = analyze_saml_input("\n".join([REQUEST, RESPONSE]), sp_metadata=idp_metadata())
    codes = _codes(result)
    assert "METADATA_WRONG_ROLE" in codes
    assert "AUTHNREQUEST_ACS_SP_METADATA_MISMATCH" not in codes
    assert "AUTHNREQUEST_ISSUER_SP_ENTITYID_MISMATCH" not in codes


def test_http_401_is_observed_not_inferred():
    key, cert = make_cert()
    signed = sign_response(key, cert)
    export = json.dumps(
        [
            {
                "method": "POST",
                "url": "https://sp.example/acs",
                "saml": signed,
                "status": 401,
                "postData": {"SAMLResponse": base64.b64encode(signed.encode()).decode()},
            }
        ]
    )
    result = analyze_saml_input(export)
    codes = _codes(result)
    assert "HTTP_RESULT_OBSERVED" in codes
    assert "RESPONSE_XML_SIGNATURE_VALID" in codes
    assert "RESPONSE_SIGNER_TRUST_NOT_EVALUATED" in codes
    http = next(f for f in result["findings"] if f["code"] == "HTTP_RESULT_OBSERVED")
    assert 401 in [row["status"] for row in http["observed"]]
    report = render_saml_report(result)
    assert "401" in report
    assert "cannot be determined from this network trace alone" in report
    assert "AUDIENCE_SP_ENTITYID_MISMATCH" not in codes
    assert "RESPONSE_SIGNING_KEY_NOT_IN_IDP_METADATA" not in codes


if __name__ == "__main__":
    test_trace_only_signature_trust_not_evaluated()
    test_matching_idp_metadata_signing_key()
    test_nonmatching_idp_metadata_signing_key()
    test_rollover_second_signing_certificate()
    test_keydescriptor_use_signing_and_unspecified()
    test_matching_sp_metadata_checks()
    test_sp_metadata_mismatch_evidence()
    test_both_metadata_cross_party()
    test_neither_metadata_trace_only_unchanged()
    test_entities_descriptor_selects_by_issuer()
    test_ambiguous_entity_is_not_guessed()
    test_multiple_acs_endpoints()
    test_binding_aware_idp_sso()
    test_malformed_metadata_does_not_crash_trace()
    test_wrong_role_slot()
    test_http_401_is_observed_not_inferred()
    print("SAML METADATA TESTS OK")
