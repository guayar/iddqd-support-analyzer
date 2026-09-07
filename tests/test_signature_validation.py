import base64
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, methods

from analyzers import analyze_saml_input


SAML_RESPONSE = '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp-signed" Version="2.0" Destination="https://sp.example/acs" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.example/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>'''


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


def sign_response(key, cert):
    root = etree.fromstring(SAML_RESPONSE.encode())
    signed = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha256",
        digest_algorithm="sha256",
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    ).sign(
        root,
        key=key,
        cert=cert.public_bytes(serialization.Encoding.PEM),
        reference_uri="#_resp-signed",
    )
    return etree.tostring(signed, encoding="unicode")


def metadata_for(cert):
    cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    return f'''<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example/entity"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>'''


key, cert = make_cert()
signed_xml = sign_response(key, cert)
metadata = metadata_for(cert)

# Metadata-backed verification: no private key is supplied to the analyzer.
valid = analyze_saml_input(signed_xml + "\n" + metadata)
codes = {f["code"] for f in valid["findings"]}
assert "RESPONSE_SIGNATURE_REFERENCE_URI_VALID" in codes
assert "RESPONSE_XML_SIGNATURE_VALID" in codes
assert "RESPONSE_SIGNING_CERT_MATCHES_METADATA" in codes
assert "RESPONSE_SIGNATURE_NOT_CRYPTO_VERIFIED" not in codes
response = next(d for d in valid["documents"] if d["type"] == "Response")
assert response["signature"]["crypto_verification"] == "VALID_TRUSTED_METADATA"

# Standalone PEM certificate verification works without metadata.
pem_cert = cert.public_bytes(serialization.Encoding.PEM)
standalone = analyze_saml_input(signed_xml, signing_cert=pem_cert)
standalone_codes = {f["code"] for f in standalone["findings"]}
assert "RESPONSE_XML_SIGNATURE_VALID_SUPPLIED_CERT" in standalone_codes
standalone_response = next(d for d in standalone["documents"] if d["type"] == "Response")
assert standalone_response["signature"]["crypto_verification"] == "VALID_SUPPLIED_CERT"
assert standalone["supplied_signing_certificates"]

# DER .cer/.crt certificate bytes are supported as well.
der_cert = cert.public_bytes(serialization.Encoding.DER)
standalone_der = analyze_saml_input(signed_xml, signing_cert=der_cert)
assert "RESPONSE_XML_SIGNATURE_VALID_SUPPLIED_CERT" in {f["code"] for f in standalone_der["findings"]}

# A PEM certificate dropped into the normal Analyze file bundle is auto-detected.
bundled = analyze_saml_input(signed_xml + "\n" + pem_cert.decode("ascii"))
assert "RESPONSE_XML_SIGNATURE_VALID_SUPPLIED_CERT" in {f["code"] for f in bundled["findings"]}

# Bare public keys are rejected with a useful diagnostic; use an X.509 cert instead.
public_key_pem = key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
bare_key = analyze_saml_input(signed_xml, signing_cert=public_key_pem)
assert "SUPPLIED_SIGNING_CERTIFICATE_INVALID" in {f["code"] for f in bare_key["findings"]}

# SAML Core §5.4.2 requires URI="#<root-ID>", not a full URL.
bad_reference = signed_xml.replace(
    'URI="#_resp-signed"',
    'URI="https://idp.example/_resp-signed"',
    1,
)
ref_result = analyze_saml_input(bad_reference + "\n" + metadata)
ref_codes = {f["code"] for f in ref_result["findings"]}
assert "RESPONSE_SIGNATURE_REFERENCE_URI_INVALID" in ref_codes

# A post-signing content modification must fail cryptographic verification.
tampered = signed_xml.replace(
    'Destination="https://sp.example/acs"',
    'Destination="https://sp.example/tampered"',
    1,
)
tampered_result = analyze_saml_input(tampered + "\n" + metadata)
tampered_codes = {f["code"] for f in tampered_result["findings"]}
assert "RESPONSE_XML_SIGNATURE_INVALID" in tampered_codes

print("SIGNATURE VALIDATION TESTS OK")
