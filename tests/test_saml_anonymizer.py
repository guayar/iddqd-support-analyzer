import base64
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree

from analyzers.anonymizer import anonymize_text


SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
XS_NS = "http://www.w3.org/2001/XMLSchema"


def make_cert_b64() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sensitive Customer Sp. z o.o."),
        x509.NameAttribute(NameOID.COMMON_NAME, "sso.customer-secret.example"),
    ])
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
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


cert_b64 = make_cert_b64()
xml = f'''<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}" xmlns:ds="{DS_NS}" ID="GOSAMLR12901174571794" Version="2.0" IssueInstant="2026-09-07T08:00:01Z" Destination="https://sp.customer-secret.example/acs">
  <saml:Issuer>https://idp.customer-secret.example/saml/metadata/13590</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:xs="{XS_NS}" xmlns:xsi="{XSI_NS}" ID="pfxa46574df-b3b0-a06a-23c8-636413198772" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">
    <saml:Issuer>https://idp.customer-secret.example/saml/metadata/13590</saml:Issuer>
    <ds:Signature>
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha256"/>
        <ds:Reference URI="#pfxa46574df-b3b0-a06a-23c8-636413198772">
          <ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue>YWJjZGVmZw==</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>c2lnbmF0dXJlLXZhbHVl</ds:SignatureValue>
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice.smith@customer-secret.example</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData Recipient="https://sp.customer-secret.example/acs" InResponseTo="REQ-CUSTOMER-123" NotOnOrAfter="2099-09-07T08:05:00Z"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions><saml:AudienceRestriction><saml:Audience>https://sp.customer-secret.example/entity</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-09-07T08:00:00Z" SessionIndex="_531c32d283bdff7e04e487bcdbc4dd8d">
      <saml:SubjectLocality Address="10.20.30.40"/>
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid"><saml:AttributeValue xsi:type="xs:string">mateusz.customer</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="department"><saml:AttributeValue>Finance Warsaw</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <saml:Assertion ID="pfxa46574df-b3b0-a06a-23c8-636413198773" Version="2.0" IssueInstant="2026-09-07T08:00:02Z">
    <saml:Issuer>https://idp.customer-secret.example/saml/metadata/13590</saml:Issuer>
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#pfxa46574df-b3b0-a06a-23c8-636413198772"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>aDI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>czI=</ds:SignatureValue></ds:Signature>
    <saml:Subject><saml:NameID>Bob Customer</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>'''


def decode_result(encoded: str) -> str:
    return base64.b64decode(encoded).decode()


encoded = base64.b64encode(xml.encode()).decode()
result = anonymize_text(encoded)
assert result["encoded_saml_payloads_anonymized"] == 1
assert result["structured_saml_payloads_anonymized"] == 1
anon_xml = decode_result(result["text"])

assert DS_NS in anon_xml
assert XS_NS in anon_xml
assert XSI_NS in anon_xml
assert "http://www.w3.org/2001/10/xml-exc-c14n#" in anon_xml
assert "http://www.w3.org/2000/09/xmldsig#rsa-sha256" in anon_xml
assert "urn:oasis:names:tc:SAML:2.0:status:Success" in anon_xml
assert "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" in anon_xml

for sensitive in (
    "customer-secret.example",
    "alice.smith@customer-secret.example",
    "mateusz.customer",
    "Finance Warsaw",
    "10.20.30.40",
    "GOSAMLR12901174571794",
    "pfxa46574df-b3b0-a06a-23c8-636413198772",
    "pfxa46574df-b3b0-a06a-23c8-636413198773",
    "REQ-CUSTOMER-123",
    "_531c32d283bdff7e04e487bcdbc4dd8d",
    cert_b64,
):
    assert sensitive not in anon_xml

root = etree.fromstring(anon_xml.encode())
ns = {"saml": SAML_NS, "samlp": SAMLP_NS, "ds": DS_NS}
assert root.get("ID").startswith("SAML_ID_")
assert root.get("Destination").startswith("https://DOMAIN_")
assert root.xpath("string(./saml:Issuer)", namespaces=ns).startswith("https://DOMAIN_")
assert root.xpath("string(.//saml:NameID[1])", namespaces=ns).startswith("EMAIL_")
uid_value = root.xpath("string(.//saml:Attribute[@Name='uid']/saml:AttributeValue)", namespaces=ns)
department_value = root.xpath("string(.//saml:Attribute[@Name='department']/saml:AttributeValue)", namespaces=ns)
assert uid_value.startswith(("ATTR_VALUE_", "DOMAIN_"))
assert department_value.startswith("ATTR_VALUE_")
assert root.xpath("string(.//saml:AuthnStatement/@SessionIndex)", namespaces=ns).startswith("SESSION_")
assert root.xpath("string(.//saml:SubjectLocality/@Address)", namespaces=ns).startswith("IP_")

assertions = root.xpath("./saml:Assertion", namespaces=ns)
first_id = assertions[0].get("ID")
second_id = assertions[1].get("ID")
first_ref = assertions[0].xpath("string(./ds:Signature/ds:SignedInfo/ds:Reference/@URI)", namespaces=ns)
second_ref = assertions[1].xpath("string(./ds:Signature/ds:SignedInfo/ds:Reference/@URI)", namespaces=ns)
assert first_ref == "#" + first_id
assert second_ref == "#" + first_id
assert second_ref != "#" + second_id

replacement_cert_b64 = root.xpath("string(.//ds:X509Certificate[1])", namespaces=ns)
replacement_cert = x509.load_der_x509_certificate(base64.b64decode(replacement_cert_b64))
assert "Anonymized Test Data" in replacement_cert.subject.rfc4514_string()
assert "Sensitive Customer" not in replacement_cert.subject.rfc4514_string()

assert base64.b64decode(root.xpath("string(.//ds:DigestValue[1])", namespaces=ns)).decode().startswith("DIGEST_")
assert base64.b64decode(root.xpath("string(.//ds:SignatureValue[1])", namespaces=ns)).decode().startswith("SIGNATURE_")

raw = anonymize_text(xml)
assert raw["structured_saml_payloads_anonymized"] == 1
assert DS_NS in raw["text"]
assert "customer-secret.example" not in raw["text"]
assert "Finance Warsaw" not in raw["text"]

log = "error docs=http://www.w3.org/2001/XMLSchema endpoint=https://private.customer.example/api ip=10.1.2.3"
log_result = anonymize_text(log)["text"]
assert "http://www.w3.org/2001/XMLSchema" in log_result
assert "private.customer.example" not in log_result
assert "10.1.2.3" not in log_result

print("SAML ANONYMIZER TESTS OK")
