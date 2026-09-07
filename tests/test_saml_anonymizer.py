import base64

from analyzers import anonymize_text

SAML = '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="resp-123" Version="2.0" Destination="https://sp.customer.example/acs" IssueInstant="2026-09-07T12:00:00Z">
  <saml:Issuer>https://idp.customer.example/metadata</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="assert-456" Version="2.0" IssueInstant="2026-09-07T12:00:00Z">
    <saml:Issuer>https://idp.customer.example/metadata</saml:Issuer>
    <ds:Signature>
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha256"/>
        <ds:Reference URI="#assert-456"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>abc</ds:DigestValue></ds:Reference>
      </ds:SignedInfo>
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICCUSTOMERCERTIFICATELEAK</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@customer.example</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.customer.example/acs" InResponseTo="request-999"/></saml:SubjectConfirmation>
    </saml:Subject>
    <saml:AuthnStatement SessionIndex="secret-session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
    <saml:AttributeStatement><saml:Attribute Name="uid"><saml:AttributeValue>alice.internal</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>'''


def decode(value: str) -> str:
    return base64.b64decode(value).decode()


# Raw XML: protocol/standard URIs survive, customer data does not.
raw = anonymize_text(SAML)
out = raw["text"]
assert "http://www.w3.org/2000/09/xmldsig#" in out
assert "http://www.w3.org/2001/10/xml-exc-c14n#" in out
assert "urn:oasis:names:tc:SAML:2.0:cm:bearer" in out
assert "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" in out
assert "customer.example" not in out
assert "alice@customer.example" not in out
assert "alice.internal" not in out
assert "MIICCUSTOMERCERTIFICATELEAK" not in out
assert 'ID="SAML_ID_001"' in out
assert 'ID="SAML_ID_002"' in out
assert 'URI="#SAML_ID_002"' in out
assert 'InResponseTo="SAML_ID_003"' in out
assert 'SessionIndex="SESSION_001"' in out
assert "CERTIFICATE_001" in out
assert "ATTRIBUTE_VALUE_001" in out
assert raw["x509_certificates_redacted"] == 1
assert raw["attribute_values_redacted"] == 1

# Base64 SAML: decode -> XML-aware anonymize -> re-encode.
b64 = base64.b64encode(SAML.encode()).decode()
encoded = anonymize_text(b64)
decoded = decode(encoded["text"])
assert "http://www.w3.org/2000/09/xmldsig#" in decoded
assert "customer.example" not in decoded
assert "MIICCUSTOMERCERTIFICATELEAK" not in decoded
assert 'URI="#SAML_ID_002"' in decoded
assert encoded["encoded_saml_payloads_anonymized"] == 1
assert encoded["encoded_saml_transports"] == ["BASE64"]

# Unrelated Base64 must remain byte-for-byte unchanged.
plain = base64.b64encode(b"this is not a SAML payload and must remain unchanged" * 4).decode()
assert anonymize_text(plain)["text"] == plain

print("SAML ANONYMIZER TESTS OK")
