import base64
import urllib.parse
import zlib

from analyzers.anonymizer import anonymize_text


RESPONSE = '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" Destination="https://sp.customer.example.com/acs" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.customer.example.com/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.customer.example.com/entity</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice.smith@customer.example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.customer.example.com/acs" NotOnOrAfter="2099-09-07T08:05:00Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="2099-09-07T08:05:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.customer.example.com/entity</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>'''

REQUEST = '''<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.customer.example.com/sso" AssertionConsumerServiceURL="https://sp.customer.example.com/acs"><saml:Issuer>https://sp.customer.example.com/entity</saml:Issuer></samlp:AuthnRequest>'''


def decode_plain_b64(value: str) -> str:
    return base64.b64decode(value).decode("utf-8")


# Standalone HTTP-POST-style Base64 SAMLResponse.
raw_b64 = base64.b64encode(RESPONSE.encode()).decode()
case = anonymize_text(raw_b64)
assert case["encoded_saml_payloads_anonymized"] == 1
assert "BASE64" in case["encoded_saml_transports"]
decoded = decode_plain_b64(case["text"])
assert "alice.smith@customer.example.com" not in decoded
assert "sp.customer.example.com" not in decoded
assert "idp.customer.example.com" not in decoded
assert "EMAIL_001" in decoded
assert "DOMAIN_" in decoded
assert "Response" in decoded and "Assertion" in decoded

# Named URL/form parameter: preserve URL-encoded transport after anonymization.
url_encoded = urllib.parse.quote_plus(raw_b64)
case_param = anonymize_text("SAMLResponse=" + url_encoded + "&RelayState=abc")
assert case_param["encoded_saml_payloads_anonymized"] == 1
new_value = case_param["text"].split("SAMLResponse=", 1)[1].split("&", 1)[0]
new_b64 = urllib.parse.unquote_plus(new_value)
decoded_param = decode_plain_b64(new_b64)
assert "alice.smith@customer.example.com" not in decoded_param
assert "EMAIL_001" in decoded_param

# HTTP-Redirect-style raw-DEFLATE + Base64 SAMLRequest.
compressor = zlib.compressobj(wbits=-15)
deflated = compressor.compress(REQUEST.encode()) + compressor.flush()
redirect_b64 = base64.b64encode(deflated).decode()
redirect_value = urllib.parse.quote_plus(redirect_b64)
case_redirect = anonymize_text("SAMLRequest=" + redirect_value + "&RelayState=xyz")
assert case_redirect["encoded_saml_payloads_anonymized"] == 1
assert "DEFLATE_BASE64" in case_redirect["encoded_saml_transports"]
new_redirect_value = case_redirect["text"].split("SAMLRequest=", 1)[1].split("&", 1)[0]
new_redirect_b64 = urllib.parse.unquote_plus(new_redirect_value)
new_deflated = base64.b64decode(new_redirect_b64)
decoded_request = zlib.decompress(new_deflated, -15).decode("utf-8")
assert "sp.customer.example.com" not in decoded_request
assert "idp.customer.example.com" not in decoded_request
assert "DOMAIN_" in decoded_request
assert "AuthnRequest" in decoded_request

# Unrelated Base64 must stay untouched.
unrelated = base64.b64encode(("not-saml-data-" * 20).encode()).decode()
case_unrelated = anonymize_text(unrelated)
assert case_unrelated["text"] == unrelated
assert case_unrelated["encoded_saml_payloads_anonymized"] == 0

print("ENCODED SAML ANONYMIZER TESTS OK")
