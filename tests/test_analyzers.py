import base64
import urllib.parse
import zlib

from analyzers.logs import analyze_log_text
from analyzers.saml import analyze_saml_input, looks_like_saml_input
from analyzers.anonymizer import anonymize_text

LOG = '''2026-09-07 10:00:00 INFO service started
2026-09-07 10:01:00 ERROR Request failed HTTP 500
java.lang.RuntimeException: wrapper
    at x.A.a(A.java:1)
Caused by: java.net.ConnectException: Connection refused
    at x.B.b(B.java:2)
2026-09-07 10:02:00 ERROR Database failed ORA-12514
Caused by: java.sql.SQLException: ORA-12514 listener does not currently know of service
2026-09-07 10:03:00 INFO done
'''

REQUEST = '''<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.example/sso" AssertionConsumerServiceURL="https://sp.example/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>https://sp.example/entity</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>'''

RESPONSE = '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" InResponseTo="_req1" Destination="https://sp.example/acs" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.example/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z"><saml:Issuer>https://idp.example/entity</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://sp.example/acs" InResponseTo="_req1" NotOnOrAfter="2099-09-07T08:05:00Z"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2026-09-07T07:59:00Z" NotOnOrAfter="2099-09-07T08:05:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example/entity</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2026-09-07T08:00:00Z" SessionIndex="abc"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="role" FriendlyName="Role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>'''

SP_METADATA = '''<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example/entity"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="false"><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example/acs" index="0" isDefault="true"/></md:SPSSODescriptor></md:EntityDescriptor>'''

IDP_METADATA = '''<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>'''

r = analyze_log_text(LOG, 'server.log')
assert r['time_range']['from'].startswith('2026-09-07T10:00:00')
assert r['time_range']['to'].startswith('2026-09-07T10:03:00')
assert 'ORA-12514' in r['error_codes']
assert r['error_event_count'] == 2

# Raw bundle: request + response + both metadata sides.
s = analyze_saml_input('\n'.join([REQUEST, RESPONSE, SP_METADATA, IDP_METADATA]))
assert s['documents_found'] >= 4
assert s['summary']['sp_metadata_entities'] == 1
assert s['summary']['idp_metadata_entities'] == 1
resp = next(x for x in s['documents'] if x['type'] == 'Response')
ass = resp['assertions'][0]
assert ass['subject']['name_id']['value'] == 'alice@example.com'
assert ass['conditions']['audiences'] == ['https://sp.example/entity']
assert ass['attributes'][0]['values'] == ['admin']
statuses = {x['check']: x['status'] for x in s['checks']}
assert statuses['AuthnRequest ACS vs Response Destination'] == 'MATCH'
assert statuses['SP metadata #1 entityID vs AuthnRequest Issuer'] == 'MATCH'
assert statuses['IdP metadata #1 entityID vs Response Issuer'] == 'MATCH'

# HTTP-POST style whole SAMLResponse Base64.
b64_resp = base64.b64encode(RESPONSE.encode()).decode()
assert looks_like_saml_input(b64_resp)
s2 = analyze_saml_input(b64_resp)
assert s2['summary']['responses'] == 1
assert s2['documents'][0]['type'] == 'Response'
assert 'Base64' in s2['documents'][0]['source']

# Same payload with XML declaration and CRLF, as copied from many IdPs / tracers.
declared = '<?xml version="1.0"?>\r\n' + RESPONSE
b64_declared = base64.b64encode(declared.encode()).decode()
assert looks_like_saml_input(b64_declared)
s2b = analyze_saml_input(b64_declared)
assert s2b['summary']['responses'] == 1

# HTTP-Redirect style URL-encoded Base64 raw-DEFLATE AuthnRequest.
compressor = zlib.compressobj(wbits=-15)
deflated = compressor.compress(REQUEST.encode()) + compressor.flush()
redir = urllib.parse.quote_plus(base64.b64encode(deflated).decode())
s3 = analyze_saml_input('SAMLRequest=' + redir + '&RelayState=abc')
assert s3['summary']['authn_requests'] == 1
assert s3['documents'][0]['acs_url'] == 'https://sp.example/acs'
assert 'DEFLATE' in s3['documents'][0]['source']

# Controlled Audience mismatch.
bad = RESPONSE.replace('https://sp.example/entity</saml:Audience>', 'https://wrong.example/entity</saml:Audience>')
s4 = analyze_saml_input('\n'.join([REQUEST, bad, SP_METADATA]))
assert any(c['status'] == 'MISMATCH' and 'Audience' in c['check'] for c in s4['checks'])

SENSITIVE_LOG = '''2026-09-07 12:00:00 ERROR host=db-gw-prod-007 customer endpoint https://api.customer.example.com:8443/v1/login?token=abc123 failed from 10.20.30.40
user email alice.smith@customer.example.com target=db.customer.internal ip=10.20.30.40
Authorization: Bearer very-secret-token
java.lang.RuntimeException: wrapper
Caused by: java.net.ConnectException: Connection refused
requestId=550e8400-e29b-41d4-a716-446655440000 mac=AA:BB:CC:DD:EE:FF
'''

a = anonymize_text(SENSITIVE_LOG)
assert '10.20.30.40' not in a['text']
assert 'customer.example.com' not in a['text']
assert 'customer.internal' not in a['text']
assert 'alice.smith@customer.example.com' not in a['text']
assert 'very-secret-token' not in a['text']
assert '550e8400-e29b-41d4-a716-446655440000' not in a['text']
assert 'AA:BB:CC:DD:EE:FF' not in a['text']
assert a['text'].count('IP_001') == 2
assert 'java.lang.RuntimeException' in a['text']
assert 'java.net.ConnectException' in a['text']
assert 'ERROR' in a['text'] and '2026-09-07 12:00:00' in a['text']
assert a['counts']['IP'] == 1
assert a['counts']['EMAIL'] == 1
print('ALL TESTS OK')

# Standards/profile validation: required Response fields + NameID semantics.
invalid_response = RESPONSE.replace(' ID="_resp1"', '', 1)
invalid_response = invalid_response.replace('<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>', '')
invalid_response = invalid_response.replace('alice@example.com', '492882615acf31c8096b627245d76ae53036c090')
case_required_fields = analyze_saml_input(invalid_response)
codes = {f['code'] for f in case_required_fields['findings']}
assert 'RESPONSE_ID_MISSING' in codes
assert 'RESPONSE_STATUS_MISSING' in codes
assert 'NAMEID_EMAIL_FORMAT_INVALID' in codes

# Required request ID and ACS index mutual-exclusion rule.
invalid_request = REQUEST.replace(' ID="_req1"', '', 1).replace(' AssertionConsumerServiceURL="https://sp.example/acs"', ' AssertionConsumerServiceURL="https://sp.example/acs" AssertionConsumerServiceIndex="0"')
case_request_fields = analyze_saml_input(invalid_request)
codes = {f['code'] for f in case_request_fields['findings']}
assert 'AUTHNREQUEST_ID_MISSING' in codes
assert 'AUTHNREQUEST_ACS_INDEX_MUTUAL_EXCLUSION' in codes

# Bearer SubjectConfirmationData MUST NOT include NotBefore.
bad_bearer = RESPONSE.replace('Recipient="https://sp.example/acs" InResponseTo="_req1" NotOnOrAfter=', 'Recipient="https://sp.example/acs" InResponseTo="_req1" NotBefore="2026-09-07T07:59:00Z" NotOnOrAfter=')
case_bearer = analyze_saml_input('\n'.join([REQUEST, bad_bearer]))
codes = {f['code'] for f in case_bearer['findings']}
assert 'BEARER_NOTBEFORE_FORBIDDEN' in codes

# Metadata: entityID and ACS are mandatory for an SP SSO role.
invalid_sp_metadata = '''<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>'''
case_metadata = analyze_saml_input(invalid_sp_metadata)
codes = {f['code'] for f in case_metadata['findings']}
assert 'METADATA_ENTITYID_MISSING' in codes
assert 'SP_METADATA_ACS_MISSING' in codes

# Parser-level re-discovery of an Assertion from a raw Response bundle must not
# create a false duplicate-ID security error.
case_duplicate_ids = analyze_saml_input(RESPONSE)
assert 'DUPLICATE_SAML_ID' not in {f['code'] for f in case_duplicate_ids['findings']}

print('VALIDATION TESTS OK')

# Malformed decoded SAML should be reported explicitly instead of looking like "0 documents".
malformed = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r" Version="2.0" IssueInstant="2026-09-07T08:00:00Z"><samlp:Status></samlp:Response>'
case_malformed_xml = analyze_saml_input(base64.b64encode(malformed.encode()).decode())
assert 'XML_NOT_WELL_FORMED' in {f['code'] for f in case_malformed_xml['findings']}

# Critical cross-document SSO mappings must be hard findings, not only visual checks.
bad_cross_response = RESPONSE.replace('Destination="https://sp.example/acs"', 'Destination="https://sp.example/wrong-acs"', 1)
bad_cross_response = bad_cross_response.replace('<saml:Audience>https://sp.example/entity</saml:Audience>', '<saml:Audience>https://wrong.example/entity</saml:Audience>')
bad_cross_response = bad_cross_response.replace('Recipient="https://sp.example/acs"', 'Recipient="https://sp.example/wrong-recipient"')
case_cross_document = analyze_saml_input('\n'.join([REQUEST, bad_cross_response, SP_METADATA, IDP_METADATA]))
codes = {f['code'] for f in case_cross_document['findings']}
assert 'RESPONSE_DESTINATION_REQUEST_ACS_MISMATCH' in codes
assert 'RESPONSE_DESTINATION_SP_ACS_MISMATCH' in codes
assert 'AUDIENCE_SP_ENTITYID_MISMATCH' in codes
assert 'BEARER_RECIPIENT_ACS_MISMATCH' in codes

# ID must not merely exist; it must be valid xs:ID/NCName syntax.
bad_id = RESPONSE.replace('ID="_resp1"', 'ID="123 bad:id"', 1)
case_invalid_id = analyze_saml_input(bad_id)
assert 'RESPONSE_ID_INVALID' in {f['code'] for f in case_invalid_id['findings']}

print('EXTENDED VALIDATION TESTS OK')
