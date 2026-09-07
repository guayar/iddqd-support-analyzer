from analyzers import analyze_saml_input
from analyzers.saml_nameid import validate_nameid


def _nameid(fmt, value, **attrs):
    extra = "".join(f' {k}="{v}"' for k, v in attrs.items() if v is not None)
    fmt_attr = f' Format="{fmt}"' if fmt is not None else ""
    return f'<saml:NameID{fmt_attr}{extra}>{value}</saml:NameID>'


def _analyze(nameid_el, request=None, extra=""):
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
        'InResponseTo="_req1" Destination="https://sp.example/acs" IssueInstant="2026-09-07T08:00:01Z">'
        '<saml:Issuer>https://idp.example/entity</saml:Issuer>'
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">'
        '<saml:Issuer>https://idp.example/entity</saml:Issuer>'
        f'<saml:Subject>{nameid_el}'
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        '<saml:SubjectConfirmationData Recipient="https://sp.example/acs" InResponseTo="_req1" NotOnOrAfter="2099-09-07T08:05:00Z"/>'
        '</saml:SubjectConfirmation></saml:Subject>'
        '<saml:Conditions NotBefore="2026-09-07T07:59:00Z" NotOnOrAfter="2099-09-07T08:05:00Z">'
        '<saml:AudienceRestriction><saml:Audience>https://sp.example/entity</saml:Audience></saml:AudienceRestriction>'
        '</saml:Conditions></saml:Assertion></samlp:Response>'
    )
    parts = [p for p in (request, xml, extra) if p]
    return analyze_saml_input("\n".join(parts))


def _codes(result):
    return {f["code"] for f in result["findings"]}


SP_METADATA = (
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example/entity">'
    '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example/acs" index="0"/>'
    "</md:SPSSODescriptor></md:EntityDescriptor>"
)
IDP_METADATA = (
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity">'
    '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>'
    "</md:IDPSSODescriptor></md:EntityDescriptor>"
)
REQ_EMAIL = (
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    'ID="_req1" Version="2.0" IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.example/sso" '
    'AssertionConsumerServiceURL="https://sp.example/acs">'
    '<saml:Issuer>https://sp.example/entity</saml:Issuer>'
    '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>'
    "</samlp:AuthnRequest>"
)
REQ_PERSISTENT = REQ_EMAIL.replace(
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
)

EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
X509 = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
WINDOWS = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
KERBEROS = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

# Unspecified / omitted Format
assert "NAMEID_EMAIL_FORMAT_INVALID" not in _codes(_analyze(_nameid(UNSPECIFIED, "arbitrary-opaque-value")))
assert "NAMEID_EMAIL_FORMAT_INVALID" not in _codes(_analyze(_nameid(None, "arbitrary-opaque-value")))

# Email
assert "NAMEID_EMAIL_FORMAT_INVALID" not in _codes(_analyze(_nameid(EMAIL, "alice@example.com")))
assert "NAMEID_EMAIL_FORMAT_INVALID" not in _codes(_analyze(_nameid(EMAIL, "user.name+tag@example.org")))
assert "NAMEID_EMAIL_FORMAT_INVALID" in _codes(_analyze(_nameid(EMAIL, "492882615acf31c8096b627245d76ae53036c090")))
assert "NAMEID_EMAIL_FORMAT_INVALID" in {
    f["code"] for f in validate_nameid({"format": EMAIL, "value": "John Smith <john@example.com>"}, "Assertion #1")
}
assert "NAMEID_EMAIL_FORMAT_INVALID" in {
    f["code"] for f in validate_nameid({"format": EMAIL, "value": "john@example.com (John)"}, "Assertion #1")
}

# X.509 subject name
assert "NAMEID_X509_SUBJECT_NAME_INVALID" not in _codes(_analyze(_nameid(X509, "CN=Alice Smith,O=Example Corp,C=US")))
assert "NAMEID_X509_SUBJECT_NAME_INVALID" in _codes(_analyze(_nameid(X509, "Alice Smith")))

# Windows DQN: domain is optional
assert "NAMEID_WINDOWS_DQN_INVALID" not in _codes(_analyze(_nameid(WINDOWS, r"CORP\alice")))
assert "NAMEID_WINDOWS_DQN_INVALID" not in _codes(_analyze(_nameid(WINDOWS, "alice")))
assert "NAMEID_WINDOWS_DQN_INVALID" in _codes(_analyze(_nameid(WINDOWS, "CORP\\")))
assert "NAMEID_WINDOWS_DQN_INVALID" in _codes(_analyze(_nameid(WINDOWS, r"\alice")))

# Kerberos principal (structural)
assert "NAMEID_KERBEROS_FORMAT_INVALID" not in _codes(_analyze(_nameid(KERBEROS, "alice@EXAMPLE.COM")))
assert "NAMEID_KERBEROS_FORMAT_INVALID" not in _codes(_analyze(_nameid(KERBEROS, "host/server.example.com@EXAMPLE.COM")))
assert "NAMEID_KERBEROS_FORMAT_INVALID" in _codes(_analyze(_nameid(KERBEROS, "alice")))
assert "NAMEID_KERBEROS_FORMAT_INVALID" in _codes(_analyze(_nameid(KERBEROS, "@EXAMPLE.COM")))
assert "NAMEID_KERBEROS_FORMAT_INVALID" in _codes(_analyze(_nameid(KERBEROS, "alice@")))
assert "NAMEID_KERBEROS_FORMAT_INVALID" in _codes(_analyze(_nameid(KERBEROS, "/server@REALM")))

# Entity
assert "NAMEID_ENTITY_URI_INVALID" not in _codes(_analyze(_nameid(ENTITY, "https://idp.example.com")))
assert "NAMEID_ENTITY_URI_INVALID" not in _codes(_analyze(_nameid(ENTITY, "urn:example:idp")))
long_uri = "https://idp.example.com/" + ("a" * 1024)
assert "NAMEID_ENTITY_TOO_LONG" in _codes(_analyze(_nameid(ENTITY, long_uri)))
assert "NAMEID_ENTITY_NAMEQUALIFIER_FORBIDDEN" in _codes(_analyze(_nameid(ENTITY, "https://idp.example.com", NameQualifier="https://idp.example.com")))
assert "NAMEID_ENTITY_SPNAMEQUALIFIER_FORBIDDEN" in _codes(_analyze(_nameid(ENTITY, "https://idp.example.com", SPNameQualifier="https://sp.example.com")))
assert "NAMEID_ENTITY_SPPROVIDEDID_FORBIDDEN" in _codes(_analyze(_nameid(ENTITY, "https://idp.example.com", SPProvidedID="sid")))

# Persistent
opaque = "_persist-opaque-001"
assert "NAMEID_PERSISTENT_TOO_LONG" not in _codes(_analyze(_nameid(PERSISTENT, opaque)))
assert "NAMEID_PERSISTENT_TOO_LONG" in _codes(_analyze(_nameid(PERSISTENT, "x" * 257)))
assert "NAMEID_PERSISTENT_VALUE_APPEARS_NON_OPAQUE" in _codes(_analyze(_nameid(PERSISTENT, "alice@example.com")))
assert "NAMEID_PERSISTENT_NAMEQUALIFIER_MISMATCH" in _codes(
    _analyze(_nameid(PERSISTENT, opaque, NameQualifier="https://other-idp.example"), extra="\n".join([SP_METADATA, IDP_METADATA]))
)
assert "NAMEID_PERSISTENT_SPNAMEQUALIFIER_MISMATCH" in _codes(
    _analyze(_nameid(PERSISTENT, opaque, SPNameQualifier="https://other-sp.example"), extra="\n".join([SP_METADATA, IDP_METADATA]))
)

# Transient
assert "NAMEID_TRANSIENT_TOO_LONG" not in _codes(_analyze(_nameid(TRANSIENT, "_tmp-abc")))
assert "NAMEID_TRANSIENT_TOO_LONG" in _codes(_analyze(_nameid(TRANSIENT, "x" * 257)))
assert "NAMEID_TRANSIENT_IDENTIFIER_SYNTAX_INVALID" in _codes(_analyze(_nameid(TRANSIENT, "123bad")))

# Custom format is not an automatic ERROR
custom = _codes(_analyze(_nameid("https://example.com/saml/nameid-format/custom", "whatever")))
assert "NAMEID_CUSTOM_FORMAT" in custom
assert "NAMEID_FORMAT_UNSUPPORTED" not in custom
assert "NAMEID_FORMAT_INVALID_URI" in _codes(_analyze(_nameid("not a uri", "whatever")))

# NameIDPolicy vs returned Format
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" not in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=REQ_EMAIL))
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=REQ_PERSISTENT))

print("NAMEID FORMAT TESTS OK")
