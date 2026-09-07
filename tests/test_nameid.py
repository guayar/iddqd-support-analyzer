from analyzers import analyze_saml_input
from analyzers.saml_nameid import validate_nameid


ENCRYPTED = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"
EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
X509 = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
WINDOWS = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
KERBEROS = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

BEARER = """<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData Recipient="https://sp.example/acs" InResponseTo="_req1" NotOnOrAfter="2099-09-07T08:05:00Z"/>
</saml:SubjectConfirmation>"""

CONDITIONS = """<saml:Conditions NotBefore="2026-09-07T07:59:00Z" NotOnOrAfter="2099-09-07T08:05:00Z">
<saml:AudienceRestriction><saml:Audience>https://sp.example/entity</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>"""

ENCRYPTED_ID = """<saml:EncryptedID>
<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
<xenc:CipherData><xenc:CipherValue>Zg==</xenc:CipherValue></xenc:CipherData>
</xenc:EncryptedData>
</saml:EncryptedID>"""


def _nameid(fmt, value, **attrs):
    extra = "".join(f' {k}="{v}"' for k, v in attrs.items() if v is not None)
    fmt_attr = f' Format="{fmt}"' if fmt is not None else ""
    return f"<saml:NameID{fmt_attr}{extra}>{value}</saml:NameID>"


def _response(subject_inner, assertion_extra="", issuer="https://idp.example/entity", assertion_id="_a1", in_response_to="_req1"):
    return (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
        f'InResponseTo="{in_response_to}" Destination="https://sp.example/acs" IssueInstant="2026-09-07T08:00:01Z">'
        f"<saml:Issuer>{issuer}</saml:Issuer>"
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'<saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">'
        f"<saml:Issuer>{issuer}</saml:Issuer>"
        f"<saml:Subject>{subject_inner}{BEARER}</saml:Subject>"
        f"{CONDITIONS}{assertion_extra}</saml:Assertion></samlp:Response>"
    )


def _analyze(nameid_el, request=None, extra=""):
    parts = [p for p in (request, _response(nameid_el), extra) if p]
    return analyze_saml_input("\n".join(parts))


def _analyze_subject(subject_inner, request=None, extra="", in_response_to="_req1"):
    parts = [p for p in (request, _response(subject_inner, in_response_to=in_response_to), extra) if p]
    return analyze_saml_input("\n".join(parts))


def _codes(result):
    return {f["code"] for f in result["findings"]}


def _sev(result, code):
    return {f["severity"] for f in result["findings"] if f["code"] == code}


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
OTHER_IDP_METADATA = IDP_METADATA.replace("https://idp.example/entity", "https://other-idp.example/entity").replace(
    "https://idp.example/sso", "https://other-idp.example/sso"
)
OTHER_SP_METADATA = SP_METADATA.replace("https://sp.example/entity", "https://other-sp.example/entity").replace(
    "https://sp.example/acs", "https://other-sp.example/acs"
)


def _req(req_id, fmt=None, extra_policy=""):
    fmt_attr = f' Format="{fmt}"' if fmt is not None else ""
    return (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{req_id}" Version="2.0" IssueInstant="2026-09-07T08:00:00Z" Destination="https://idp.example/sso" '
        'AssertionConsumerServiceURL="https://sp.example/acs">'
        "<saml:Issuer>https://sp.example/entity</saml:Issuer>"
        f"<samlp:NameIDPolicy{fmt_attr}{extra_policy}/>"
        "</samlp:AuthnRequest>"
    )


REQ_EMAIL = _req("_req1", EMAIL)
REQ_PERSISTENT = _req("_req1", PERSISTENT)

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
assert "ERROR" not in _sev(
    _analyze(_nameid(PERSISTENT, opaque, NameQualifier="https://other-idp.example"), extra="\n".join([SP_METADATA, IDP_METADATA])),
    "NAMEID_PERSISTENT_NAMEQUALIFIER_MISMATCH",
)
assert "NAMEID_PERSISTENT_NAMEQUALIFIER_MISMATCH" not in _codes(
    _analyze(_nameid(PERSISTENT, opaque, NameQualifier="https://other-idp.example"), extra="\n".join([SP_METADATA, IDP_METADATA]))
)
assert "NAMEID_PERSISTENT_NAMEQUALIFIER_NOT_CHECKED" in _codes(
    _analyze(_nameid(PERSISTENT, opaque, NameQualifier="https://other-idp.example"), extra="\n".join([SP_METADATA, IDP_METADATA]))
)
assert "NAMEID_PERSISTENT_SPNAMEQUALIFIER_MISMATCH" not in _codes(
    _analyze(_nameid(PERSISTENT, opaque, SPNameQualifier="https://other-sp.example"), extra="\n".join([SP_METADATA, IDP_METADATA]))
)
assert "NAMEID_PERSISTENT_SPNAMEQUALIFIER_NOT_CHECKED" in _codes(
    _analyze(_nameid(PERSISTENT, opaque, SPNameQualifier="https://other-sp.example"), extra="\n".join([SP_METADATA, IDP_METADATA]))
)

# Transient
assert "NAMEID_TRANSIENT_TOO_LONG" not in _codes(_analyze(_nameid(TRANSIENT, "_tmp-abc")))
assert "NAMEID_TRANSIENT_TOO_LONG" in _codes(_analyze(_nameid(TRANSIENT, "x" * 257)))
assert "NAMEID_TRANSIENT_IDENTIFIER_SYNTAX_INVALID" in _codes(_analyze(_nameid(TRANSIENT, "123bad")))
assert _sev(_analyze(_nameid(TRANSIENT, "123bad")), "NAMEID_TRANSIENT_IDENTIFIER_SYNTAX_INVALID") == {"WARNING"}

# Custom format is not an automatic ERROR
custom = _codes(_analyze(_nameid("https://example.com/saml/nameid-format/custom", "whatever")))
assert "NAMEID_CUSTOM_FORMAT" in custom
assert "NAMEID_FORMAT_UNSUPPORTED" not in custom
assert "NAMEID_FORMAT_INVALID_URI" in _codes(_analyze(_nameid("not a uri", "whatever")))
assert "NAMEID_EMAIL_FORMAT_INVALID" not in _codes(_analyze(_nameid("not a uri", "alice@example.com")))

# NameIDPolicy vs returned Format
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" not in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=REQ_EMAIL))
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=REQ_PERSISTENT))

# --- 1. plaintext NameID with encrypted Format (Errata E6/E15) ---
enc_plain = _codes(_analyze(_nameid(ENCRYPTED, "alice")))
assert "NAMEID_ENCRYPTED_FORMAT_PLAINTEXT" in enc_plain
assert _sev(_analyze(_nameid(ENCRYPTED, "alice")), "NAMEID_ENCRYPTED_FORMAT_PLAINTEXT") == {"ERROR"}
enc_only = _codes(_analyze_subject(ENCRYPTED_ID))
assert "NAMEID_ENCRYPTED_FORMAT_PLAINTEXT" not in enc_only
assert "NAMEID_EMPTY" not in enc_only
req_enc = _req("_req1", ENCRYPTED)
assert "NAMEIDPOLICY_ENCRYPTED_NOT_SATISFIED" not in _codes(_analyze_subject(ENCRYPTED_ID, request=req_enc))
assert "NAMEIDPOLICY_ENCRYPTED_NOT_SATISFIED" in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=req_enc))

# --- 2. Format omitted vs empty vs whitespace vs unspecified URI ---
assert "NAMEID_FORMAT_INVALID_URI" not in _codes(_analyze(_nameid(None, "alice")))
assert "NAMEID_FORMAT_INVALID_URI" in _codes(_analyze(_nameid("", "alice")))
assert "NAMEID_FORMAT_INVALID_URI" in _codes(_analyze(_nameid("   ", "alice")))
assert "NAMEID_FORMAT_INVALID_URI" not in _codes(_analyze(_nameid(UNSPECIFIED, "alice")))
assert "NAMEID_EMAIL_FORMAT_INVALID" not in _codes(_analyze(_nameid("", "alice@example.com")))

# --- 3. empty / whitespace NameID values ---
empty_el = _codes(_analyze("<saml:NameID></saml:NameID>"))
empty_sc = _codes(_analyze("<saml:NameID/>"))
ws_only = _codes(_analyze("<saml:NameID>   </saml:NameID>"))
tabs = _codes(_analyze("<saml:NameID>\t\n</saml:NameID>"))
for codes in (empty_el, empty_sc, ws_only, tabs):
    assert "NAMEID_EMPTY" in codes
assert "NAMEID_EMPTY" not in _codes(_analyze_subject(ENCRYPTED_ID))

# --- 4. custom Format URI ---
assert "NAMEID_FORMAT_INVALID_URI" not in _codes(_analyze(_nameid("https://idp.example/formats/custom", "x")))
assert "NAMEID_CUSTOM_FORMAT" in _codes(_analyze(_nameid("https://idp.example/formats/custom", "x")))
assert "NAMEID_FORMAT_INVALID_URI" not in _codes(_analyze(_nameid("urn:example:nameid:custom", "x")))
assert "NAMEID_FORMAT_INVALID_URI" in _codes(_analyze(_nameid("http://example.com/fmt with space", "x")))
assert "NAMEID_FORMAT_INVALID_URI" in _codes(_analyze(_nameid("/relative/format", "x")))

# --- 5. email addr-spec edge cases ---
assert "NAMEID_EMAIL_FORMAT_INVALID" not in _codes(_analyze(_nameid(EMAIL, "alice@[192.0.2.1]")))
quoted = _codes(_analyze(_nameid(EMAIL, '"quoted local"@example.com')))
assert "NAMEID_EMAIL_FORMAT_INVALID" not in quoted
assert "NAMEID_EMAIL_FORMAT_NOT_FULLY_CHECKED" in quoted
assert _sev(_analyze(_nameid(EMAIL, '"quoted local"@example.com')), "NAMEID_EMAIL_FORMAT_NOT_FULLY_CHECKED") == {"WARNING"}
assert "NAMEID_EMAIL_FORMAT_INVALID" in {
    f["code"] for f in validate_nameid({"format": EMAIL, "value": "<alice@example.com>"}, "Assertion #1")
}
assert "NAMEID_EMAIL_FORMAT_INVALID" in _codes(_analyze(_nameid(EMAIL, "alice@")))
assert "NAMEID_EMAIL_FORMAT_INVALID" in _codes(_analyze(_nameid(EMAIL, "@example.com")))
assert "NAMEID_EMAIL_FORMAT_INVALID" in _codes(_analyze(_nameid(EMAIL, "alice@@example.com")))
assert "NAMEID_EMAIL_FORMAT_INVALID" not in _codes(_analyze(_nameid(EMAIL, "alizé@example.com")))

# --- 6. X509 ---
assert "NAMEID_X509_SUBJECT_NAME_INVALID" not in _codes(_analyze(_nameid(X509, r"CN=Smith\, John,O=Example")))
assert "NAMEID_X509_SUBJECT_NAME_INVALID" in _codes(_analyze(_nameid(X509, "not-a-dn")))
assert "NAMEID_X509_SUBJECT_NAME_UNVERIFIED" in _codes(_analyze(_nameid(X509, "CN=Alice,")))
assert _sev(_analyze(_nameid(X509, "CN=Alice,")), "NAMEID_X509_SUBJECT_NAME_UNVERIFIED") == {"WARNING"}

# --- 7-8. Windows spaces and separators ---
assert "NAMEID_WINDOWS_DQN_INVALID" not in _codes(_analyze(_nameid(WINDOWS, r"CORP\John Smith")))
assert "NAMEID_WINDOWS_DQN_INVALID" not in _codes(_analyze(_nameid(WINDOWS, "John Smith")))
assert "NAMEID_WINDOWS_DQN_INVALID" in _codes(_analyze(_nameid(WINDOWS, r"CORP\\alice")))
assert "NAMEID_EMPTY" in _codes(_analyze("<saml:NameID Format=\"" + WINDOWS + "\"></saml:NameID>"))

# --- 9. Kerberos extra instance ---
assert "NAMEID_KERBEROS_FORMAT_INVALID" not in _codes(
    _analyze(_nameid(KERBEROS, "service/instance/subinstance@EXAMPLE.COM"))
)
assert "NAMEID_KERBEROS_FORMAT_INVALID" in _codes(_analyze(_nameid(KERBEROS, "alice@bob@EXAMPLE.COM")))
assert "NAMEID_KERBEROS_FORMAT_INVALID" in _codes(_analyze(_nameid(KERBEROS, "alice @EXAMPLE.COM")))

# --- 10-11. entity URI bounds and empty forbidden attrs ---
assert "NAMEID_ENTITY_TOO_LONG" not in _codes(_analyze(_nameid(ENTITY, "https://idp.example.com/" + ("a" * (1024 - len("https://idp.example.com/"))))))
assert "NAMEID_ENTITY_NAMEQUALIFIER_FORBIDDEN" in _codes(_analyze(_nameid(ENTITY, "https://idp.example.com", NameQualifier="")))
assert "NAMEID_ENTITY_SPNAMEQUALIFIER_FORBIDDEN" in _codes(_analyze(_nameid(ENTITY, "https://idp.example.com", SPNameQualifier="")))
assert "NAMEID_ENTITY_SPPROVIDEDID_FORBIDDEN" in _codes(_analyze(_nameid(ENTITY, "https://idp.example.com", SPProvidedID="")))
assert "NAMEID_ENTITY_URI_INVALID" in _codes(_analyze(_nameid(ENTITY, "not a uri")))
ldap_uri = _codes(_analyze(_nameid(ENTITY, "ldap://ldap.example.com/dc=example")))
assert "NAMEID_ENTITY_URI_INVALID" not in ldap_uri

# --- 12. persistent length 255/256/257 ---
assert "NAMEID_PERSISTENT_TOO_LONG" not in _codes(_analyze(_nameid(PERSISTENT, "x" * 255)))
assert "NAMEID_PERSISTENT_TOO_LONG" not in _codes(_analyze(_nameid(PERSISTENT, "x" * 256)))
assert "NAMEID_PERSISTENT_TOO_LONG" in _codes(_analyze(_nameid(PERSISTENT, "x" * 257)))

# --- 13. opacity heuristic stays WARNING ---
assert _sev(_analyze(_nameid(PERSISTENT, "alice")), "NAMEID_PERSISTENT_VALUE_APPEARS_NON_OPAQUE") == {"WARNING"}
assert _sev(_analyze(_nameid(PERSISTENT, "employee123")), "NAMEID_PERSISTENT_VALUE_APPEARS_NON_OPAQUE") == {"WARNING"}
assert _sev(_analyze(_nameid(PERSISTENT, "Alice Smith")), "NAMEID_PERSISTENT_VALUE_APPEARS_NON_OPAQUE") == {"WARNING"}
uuid = "550e8400-e29b-41d4-a716-446655440000"
assert "NAMEID_PERSISTENT_VALUE_APPEARS_NON_OPAQUE" not in _codes(_analyze(_nameid(PERSISTENT, uuid)))
assert "NAMEID_PERSISTENT_VALUE_APPEARS_NON_OPAQUE" not in _codes(
    _analyze(_nameid(PERSISTENT, "deadbeefdeadbeefdeadbeefdeadbeef"))
)

# --- 14. re-issuance: NameQualifier != current issuer is not ERROR ---
reissue = _analyze(_nameid(PERSISTENT, opaque, NameQualifier="https://original-idp.example"))
assert "NAMEID_PERSISTENT_NAMEQUALIFIER_NOT_CHECKED" in _codes(reissue)
assert "INFO" in _sev(reissue, "NAMEID_PERSISTENT_NAMEQUALIFIER_NOT_CHECKED")
same_issuer = _analyze(_nameid(PERSISTENT, opaque, NameQualifier="https://idp.example/entity"))
assert "NAMEID_PERSISTENT_NAMEQUALIFIER_NOT_CHECKED" not in _codes(same_issuer)

# --- 15. affiliation SPNameQualifier ---
aff = _analyze(_nameid(PERSISTENT, opaque, SPNameQualifier="https://aff.example/affiliation"), extra=SP_METADATA)
assert "NAMEID_PERSISTENT_SPNAMEQUALIFIER_NOT_CHECKED" in _codes(aff)
exact_sp = _analyze(_nameid(PERSISTENT, opaque, SPNameQualifier="https://sp.example/entity"), extra=SP_METADATA)
assert "NAMEID_PERSISTENT_SPNAMEQUALIFIER_NOT_CHECKED" not in _codes(exact_sp)

# --- 16. SPProvidedID without management history ---
assert "NAMEID_PERSISTENT_SPPROVIDEDID_NOT_CHECKED" in _codes(
    _analyze(_nameid(PERSISTENT, opaque, SPProvidedID="sp-side-id"))
)
assert _sev(_analyze(_nameid(PERSISTENT, opaque, SPProvidedID="sp-side-id")), "NAMEID_PERSISTENT_SPPROVIDEDID_NOT_CHECKED") == {"INFO"}
assert "NAMEID_SPPROVIDEDID_EMPTY" in _codes(_analyze(_nameid(PERSISTENT, opaque, SPProvidedID="")))

# --- 18-19. transient xs:ID WARNING, uniqueness not ERROR ---
assert "NAMEID_TRANSIENT_IDENTIFIER_SYNTAX_INVALID" not in _codes(_analyze(_nameid(TRANSIENT, "_abc")))
assert "NAMEID_TRANSIENT_IDENTIFIER_SYNTAX_INVALID" not in _codes(_analyze(_nameid(TRANSIENT, "abc")))
assert "NAMEID_TRANSIENT_IDENTIFIER_SYNTAX_INVALID" in _codes(_analyze(_nameid(TRANSIENT, "123abc")))
assert "NAMEID_TRANSIENT_IDENTIFIER_SYNTAX_INVALID" in _codes(_analyze(_nameid(TRANSIENT, "a:b")))
assert "NAMEID_TRANSIENT_TOO_LONG" not in _codes(_analyze(_nameid(TRANSIENT, "a" + ("b" * 255))))
assert "NAMEID_TRANSIENT_TOO_LONG" in _codes(_analyze(_nameid(TRANSIENT, "a" + ("b" * 256))))
assert not any(f["code"] == "NAMEID_TRANSIENT_NOT_UNIQUE" for f in _analyze(_nameid(TRANSIENT, "_tmp-abc"))["findings"])

# --- 20. transient qualifiers ---
assert "NAMEID_TRANSIENT_NAMEQUALIFIER_MISMATCH" not in _codes(
    _analyze(_nameid(TRANSIENT, "_tmp-abc", NameQualifier="https://original-idp.example"))
)
assert "NAMEID_TRANSIENT_NAMEQUALIFIER_NOT_CHECKED" in _codes(
    _analyze(_nameid(TRANSIENT, "_tmp-abc", NameQualifier="https://original-idp.example"))
)

# --- 21. SPProvidedID on transient is not a format ERROR ---
assert "NAMEID_ENTITY_SPPROVIDEDID_FORBIDDEN" not in _codes(
    _analyze(_nameid(TRANSIENT, "_tmp-abc", SPProvidedID="sid"))
)

# --- 22. qualifier SHOULD omit vs MAY vs MUST ---
assert "NAMEID_NAMEQUALIFIER_UNEXPECTED" in _codes(_analyze(_nameid(EMAIL, "alice@example.com", NameQualifier="https://idp.example/entity")))
assert _sev(_analyze(_nameid(EMAIL, "alice@example.com", NameQualifier="https://idp.example/entity")), "NAMEID_NAMEQUALIFIER_UNEXPECTED") == {"WARNING"}
assert "NAMEID_NAMEQUALIFIER_UNEXPECTED" not in _codes(_analyze(_nameid(PERSISTENT, opaque, NameQualifier="https://idp.example/entity")))
assert "NAMEID_NAMEQUALIFIER_UNEXPECTED" not in _codes(_analyze(_nameid("https://example.com/custom-nid", "x", NameQualifier="https://idp.example/entity")))

# --- 24-26. NameIDPolicy omitted / unspecified / mismatch / custom ---
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" not in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=_req("_req1")))
assert "NAMEIDPOLICY_FORMAT_INVALID_URI" in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=_req("_req1", "")))
req_unspec = _req("_req1", UNSPECIFIED)
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" not in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=req_unspec))
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" not in _codes(_analyze(_nameid(PERSISTENT, opaque), request=req_unspec))
custom_fmt = "https://example.com/saml/nameid-format/custom"
req_custom = _req("_req1", custom_fmt)
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" not in _codes(_analyze(_nameid(custom_fmt, "whatever"), request=req_custom))
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" in _codes(
    _analyze(_nameid("https://example.com/saml/nameid-format/other", "whatever"), request=req_custom)
)
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" in _codes(_analyze(_nameid(None, "alice@example.com"), request=REQ_EMAIL))

# --- 27. NameIDPolicy SPNameQualifier ---
req_spq = _req("_req1", PERSISTENT, extra_policy=' SPNameQualifier="https://sp.example/entity"')
assert "NAMEIDPOLICY_SPNAMEQUALIFIER_MISMATCH" not in _codes(
    _analyze(_nameid(PERSISTENT, opaque, SPNameQualifier="https://sp.example/entity"), request=req_spq)
)
assert "NAMEIDPOLICY_SPNAMEQUALIFIER_MISMATCH" in _codes(_analyze(_nameid(PERSISTENT, opaque), request=req_spq))

# --- 28. AllowCreate xs:boolean ---
assert "NAMEIDPOLICY_ALLOWCREATE_INVALID" not in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=_req("_req1", EMAIL, extra_policy=' AllowCreate="true"')))
assert "NAMEIDPOLICY_ALLOWCREATE_INVALID" not in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=_req("_req1", EMAIL, extra_policy=' AllowCreate="1"')))
assert "NAMEIDPOLICY_ALLOWCREATE_INVALID" in _codes(_analyze(_nameid(EMAIL, "alice@example.com"), request=_req("_req1", EMAIL, extra_policy=' AllowCreate="TRUE"')))
assert "NAMEIDPOLICY_TRANSIENT_ALLOWCREATE" in _codes(
    _analyze(_nameid(TRANSIENT, "_tmp-abc"), request=_req("_req1", TRANSIENT, extra_policy=' AllowCreate="true"'))
)
assert "NAMEIDPOLICY_TRANSIENT_ALLOWCREATE" not in _codes(
    _analyze(_nameid(PERSISTENT, opaque), request=_req("_req1", PERSISTENT, extra_policy=' AllowCreate="false"'))
)

# --- 29. identifier exclusivity ---
assert "SUBJECT_IDENTIFIER_CHOICE_INVALID" in _codes(_analyze_subject(_nameid(EMAIL, "alice@example.com") + ENCRYPTED_ID))
assert "SUBJECT_IDENTIFIER_CHOICE_INVALID" in _codes(_analyze_subject(_nameid(EMAIL, "alice@example.com") + "<saml:BaseID/>"))
assert "SUBJECT_IDENTIFIER_CHOICE_INVALID" not in _codes(_analyze(_nameid(EMAIL, "alice@example.com")))
assert "SUBJECT_IDENTIFIER_CHOICE_INVALID" not in _codes(_analyze_subject(ENCRYPTED_ID))

# --- 30. EncryptedID + bearer does not require NameID ---
assert "BROWSER_SSO_SUBJECT_MISSING" not in _codes(_analyze_subject(ENCRYPTED_ID))

# --- 31. two assertions, findings scoped ---
two_assert = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
    'InResponseTo="_req1" Destination="https://sp.example/acs" IssueInstant="2026-09-07T08:00:01Z">'
    "<saml:Issuer>https://idp.example/entity</saml:Issuer>"
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    '<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">'
    "<saml:Issuer>https://idp.example/entity</saml:Issuer>"
    f"<saml:Subject>{_nameid(PERSISTENT, opaque)}{BEARER}</saml:Subject>{CONDITIONS}</saml:Assertion>"
    '<saml:Assertion ID="_a2" Version="2.0" IssueInstant="2026-09-07T08:00:01Z">'
    "<saml:Issuer>https://idp-b.example/entity</saml:Issuer>"
    f"<saml:Subject>{_nameid(EMAIL, 'not-an-email')}{BEARER}</saml:Subject>{CONDITIONS}</saml:Assertion>"
    "</samlp:Response>"
)
two = analyze_saml_input(two_assert)
email_scopes = [f["scope"] for f in two["findings"] if f["code"] == "NAMEID_EMAIL_FORMAT_INVALID"]
assert email_scopes == ["Assertion #2"]
assert not any(f["code"] == "NAMEID_EMAIL_FORMAT_INVALID" and f["scope"] == "Assertion #1" for f in two["findings"])

# --- 32. correlate NameIDPolicy via InResponseTo ---
req_a = _req("_reqA", EMAIL)
req_b = _req("_reqB", PERSISTENT)
mixed = analyze_saml_input("\n".join([req_a, req_b, _response(_nameid(EMAIL, "alice@example.com"), in_response_to="_reqB")]))
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" in _codes(mixed)
matched = analyze_saml_input("\n".join([req_a, req_b, _response(_nameid(PERSISTENT, opaque), in_response_to="_reqB")]))
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" not in _codes(matched)

# --- 33. unrelated metadata must not force qualifier ERROR ---
unrelated = _analyze(
    _nameid(PERSISTENT, opaque, NameQualifier="https://original-idp.example"),
    extra="\n".join([OTHER_IDP_METADATA, OTHER_SP_METADATA, SP_METADATA, IDP_METADATA]),
)
assert "NAMEID_PERSISTENT_NAMEQUALIFIER_MISMATCH" not in _codes(unrelated)

# --- 34. exact Format comparison (no case folding) ---
assert "NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH" in _codes(_analyze(_nameid(EMAIL.replace("oasis", "OASIS"), "alice@example.com"), request=REQ_EMAIL))

# --- 37. duplicate NameID ---
dup = _codes(_analyze_subject(_nameid(EMAIL, "a@example.com") + _nameid(EMAIL, "b@example.com")))
assert "SUBJECT_NAMEID_DUPLICATE" in dup

# --- 38. wrong namespace is not saml:NameID ---
fake = _codes(_analyze_subject('<foo:NameID xmlns:foo="urn:example:foo">alice@example.com</foo:NameID>'))
assert "NAMEID_EMAIL_FORMAT_INVALID" not in fake
assert "NAMEID_EMPTY" not in fake
plain = _codes(_analyze_subject("<NameID>alice@example.com</NameID>"))
assert "NAMEID_EMAIL_FORMAT_INVALID" not in plain

# --- 39. invalid Format must not dispatch email checks ---
bad_fmt = _codes(_analyze(_nameid("not a uri", "alice@example.com")))
assert "NAMEID_FORMAT_INVALID_URI" in bad_fmt
assert "NAMEID_EMAIL_FORMAT_INVALID" not in bad_fmt
assert "NAMEID_CUSTOM_FORMAT" not in bad_fmt

print("NAMEID FORMAT TESTS OK")
