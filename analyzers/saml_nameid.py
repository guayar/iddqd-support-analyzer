from __future__ import annotations

import re
from typing import Any

EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
X509_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
WINDOWS_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
KERBEROS_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
ENTITY_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
PERSISTENT_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
TRANSIENT_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
UNSPECIFIED_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
ENCRYPTED_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"

STANDARD_FORMATS = {
    EMAIL_FORMAT,
    X509_FORMAT,
    WINDOWS_FORMAT,
    KERBEROS_FORMAT,
    ENTITY_FORMAT,
    PERSISTENT_FORMAT,
    TRANSIENT_FORMAT,
    UNSPECIFIED_FORMAT,
    ENCRYPTED_FORMAT,
}

# Formats that define NameQualifier / SPNameQualifier usage.
QUALIFIER_DEFINED_FORMATS = {PERSISTENT_FORMAT, TRANSIENT_FORMAT, ENTITY_FORMAT}


def _sv():
    from . import saml_validation as sv

    return sv


def _attr_present(nameid: dict[str, Any], field: str) -> bool:
    flag = f"{field}_present"
    if flag in nameid:
        return bool(nameid[flag])
    return nameid.get(field) is not None


def _format_present(nameid: dict[str, Any]) -> bool:
    return _attr_present(nameid, "format")


def _effective_format(nameid: dict[str, Any]) -> str | None:
    """Omitted Format means unspecified. Empty/whitespace Format is not omission."""
    if not _format_present(nameid):
        return UNSPECIFIED_FORMAT
    fmt = nameid.get("format")
    if fmt is None or not str(fmt).strip():
        return None
    return fmt


def _nameid_element_present(nameid: dict[str, Any]) -> bool:
    if "element_present" in nameid:
        return bool(nameid["element_present"])
    return any(
        nameid.get(k) not in {None, ""}
        for k in ("value", "format", "name_qualifier", "sp_name_qualifier", "sp_provided_id")
    ) or nameid.get("value") == "" or nameid.get("empty") is True


def _generic_checks(sv, nameid: dict[str, Any], scope: str, fmt: str | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if _format_present(nameid):
        declared = nameid.get("format")
        declared_s = "" if declared is None else str(declared)
        if not declared_s.strip() or not sv._valid_uri(declared_s):
            out.append(
                sv._issue(
                    "NAMEID_FORMAT_INVALID_URI",
                    "ERROR",
                    scope,
                    "NameID Format is not a valid URI. An explicit empty Format is not equivalent to omitting the attribute (omission means unspecified).",
                    observed=declared,
                    standard="SAML Core 2.0 §1.3.2 / §8.3",
                )
            )
            return out
    empty = nameid.get("empty")
    if empty is None:
        empty = nameid.get("value") == ""
    if empty:
        out.append(
            sv._issue(
                "NAMEID_EMPTY",
                "ERROR",
                scope,
                "NameID is present but empty or whitespace-only. SAML string values require at least one non-whitespace character.",
                observed=nameid.get("raw_value", nameid.get("value")),
                standard="SAML Core 2.0 §1.3.3 / §2.2.2 NameIDType",
            )
        )
    if fmt != ENTITY_FORMAT:
        if _attr_present(nameid, "name_qualifier") and not (nameid.get("name_qualifier") or "").strip():
            out.append(
                sv._issue(
                    "NAMEID_NAMEQUALIFIER_EMPTY",
                    "ERROR",
                    scope,
                    "NameQualifier is present but empty.",
                    observed=nameid.get("name_qualifier"),
                    standard="SAML Core 2.0 §1.3.3 / §2.2.2 NameIDType",
                )
            )
        if _attr_present(nameid, "sp_name_qualifier") and not (nameid.get("sp_name_qualifier") or "").strip():
            out.append(
                sv._issue(
                    "NAMEID_SPNAMEQUALIFIER_EMPTY",
                    "ERROR",
                    scope,
                    "SPNameQualifier is present but empty.",
                    observed=nameid.get("sp_name_qualifier"),
                    standard="SAML Core 2.0 §1.3.3 / §2.2.2 NameIDType",
                )
            )
        if _attr_present(nameid, "sp_provided_id") and not (nameid.get("sp_provided_id") or "").strip():
            out.append(
                sv._issue(
                    "NAMEID_SPPROVIDEDID_EMPTY",
                    "ERROR",
                    scope,
                    "SPProvidedID is present but empty.",
                    observed=nameid.get("sp_provided_id"),
                    standard="SAML Core 2.0 §1.3.3 / §2.2.2 NameIDType",
                )
            )
    if fmt in STANDARD_FORMATS and fmt not in QUALIFIER_DEFINED_FORMATS and fmt != ENCRYPTED_FORMAT:
        if _attr_present(nameid, "name_qualifier") and (nameid.get("name_qualifier") or "").strip():
            out.append(
                sv._issue(
                    "NAMEID_NAMEQUALIFIER_UNEXPECTED",
                    "WARNING",
                    scope,
                    "NameQualifier is present on a NameID format that does not define qualifier semantics. SAML Core says qualifiers SHOULD be omitted unless the format uses them.",
                    observed=nameid.get("name_qualifier"),
                    standard="SAML Core 2.0 §2.2.2 NameIDType",
                )
            )
        if _attr_present(nameid, "sp_name_qualifier") and (nameid.get("sp_name_qualifier") or "").strip():
            out.append(
                sv._issue(
                    "NAMEID_SPNAMEQUALIFIER_UNEXPECTED",
                    "WARNING",
                    scope,
                    "SPNameQualifier is present on a NameID format that does not define qualifier semantics. SAML Core says qualifiers SHOULD be omitted unless the format uses them.",
                    observed=nameid.get("sp_name_qualifier"),
                    standard="SAML Core 2.0 §2.2.2 NameIDType",
                )
            )
    return out


def _clearly_not_addr_spec(value: str) -> bool:
    if not value or any(ch in value for ch in "<>()"):
        return True
    if value.count("@") != 1:
        return True
    local, domain = value.split("@", 1)
    return not local or not domain


def _validate_email(sv, value: str | None, scope: str) -> list[dict[str, Any]]:
    if value is None or value == "":
        return []
    if sv._valid_email_addr_spec(value):
        return []
    if _clearly_not_addr_spec(value):
        return [
            sv._issue(
                "NAMEID_EMAIL_FORMAT_INVALID",
                "ERROR",
                scope,
                "NameID declares emailAddress format but the value is not an RFC 2822 addr-spec (local-part@domain). Display names, comments and angle-addr forms are not addr-spec.",
                observed=value,
                expected="addr-spec",
                standard="SAML Core 2.0 §8.3.2",
            )
        ]
    return [
        sv._issue(
            "NAMEID_EMAIL_FORMAT_NOT_FULLY_CHECKED",
            "WARNING",
            scope,
            "NameID declares emailAddress format. The value is not rejected as a non-addr-spec, but this analyzer uses a reduced RFC 2822 check and cannot confirm quoted-string / domain-literal forms.",
            observed=value,
            expected="RFC 2822 addr-spec",
            standard="SAML Core 2.0 §8.3.2",
        )
    ]


def _valid_x509_subject_name(value: str) -> bool | None:
    """True=parsed, False=not a DN, None=parser unavailable."""
    try:
        from cryptography import x509
    except Exception:
        return None
    try:
        name = x509.Name.from_rfc4514_string(value)
    except Exception:
        return False
    return bool(list(name))


def _validate_x509(sv, value: str | None, scope: str) -> list[dict[str, Any]]:
    if value is None or value == "":
        return []
    parsed = _valid_x509_subject_name(value)
    if parsed is None:
        return [
            sv._issue(
                "NAMEID_X509_NOT_CHECKED",
                "INFO",
                scope,
                "X509SubjectName cannot be parsed because the cryptography package is unavailable.",
                observed=value,
                standard="SAML Core 2.0 §8.3.3",
            )
        ]
    if parsed:
        return []
    if "=" not in value:
        return [
            sv._issue(
                "NAMEID_X509_SUBJECT_NAME_INVALID",
                "ERROR",
                scope,
                "NameID declares X509SubjectName format but the value is not a distinguished name (no attribute=value encoding).",
                observed=value,
                standard="SAML Core 2.0 §8.3.3 + XML Signature ds:X509SubjectName",
            )
        ]
    return [
        sv._issue(
            "NAMEID_X509_SUBJECT_NAME_UNVERIFIED",
            "WARNING",
            scope,
            "NameID declares X509SubjectName format. SAML requires ds:X509SubjectName encoding, which XML Signature warns is not identical to RFC 2253/4514. This RFC 4514 parser could not accept the value; that is not a proven XML Signature syntax violation.",
            observed=value,
            standard="SAML Core 2.0 §8.3.3 + XML Signature ds:X509SubjectName",
        )
    ]


def _valid_windows_dqn(value: str) -> bool:
    """SAML Core §8.3.4: DomainName\\UserName, with DomainName and backslash optional.

    Spaces are not forbidden by SAML. Additional unescaped backslashes are not the defined form.
    """
    if not value or not value.strip():
        return False
    if any(ch in value for ch in "\n\r\t"):
        return False
    if value.startswith("\\") or value.endswith("\\"):
        return False
    n = value.count("\\")
    if n == 0:
        return True
    if n != 1:
        return False
    domain, user = value.split("\\", 1)
    return bool(domain) and bool(user)


def _validate_windows(sv, value: str | None, scope: str) -> list[dict[str, Any]]:
    if value is None or value == "":
        return []
    if _valid_windows_dqn(value):
        return []
    return [
        sv._issue(
            "NAMEID_WINDOWS_DQN_INVALID",
            "ERROR",
            scope,
            "NameID declares WindowsDomainQualifiedName format but the value is not DomainName\\UserName, and is not a username with the optional domain omitted.",
            observed=value,
            expected="DomainName\\UserName or UserName",
            standard="SAML Core 2.0 §8.3.4",
        )
    ]


def _valid_kerberos_principal(value: str) -> bool:
    """Structural Kerberos principal check: name[/instance[/...]]@REALM. Not a full RFC 1510/1964 parser."""
    if not value or any(ch.isspace() for ch in value) or value.count("@") != 1:
        return False
    name, realm = value.split("@", 1)
    if not name or not realm:
        return False
    if name.startswith("/") or name.endswith("/") or "//" in name:
        return False
    return True


def _validate_kerberos(sv, value: str | None, scope: str) -> list[dict[str, Any]]:
    if value is None or value == "":
        return []
    if _valid_kerberos_principal(value):
        return []
    return [
        sv._issue(
            "NAMEID_KERBEROS_FORMAT_INVALID",
            "ERROR",
            scope,
            "NameID declares kerberos format but the value is not a structural name[/instance]@REALM principal. This is not a complete Kerberos RFC parser.",
            observed=value,
            expected="name[/instance]@REALM",
            standard="SAML Core 2.0 §8.3.5",
        )
    ]


def _validate_entity(sv, nameid: dict[str, Any], scope: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    value = nameid.get("value")
    if value:
        if len(value) > 1024:
            out.append(
                sv._issue(
                    "NAMEID_ENTITY_TOO_LONG",
                    "ERROR",
                    scope,
                    "Entity NameID exceeds 1024 characters.",
                    observed=len(value),
                    expected="<= 1024",
                    standard="SAML Core 2.0 §8.3.6",
                )
            )
        elif not sv._valid_uri(value):
            out.append(
                sv._issue(
                    "NAMEID_ENTITY_URI_INVALID",
                    "ERROR",
                    scope,
                    "Entity NameID is not a valid URI. HTTP/HTTPS is not required; any URI scheme is allowed.",
                    observed=value,
                    standard="SAML Core 2.0 §8.3.6",
                )
            )
    if _attr_present(nameid, "name_qualifier"):
        out.append(
            sv._issue(
                "NAMEID_ENTITY_NAMEQUALIFIER_FORBIDDEN",
                "ERROR",
                scope,
                "Entity NameID MUST omit NameQualifier. An empty NameQualifier attribute is still present.",
                observed=nameid.get("name_qualifier"),
                standard="SAML Core 2.0 §8.3.6",
            )
        )
    if _attr_present(nameid, "sp_name_qualifier"):
        out.append(
            sv._issue(
                "NAMEID_ENTITY_SPNAMEQUALIFIER_FORBIDDEN",
                "ERROR",
                scope,
                "Entity NameID MUST omit SPNameQualifier. An empty SPNameQualifier attribute is still present.",
                observed=nameid.get("sp_name_qualifier"),
                standard="SAML Core 2.0 §8.3.6",
            )
        )
    if _attr_present(nameid, "sp_provided_id"):
        out.append(
            sv._issue(
                "NAMEID_ENTITY_SPPROVIDEDID_FORBIDDEN",
                "ERROR",
                scope,
                "Entity NameID MUST omit SPProvidedID. An empty SPProvidedID attribute is still present.",
                observed=nameid.get("sp_provided_id"),
                standard="SAML Core 2.0 §8.3.6",
            )
        )
    return out


def _looks_like_email(value: str) -> bool:
    return "@" in value and " " not in value


def _looks_non_opaque_persistent(value: str) -> bool:
    if _looks_like_email(value):
        return True
    if " " in value.strip():
        return True
    if re.fullmatch(r"(?i)(employee|user|uid|emp)\d+", value):
        return True
    if re.fullmatch(r"[A-Za-z][A-Za-z._-]{0,11}", value):
        return True
    return False


def _qualifier_not_checked(sv, code: str, scope: str, message: str, observed: Any, standard: str) -> dict[str, Any]:
    return sv._issue(code, "INFO", scope, message, observed=observed, standard=standard)


def _validate_persistent(
    sv,
    nameid: dict[str, Any],
    scope: str,
    sp_entity_ids: list[str],
    assertion_issuer: str | None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    value = nameid.get("value")
    if value and len(value) > 256:
        out.append(
            sv._issue(
                "NAMEID_PERSISTENT_TOO_LONG",
                "ERROR",
                scope,
                "Persistent NameID exceeds 256 characters.",
                observed=len(value),
                expected="<= 256",
                standard="SAML Core 2.0 §8.3.7",
            )
        )
    elif value and _looks_like_email(value):
        out.append(
            sv._issue(
                "NAMEID_PERSISTENT_VALUE_APPEARS_NON_OPAQUE",
                "WARNING",
                scope,
                "Persistent NameID should be an opaque pair-wise identifier generated by the IdP. The value looks like an email address; this is a heuristic, not a proven Core violation from one sample.",
                observed=value,
                standard="SAML Core 2.0 §8.3.7",
            )
        )
    elif value and _looks_non_opaque_persistent(value):
        out.append(
            sv._issue(
                "NAMEID_PERSISTENT_VALUE_APPEARS_NON_OPAQUE",
                "WARNING",
                scope,
                "Persistent NameID should be an opaque pair-wise identifier generated by the IdP. The value looks personally identifying; this is a heuristic, not a proven Core violation from one sample.",
                observed=value,
                standard="SAML Core 2.0 §8.3.7",
            )
        )
    nq = nameid.get("name_qualifier")
    if _attr_present(nameid, "name_qualifier") and (nq or "").strip():
        if assertion_issuer and nq == assertion_issuer:
            pass
        else:
            out.append(
                _qualifier_not_checked(
                    sv,
                    "NAMEID_PERSISTENT_NAMEQUALIFIER_NOT_CHECKED",
                    scope,
                    "Persistent NameID NameQualifier identifies the IdP that originally generated the identifier, which may differ from the current Assertion Issuer. This run cannot prove that the qualifier is wrong.",
                    nq,
                    "SAML Core 2.0 §8.3.7",
                )
            )
    spq = nameid.get("sp_name_qualifier")
    if _attr_present(nameid, "sp_name_qualifier") and (spq or "").strip():
        if sp_entity_ids and spq in sp_entity_ids:
            pass
        else:
            out.append(
                _qualifier_not_checked(
                    sv,
                    "NAMEID_PERSISTENT_SPNAMEQUALIFIER_NOT_CHECKED",
                    scope,
                    "Persistent NameID SPNameQualifier may identify an SP or an affiliation of providers. Without affiliation metadata this value cannot be proven invalid.",
                    spq,
                    "SAML Core 2.0 §8.3.7",
                )
            )
    if _attr_present(nameid, "sp_provided_id") and (nameid.get("sp_provided_id") or "").strip():
        out.append(
            sv._issue(
                "NAMEID_PERSISTENT_SPPROVIDEDID_NOT_CHECKED",
                "INFO",
                scope,
                "Persistent NameID SPProvidedID is present. Correctness depends on Name Identifier Management history, which is not available in this paste.",
                observed=nameid.get("sp_provided_id"),
                standard="SAML Core 2.0 §8.3.7",
            )
        )
    return out


def _validate_transient(
    sv,
    nameid: dict[str, Any],
    scope: str,
    sp_entity_ids: list[str],
    assertion_issuer: str | None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    value = nameid.get("value")
    if value and len(value) > 256:
        out.append(
            sv._issue(
                "NAMEID_TRANSIENT_TOO_LONG",
                "ERROR",
                scope,
                "Transient NameID exceeds 256 characters.",
                observed=len(value),
                expected="<= 256",
                standard="SAML Core 2.0 §8.3.8",
            )
        )
    elif value and not sv._valid_xs_id(value):
        out.append(
            sv._issue(
                "NAMEID_TRANSIENT_IDENTIFIER_SYNTAX_INVALID",
                "WARNING",
                scope,
                "Transient NameID is not in the xs:ID / SAML identifier lexical space of Core §1.3.4. Core §8.3.8 also allows other constructions; uniqueness, entropy and temporariness cannot be proven from one message.",
                observed=value,
                standard="SAML Core 2.0 §8.3.8 + §1.3.4",
            )
        )
    nq = nameid.get("name_qualifier")
    if _attr_present(nameid, "name_qualifier") and (nq or "").strip():
        if assertion_issuer and nq == assertion_issuer:
            pass
        else:
            out.append(
                _qualifier_not_checked(
                    sv,
                    "NAMEID_TRANSIENT_NAMEQUALIFIER_NOT_CHECKED",
                    scope,
                    "Transient NameID NameQualifier MAY identify the original generating IdP for pair-wise identifiers and need not equal the current Assertion Issuer.",
                    nq,
                    "SAML Core 2.0 §8.3.8",
                )
            )
    spq = nameid.get("sp_name_qualifier")
    if _attr_present(nameid, "sp_name_qualifier") and (spq or "").strip():
        if sp_entity_ids and spq in sp_entity_ids:
            pass
        else:
            out.append(
                _qualifier_not_checked(
                    sv,
                    "NAMEID_TRANSIENT_SPNAMEQUALIFIER_NOT_CHECKED",
                    scope,
                    "Transient NameID SPNameQualifier MAY identify an SP or affiliation. Without affiliation metadata this value cannot be proven invalid.",
                    spq,
                    "SAML Core 2.0 §8.3.8",
                )
            )
    return out


def _validate_custom(sv, fmt: str, scope: str) -> list[dict[str, Any]]:
    return [
        sv._issue(
            "NAMEID_CUSTOM_FORMAT",
            "INFO",
            scope,
            "Non-standard NameID Format. Value semantics cannot be validated without the definition/profile for this custom format.",
            observed=fmt,
            standard="SAML Core 2.0 §7.3 Identifier Extension",
        )
    ]


def validate_nameid(
    nameid: dict[str, Any] | None,
    scope: str,
    *,
    idp_entity_ids: list[str] | None = None,
    sp_entity_ids: list[str] | None = None,
    assertion_issuer: str | None = None,
) -> list[dict[str, Any]]:
    """Format-aware NameIDType validator. Omitted Format means unspecified, unlike Issuer."""
    if not nameid or not _nameid_element_present(nameid):
        return []
    sv = _sv()
    _ = idp_entity_ids
    sp_entity_ids = [x for x in (sp_entity_ids or []) if x]
    fmt = _effective_format(nameid)
    out = _generic_checks(sv, nameid, scope, fmt)
    if _format_present(nameid):
        declared = nameid.get("format")
        declared_s = "" if declared is None else str(declared)
        if not declared_s.strip() or not sv._valid_uri(declared_s):
            return out
    if fmt == ENCRYPTED_FORMAT:
        out.append(
            sv._issue(
                "NAMEID_ENCRYPTED_FORMAT_PLAINTEXT",
                "ERROR",
                scope,
                "NameID Format urn:...:encrypted is the NameIDPolicy special value. An assertion must carry EncryptedID instead of a plaintext NameID with this Format. EncryptedID and NameID are not interchangeable.",
                observed=nameid.get("value"),
                expected="saml:EncryptedID",
                standard="SAML Approved Errata E6 / E15",
            )
        )
        return out
    if fmt == UNSPECIFIED_FORMAT:
        return out
    if fmt == EMAIL_FORMAT:
        out.extend(_validate_email(sv, nameid.get("value"), scope))
    elif fmt == X509_FORMAT:
        out.extend(_validate_x509(sv, nameid.get("value"), scope))
    elif fmt == WINDOWS_FORMAT:
        out.extend(_validate_windows(sv, nameid.get("value"), scope))
    elif fmt == KERBEROS_FORMAT:
        out.extend(_validate_kerberos(sv, nameid.get("value"), scope))
    elif fmt == ENTITY_FORMAT:
        out.extend(_validate_entity(sv, nameid, scope))
    elif fmt == PERSISTENT_FORMAT:
        out.extend(_validate_persistent(sv, nameid, scope, sp_entity_ids, assertion_issuer))
    elif fmt == TRANSIENT_FORMAT:
        out.extend(_validate_transient(sv, nameid, scope, sp_entity_ids, assertion_issuer))
    else:
        out.extend(_validate_custom(sv, fmt or "", scope))
    return out
