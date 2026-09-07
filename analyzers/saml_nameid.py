from __future__ import annotations

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

# Formats that define NameQualifier / SPNameQualifier / SPProvidedID usage.
QUALIFIER_DEFINED_FORMATS = {PERSISTENT_FORMAT, TRANSIENT_FORMAT, ENTITY_FORMAT}


def _sv():
    from . import saml_validation as sv

    return sv


def _effective_format(nameid: dict[str, Any]) -> str | None:
    fmt = nameid.get("format")
    if fmt in {None, ""}:
        return UNSPECIFIED_FORMAT
    return fmt


def _generic_checks(sv, nameid: dict[str, Any], scope: str, fmt: str | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    declared = nameid.get("format")
    if declared not in {None, ""} and not sv._valid_uri(declared):
        out.append(
            sv._issue(
                "NAMEID_FORMAT_INVALID_URI",
                "ERROR",
                scope,
                "NameID Format is not a valid URI.",
                observed=declared,
                standard="SAML Core 2.0 §8.3",
            )
        )
        return out
    if nameid.get("value") is not None and nameid.get("value") == "":
        out.append(sv._issue("NAMEID_EMPTY", "ERROR", scope, "NameID is present but empty.", standard="SAML Core 2.0 §2.2.2 NameIDType"))
    if fmt in STANDARD_FORMATS and fmt not in QUALIFIER_DEFINED_FORMATS and fmt != ENCRYPTED_FORMAT:
        if nameid.get("name_qualifier"):
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
        if nameid.get("sp_name_qualifier"):
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


def _validate_email(sv, value: str | None, scope: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if sv._valid_email_addr_spec(value):
        return []
    return [
        sv._issue(
            "NAMEID_EMAIL_FORMAT_INVALID",
            "ERROR",
            scope,
            "NameID declares emailAddress format but the value is not a reduced RFC 2822 addr-spec (local-part@domain). This is not a complete RFC 2822 parser.",
            observed=value,
            expected="local-part@domain",
            standard="SAML Core 2.0 §8.3.2",
        )
    ]


def _valid_x509_subject_name(value: str) -> bool:
    try:
        from cryptography import x509
    except Exception:
        return False
    try:
        name = x509.Name.from_rfc4514_string(value)
    except Exception:
        return False
    return bool(list(name))


def _validate_x509(sv, value: str | None, scope: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if _valid_x509_subject_name(value):
        return []
    return [
        sv._issue(
            "NAMEID_X509_SUBJECT_NAME_INVALID",
            "ERROR",
            scope,
            "NameID declares X509SubjectName format but the value does not parse as an X.509 subject name / ds:X509SubjectName. This uses an RFC 4514 DN parser and does not claim XML Signature encoding identity with RFC 2253.",
            observed=value,
            standard="SAML Core 2.0 §8.3.3 + XML Signature ds:X509SubjectName",
        )
    ]


def _valid_windows_dqn(value: str) -> bool:
    if not value or any(ch.isspace() for ch in value):
        return False
    if value.startswith("\\") or value.endswith("\\"):
        return False
    if value.count("\\") == 0:
        return True
    if value.count("\\") != 1:
        return False
    domain, user = value.split("\\", 1)
    return bool(domain) and bool(user)


def _validate_windows(sv, value: str | None, scope: str) -> list[dict[str, Any]]:
    if value is None:
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
    """Structural Kerberos principal check: name[/instance]@REALM. Not a full RFC 1964 parser."""
    if not value or any(ch.isspace() for ch in value) or value.count("@") != 1:
        return False
    name, realm = value.split("@", 1)
    if not name or not realm:
        return False
    if name.startswith("/") or name.endswith("/"):
        return False
    if "//" in name:
        return False
    return True


def _validate_kerberos(sv, value: str | None, scope: str) -> list[dict[str, Any]]:
    if value is None:
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
    if value is not None:
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
    if nameid.get("name_qualifier"):
        out.append(
            sv._issue(
                "NAMEID_ENTITY_NAMEQUALIFIER_FORBIDDEN",
                "ERROR",
                scope,
                "Entity NameID MUST omit NameQualifier.",
                observed=nameid.get("name_qualifier"),
                standard="SAML Core 2.0 §8.3.6",
            )
        )
    if nameid.get("sp_name_qualifier"):
        out.append(
            sv._issue(
                "NAMEID_ENTITY_SPNAMEQUALIFIER_FORBIDDEN",
                "ERROR",
                scope,
                "Entity NameID MUST omit SPNameQualifier.",
                observed=nameid.get("sp_name_qualifier"),
                standard="SAML Core 2.0 §8.3.6",
            )
        )
    if nameid.get("sp_provided_id"):
        out.append(
            sv._issue(
                "NAMEID_ENTITY_SPPROVIDEDID_FORBIDDEN",
                "ERROR",
                scope,
                "Entity NameID MUST omit SPProvidedID.",
                observed=nameid.get("sp_provided_id"),
                standard="SAML Core 2.0 §8.3.6",
            )
        )
    return out


def _looks_like_email(value: str) -> bool:
    return "@" in value and " " not in value


def _validate_persistent(sv, nameid: dict[str, Any], scope: str, idp_entity_ids: list[str], sp_entity_ids: list[str]) -> list[dict[str, Any]]:
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
                "Persistent NameID should be an opaque pair-wise identifier. The value looks like an email address; this is a heuristic, not a proven Core violation.",
                observed=value,
                standard="SAML Core 2.0 §8.3.7",
            )
        )
    nq = nameid.get("name_qualifier")
    if nq and idp_entity_ids and nq not in idp_entity_ids:
        out.append(
            sv._issue(
                "NAMEID_PERSISTENT_NAMEQUALIFIER_MISMATCH",
                "ERROR",
                scope,
                "Persistent NameID NameQualifier does not match a supplied IdP entityID.",
                observed=nq,
                expected=idp_entity_ids,
                standard="SAML Core 2.0 §8.3.7",
            )
        )
    spq = nameid.get("sp_name_qualifier")
    if spq and sp_entity_ids and spq not in sp_entity_ids:
        out.append(
            sv._issue(
                "NAMEID_PERSISTENT_SPNAMEQUALIFIER_MISMATCH",
                "ERROR",
                scope,
                "Persistent NameID SPNameQualifier does not match a supplied SP entityID.",
                observed=spq,
                expected=sp_entity_ids,
                standard="SAML Core 2.0 §8.3.7",
            )
        )
    return out


def _validate_transient(sv, nameid: dict[str, Any], scope: str, idp_entity_ids: list[str], sp_entity_ids: list[str]) -> list[dict[str, Any]]:
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
                "ERROR",
                scope,
                "Transient NameID is not in the SAML identifier / xs:ID lexical space referenced by Core §1.3.4. Randomness and actual temporariness cannot be proven from one message.",
                observed=value,
                standard="SAML Core 2.0 §8.3.8 + §1.3.4",
            )
        )
    nq = nameid.get("name_qualifier")
    if nq and idp_entity_ids and nq not in idp_entity_ids:
        out.append(
            sv._issue(
                "NAMEID_TRANSIENT_NAMEQUALIFIER_MISMATCH",
                "ERROR",
                scope,
                "Transient NameID NameQualifier does not match a supplied IdP entityID.",
                observed=nq,
                expected=idp_entity_ids,
                standard="SAML Core 2.0 §8.3.8",
            )
        )
    spq = nameid.get("sp_name_qualifier")
    if spq and sp_entity_ids and spq not in sp_entity_ids:
        out.append(
            sv._issue(
                "NAMEID_TRANSIENT_SPNAMEQUALIFIER_MISMATCH",
                "ERROR",
                scope,
                "Transient NameID SPNameQualifier does not match a supplied SP entityID.",
                observed=spq,
                expected=sp_entity_ids,
                standard="SAML Core 2.0 §8.3.8",
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
) -> list[dict[str, Any]]:
    """Format-aware NameIDType validator. NameID Format omitted means unspecified, unlike Issuer."""
    if not nameid:
        return []
    if not any(nameid.get(k) not in {None, ""} for k in ("value", "format", "name_qualifier", "sp_name_qualifier", "sp_provided_id")):
        if nameid.get("value") != "":
            return []
    sv = _sv()
    idp_entity_ids = [x for x in (idp_entity_ids or []) if x]
    sp_entity_ids = [x for x in (sp_entity_ids or []) if x]
    declared = nameid.get("format")
    fmt = _effective_format(nameid)
    out = _generic_checks(sv, nameid, scope, fmt if declared not in {None, ""} or fmt == UNSPECIFIED_FORMAT else fmt)
    if declared not in {None, ""} and not sv._valid_uri(declared):
        return out
    if fmt == ENCRYPTED_FORMAT:
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
        out.extend(_validate_persistent(sv, nameid, scope, idp_entity_ids, sp_entity_ids))
    elif fmt == TRANSIENT_FORMAT:
        out.extend(_validate_transient(sv, nameid, scope, idp_entity_ids, sp_entity_ids))
    else:
        out.extend(_validate_custom(sv, fmt or "", scope))
    return out
