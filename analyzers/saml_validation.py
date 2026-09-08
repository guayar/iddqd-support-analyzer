from __future__ import annotations

import json
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from .saml_nameid import validate_nameid

SAML2_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
ENTITY_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
PERSISTENT_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
TRANSIENT_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
UNSPECIFIED_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
ENCRYPTED_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"
UNSPECIFIED_ATTR_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
BEARER_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
TOP_STATUS_CODES = {SUCCESS, REQUESTER, RESPONDER, VERSION_MISMATCH}


def _issue(
    code: str,
    severity: str,
    scope: str,
    message: str,
    *,
    observed: Any = None,
    expected: Any = None,
    standard: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "scope": scope,
        "message": message,
        "observed": observed,
        "expected": expected,
        "standard": standard,
        "note": note,
    }


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        v = value.strip()
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            return None
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _is_utc_time(value: str | None) -> bool:
    if not value:
        return False
    try:
        v = value.strip()
        if v.endswith("Z"):
            return True
        dt = datetime.fromisoformat(v)
        return dt.tzinfo is not None and dt.utcoffset() is not None and dt.utcoffset().total_seconds() == 0
    except Exception:
        return False


def _valid_uri(value: str | None) -> bool:
    if not value or any(ch.isspace() for ch in value):
        return False
    try:
        p = urllib.parse.urlparse(value)
        return bool(p.scheme)
    except Exception:
        return False


def _expected_response_acs(req, sp_acs_locations: list[str]) -> list[str]:
    """ACS endpoints that can be used to verify Response Destination when present.

    SubjectConfirmation Recipient is not treated as ACS configuration.
    """
    out: list[str] = []
    for value in list(sp_acs_locations) + ([req.get("acs_url")] if req and req.get("acs_url") else []):
        if value and value not in out:
            out.append(value)
    return out


def _validate_response_destination(r: dict[str, Any], scope: str, expected_acs: list[str]) -> list[dict[str, Any]]:
    """SAML Core §3.2.2: Destination is optional, but if present it must be the delivery location."""
    dest = r.get("destination")
    standard = "SAML Core 2.0 §3.2.2 Destination"
    if dest is None:
        return [
            _issue(
                "RESPONSE_DESTINATION_NOT_CHECKED",
                "INFO",
                scope,
                "Response Destination attribute is absent. SAML Core treats Destination as optional, so delivery-location verification was not performed.",
                expected=expected_acs or "receiving ACS endpoint if Destination is present",
                standard=standard,
            )
        ]
    if not str(dest).strip():
        return [
            _issue(
                "RESPONSE_DESTINATION_EMPTY",
                "ERROR",
                scope,
                "Response Destination attribute is present but empty.",
                observed="",
                expected="receiving ACS endpoint",
                standard=standard,
            )
        ]
    if not _valid_uri(dest):
        return [
            _issue(
                "RESPONSE_DESTINATION_INVALID",
                "ERROR",
                scope,
                "Destination is not a valid URI.",
                observed=dest,
                expected="receiving ACS endpoint URI",
                standard=standard,
            )
        ]
    if not expected_acs:
        return [
            _issue(
                "RESPONSE_DESTINATION_NOT_CHECKED",
                "INFO",
                scope,
                "Response Destination is present, but this run has no ACS/receiving-endpoint context to compare it against.",
                observed=dest,
                expected="SP ACS or AuthnRequest AssertionConsumerServiceURL",
                standard=standard,
                note="Recipient in SubjectConfirmationData is not used as ACS configuration.",
            )
        ]
    if dest in expected_acs:
        return [
            _issue(
                "RESPONSE_DESTINATION_MATCH",
                "INFO",
                scope,
                "Response Destination matches the expected receiving ACS endpoint.",
                observed=dest,
                expected=expected_acs,
                standard=standard,
            )
        ]
    return [
        _issue(
            "RESPONSE_DESTINATION_MISMATCH",
            "ERROR",
            scope,
            "Response Destination does not match the expected receiving ACS endpoint.",
            observed=dest,
            expected=expected_acs,
            standard=standard,
        )
    ]


def _valid_xs_id(value: str | None) -> bool:
    if not value or ":" in value or any(ch.isspace() for ch in value):
        return False
    # xs:ID uses the XML NCName lexical space. This Unicode-aware approximation
    # accepts a letter or underscore first, followed by word chars, dot or dash.
    return bool(re.fullmatch(r"(?:[^\W\d]|_)[\w.-]*", value, flags=re.UNICODE))


def _valid_email_addr_spec(value: str | None) -> bool:
    if not value or len(value) > 320 or value.startswith("<") or value.endswith(">"):
        return False
    if "(" in value or ")" in value or any(ch.isspace() for ch in value):
        return False
    # Deliberately conservative addr-spec check. This is not intended to replace
    # a full RFC 2822 parser, but catches the interoperability failures seen in SAML.
    return bool(re.fullmatch(r"[^@\s<>]+@[^@\s<>]+", value))


def _bool_lexical_ok(value: Any) -> bool:
    if value is None:
        return True
    # xs:boolean lexical space is case-sensitive: true | false | 1 | 0
    return str(value) in {"true", "false", "1", "0"}


def _nonnegative_int_ok(value: Any) -> bool:
    if value is None:
        return False
    raw = str(value).strip()
    if not re.fullmatch(r"\+?\d+", raw):
        return False
    try:
        return int(raw) >= 0
    except Exception:
        return False


def _unsigned_short_ok(value: Any) -> bool:
    if not _nonnegative_int_ok(value):
        return False
    try:
        return int(str(value).strip()) <= 65535
    except Exception:
        return False


def _uri_list(values: list[Any]) -> list[str]:
    return [str(v) for v in values if v]


def _issuer_value(obj: dict[str, Any] | None) -> str | None:
    return (obj or {}).get("value")


def _entity_identifier_issues(value: str | None, issuer: dict[str, Any] | None, scope: str, code_prefix: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if value and (not _valid_uri(value) or len(value) > 1024):
        out.append(_issue(
            f"{code_prefix}_ENTITY_ID_INVALID",
            "ERROR", scope,
            "Entity-format identifier is not a valid URI of at most 1024 characters.",
            observed=value, expected="URI <= 1024 characters",
            standard="SAML Core 2.0 §8.3.6",
        ))
    obj = issuer or {}
    fmt = obj.get("format")
    if fmt in {None, "", ENTITY_FORMAT}:
        forbidden = {k: obj.get(k) for k in ("name_qualifier", "sp_name_qualifier", "sp_provided_id") if obj.get(k)}
        if forbidden:
            out.append(_issue(
                f"{code_prefix}_ENTITY_QUALIFIERS_FORBIDDEN",
                "ERROR", scope,
                "Entity-format NameID/Issuer must not carry NameQualifier, SPNameQualifier or SPProvidedID.",
                observed=forbidden, expected="qualifiers omitted",
                standard="SAML Core 2.0 §8.3.6",
            ))
    return out


def _validate_common_message(obj: dict[str, Any], scope: str, prefix: str, standard_section: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not obj.get("id"):
        out.append(_issue(f"{prefix}_ID_MISSING", "ERROR", scope, "Required ID attribute is missing.", expected="non-empty xs:ID", standard=standard_section))
    elif not _valid_xs_id(obj.get("id")):
        out.append(_issue(f"{prefix}_ID_INVALID", "ERROR", scope, "ID is not valid in the XML xs:ID/NCName lexical space.", observed=obj.get("id"), expected="valid xs:ID / NCName", standard=standard_section))
    version = obj.get("version")
    if not version:
        out.append(_issue(f"{prefix}_VERSION_MISSING", "ERROR", scope, "Required Version attribute is missing.", expected="2.0", standard=standard_section))
    elif version != "2.0":
        out.append(_issue(f"{prefix}_VERSION_INVALID", "ERROR", scope, "Unsupported/invalid SAML Version.", observed=version, expected="2.0", standard=standard_section))
    instant = obj.get("issue_instant")
    if not instant:
        out.append(_issue(f"{prefix}_ISSUEINSTANT_MISSING", "ERROR", scope, "Required IssueInstant attribute is missing.", expected="UTC xs:dateTime", standard=standard_section))
    elif _parse_time(instant) is None:
        out.append(_issue(f"{prefix}_ISSUEINSTANT_INVALID", "ERROR", scope, "IssueInstant is not a valid timezone-aware xs:dateTime.", observed=instant, expected="UTC xs:dateTime", standard=standard_section))
    elif not _is_utc_time(instant):
        out.append(_issue(f"{prefix}_ISSUEINSTANT_NOT_UTC", "ERROR", scope, "SAML time values must be expressed in UTC.", observed=instant, expected="UTC", standard="SAML Core 2.0 §1.3.3"))
    return out


def _validate_issuer(issuer: dict[str, Any] | None, scope: str, prefix: str, *, required: bool, browser_profile: bool = False) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    value = _issuer_value(issuer)
    if required and not value:
        out.append(_issue(f"{prefix}_ISSUER_MISSING", "ERROR", scope, "Issuer is required for this SAML object/profile.", expected="entity identifier", standard="SAML Core 2.0 / SAML Profiles 2.0 Web Browser SSO"))
        return out
    if not value:
        return out
    fmt = (issuer or {}).get("format")
    if browser_profile and fmt not in {None, "", ENTITY_FORMAT}:
        out.append(_issue(f"{prefix}_ISSUER_FORMAT_INVALID", "ERROR", scope, "Web Browser SSO Issuer Format must be omitted or use the entity NameID format.", observed=fmt, expected=ENTITY_FORMAT, standard="SAML Profiles 2.0 §4.1.4.1/§4.1.4.2"))
    if fmt in {None, "", ENTITY_FORMAT}:
        out.extend(_entity_identifier_issues(value, issuer, scope, prefix + "_ISSUER"))
    return out


def _validate_signature_shape(sig: dict[str, Any] | None, scope: str, prefix: str, signed_id: str | None) -> list[dict[str, Any]]:
    sig = sig or {}
    if not sig.get("present"):
        return []
    out = [_issue(
        f"{prefix}_SIGNATURE_NOT_CRYPTO_VERIFIED", "WARNING", scope,
        "XML Signature is present, but the current validator does not cryptographically validate the signature or certificate trust chain.",
        observed=sig.get("signature_method"), expected="cryptographic verification before trust",
        standard="SAML Core 2.0 §5 / Web Browser SSO processing rules",
    )]
    if not sig.get("signed_info_present"):
        out.append(_issue(f"{prefix}_SIGNATURE_SIGNEDINFO_MISSING", "ERROR", scope, "ds:Signature is present but ds:SignedInfo is missing.", standard="XML Signature schema/profile"))
    if not sig.get("signature_value_present"):
        out.append(_issue(f"{prefix}_SIGNATURE_VALUE_MISSING", "ERROR", scope, "ds:Signature is present but SignatureValue is missing or empty.", standard="XML Signature schema/profile"))
    if not sig.get("signature_method"):
        out.append(_issue(f"{prefix}_SIGNATURE_METHOD_MISSING", "ERROR", scope, "SignatureMethod Algorithm is missing.", standard="XML Signature schema/profile"))
    elif not _valid_uri(sig.get("signature_method")):
        out.append(_issue(f"{prefix}_SIGNATURE_METHOD_INVALID", "ERROR", scope, "SignatureMethod Algorithm is not a valid URI.", observed=sig.get("signature_method")))
    if not sig.get("canonicalization_method"):
        out.append(_issue(f"{prefix}_CANONICALIZATION_METHOD_MISSING", "ERROR", scope, "CanonicalizationMethod Algorithm is missing.", standard="XML Signature schema/profile"))
    elif not _valid_uri(sig.get("canonicalization_method")):
        out.append(_issue(f"{prefix}_CANONICALIZATION_METHOD_INVALID", "ERROR", scope, "CanonicalizationMethod Algorithm is not a valid URI.", observed=sig.get("canonicalization_method")))
    if not sig.get("reference_count"):
        out.append(_issue(f"{prefix}_SIGNATURE_REFERENCE_MISSING", "ERROR", scope, "SignedInfo contains no Reference element.", expected=">= 1 Reference", standard="XML Signature schema/profile"))
    if sig.get("reference_count") and len(sig.get("digest_methods") or []) < sig.get("reference_count"):
        out.append(_issue(f"{prefix}_DIGEST_METHOD_MISSING", "ERROR", scope, "One or more signature References have no DigestMethod.", observed=len(sig.get("digest_methods") or []), expected=sig.get("reference_count"), standard="XML Signature schema/profile"))
    for method in sig.get("digest_methods") or []:
        if not _valid_uri(method):
            out.append(_issue(f"{prefix}_DIGEST_METHOD_INVALID", "ERROR", scope, "DigestMethod Algorithm is not a valid URI.", observed=method))
    if sig.get("reference_count") and int(sig.get("digest_value_count") or 0) < sig.get("reference_count"):
        out.append(_issue(f"{prefix}_DIGEST_VALUE_MISSING", "ERROR", scope, "One or more signature References have no DigestValue.", observed=sig.get("digest_value_count"), expected=sig.get("reference_count"), standard="XML Signature schema/profile"))
    refs = sig.get("reference_uris") or []
    if signed_id and refs and f"#{signed_id}" not in refs:
        out.append(_issue(
            f"{prefix}_SIGNATURE_REFERENCE_SUSPICIOUS", "ERROR", scope,
            "Signature does not reference the ID of the SAML element that contains it.",
            observed=refs, expected=f"#{signed_id}",
            standard="SAML XML Signature profile",
            note="This is a structural signature check only, not cryptographic validation.",
        ))
    if "unparseable certificate" in (sig.get("x509_sha256_fingerprints") or []):
        out.append(_issue(f"{prefix}_X509_MALFORMED", "ERROR", scope, "Embedded X509Certificate could not be Base64/DER parsed.", standard="XML Signature / X.509 data integrity"))
    return out


def _detect_transport(raw_input: str) -> dict[str, Any]:
    info: dict[str, Any] = {
        "request_binding": None,
        "response_binding": None,
        "request_http_method": None,
        "response_http_method": None,
        "redirect_signature_present": False,
        "redirect_sigalg": None,
        "redirect_signature_parameter_present": False,
        "relaystate_values": [],
        "evidence": [],
    }

    def inspect_params(params: dict[str, list[str]], method: str | None, source: str):
        keys = set(params)
        if "SAMLRequest" in keys:
            if method == "GET" or ("SigAlg" in keys and "Signature" in keys):
                info["request_binding"] = HTTP_REDIRECT
            elif method == "POST":
                info["request_binding"] = HTTP_POST
            info["request_http_method"] = method or info["request_http_method"]
            info["evidence"].append(f"SAMLRequest in {source}")
        if "SAMLResponse" in keys:
            if method == "GET" or ("SigAlg" in keys and "Signature" in keys):
                info["response_binding"] = HTTP_REDIRECT
            elif method == "POST":
                info["response_binding"] = HTTP_POST
            info["response_http_method"] = method or info["response_http_method"]
            info["evidence"].append(f"SAMLResponse in {source}")
        if "SigAlg" in keys:
            info["redirect_sigalg"] = params.get("SigAlg", [None])[0]
        if "Signature" in keys:
            info["redirect_signature_parameter_present"] = True
        if "SigAlg" in keys and "Signature" in keys and "SAMLRequest" in keys:
            info["redirect_signature_present"] = True
        info["relaystate_values"].extend(params.get("RelayState", []))

    # HAR provides the strongest binding evidence.
    try:
        obj = json.loads(raw_input)
        entries = (((obj or {}).get("log") or {}).get("entries") or []) if isinstance(obj, dict) else []
        for entry in entries:
            req = entry.get("request") or {}
            method = str(req.get("method") or "").upper() or None
            url = req.get("url") or ""
            if url:
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True)
                inspect_params(q, method, "HAR URL")
            post = req.get("postData") or {}
            params: dict[str, list[str]] = {}
            for p in post.get("params") or []:
                if p.get("name"):
                    params.setdefault(str(p["name"]), []).append(str(p.get("value") or ""))
            if post.get("text"):
                for k, vals in urllib.parse.parse_qs(str(post["text"]), keep_blank_values=True).items():
                    params.setdefault(k, []).extend(vals)
            if params:
                inspect_params(params, method or "POST", "HAR POST body")
    except Exception:
        pass

    # Pasted query strings / form bodies.
    candidates = [raw_input]
    for m in re.finditer(r"https?://[^\s]+", raw_input):
        candidates.append(m.group(0))
    for candidate in candidates:
        try:
            if "?" in candidate:
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(candidate).query, keep_blank_values=True)
                if q:
                    inspect_params(q, "GET", "pasted URL/query")
            form = urllib.parse.parse_qs(candidate.strip(), keep_blank_values=True)
            if "SAMLRequest" in form or "SAMLResponse" in form:
                # Without an HTTP method this is only weak evidence; Base64 form
                # payloads are normally HTTP-POST, while SigAlg+Signature indicate Redirect.
                method = "GET" if ("SigAlg" in form and "Signature" in form) else None
                inspect_params(form, method, "pasted parameters")
        except Exception:
            pass

    if info["redirect_sigalg"] and "sha1" in str(info["redirect_sigalg"]).lower():
        info["weak_redirect_sigalg"] = True
    else:
        info["weak_redirect_sigalg"] = False
    # Deduplicate relay/evidence while preserving order.
    info["relaystate_values"] = list(dict.fromkeys(info["relaystate_values"]))
    info["evidence"] = list(dict.fromkeys(info["evidence"]))
    return info


def _selected_acs(sp_md: dict[str, Any], req: dict[str, Any] | None, resp: dict[str, Any] | None) -> list[dict[str, Any]]:
    sp = sp_md.get("sp") or {}
    endpoints = sp.get("assertion_consumer_services") or []
    if req and req.get("acs_index") is not None:
        return [e for e in endpoints if str(e.get("index")) == str(req.get("acs_index"))]
    target = (req or {}).get("acs_url") or (resp or {}).get("destination")
    if target:
        return [e for e in endpoints if e.get("location") == target]
    defaults = [e for e in endpoints if str(e.get("is_default") or "").lower() in {"true", "1"}]
    if defaults:
        return defaults
    return endpoints[:1]


def _authn_request_for_nameidpolicy(
    requests: list[dict[str, Any]],
    resp: dict[str, Any] | None,
    assertion: dict[str, Any],
) -> dict[str, Any] | None:
    """Correlate NameIDPolicy via Response/SubjectConfirmation InResponseTo, not document order."""
    irt = (resp or {}).get("in_response_to") if resp else None
    if not irt:
        for sc in (assertion.get("subject") or {}).get("confirmations") or []:
            irt = (sc.get("data") or {}).get("InResponseTo")
            if irt:
                break
    if irt:
        for r in requests:
            if r.get("id") == irt:
                return r
        return None
    if len(requests) == 1:
        return requests[0]
    return None


def _relevant_sp_entity_ids(assertion: dict[str, Any], sp_entity_ids: list[str]) -> list[str]:
    audiences = (assertion.get("conditions") or {}).get("audiences") or []
    if audiences:
        return [x for x in sp_entity_ids if x in audiences]
    if len(sp_entity_ids) == 1:
        return list(sp_entity_ids)
    return []


def validate_saml(
    *,
    raw_input: str,
    requests: list[dict[str, Any]],
    responses: list[dict[str, Any]],
    standalone_assertions: list[dict[str, Any]],
    metadata: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Standards/profile-oriented SAML validation.

    ERROR is reserved for a violated MUST/schema-level requirement or a response
    that explicitly reports SSO failure. WARNING is used where binding/profile
    context is incomplete, crypto cannot be verified, or the finding is a hardening
    concern rather than an XML/SAML validity failure.
    """
    issues: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    transport = _detect_transport(raw_input)
    req = requests[-1] if requests else None
    resp = responses[-1] if responses else None
    response_assertions = (resp.get("assertions") or []) if resp else []
    assertions = response_assertions or standalone_assertions
    sp_metadata = [m for m in metadata if "SP" in (m.get("roles") or [])]
    idp_metadata = [m for m in metadata if "IdP" in (m.get("roles") or [])]
    sp_entity_ids = [m.get("entity_id") for m in sp_metadata if m.get("entity_id")]
    idp_entity_ids = [m.get("entity_id") for m in idp_metadata if m.get("entity_id")]

    # -------- AuthnRequest: Core + Web Browser SSO profile --------
    for i, r in enumerate(requests, 1):
        scope = f"AuthnRequest #{i}"
        issues.extend(_validate_common_message(r, scope, "AUTHNREQUEST", "SAML Core 2.0 §3.2.1 RequestAbstractType"))
        issues.extend(_validate_issuer(r.get("issuer"), scope, "AUTHNREQUEST", required=True, browser_profile=True))
        issues.extend(_validate_signature_shape(r.get("signature"), scope, "AUTHNREQUEST", r.get("id")))
        if r.get("destination") and not _valid_uri(r.get("destination")):
            issues.append(_issue("AUTHNREQUEST_DESTINATION_INVALID", "ERROR", scope, "Destination is not a valid URI.", observed=r.get("destination"), standard="SAML Core 2.0 §3.2.1"))
        if r.get("consent") and not _valid_uri(r.get("consent")):
            issues.append(_issue("AUTHNREQUEST_CONSENT_INVALID", "ERROR", scope, "Consent is not a valid URI.", observed=r.get("consent"), standard="SAML Core 2.0 §3.2.1 / §8.4"))
        if r.get("acs_url") and not _valid_uri(r.get("acs_url")):
            issues.append(_issue("AUTHNREQUEST_ACS_INVALID", "ERROR", scope, "AssertionConsumerServiceURL is not a valid URI.", observed=r.get("acs_url"), standard="SAML Core 2.0 §3.4.1"))
        if r.get("protocol_binding") and not _valid_uri(r.get("protocol_binding")):
            issues.append(_issue("AUTHNREQUEST_PROTOCOL_BINDING_INVALID", "ERROR", scope, "ProtocolBinding is not a valid URI.", observed=r.get("protocol_binding"), standard="SAML Core 2.0 §3.4.1"))
        if r.get("acs_index") is not None and (r.get("acs_url") or r.get("protocol_binding")):
            issues.append(_issue(
                "AUTHNREQUEST_ACS_INDEX_MUTUAL_EXCLUSION", "ERROR", scope,
                "AssertionConsumerServiceIndex is mutually exclusive with AssertionConsumerServiceURL and ProtocolBinding.",
                observed={"AssertionConsumerServiceIndex": r.get("acs_index"), "AssertionConsumerServiceURL": r.get("acs_url"), "ProtocolBinding": r.get("protocol_binding")},
                expected="use ACS index OR ACS URL/ProtocolBinding",
                standard="SAML Core 2.0 §3.4.1",
            ))
        if r.get("acs_index") is not None and not _unsigned_short_ok(r.get("acs_index")):
            issues.append(_issue("AUTHNREQUEST_ACS_INDEX_INVALID", "ERROR", scope, "AssertionConsumerServiceIndex must be a non-negative integer.", observed=r.get("acs_index"), expected="non-negative integer", standard="SAML Core 2.0 AuthnRequestType"))
        if r.get("attribute_consuming_service_index") is not None and not _unsigned_short_ok(r.get("attribute_consuming_service_index")):
            issues.append(_issue("AUTHNREQUEST_ATTRIBUTE_CONSUMING_INDEX_INVALID", "ERROR", scope, "AttributeConsumingServiceIndex must be a non-negative integer.", observed=r.get("attribute_consuming_service_index"), expected="non-negative integer", standard="SAML Core 2.0 AuthnRequestType"))
        for attr in ("force_authn", "is_passive"):
            if not _bool_lexical_ok(r.get(attr)):
                issues.append(_issue(f"AUTHNREQUEST_{attr.upper()}_INVALID", "ERROR", scope, f"{attr} is not a valid XML boolean.", observed=r.get(attr), expected="true/false/1/0"))
        nip = r.get("name_id_policy") or {}
        if nip.get("AllowCreate") is not None and not _bool_lexical_ok(nip.get("AllowCreate")):
            issues.append(_issue("NAMEIDPOLICY_ALLOWCREATE_INVALID", "ERROR", scope, "NameIDPolicy AllowCreate is not a valid XML boolean.", observed=nip.get("AllowCreate"), expected="true/false/1/0", standard="SAML Core 2.0 NameIDPolicyType"))
        if "SPNameQualifier" in nip:
            spq = nip.get("SPNameQualifier")
            if not spq or not str(spq).strip() or not _valid_uri(spq) or len(str(spq)) > 1024:
                issues.append(_issue("NAMEIDPOLICY_SPNAMEQUALIFIER_INVALID", "ERROR", scope, "NameIDPolicy SPNameQualifier must identify an SP/affiliation with a URI of at most 1024 characters. An empty attribute is not omission.", observed=spq, expected="entity identifier URI <= 1024", standard="SAML Core 2.0 NameIDPolicyType"))
        if "Format" in nip:
            nip_fmt = nip.get("Format")
            if not nip_fmt or not str(nip_fmt).strip() or not _valid_uri(nip_fmt):
                issues.append(_issue("NAMEIDPOLICY_FORMAT_INVALID_URI", "ERROR", scope, "NameIDPolicy Format is present but is not a valid URI. An empty Format is not equivalent to omitting Format.", observed=nip_fmt, standard="SAML Core 2.0 §3.4.1.1"))
        if nip.get("Format") == TRANSIENT_FORMAT and str(nip.get("AllowCreate") or "") in {"true", "1"}:
            issues.append(_issue("NAMEIDPOLICY_TRANSIENT_ALLOWCREATE", "ERROR", scope, "AllowCreate must not be used with transient NameID format.", observed=nip, standard="SAML V2.0 Approved Errata"))
        comp = (r.get("requested_authn_context") or {}).get("comparison")
        if comp and comp not in {"exact", "minimum", "maximum", "better"}:
            issues.append(_issue("REQUESTED_AUTHN_CONTEXT_COMPARISON_INVALID", "ERROR", scope, "RequestedAuthnContext Comparison has an invalid value.", observed=comp, expected="exact|minimum|maximum|better", standard="SAML Core 2.0 AuthnContextComparisonType"))
        for class_ref in (r.get("requested_authn_context") or {}).get("class_refs") or []:
            if not _valid_uri(class_ref):
                issues.append(_issue("REQUESTED_AUTHN_CONTEXT_CLASSREF_INVALID", "ERROR", scope, "Requested AuthnContextClassRef is not a valid URI.", observed=class_ref, standard="SAML Core 2.0 RequestedAuthnContext"))

    if transport.get("redirect_signature_parameter_present") and not transport.get("redirect_sigalg"):
        issues.append(_issue("REDIRECT_SIGNATURE_WITHOUT_SIGALG", "ERROR", "Transport", "HTTP-Redirect Signature parameter is present without SigAlg.", standard="SAML Bindings 2.0 HTTP-Redirect"))
    if transport.get("redirect_sigalg") and not transport.get("redirect_signature_parameter_present"):
        issues.append(_issue("REDIRECT_SIGALG_WITHOUT_SIGNATURE", "ERROR", "Transport", "HTTP-Redirect SigAlg is present without Signature.", standard="SAML Bindings 2.0 HTTP-Redirect"))
    if transport.get("weak_redirect_sigalg"):
        issues.append(_issue("REDIRECT_SHA1", "WARNING", "Transport", "HTTP-Redirect signature uses SHA-1, which is obsolete for modern deployments.", observed=transport.get("redirect_sigalg"), standard="Security hardening"))

    # -------- Response: Core + Web Browser SSO --------
    for ri, r in enumerate(responses, 1):
        scope = f"Response #{ri}"
        issues.extend(_validate_common_message(r, scope, "RESPONSE", "SAML Core 2.0 §3.2.2 StatusResponseType"))
        issues.extend(_validate_issuer(r.get("issuer"), scope, "RESPONSE", required=False, browser_profile=True))
        issues.extend(_validate_signature_shape(r.get("signature"), scope, "RESPONSE", r.get("id")))
        codes = r.get("status_codes") or []
        if not codes:
            issues.append(_issue("RESPONSE_STATUS_MISSING", "ERROR", scope, "Required samlp:Status/StatusCode is missing.", expected="Status with StatusCode Value", standard="SAML Core 2.0 §3.2.2"))
        else:
            top = codes[0]
            if top not in TOP_STATUS_CODES:
                issues.append(_issue("RESPONSE_TOP_STATUS_INVALID", "ERROR", scope, "Top-level StatusCode is not one of the SAML-defined top-level status codes.", observed=top, expected=sorted(TOP_STATUS_CODES), standard="SAML Core 2.0 §3.2.2.2"))
            if top != SUCCESS:
                issues.append(_issue("SSO_RESPONSE_ERROR_STATUS", "ERROR", scope, "SAML Response reports an unsuccessful SSO status.", observed=codes, expected=SUCCESS, standard="SAML protocol status (message may still be structurally valid)"))
                if (r.get("assertions") or []) or r.get("encrypted_assertion_count"):
                    issues.append(_issue("ERROR_RESPONSE_CONTAINS_ASSERTION", "ERROR", scope, "A Web Browser SSO error Response must not include assertions.", observed={"assertions": len(r.get("assertions") or []), "encrypted": r.get("encrypted_assertion_count")}, expected=0, standard="SAML Profiles 2.0 §4.1.4.2"))
            else:
                if not (r.get("assertions") or []) and not r.get("encrypted_assertion_count"):
                    issues.append(_issue("SUCCESS_RESPONSE_NO_ASSERTION", "ERROR", scope, "Successful Web Browser SSO Response must contain at least one Assertion.", expected=">= 1 Assertion", standard="SAML Profiles 2.0 §4.1.4.2"))
        if r.get("consent") and not _valid_uri(r.get("consent")):
            issues.append(_issue("RESPONSE_CONSENT_INVALID", "ERROR", scope, "Consent is not a valid URI.", observed=r.get("consent"), standard="SAML Core 2.0 §3.2.2 / §8.4"))
        for nested_code in (r.get("status_codes") or [])[1:]:
            if not _valid_uri(nested_code):
                issues.append(_issue("RESPONSE_NESTED_STATUS_INVALID", "ERROR", scope, "Nested StatusCode Value is not a valid URI.", observed=nested_code, standard="SAML Core 2.0 StatusCodeType"))
        if req:
            if not r.get("in_response_to"):
                issues.append(_issue("RESPONSE_INRESPONSETO_MISSING", "ERROR", scope, "Response to a known request must carry InResponseTo.", observed=None, expected=req.get("id"), standard="SAML Core 2.0 §3.2.2"))
            elif req.get("id") and r.get("in_response_to") != req.get("id"):
                issues.append(_issue("RESPONSE_INRESPONSETO_MISMATCH", "ERROR", scope, "Response InResponseTo does not match AuthnRequest ID.", observed=r.get("in_response_to"), expected=req.get("id"), standard="SAML Core 2.0 §3.2.2"))
        if r.get("encrypted_assertion_count"):
            issues.append(_issue("ENCRYPTED_ASSERTION_NOT_INSPECTED", "WARNING", scope, "EncryptedAssertion is present; inner assertion structure, subject, audience and signature cannot be validated without the SP private key.", observed=r.get("encrypted_assertion_count")))

    # Infer response binding from request/metadata where possible.
    inferred_response_binding = transport.get("response_binding")
    if not inferred_response_binding and req and req.get("protocol_binding"):
        inferred_response_binding = req.get("protocol_binding")
    if not inferred_response_binding and resp and sp_metadata:
        for md in sp_metadata:
            for ep in _selected_acs(md, req, resp):
                if ep.get("binding"):
                    inferred_response_binding = ep.get("binding")
                    break
            if inferred_response_binding:
                break
    transport["inferred_response_binding"] = inferred_response_binding

    # -------- Assertions --------
    for ai, a in enumerate(assertions, 1):
        scope = f"Assertion #{ai}"
        issues.extend(_validate_common_message(a, scope, "ASSERTION", "SAML Core 2.0 §2.3.3 Assertion"))
        issues.extend(_validate_issuer(a.get("issuer"), scope, "ASSERTION", required=True, browser_profile=bool(resp)))
        issues.extend(_validate_signature_shape(a.get("signature"), scope, "ASSERTION", a.get("id")))

        subject = a.get("subject") or {}
        nameid = subject.get("name_id") or {}
        confirmations = subject.get("confirmations") or []
        has_subject_content = bool(
            nameid.get("element_present")
            or nameid.get("value")
            or subject.get("encrypted_id_present")
            or subject.get("base_id_present")
            or confirmations
        )
        if resp and not has_subject_content:
            issues.append(_issue("BROWSER_SSO_SUBJECT_MISSING", "ERROR", scope, "Web Browser SSO assertion must contain a Subject with usable subject confirmation.", expected="Subject + bearer SubjectConfirmation", standard="SAML Profiles 2.0 §4.1.4.2"))

        if subject.get("nameid_count", 0) > 1:
            issues.append(_issue("SUBJECT_NAMEID_DUPLICATE", "ERROR", scope, "Subject contains more than one NameID. Schema allows at most one of BaseID, NameID or EncryptedID.", observed=subject.get("nameid_count"), expected="maxOccurs=1", standard="SAML Core 2.0 SubjectType"))
        choice = subject.get("subject_identifier_choice_count") or 0
        if choice > 1:
            issues.append(_issue("SUBJECT_IDENTIFIER_CHOICE_INVALID", "ERROR", scope, "Subject contains more than one of BaseID, NameID and EncryptedID. These identifier forms are mutually exclusive.", observed=choice, expected="exactly one of BaseID | NameID | EncryptedID", standard="SAML Core 2.0 SubjectType"))

        enc_id = subject.get("encrypted_id")
        if subject.get("encrypted_id_present") and enc_id:
            content = enc_id.get("content_encryption")
            key_enc = enc_id.get("key_encryption") or []
            issues.append(_issue(
                "ENCRYPTED_ID_PRESENT",
                "INFO",
                scope,
                "EncryptedID was detected. The analyzer can inspect the XML Encryption structure and algorithms, but cannot recover the plaintext NameID without the corresponding SP private key.",
                observed={
                    "content encryption": content,
                    "key encryption": key_enc[0] if len(key_enc) == 1 else key_enc,
                    "KeyInfo present": enc_id.get("key_info_present"),
                    "EncryptedKey count": enc_id.get("encrypted_key_count"),
                },
                expected="SP private key required for decryption",
                standard="SAML Core 2.0 §2.2.4 EncryptedID / XML Encryption",
            ))
            if not enc_id.get("content_encryption_method_present"):
                issues.append(_issue(
                    "ENCRYPTED_ID_ENCRYPTION_METHOD_MISSING",
                    "WARNING",
                    scope,
                    "EncryptedID EncryptedData has no EncryptionMethod Algorithm. XML Encryption allows the omission if the recipient already knows the algorithm; typical SAML libraries cannot decrypt without it.",
                    observed={"content encryption": content},
                    expected="xenc:EncryptionMethod Algorithm on EncryptedData",
                    standard="XML Encryption EncryptedType EncryptionMethod (optional) / SAML Core 2.0 §2.2.4",
                ))
            if enc_id.get("encrypted_key_missing_encryption_method_count"):
                issues.append(_issue(
                    "ENCRYPTED_ID_KEY_ENCRYPTION_METHOD_MISSING",
                    "WARNING",
                    scope,
                    "EncryptedID contains EncryptedKey without EncryptionMethod. XML Encryption allows the omission if the recipient already knows the key wrap algorithm; python3-saml / xmlsec typically fail this case.",
                    observed={"EncryptedKey count": enc_id.get("encrypted_key_count"), "key encryption": key_enc},
                    expected="xenc:EncryptionMethod Algorithm on EncryptedKey",
                    standard="XML Encryption EncryptedKey EncryptionMethod (optional)",
                ))
            if not enc_id.get("key_info_present") and not enc_id.get("encrypted_key_count"):
                issues.append(_issue(
                    "ENCRYPTED_ID_KEYINFO_MISSING",
                    "WARNING",
                    scope,
                    "EncryptedID EncryptedData has no ds:KeyInfo and no EncryptedKey. XML Encryption allows KeyInfo to be omitted if the recipient already has the key; python3-saml treats this as invalid and a typical Web SSO SP cannot unwrap the content key from the message.",
                    observed={"KeyInfo present": False, "EncryptedKey count": 0},
                    expected="ds:KeyInfo with EncryptedKey, or a sibling xenc:EncryptedKey",
                    standard="XML Encryption EncryptedData KeyInfo (optional) / SAML Core 2.0 EncryptedElementType",
                ))

        issues.extend(
            validate_nameid(
                nameid,
                scope,
                idp_entity_ids=idp_entity_ids,
                sp_entity_ids=_relevant_sp_entity_ids(a, sp_entity_ids),
                assertion_issuer=(a.get("issuer") or {}).get("value"),
            )
        )
        fmt = nameid.get("format")

        policy_req = _authn_request_for_nameidpolicy(requests, resp, a)
        if requests and policy_req is None and len(requests) > 1:
            issues.append(_issue("NAMEIDPOLICY_REQUEST_NOT_CORRELATED", "INFO", scope, "Multiple AuthnRequest documents are present and none matches this Response/assertion InResponseTo, so NameIDPolicy Format comparison was not performed.", standard="SAML Core 2.0 §3.2.2 InResponseTo"))
        elif policy_req:
            nip = policy_req.get("name_id_policy") or {}
            requested_fmt = nip.get("Format")
            if requested_fmt == ENCRYPTED_FORMAT:
                if not subject.get("encrypted_id_present"):
                    issues.append(_issue("NAMEIDPOLICY_ENCRYPTED_NOT_SATISFIED", "ERROR", scope, "AuthnRequest requested encrypted NameID but Assertion does not contain EncryptedID.", expected="EncryptedID", standard="SAML Approved Errata E15"))
            elif requested_fmt and requested_fmt not in {UNSPECIFIED_FORMAT} and nameid.get("value"):
                if (fmt or UNSPECIFIED_FORMAT) != requested_fmt:
                    issues.append(_issue("NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH", "ERROR", scope, "Returned NameID Format does not match AuthnRequest NameIDPolicy.", observed=fmt or UNSPECIFIED_FORMAT, expected=requested_fmt, standard="SAML Core 2.0 NameIDPolicy + Approved Errata E15"))
                requested_spq = nip.get("SPNameQualifier")
                if requested_spq and nameid.get("sp_name_qualifier") != requested_spq:
                    issues.append(_issue("NAMEIDPOLICY_SPNAMEQUALIFIER_MISMATCH", "ERROR", scope, "Returned NameID SPNameQualifier does not match AuthnRequest NameIDPolicy.", observed=nameid.get("sp_name_qualifier"), expected=requested_spq, standard="SAML Approved Errata E15"))

        bearer = [sc for sc in confirmations if sc.get("method") == BEARER_METHOD]
        for ci, sc in enumerate(confirmations, 1):
            if not sc.get("method"):
                issues.append(_issue("SUBJECTCONFIRMATION_METHOD_MISSING", "ERROR", f"{scope} SubjectConfirmation #{ci}", "SubjectConfirmation Method is required.", standard="SAML Core 2.0 SubjectConfirmationType"))
            elif not _valid_uri(sc.get("method")):
                issues.append(_issue("SUBJECTCONFIRMATION_METHOD_INVALID", "ERROR", f"{scope} SubjectConfirmation #{ci}", "SubjectConfirmation Method is not a valid URI.", observed=sc.get("method"), standard="SAML Core 2.0 SubjectConfirmationType"))
        if resp and not bearer:
            issues.append(_issue("BROWSER_SSO_BEARER_CONFIRMATION_MISSING", "ERROR", scope, "Web Browser SSO assertion must contain at least one bearer SubjectConfirmation.", expected=BEARER_METHOD, standard="SAML Profiles 2.0 §4.1.4.2 + Errata E52"))

        for bi, sc in enumerate(bearer, 1):
            sc_scope = f"{scope} bearer SubjectConfirmation #{bi}"
            data = sc.get("data") or {}
            if not data.get("Recipient"):
                issues.append(_issue("BEARER_RECIPIENT_MISSING", "ERROR", sc_scope, "Bearer SubjectConfirmationData requires Recipient.", standard="SAML Profiles 2.0 §4.1.4.2 + Errata E52"))
            elif not _valid_uri(data.get("Recipient")):
                issues.append(_issue("BEARER_RECIPIENT_INVALID", "ERROR", sc_scope, "Recipient is not a valid URI.", observed=data.get("Recipient")))
            if not data.get("NotOnOrAfter"):
                issues.append(_issue("BEARER_NOTONORAFTER_MISSING", "ERROR", sc_scope, "Bearer SubjectConfirmationData requires NotOnOrAfter.", standard="SAML Profiles 2.0 §4.1.4.2 + Errata E52"))
            elif _parse_time(data.get("NotOnOrAfter")) is None:
                issues.append(_issue("BEARER_NOTONORAFTER_INVALID", "ERROR", sc_scope, "SubjectConfirmationData NotOnOrAfter is not a valid timezone-aware dateTime.", observed=data.get("NotOnOrAfter")))
            elif not _is_utc_time(data.get("NotOnOrAfter")):
                issues.append(_issue("BEARER_NOTONORAFTER_NOT_UTC", "ERROR", sc_scope, "SubjectConfirmationData NotOnOrAfter must be expressed in UTC.", observed=data.get("NotOnOrAfter"), expected="UTC", standard="SAML Core 2.0 §1.3.3"))
            elif now >= _parse_time(data.get("NotOnOrAfter")):
                issues.append(_issue("BEARER_CONFIRMATION_EXPIRED", "ERROR", sc_scope, "Bearer SubjectConfirmationData has expired at analyzer runtime.", observed=data.get("NotOnOrAfter"), expected=f"> {now.isoformat()}", standard="SAML Profiles 2.0 §4.1.4.3"))
            if data.get("NotBefore"):
                issues.append(_issue("BEARER_NOTBEFORE_FORBIDDEN", "ERROR", sc_scope, "Bearer SubjectConfirmationData must not contain NotBefore.", observed=data.get("NotBefore"), expected="omitted", standard="SAML Profiles 2.0 Approved Errata E52"))
            if req:
                if not data.get("InResponseTo"):
                    issues.append(_issue("BEARER_INRESPONSETO_MISSING", "ERROR", sc_scope, "Solicited Browser SSO bearer SubjectConfirmationData requires InResponseTo.", expected=req.get("id"), standard="SAML Profiles 2.0 §4.1.4.2/§4.1.4.3"))
                elif req.get("id") and data.get("InResponseTo") != req.get("id"):
                    issues.append(_issue("BEARER_INRESPONSETO_MISMATCH", "ERROR", sc_scope, "SubjectConfirmationData InResponseTo does not match AuthnRequest ID.", observed=data.get("InResponseTo"), expected=req.get("id"), standard="SAML Profiles 2.0 §4.1.4.3"))

        cond = a.get("conditions") or {}
        nb_raw = cond.get("NotBefore")
        noa_raw = cond.get("NotOnOrAfter")
        nb = _parse_time(nb_raw)
        noa = _parse_time(noa_raw)
        if nb_raw and nb is None:
            issues.append(_issue("CONDITIONS_NOTBEFORE_INVALID", "ERROR", scope, "Conditions NotBefore is not a valid timezone-aware dateTime.", observed=nb_raw))
        elif nb_raw and not _is_utc_time(nb_raw):
            issues.append(_issue("CONDITIONS_NOTBEFORE_NOT_UTC", "ERROR", scope, "Conditions NotBefore must be expressed in UTC.", observed=nb_raw, expected="UTC", standard="SAML Core 2.0 §1.3.3"))
        if noa_raw and noa is None:
            issues.append(_issue("CONDITIONS_NOTONORAFTER_INVALID", "ERROR", scope, "Conditions NotOnOrAfter is not a valid timezone-aware dateTime.", observed=noa_raw))
        elif noa_raw and not _is_utc_time(noa_raw):
            issues.append(_issue("CONDITIONS_NOTONORAFTER_NOT_UTC", "ERROR", scope, "Conditions NotOnOrAfter must be expressed in UTC.", observed=noa_raw, expected="UTC", standard="SAML Core 2.0 §1.3.3"))
        if nb and noa and nb >= noa:
            issues.append(_issue("CONDITIONS_INTERVAL_INVALID", "ERROR", scope, "Conditions validity interval is empty or inverted (NotBefore >= NotOnOrAfter).", observed={"NotBefore": nb_raw, "NotOnOrAfter": noa_raw}, expected="NotBefore < NotOnOrAfter"))
        if nb and now < nb:
            issues.append(_issue("ASSERTION_NOT_YET_VALID", "ERROR", scope, "Assertion is not yet valid at analyzer runtime.", observed=nb_raw, expected=f"<= {now.isoformat()}", standard="SAML Core 2.0 Conditions processing"))
        if noa and now >= noa:
            issues.append(_issue("ASSERTION_EXPIRED", "ERROR", scope, "Assertion Conditions have expired at analyzer runtime.", observed=noa_raw, expected=f"> {now.isoformat()}", standard="SAML Core 2.0 Conditions processing"))
        if resp and bearer and not (cond.get("audience_restrictions") or []):
            issues.append(_issue("AUDIENCE_RESTRICTION_MISSING", "ERROR", scope, "Bearer Web Browser SSO assertion must contain AudienceRestriction including the SP identifier.", expected="AudienceRestriction/Audience", standard="SAML Profiles 2.0 §4.1.4.2"))
        for gi, group in enumerate(cond.get("audience_restrictions") or [], 1):
            if not group:
                issues.append(_issue("AUDIENCE_RESTRICTION_EMPTY", "ERROR", scope, f"AudienceRestriction group #{gi} contains no Audience values.", standard="SAML Assertion schema/profile"))
            for aud in group:
                if not _valid_uri(aud):
                    issues.append(_issue("AUDIENCE_INVALID_URI", "ERROR", scope, "Audience value is not a valid URI.", observed=aud))
        proxy = cond.get("proxy_restriction") or {}
        if proxy:
            if proxy.get("count") is not None and not _nonnegative_int_ok(proxy.get("count")):
                issues.append(_issue("PROXY_RESTRICTION_COUNT_INVALID", "ERROR", scope, "ProxyRestriction Count must be a non-negative integer.", observed=proxy.get("count"), expected="non-negative integer", standard="SAML Core 2.0 ProxyRestrictionType"))
            for aud in proxy.get("audiences") or []:
                if not _valid_uri(aud):
                    issues.append(_issue("PROXY_RESTRICTION_AUDIENCE_INVALID", "ERROR", scope, "ProxyRestriction Audience is not a valid URI.", observed=aud, standard="SAML Core 2.0 ProxyRestrictionType"))

        for si, st in enumerate(a.get("authn_statements") or [], 1):
            st_scope = f"{scope} AuthnStatement #{si}"
            authn_raw = st.get("AuthnInstant")
            authn_dt = _parse_time(authn_raw)
            if not authn_raw:
                issues.append(_issue("AUTHNINSTANT_MISSING", "ERROR", st_scope, "AuthnStatement requires AuthnInstant.", standard="SAML Assertion schema"))
            elif authn_dt is None:
                issues.append(_issue("AUTHNINSTANT_INVALID", "ERROR", st_scope, "AuthnInstant is not a valid timezone-aware dateTime.", observed=authn_raw))
            elif not _is_utc_time(authn_raw):
                issues.append(_issue("AUTHNINSTANT_NOT_UTC", "ERROR", st_scope, "AuthnInstant must be expressed in UTC.", observed=authn_raw, expected="UTC", standard="SAML Core 2.0 §1.3.3"))
            if not (st.get("authn_context_class_ref") or st.get("authn_context_decl_ref") or st.get("authn_context_decl_present")):
                issues.append(_issue("AUTHNCONTEXT_MISSING", "ERROR", st_scope, "AuthnStatement must contain an AuthnContext identifying/describing the authentication context.", standard="SAML Core 2.0 AuthnStatementType"))
            session_noa = _parse_time(st.get("SessionNotOnOrAfter"))
            if st.get("SessionNotOnOrAfter") and session_noa is None:
                issues.append(_issue("SESSION_NOTONORAFTER_INVALID", "ERROR", st_scope, "SessionNotOnOrAfter is not a valid timezone-aware dateTime.", observed=st.get("SessionNotOnOrAfter")))
            elif st.get("SessionNotOnOrAfter") and not _is_utc_time(st.get("SessionNotOnOrAfter")):
                issues.append(_issue("SESSION_NOTONORAFTER_NOT_UTC", "ERROR", st_scope, "SessionNotOnOrAfter must be expressed in UTC.", observed=st.get("SessionNotOnOrAfter"), expected="UTC", standard="SAML Core 2.0 §1.3.3"))
            if st.get("authn_context_class_ref") and not _valid_uri(st.get("authn_context_class_ref")):
                issues.append(_issue("AUTHNCONTEXT_CLASSREF_INVALID", "ERROR", st_scope, "AuthnContextClassRef is not a valid URI.", observed=st.get("authn_context_class_ref"), standard="SAML Core 2.0 AuthnContext"))
            if st.get("authn_context_decl_ref") and not _valid_uri(st.get("authn_context_decl_ref")):
                issues.append(_issue("AUTHNCONTEXT_DECLREF_INVALID", "ERROR", st_scope, "AuthnContextDeclRef is not a valid URI.", observed=st.get("authn_context_decl_ref"), standard="SAML Core 2.0 AuthnContext"))
            for authority in st.get("authenticating_authorities") or []:
                if not _valid_uri(authority):
                    issues.append(_issue("AUTHENTICATING_AUTHORITY_INVALID", "ERROR", st_scope, "AuthenticatingAuthority is not a valid URI.", observed=authority, standard="SAML Core 2.0 AuthnContext"))
            if authn_dt and session_noa and session_noa <= authn_dt:
                issues.append(_issue("SESSION_INTERVAL_INVALID", "ERROR", st_scope, "SessionNotOnOrAfter is not later than AuthnInstant.", observed={"AuthnInstant": authn_raw, "SessionNotOnOrAfter": st.get("SessionNotOnOrAfter")}, expected="SessionNotOnOrAfter > AuthnInstant"))

        for ati, attr in enumerate(a.get("attributes") or [], 1):
            attr_scope = f"{scope} Attribute #{ati}"
            if not attr.get("name"):
                issues.append(_issue("ATTRIBUTE_NAME_MISSING", "ERROR", attr_scope, "SAML Attribute Name is required.", standard="SAML Core 2.0 AttributeType"))
            if attr.get("name_format") and not _valid_uri(attr.get("name_format")):
                issues.append(_issue("ATTRIBUTE_NAMEFORMAT_INVALID_URI", "ERROR", attr_scope, "Attribute NameFormat is not a valid URI.", observed=attr.get("name_format")))
            xsi_types = [t for t in (attr.get("xsi_types") or []) if t]
            assigned = [t for t in (attr.get("xsi_types") or [])]
            if any(assigned) and (len(set(xsi_types)) != 1 or any(t is None for t in assigned)):
                issues.append(_issue(
                    "ATTRIBUTE_VALUE_TYPE_MISMATCH",
                    "ERROR",
                    attr_scope,
                    "If any AttributeValue has xsi:type, every AttributeValue of that Attribute must use the identical datatype.",
                    observed=assigned,
                    expected="identical xsi:type on every AttributeValue, or omit xsi:type on all",
                    standard="SAML Core 2.0 §2.7.3.1 AttributeValue",
                ))

        # Core identifies an Attribute by Name + NameFormat (omitted NameFormat = unspecified).
        # AttributeStatement schema allows repeats; AttributeQuery MUST NOT repeat the same pair.
        name_groups: dict[tuple[str, str], list[list[Any]]] = {}
        for attr in a.get("attributes") or []:
            name = attr.get("name")
            if not name:
                continue
            fmt = (attr.get("name_format") or "").strip() or UNSPECIFIED_ATTR_FORMAT
            name_groups.setdefault((name, fmt), []).append(list(attr.get("values") or []))
        for (name, name_format), value_groups in name_groups.items():
            if len(value_groups) < 2:
                continue
            issues.append(_issue(
                "ATTRIBUTE_NAME_DUPLICATE",
                "WARNING",
                scope,
                "The same SAML attribute (Name + NameFormat) appears more than once. Core identifies attributes by that pair and RECOMMENDS multiple values as AttributeValue children of one Attribute. Repeating the Attribute element is not forbidden in AttributeStatement, but AttributeQuery MUST NOT name an attribute twice, and many SPs keep only one occurrence.",
                observed={"name": name, "name_format": name_format, "occurrences": len(value_groups), "value_groups": value_groups},
                expected="one Attribute element per Name+NameFormat (multi-valued via AttributeValue)",
                standard="SAML Core 2.0 §2.7.3.1 AttributeType and §3.3.2.3 AttributeQuery",
            ))

        enc_attrs = a.get("encrypted_attributes") or []
        if enc_attrs:
            content = list(dict.fromkeys(e.get("content_encryption") for e in enc_attrs if e.get("content_encryption")))
            key_enc = list(dict.fromkeys(
                name
                for e in enc_attrs
                for name in (e.get("key_encryption") or [])
                if name
            ))
            issues.append(_issue(
                "ENCRYPTED_ATTRIBUTE_PRESENT",
                "INFO",
                scope,
                "Encrypted AttributeStatement content was detected. The analyzer can inspect the XML Encryption structure and algorithms, but cannot recover the plaintext attribute without the corresponding SP private key.",
                observed={
                    "EncryptedAttribute count": len(enc_attrs),
                    "content encryption": content[0] if len(content) == 1 else content,
                    "key encryption": key_enc[0] if len(key_enc) == 1 else key_enc,
                },
                expected="SP private key required for decryption",
                standard="SAML Core 2.0 §2.7.3.2 EncryptedAttribute / XML Encryption",
            ))

    # Successful browser SSO response needs at least one AuthnStatement across the set.
    if resp and (resp.get("status_codes") or [None])[0] == SUCCESS and assertions:
        if sum(len(a.get("authn_statements") or []) for a in assertions) == 0:
            issues.append(_issue("AUTHNSTATEMENT_MISSING", "ERROR", "Response", "Successful Web Browser SSO assertion set must contain at least one AuthnStatement.", expected=">= 1 AuthnStatement", standard="SAML Profiles 2.0 §4.1.4.2"))
        issuers = [_issuer_value(a.get("issuer")) for a in assertions if _issuer_value(a.get("issuer"))]
        if len(set(issuers)) > 1:
            issues.append(_issue("MULTIPLE_ASSERTION_ISSUERS", "ERROR", "Response", "All assertions in a Web Browser SSO response must be issued by the same entity.", observed=issuers, standard="SAML Profiles 2.0 §4.1.4.2 + Approved Errata"))

    # HTTP-POST signature protection rule (errata permits Response OR each Assertion signature).
    if resp and (resp.get("status_codes") or [None])[0] == SUCCESS and assertions:
        response_signed = bool((resp.get("signature") or {}).get("present"))
        unsigned_assertions = [i for i, a in enumerate(assertions, 1) if not (a.get("signature") or {}).get("present")]
        if inferred_response_binding == HTTP_POST:
            if not response_signed and unsigned_assertions:
                issues.append(_issue("POST_ASSERTION_NOT_SIGNATURE_PROTECTED", "ERROR", "Response", "HTTP-POST Web Browser SSO requires every assertion to be protected by a digital signature (Response signature or individual Assertion signature).", observed={"response_signed": response_signed, "unsigned_assertions": unsigned_assertions}, expected="signed Response OR every Assertion signed", standard="SAML Profiles 2.0 §4.1.4.5 + Approved Errata"))
        elif not response_signed and len(unsigned_assertions) == len(assertions):
            issues.append(_issue("NO_SIGNATURE_BINDING_UNKNOWN", "WARNING", "Response", "No XML signature is present. This is invalid for Web Browser SSO HTTP-POST, but the analyzer cannot prove the response binding from the supplied input.", observed="no Response/Assertion Signature", standard="SAML Profiles 2.0 §4.1.4.5"))

    # -------- Metadata structural validity / expiration --------
    for mi, md in enumerate(metadata, 1):
        scope = f"Metadata entity #{mi}"
        eid = md.get("entity_id")
        if not eid:
            issues.append(_issue("METADATA_ENTITYID_MISSING", "ERROR", scope, "EntityDescriptor entityID is required.", expected="unique URI", standard="SAML Metadata 2.0 §2.3.2"))
        elif not _valid_uri(eid) or len(eid) > 1024:
            issues.append(_issue("METADATA_ENTITYID_INVALID", "ERROR", scope, "entityID must be a URI of at most 1024 characters.", observed=eid, expected="URI <= 1024", standard="SAML Metadata 2.0 / SAML Core entity identifier"))
        vu = md.get("valid_until")
        if vu:
            vudt = _parse_time(vu)
            if vudt is None:
                issues.append(_issue("METADATA_VALIDUNTIL_INVALID", "ERROR", scope, "Metadata validUntil is not a valid timezone-aware dateTime.", observed=vu))
            elif now >= vudt:
                issues.append(_issue("METADATA_EXPIRED", "ERROR", scope, "Metadata has expired at analyzer runtime.", observed=vu, expected=f"> {now.isoformat()}", standard="SAML Metadata 2.0 caching/validity rules"))
        if not md.get("roles"):
            issues.append(_issue("METADATA_NO_SSO_ROLE", "WARNING", scope, "EntityDescriptor contains no SPSSODescriptor or IDPSSODescriptor, so this SSO analyzer has no SSO role to validate."))
        for ci, contact in enumerate(md.get("contacts") or [], 1):
            cscope = f"{scope} ContactPerson #{ci}"
            if contact.get("type") not in {"technical", "support", "administrative", "billing", "other"}:
                issues.append(_issue("METADATA_CONTACT_TYPE_INVALID", "ERROR", cscope, "ContactPerson contactType is required and must use a metadata-defined value.", observed=contact.get("type"), expected="technical|support|administrative|billing|other"))
        org = md.get("organization")
        if org is not None:
            if not (org.get("names") or []):
                issues.append(_issue("METADATA_ORG_NAME_MISSING", "ERROR", scope, "Organization requires at least one OrganizationName."))
            if not (org.get("display_names") or []):
                issues.append(_issue("METADATA_ORG_DISPLAYNAME_MISSING", "ERROR", scope, "Organization requires at least one OrganizationDisplayName."))
            if not (org.get("urls") or []):
                issues.append(_issue("METADATA_ORG_URL_MISSING", "ERROR", scope, "Organization requires at least one OrganizationURL."))
            for url in org.get("urls") or []:
                if not _valid_uri(url):
                    issues.append(_issue("METADATA_ORG_URL_INVALID", "ERROR", scope, "OrganizationURL is not a valid URI.", observed=url))

        sp = md.get("sp")
        if sp:
            pse = sp.get("protocol_support_enumeration")
            if not pse:
                issues.append(_issue("SP_METADATA_PROTOCOL_SUPPORT_MISSING", "ERROR", scope, "SPSSODescriptor protocolSupportEnumeration is required.", expected=SAML2_PROTOCOL, standard="SAML Metadata 2.0 RoleDescriptor"))
            elif SAML2_PROTOCOL not in pse.split():
                issues.append(_issue("SP_METADATA_SAML2_PROTOCOL_MISSING", "ERROR", scope, "SPSSODescriptor does not advertise the SAML 2.0 protocol.", observed=pse, expected=SAML2_PROTOCOL))
            for flag_name, flag_value in (("AuthnRequestsSigned", sp.get("authn_requests_signed")), ("WantAssertionsSigned", sp.get("want_assertions_signed"))):
                if flag_value is not None and not _bool_lexical_ok(flag_value):
                    issues.append(_issue("SP_METADATA_BOOLEAN_INVALID", "ERROR", scope, f"SPSSODescriptor {flag_name} is not a valid XML boolean.", observed=flag_value, expected="true/false/1/0"))
            for fmt in sp.get("name_id_formats") or []:
                if not _valid_uri(fmt):
                    issues.append(_issue("SP_METADATA_NAMEIDFORMAT_INVALID", "ERROR", scope, "SP metadata NameIDFormat is not a valid URI.", observed=fmt))
            acs = sp.get("assertion_consumer_services") or []
            if not acs:
                issues.append(_issue("SP_METADATA_ACS_MISSING", "ERROR", scope, "SPSSODescriptor requires at least one AssertionConsumerService endpoint for SSO.", standard="SAML Metadata 2.0 SPSSODescriptor"))
            indexes = []
            defaults = 0
            for ei, ep in enumerate(acs, 1):
                ep_scope = f"{scope} ACS #{ei}"
                if not ep.get("binding"):
                    issues.append(_issue("ACS_BINDING_MISSING", "ERROR", ep_scope, "AssertionConsumerService Binding is required."))
                elif not _valid_uri(ep.get("binding")):
                    issues.append(_issue("ACS_BINDING_INVALID", "ERROR", ep_scope, "AssertionConsumerService Binding is not a valid URI.", observed=ep.get("binding")))
                if not ep.get("location"):
                    issues.append(_issue("ACS_LOCATION_MISSING", "ERROR", ep_scope, "AssertionConsumerService Location is required."))
                elif not _valid_uri(ep.get("location")):
                    issues.append(_issue("ACS_LOCATION_INVALID", "ERROR", ep_scope, "AssertionConsumerService Location is not a valid URI.", observed=ep.get("location")))
                if ep.get("index") is None:
                    issues.append(_issue("ACS_INDEX_MISSING", "ERROR", ep_scope, "AssertionConsumerService index is required."))
                else:
                    indexes.append(str(ep.get("index")))
                    if not _unsigned_short_ok(ep.get("index")):
                        issues.append(_issue("ACS_INDEX_INVALID", "ERROR", ep_scope, "AssertionConsumerService index must be a non-negative integer.", observed=ep.get("index"), expected="non-negative integer"))
                if ep.get("is_default") is not None and not _bool_lexical_ok(ep.get("is_default")):
                    issues.append(_issue("ACS_ISDEFAULT_INVALID", "ERROR", ep_scope, "AssertionConsumerService isDefault is not a valid XML boolean.", observed=ep.get("is_default"), expected="true/false/1/0"))
                if ep.get("response_location") and not _valid_uri(ep.get("response_location")):
                    issues.append(_issue("ACS_RESPONSELOCATION_INVALID", "ERROR", ep_scope, "AssertionConsumerService ResponseLocation is not a valid URI.", observed=ep.get("response_location")))
                if str(ep.get("is_default") or "").lower() in {"true", "1"}:
                    defaults += 1
            if len(indexes) != len(set(indexes)):
                issues.append(_issue("ACS_INDEX_DUPLICATE", "ERROR", scope, "AssertionConsumerService indexes must be unique within the SP role.", observed=indexes))
            if defaults > 1:
                issues.append(_issue("ACS_MULTIPLE_DEFAULTS", "ERROR", scope, "More than one AssertionConsumerService is marked isDefault=true.", observed=defaults, expected="0 or 1"))
            for ei, ep in enumerate(sp.get("single_logout_services") or [], 1):
                ep_scope = f"{scope} SP SLO #{ei}"
                if not ep.get("binding") or not _valid_uri(ep.get("binding")):
                    issues.append(_issue("SP_SLO_BINDING_INVALID", "ERROR", ep_scope, "SingleLogoutService Binding is required and must be a URI.", observed=ep.get("binding")))
                if not ep.get("location") or not _valid_uri(ep.get("location")):
                    issues.append(_issue("SP_SLO_LOCATION_INVALID", "ERROR", ep_scope, "SingleLogoutService Location is required and must be a URI.", observed=ep.get("location")))
                if ep.get("response_location") and not _valid_uri(ep.get("response_location")):
                    issues.append(_issue("SP_SLO_RESPONSELOCATION_INVALID", "ERROR", ep_scope, "SingleLogoutService ResponseLocation is not a valid URI.", observed=ep.get("response_location")))
            for ai, svc in enumerate(sp.get("attribute_consuming_services") or [], 1):
                svc_scope = f"{scope} AttributeConsumingService #{ai}"
                if svc.get("index") is None or not _unsigned_short_ok(svc.get("index")):
                    issues.append(_issue("ATTRIBUTE_CONSUMING_SERVICE_INDEX_INVALID", "ERROR", svc_scope, "AttributeConsumingService requires a non-negative index.", observed=svc.get("index"), expected="non-negative integer"))
                if svc.get("is_default") is not None and not _bool_lexical_ok(svc.get("is_default")):
                    issues.append(_issue("ATTRIBUTE_CONSUMING_SERVICE_ISDEFAULT_INVALID", "ERROR", svc_scope, "AttributeConsumingService isDefault is not a valid XML boolean.", observed=svc.get("is_default"), expected="true/false/1/0"))
                if not (svc.get("service_names") or []):
                    issues.append(_issue("ATTRIBUTE_CONSUMING_SERVICE_NAME_MISSING", "ERROR", svc_scope, "AttributeConsumingService requires at least one ServiceName."))
                for rai, ra in enumerate(svc.get("requested_attributes") or [], 1):
                    ra_scope = f"{svc_scope} RequestedAttribute #{rai}"
                    if not ra.get("name"):
                        issues.append(_issue("REQUESTED_ATTRIBUTE_NAME_MISSING", "ERROR", ra_scope, "RequestedAttribute Name is required."))
                    if ra.get("name_format") and not _valid_uri(ra.get("name_format")):
                        issues.append(_issue("REQUESTED_ATTRIBUTE_NAMEFORMAT_INVALID", "ERROR", ra_scope, "RequestedAttribute NameFormat is not a valid URI.", observed=ra.get("name_format")))
                    if ra.get("is_required") is not None and not _bool_lexical_ok(ra.get("is_required")):
                        issues.append(_issue("REQUESTED_ATTRIBUTE_ISREQUIRED_INVALID", "ERROR", ra_scope, "RequestedAttribute isRequired is not a valid XML boolean.", observed=ra.get("is_required"), expected="true/false/1/0"))
            for ki, key in enumerate(sp.get("keys") or [], 1):
                key_scope = f"{scope} SP KeyDescriptor #{ki}"
                if key.get("use") not in {"unspecified", "signing", "encryption"}:
                    issues.append(_issue("SP_METADATA_KEY_USE_INVALID", "ERROR", key_scope, "KeyDescriptor use must be signing or encryption when present.", observed=key.get("use"), expected="signing|encryption"))
                if not key.get("key_info_present"):
                    issues.append(_issue("SP_METADATA_KEYINFO_MISSING", "ERROR", key_scope, "KeyDescriptor requires ds:KeyInfo."))
                if "unparseable certificate" in (key.get("x509_sha256_fingerprints") or []):
                    issues.append(_issue("SP_METADATA_X509_MALFORMED", "ERROR", key_scope, "SP metadata contains an unparseable X509Certificate."))
                for alg in key.get("encryption_methods") or []:
                    if not _valid_uri(alg):
                        issues.append(_issue("SP_METADATA_ENCRYPTION_METHOD_INVALID", "ERROR", key_scope, "EncryptionMethod Algorithm is not a valid URI.", observed=alg))

        idp = md.get("idp")
        if idp:
            pse = idp.get("protocol_support_enumeration")
            if not pse:
                issues.append(_issue("IDP_METADATA_PROTOCOL_SUPPORT_MISSING", "ERROR", scope, "IDPSSODescriptor protocolSupportEnumeration is required.", expected=SAML2_PROTOCOL, standard="SAML Metadata 2.0 RoleDescriptor"))
            elif SAML2_PROTOCOL not in pse.split():
                issues.append(_issue("IDP_METADATA_SAML2_PROTOCOL_MISSING", "ERROR", scope, "IDPSSODescriptor does not advertise the SAML 2.0 protocol.", observed=pse, expected=SAML2_PROTOCOL))
            if idp.get("want_authn_requests_signed") is not None and not _bool_lexical_ok(idp.get("want_authn_requests_signed")):
                issues.append(_issue("IDP_METADATA_WANT_AUTHNREQUESTS_SIGNED_INVALID", "ERROR", scope, "IDPSSODescriptor WantAuthnRequestsSigned is not a valid XML boolean.", observed=idp.get("want_authn_requests_signed"), expected="true/false/1/0"))
            for fmt in idp.get("name_id_formats") or []:
                if not _valid_uri(fmt):
                    issues.append(_issue("IDP_METADATA_NAMEIDFORMAT_INVALID", "ERROR", scope, "IdP metadata NameIDFormat is not a valid URI.", observed=fmt))
            sso = idp.get("single_sign_on_services") or []
            if not sso:
                issues.append(_issue("IDP_METADATA_SSO_SERVICE_MISSING", "ERROR", scope, "IDPSSODescriptor requires at least one SingleSignOnService endpoint.", standard="SAML Metadata 2.0 IDPSSODescriptor"))
            for ei, ep in enumerate(sso, 1):
                ep_scope = f"{scope} SSO #{ei}"
                if not ep.get("binding"):
                    issues.append(_issue("SSO_BINDING_MISSING", "ERROR", ep_scope, "SingleSignOnService Binding is required."))
                elif not _valid_uri(ep.get("binding")):
                    issues.append(_issue("SSO_BINDING_INVALID", "ERROR", ep_scope, "SingleSignOnService Binding is not a valid URI.", observed=ep.get("binding")))
                if not ep.get("location"):
                    issues.append(_issue("SSO_LOCATION_MISSING", "ERROR", ep_scope, "SingleSignOnService Location is required."))
                elif not _valid_uri(ep.get("location")):
                    issues.append(_issue("SSO_LOCATION_INVALID", "ERROR", ep_scope, "SingleSignOnService Location is not a valid URI.", observed=ep.get("location")))
                if ep.get("response_location") and not _valid_uri(ep.get("response_location")):
                    issues.append(_issue("SSO_RESPONSELOCATION_INVALID", "ERROR", ep_scope, "SingleSignOnService ResponseLocation is not a valid URI.", observed=ep.get("response_location")))
            for ei, ep in enumerate(idp.get("single_logout_services") or [], 1):
                ep_scope = f"{scope} IdP SLO #{ei}"
                if not ep.get("binding") or not _valid_uri(ep.get("binding")):
                    issues.append(_issue("IDP_SLO_BINDING_INVALID", "ERROR", ep_scope, "SingleLogoutService Binding is required and must be a URI.", observed=ep.get("binding")))
                if not ep.get("location") or not _valid_uri(ep.get("location")):
                    issues.append(_issue("IDP_SLO_LOCATION_INVALID", "ERROR", ep_scope, "SingleLogoutService Location is required and must be a URI.", observed=ep.get("location")))
                if ep.get("response_location") and not _valid_uri(ep.get("response_location")):
                    issues.append(_issue("IDP_SLO_RESPONSELOCATION_INVALID", "ERROR", ep_scope, "SingleLogoutService ResponseLocation is not a valid URI.", observed=ep.get("response_location")))
            artifact_indexes = []
            for ei, ep in enumerate(idp.get("artifact_resolution_services") or [], 1):
                ep_scope = f"{scope} ArtifactResolutionService #{ei}"
                if not ep.get("binding") or not _valid_uri(ep.get("binding")):
                    issues.append(_issue("ARTIFACT_RESOLUTION_BINDING_INVALID", "ERROR", ep_scope, "ArtifactResolutionService Binding is required and must be a URI.", observed=ep.get("binding")))
                if not ep.get("location") or not _valid_uri(ep.get("location")):
                    issues.append(_issue("ARTIFACT_RESOLUTION_LOCATION_INVALID", "ERROR", ep_scope, "ArtifactResolutionService Location is required and must be a URI.", observed=ep.get("location")))
                if ep.get("index") is None or not _unsigned_short_ok(ep.get("index")):
                    issues.append(_issue("ARTIFACT_RESOLUTION_INDEX_INVALID", "ERROR", ep_scope, "ArtifactResolutionService requires a non-negative index.", observed=ep.get("index"), expected="non-negative integer"))
                else:
                    artifact_indexes.append(str(ep.get("index")))
                if ep.get("is_default") is not None and not _bool_lexical_ok(ep.get("is_default")):
                    issues.append(_issue("ARTIFACT_RESOLUTION_ISDEFAULT_INVALID", "ERROR", ep_scope, "ArtifactResolutionService isDefault is not a valid XML boolean.", observed=ep.get("is_default"), expected="true/false/1/0"))
            if len(artifact_indexes) != len(set(artifact_indexes)):
                issues.append(_issue("ARTIFACT_RESOLUTION_INDEX_DUPLICATE", "ERROR", scope, "ArtifactResolutionService indexes must be unique.", observed=artifact_indexes))
            for ki, key in enumerate(idp.get("keys") or [], 1):
                key_scope = f"{scope} IdP KeyDescriptor #{ki}"
                if key.get("use") not in {"unspecified", "signing", "encryption"}:
                    issues.append(_issue("IDP_METADATA_KEY_USE_INVALID", "ERROR", key_scope, "KeyDescriptor use must be signing or encryption when present.", observed=key.get("use"), expected="signing|encryption"))
                if not key.get("key_info_present"):
                    issues.append(_issue("IDP_METADATA_KEYINFO_MISSING", "ERROR", key_scope, "KeyDescriptor requires ds:KeyInfo."))
                if "unparseable certificate" in (key.get("x509_sha256_fingerprints") or []):
                    issues.append(_issue("IDP_METADATA_X509_MALFORMED", "ERROR", key_scope, "IdP metadata contains an unparseable X509Certificate."))
                for alg in key.get("encryption_methods") or []:
                    if not _valid_uri(alg):
                        issues.append(_issue("IDP_METADATA_ENCRYPTION_METHOD_INVALID", "ERROR", key_scope, "EncryptionMethod Algorithm is not a valid URI.", observed=alg))

    # -------- Cross-document SSO consistency: turn important mismatches into errors --------
    sp_entity_ids = [m.get("entity_id") for m in sp_metadata if m.get("entity_id")]
    idp_entity_ids = [m.get("entity_id") for m in idp_metadata if m.get("entity_id")]
    sp_acs_locations = list(dict.fromkeys(
        ep.get("location")
        for m in sp_metadata
        for ep in ((m.get("sp") or {}).get("assertion_consumer_services") or [])
        if ep.get("location")
    ))
    idp_sso_locations = list(dict.fromkeys(
        ep.get("location")
        for m in idp_metadata
        for ep in ((m.get("idp") or {}).get("single_sign_on_services") or [])
        if ep.get("location")
    ))

    if req:
        req_issuer = _issuer_value(req.get("issuer"))
        if sp_entity_ids and req_issuer and req_issuer not in sp_entity_ids:
            issues.append(_issue("AUTHNREQUEST_ISSUER_SP_ENTITYID_MISMATCH", "ERROR", "AuthnRequest", "AuthnRequest Issuer does not match any supplied SP metadata entityID.", observed=req_issuer, expected=sp_entity_ids, standard="SAML Profiles 2.0 Web Browser SSO + SAML Metadata 2.0"))
        if idp_sso_locations and req.get("destination") and req.get("destination") not in idp_sso_locations:
            issues.append(_issue("AUTHNREQUEST_DESTINATION_IDP_SSO_MISMATCH", "ERROR", "AuthnRequest", "AuthnRequest Destination is not an SSO endpoint advertised by the supplied IdP metadata.", observed=req.get("destination"), expected=idp_sso_locations, standard="SAML Core Destination processing + SAML Metadata 2.0"))
        if sp_acs_locations and req.get("acs_url") and req.get("acs_url") not in sp_acs_locations:
            issues.append(_issue("AUTHNREQUEST_ACS_SP_METADATA_MISMATCH", "ERROR", "AuthnRequest", "AuthnRequest AssertionConsumerServiceURL is not registered in supplied SP metadata.", observed=req.get("acs_url"), expected=sp_acs_locations, standard="SAML Web Browser SSO / SP metadata ACS selection"))
        if req.get("attribute_consuming_service_index") is not None and sp_metadata:
            available = [
                str(svc.get("index"))
                for m in sp_metadata
                for svc in ((m.get("sp") or {}).get("attribute_consuming_services") or [])
                if svc.get("index") is not None
            ]
            if str(req.get("attribute_consuming_service_index")) not in available:
                issues.append(_issue("AUTHNREQUEST_ATTRIBUTE_CONSUMING_INDEX_NOT_FOUND", "ERROR", "AuthnRequest", "AttributeConsumingServiceIndex does not exist in supplied SP metadata.", observed=req.get("attribute_consuming_service_index"), expected=available, standard="SAML Core AuthnRequest + SAML Metadata AttributeConsumingService"))

    if req and resp and req.get("acs_url") and resp.get("destination") and req.get("acs_url") != resp.get("destination"):
        issues.append(_issue("RESPONSE_DESTINATION_REQUEST_ACS_MISMATCH", "ERROR", "Response", "Response Destination does not match the ACS URL requested by the AuthnRequest.", observed=resp.get("destination"), expected=req.get("acs_url"), standard="SAML destination/recipient validation for Web Browser SSO"))

    if resp:
        expected_acs = _expected_response_acs(req, sp_acs_locations)
        for ri, r in enumerate(responses, 1):
            issues.extend(_validate_response_destination(r, f"Response #{ri}", expected_acs))
        if sp_acs_locations and resp.get("destination") and resp.get("destination") not in sp_acs_locations:
            issues.append(_issue("RESPONSE_DESTINATION_SP_ACS_MISMATCH", "ERROR", "Response", "Response Destination is not one of the ACS endpoints registered in supplied SP metadata.", observed=resp.get("destination"), expected=sp_acs_locations, standard="SAML Core Destination processing + SAML Metadata 2.0"))
        response_issuer = _issuer_value(resp.get("issuer"))
        if idp_entity_ids and response_issuer and response_issuer not in idp_entity_ids:
            issues.append(_issue("RESPONSE_ISSUER_IDP_ENTITYID_MISMATCH", "ERROR", "Response", "Response Issuer does not match any supplied IdP metadata entityID.", observed=response_issuer, expected=idp_entity_ids, standard="SAML Web Browser SSO issuer identification"))

        for ai, a in enumerate(assertions, 1):
            ascope = f"Assertion #{ai}"
            assertion_issuer = _issuer_value(a.get("issuer"))
            if idp_entity_ids and assertion_issuer and assertion_issuer not in idp_entity_ids:
                issues.append(_issue("ASSERTION_ISSUER_IDP_ENTITYID_MISMATCH", "ERROR", ascope, "Assertion Issuer does not match any supplied IdP metadata entityID.", observed=assertion_issuer, expected=idp_entity_ids, standard="SAML Profiles 2.0 Web Browser SSO"))
            if response_issuer and assertion_issuer and response_issuer != assertion_issuer:
                issues.append(_issue("RESPONSE_ASSERTION_ISSUER_MISMATCH", "ERROR", ascope, "Response Issuer and Assertion Issuer identify different entities.", observed={"Response": response_issuer, "Assertion": assertion_issuer}, expected="same issuing IdP for Browser SSO", standard="SAML Profiles 2.0 Web Browser SSO"))

            cond = a.get("conditions") or {}
            groups = cond.get("audience_restrictions") or []
            expected_sp_ids = sp_entity_ids or ([_issuer_value(req.get("issuer"))] if req and _issuer_value(req.get("issuer")) else [])
            if expected_sp_ids:
                for gi, group in enumerate(groups, 1):
                    # Multiple AudienceRestriction elements are ANDed; therefore the SP
                    # must satisfy every restriction, not merely appear somewhere in the flattened list.
                    if group and not any(spid in group for spid in expected_sp_ids):
                        issues.append(_issue("AUDIENCE_SP_ENTITYID_MISMATCH", "ERROR", f"{ascope} AudienceRestriction #{gi}", "AudienceRestriction does not include the expected SP entityID.", observed=group, expected=expected_sp_ids, standard="SAML Core AudienceRestriction + Web Browser SSO profile"))

            bearer = [sc for sc in ((a.get("subject") or {}).get("confirmations") or []) if sc.get("method") == BEARER_METHOD]
            recipients = [((sc.get("data") or {}).get("Recipient")) for sc in bearer if (sc.get("data") or {}).get("Recipient")]
            allowed_acs = sp_acs_locations or ([req.get("acs_url")] if req and req.get("acs_url") else ([resp.get("destination")] if resp.get("destination") else []))
            if recipients and allowed_acs and not any(rec in allowed_acs for rec in recipients):
                issues.append(_issue("BEARER_RECIPIENT_ACS_MISMATCH", "ERROR", ascope, "No bearer SubjectConfirmation Recipient matches the expected/registered ACS endpoint.", observed=recipients, expected=allowed_acs, standard="SAML Profiles 2.0 §4.1.4.3"))
            if recipients and resp.get("destination") and resp.get("destination") not in recipients:
                issues.append(_issue("RESPONSE_DESTINATION_RECIPIENT_MISMATCH", "ERROR", ascope, "Response Destination does not match any bearer SubjectConfirmation Recipient.", observed=resp.get("destination"), expected=recipients, standard="SAML Profiles 2.0 bearer recipient processing"))
            if req and recipients and req.get("acs_url") and req.get("acs_url") not in recipients:
                issues.append(_issue("REQUEST_ACS_RECIPIENT_MISMATCH", "ERROR", ascope, "AuthnRequest ACS does not match any bearer SubjectConfirmation Recipient.", observed=recipients, expected=req.get("acs_url"), standard="SAML Profiles 2.0 bearer recipient processing"))

            # RequestedAuthnContext 'exact' can be evaluated without vendor-specific assurance ordering.
            if req:
                rac = req.get("requested_authn_context") or {}
                requested_classes = rac.get("class_refs") or []
                if requested_classes and (rac.get("comparison") or "exact") == "exact":
                    returned_classes = [st.get("authn_context_class_ref") for st in a.get("authn_statements") or [] if st.get("authn_context_class_ref")]
                    if returned_classes and not any(rc in requested_classes for rc in returned_classes):
                        issues.append(_issue("AUTHNCONTEXT_EXACT_MISMATCH", "ERROR", ascope, "Returned AuthnContextClassRef does not satisfy RequestedAuthnContext Comparison=exact.", observed=returned_classes, expected=requested_classes, standard="SAML Core 2.0 RequestedAuthnContext processing"))

    # If IdP metadata advertises SLO support, Browser SSO AuthnStatements need a
    # SessionIndex so the session can be targeted by the Single Logout profile.
    idp_supports_slo = any(((m.get("idp") or {}).get("single_logout_services") or []) for m in idp_metadata)
    if resp and idp_supports_slo:
        for ai, a in enumerate(assertions, 1):
            for si, st in enumerate(a.get("authn_statements") or [], 1):
                if not st.get("SessionIndex"):
                    issues.append(_issue("SESSIONINDEX_MISSING_WITH_SLO", "ERROR", f"Assertion #{ai} AuthnStatement #{si}", "IdP metadata advertises Single Logout, but AuthnStatement has no SessionIndex.", expected="SessionIndex", standard="SAML Profiles 2.0 Web Browser SSO / Single Logout"))

    # Multiple assertions in one Browser SSO response must refer to the same
    # principal. Exact NameID equality is only a safe hard check when the format
    # and qualifiers are the same; otherwise we cannot prove principal mismatch.
    if resp and len(assertions) > 1:
        principals = []
        for a in assertions:
            n = ((a.get("subject") or {}).get("name_id") or {})
            if n.get("value"):
                principals.append((n.get("format"), n.get("name_qualifier"), n.get("sp_name_qualifier"), n.get("value")))
        if len(principals) > 1:
            comparable = {(x[0], x[1], x[2]) for x in principals}
            if len(comparable) == 1 and len({x[3] for x in principals}) > 1:
                issues.append(_issue("MULTIPLE_ASSERTION_SUBJECT_MISMATCH", "ERROR", "Response", "Multiple assertions use the same NameID format/qualifiers but different subject identifiers.", observed=[x[3] for x in principals], expected="same principal", standard="SAML Profiles 2.0 Web Browser SSO + Approved Errata"))
            elif len(set(principals)) > 1:
                issues.append(_issue("MULTIPLE_ASSERTION_SUBJECT_UNVERIFIED", "WARNING", "Response", "Multiple assertions carry different Subject/NameID representations. Browser SSO requires them to refer to the same principal, but equivalence cannot be proven from syntax alone.", observed=principals, standard="SAML Profiles 2.0 Web Browser SSO + Approved Errata"))

    # -------- Cross-metadata/profile requirements --------
    if req:
        actual_req_signed = bool((req.get("signature") or {}).get("present")) or bool(transport.get("redirect_signature_present"))
        for mi, md in enumerate(idp_metadata, 1):
            idp = md.get("idp") or {}
            if str(idp.get("want_authn_requests_signed") or "").lower() in {"true", "1"} and not actual_req_signed:
                issues.append(_issue("IDP_REQUIRES_SIGNED_AUTHNREQUEST", "ERROR", f"IdP metadata #{mi}", "IdP metadata requires signed AuthnRequests, but no XML or HTTP-Redirect binding signature was detected.", observed=False, expected=True, standard="SAML Metadata 2.0 + Approved Errata E7"))
            req_fmt = (req.get("name_id_policy") or {}).get("Format")
            formats = idp.get("name_id_formats") or []
            if req_fmt and formats and req_fmt not in {UNSPECIFIED_FORMAT, ENCRYPTED_FORMAT} and req_fmt not in formats:
                issues.append(_issue("NAMEIDPOLICY_NOT_ADVERTISED_BY_IDP", "ERROR", f"IdP metadata #{mi}", "AuthnRequest NameIDPolicy Format is not advertised by the IdP metadata.", observed=req_fmt, expected=formats))
        for mi, md in enumerate(sp_metadata, 1):
            sp = md.get("sp") or {}
            if str(sp.get("authn_requests_signed") or "").lower() in {"true", "1"} and not actual_req_signed:
                issues.append(_issue("SP_SAYS_AUTHNREQUEST_SIGNED_BUT_UNSIGNED", "ERROR", f"SP metadata #{mi}", "SP metadata says AuthnRequestsSigned=true, but the supplied AuthnRequest is not signed/protected by a detected Redirect signature.", observed=False, expected=True, standard="SAML Metadata 2.0"))
            selected = _selected_acs(md, req, resp)
            if req.get("acs_index") is not None and not selected:
                issues.append(_issue("AUTHNREQUEST_ACS_INDEX_NOT_FOUND", "ERROR", f"SP metadata #{mi}", "AuthnRequest AssertionConsumerServiceIndex does not exist in SP metadata.", observed=req.get("acs_index"), expected=[e.get("index") for e in sp.get("assertion_consumer_services") or []]))
            if req.get("protocol_binding") and selected:
                bindings = [e.get("binding") for e in selected if e.get("binding")]
                if bindings and req.get("protocol_binding") not in bindings:
                    issues.append(_issue("AUTHNREQUEST_PROTOCOL_BINDING_ACS_MISMATCH", "ERROR", f"SP metadata #{mi}", "AuthnRequest ProtocolBinding does not match the selected ACS Binding in SP metadata.", observed=req.get("protocol_binding"), expected=bindings))

    for mi, md in enumerate(sp_metadata, 1):
        sp = md.get("sp") or {}
        formats = sp.get("name_id_formats") or []
        for ai, a in enumerate(assertions, 1):
            nameid = ((a.get("subject") or {}).get("name_id") or {})
            if formats and nameid.get("format") and nameid.get("format") not in formats:
                issues.append(_issue("ASSERTION_NAMEID_FORMAT_NOT_ADVERTISED_BY_SP", "ERROR", f"SP metadata #{mi} / Assertion #{ai}", "Assertion NameID Format is not advertised by SP metadata.", observed=nameid.get("format"), expected=formats))
            if str(sp.get("want_assertions_signed") or "").lower() in {"true", "1"} and not (a.get("signature") or {}).get("present"):
                issues.append(_issue("SP_WANTS_ASSERTION_SIGNED", "ERROR", f"SP metadata #{mi} / Assertion #{ai}", "SP metadata has WantAssertionsSigned=true but the Assertion itself is not signed.", observed=False, expected=True, standard="SAML Metadata 2.0"))

    # Duplicate IDs are dangerous because XML signatures and correlation rely on unique IDs.
    seen_ids: dict[str, str] = {}
    for i, r in enumerate(requests, 1):
        if r.get("id"):
            if r["id"] in seen_ids:
                issues.append(_issue("DUPLICATE_SAML_ID", "ERROR", f"AuthnRequest #{i}", "Duplicate SAML ID detected across supplied documents.", observed=r["id"], expected="unique ID", note=f"First seen in {seen_ids[r['id']]}"))
            else:
                seen_ids[r["id"]] = f"AuthnRequest #{i}"
    for i, r in enumerate(responses, 1):
        if r.get("id"):
            if r["id"] in seen_ids:
                issues.append(_issue("DUPLICATE_SAML_ID", "ERROR", f"Response #{i}", "Duplicate SAML ID detected across supplied documents.", observed=r["id"], expected="unique ID", note=f"First seen in {seen_ids[r['id']]}"))
            else:
                seen_ids[r["id"]] = f"Response #{i}"
        for j, a in enumerate(r.get("assertions") or [], 1):
            if a.get("id"):
                if a["id"] in seen_ids:
                    issues.append(_issue("DUPLICATE_SAML_ID", "ERROR", f"Response #{i} Assertion #{j}", "Duplicate SAML ID detected across supplied documents.", observed=a["id"], expected="unique ID", note=f"First seen in {seen_ids[a['id']]}"))
                else:
                    seen_ids[a["id"]] = f"Response #{i} Assertion #{j}"
    # A raw XML bundle can cause the same Assertion to be discovered both inside a
    # Response and as a standalone XML fragment. Do not report that parser-level
    # duplication as a SAML duplicate-ID vulnerability. Standalone assertions are
    # checked for duplicate IDs only when no Response assertions were supplied.
    if not response_assertions:
        for i, a in enumerate(standalone_assertions, 1):
            if a.get("id"):
                if a["id"] in seen_ids:
                    issues.append(_issue("DUPLICATE_SAML_ID", "ERROR", f"Standalone Assertion #{i}", "Duplicate SAML ID detected across supplied documents.", observed=a["id"], expected="unique ID", note=f"First seen in {seen_ids[a['id']]}"))
                else:
                    seen_ids[a["id"]] = f"Standalone Assertion #{i}"

    # Stable ordering: hard errors first, then warnings/info, while preserving discovery order.
    rank = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    issues = sorted(enumerate(issues), key=lambda x: (rank.get(x[1]["severity"], 9), x[0]))
    issues = [x[1] for x in issues]
    return issues, transport
