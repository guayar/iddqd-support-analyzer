from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import urllib.parse
import zlib
from datetime import datetime, timezone
from typing import Any

from defusedxml import ElementTree as ET

from .saml_validation import validate_saml

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xenc": "http://www.w3.org/2001/04/xmlenc#",
}

SAMLISH_ROOTS = {"AuthnRequest", "Response", "Assertion", "EntityDescriptor", "EntitiesDescriptor"}
_SAML_ROOT_RE = re.compile(
    r"<(?:[A-Za-z_][\w.-]*:)?(?:AuthnRequest|Response|Assertion|EntityDescriptor|EntitiesDescriptor)\b",
    re.I,
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(el):
    return (el.text or "").strip() if el is not None else None


def _all_text(el) -> str | None:
    if el is None:
        return None
    value = "".join(el.itertext()).strip()
    return value or None


def _attrs(el, keys):
    if el is None:
        return {}
    return {k: el.attrib.get(k) for k in keys if el.attrib.get(k) is not None}


def _nameid_from_element(el) -> dict[str, Any] | None:
    """Extract NameID with attribute-presence flags (empty string ≠ omitted)."""
    if el is None:
        return None
    raw = el.text if el.text is not None else ""
    stripped = raw.strip()
    return {
        "element_present": True,
        "value": stripped,
        "raw_value": raw,
        "empty": not stripped,
        "format": el.attrib.get("Format"),
        "format_present": "Format" in el.attrib,
        "name_qualifier": el.attrib.get("NameQualifier"),
        "name_qualifier_present": "NameQualifier" in el.attrib,
        "sp_name_qualifier": el.attrib.get("SPNameQualifier"),
        "sp_name_qualifier_present": "SPNameQualifier" in el.attrib,
        "sp_provided_id": el.attrib.get("SPProvidedID"),
        "sp_provided_id_present": "SPProvidedID" in el.attrib,
    }


def _issuer(el) -> dict[str, Any] | None:
    if el is None:
        return None
    return {
        "value": _text(el),
        "format": el.attrib.get("Format"),
        "name_qualifier": el.attrib.get("NameQualifier"),
        "sp_name_qualifier": el.attrib.get("SPNameQualifier"),
        "sp_provided_id": el.attrib.get("SPProvidedID"),
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
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _looks_like_xml_bytes(data: bytes) -> bool:
    stripped = data.lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    return stripped.startswith(b"<")


def _decode_bytes_as_xml(data: bytes) -> str | None:
    if not _looks_like_xml_bytes(data):
        return None
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-16", errors="strict")
        except Exception:
            return None
    if any(x in text for x in ("AuthnRequest", "Response", "Assertion", "EntityDescriptor", "EntitiesDescriptor", "urn:oasis:names:tc:SAML")):
        return text
    return None


def _b64decode_loose(raw: str) -> bytes | None:
    compact = re.sub(r"\s+", "", raw)
    if len(compact) < 16:
        return None
    pad = "=" * ((4 - len(compact) % 4) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            if decoder is base64.b64decode:
                return decoder(compact + pad, validate=False)
            return decoder((compact + pad).encode("ascii"))
        except Exception:
            continue
    return None


def _decode_saml_payload(value: str) -> list[tuple[str, str]]:
    """Return decoded XML variants with an explanation of the encoding chain.

    Supports raw XML, URL encoding, HTTP-POST Base64 and Redirect binding
    URL->Base64->raw DEFLATE. It intentionally does not recursively decode
    arbitrary Base64 text inside parsed XML (e.g. X509Certificate).
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(text: str, chain: str):
        text = text.strip()
        if text and text not in seen:
            seen.add(text)
            out.append((text, chain))

    raw = html.unescape(value.strip())
    if not raw:
        return []

    if "<" in raw and any(k in raw for k in SAMLISH_ROOTS):
        add(raw, "raw XML")

    variants = [(raw, "raw")]
    # Do not use unquote_plus here: a literal '+' is valid Base64 data. Form/query
    # parsing already converts '+' to space where HTML form semantics require it.
    unquoted = urllib.parse.unquote(raw)
    if unquoted != raw:
        variants.append((unquoted, "URL-decoded"))

    # Two levels are useful for copied form bodies / tracer exports without
    # wandering into arbitrary nested Base64 data such as certificates.
    for text_variant, prefix in variants:
        current = text_variant
        for level in range(2):
            data = _b64decode_loose(current)
            if data is None:
                break
            xml = _decode_bytes_as_xml(data)
            if xml:
                add(xml, f"{prefix} + Base64" if level == 0 else f"{prefix} + Base64 x{level + 1}")
                break

            for wbits, label in ((-15, "raw DEFLATE"), (zlib.MAX_WBITS, "zlib"), (16 + zlib.MAX_WBITS, "gzip")):
                try:
                    inflated = zlib.decompress(data, wbits)
                except Exception:
                    continue
                xml = _decode_bytes_as_xml(inflated)
                if xml:
                    add(xml, f"{prefix} + Base64 + {label}")
                    break
            try:
                current = data.decode("utf-8", errors="strict")
            except Exception:
                break

    return out


def _har_payloads(text: str) -> list[tuple[str, str]]:
    try:
        obj = json.loads(text)
    except Exception:
        return []
    out: list[tuple[str, str]] = []
    entries = (((obj or {}).get("log") or {}).get("entries") or []) if isinstance(obj, dict) else []
    for entry in entries:
        req = entry.get("request") or {}
        post = req.get("postData") or {}
        params = post.get("params") or []
        for p in params:
            if p.get("name") in {"SAMLRequest", "SAMLResponse"} and p.get("value"):
                out.append((str(p["value"]), f"HAR {p.get('name')}"))
        if post.get("text"):
            out.append((str(post["text"]), "HAR POST body"))
        url = req.get("url")
        if url and ("SAMLRequest=" in url or "SAMLResponse=" in url):
            out.append((url, "HAR URL"))
    return out


def _extract_candidates(text: str) -> list[tuple[str, str]]:
    text = html.unescape(text.strip())
    candidates: list[tuple[str, str]] = [(text, "input")]
    candidates.extend(_har_payloads(text))

    for name in ("SAMLRequest", "SAMLResponse"):
        for m in re.finditer(rf"(?:^|[?&\s]){name}=([^&\s]+)", text):
            candidates.append((m.group(1), name))

    # Raw embedded XML documents from SAML-tracer exports or pasted bundles.
    xml_patterns = [
        ("AuthnRequest", r"(<(?:\w+:)?AuthnRequest\b.*?</(?:\w+:)?AuthnRequest>)"),
        ("Response", r"(<(?:\w+:)?Response\b.*?</(?:\w+:)?Response>)"),
        ("Assertion", r"(<(?:\w+:)?Assertion\b.*?</(?:\w+:)?Assertion>)"),
        ("EntityDescriptor", r"(<(?:\w+:)?EntityDescriptor\b.*?</(?:\w+:)?EntityDescriptor>)"),
        ("EntitiesDescriptor", r"(<(?:\w+:)?EntitiesDescriptor\b.*?</(?:\w+:)?EntitiesDescriptor>)"),
    ]
    for label, pat in xml_patterns:
        candidates.extend((m.group(1), f"embedded {label}") for m in re.finditer(pat, text, re.I | re.S))

    expanded: list[tuple[str, str]] = []
    for candidate, source in candidates:
        expanded.append((candidate, source))
        for decoded, chain in _decode_saml_payload(candidate):
            expanded.append((decoded, f"{source}: {chain}"))

        # Form body parsing also handles SAMLResponse=<...>&RelayState=...
        try:
            parsed = urllib.parse.parse_qs(candidate, keep_blank_values=True)
            for key in ("SAMLRequest", "SAMLResponse"):
                for value in parsed.get(key, []):
                    expanded.append((value, f"form {key}"))
                    for decoded, chain in _decode_saml_payload(value):
                        expanded.append((decoded, f"form {key}: {chain}"))
        except Exception:
            pass

    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for candidate, source in expanded:
        candidate = candidate.strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            out.append((candidate, source))
    return out


def _skip_xml_prologue(xml: str) -> str:
    """Drop BOM, XML declaration and comments so the SAML root can be recognized."""
    body = xml.lstrip("\ufeff \t\r\n")
    for _ in range(8):
        body = body.lstrip("\ufeff \t\r\n")
        if body.startswith("<?"):
            end = body.find("?>")
            if end < 0:
                break
            body = body[end + 2 :]
            continue
        if body.startswith("<!--"):
            end = body.find("-->")
            if end < 0:
                break
            body = body[end + 3 :]
            continue
        break
    return body.lstrip("\ufeff \t\r\n")


def _parse_xml_detailed(candidate: str):
    start = candidate.find("<")
    if start < 0:
        return None, None
    xml = candidate[start:]
    # Only classify parse errors as SAML/XML errors when the candidate actually
    # starts with a SAML document root. Generic tracer text may contain unrelated XML.
    # HTTP-POST Base64 payloads often decode to `<?xml ...?><samlp:Response>`.
    if not _SAML_ROOT_RE.match(_skip_xml_prologue(xml)):
        return None, None
    try:
        return ET.fromstring(xml), None
    except Exception as exc:
        return None, str(exc)


def _parse_xml(candidate: str):
    root, _error = _parse_xml_detailed(candidate)
    return root


def _signature_details(parent) -> dict[str, Any]:
    sig = parent.find("ds:Signature", NS) if parent is not None else None
    if sig is None:
        return {"present": False}
    signed_info = sig.find("ds:SignedInfo", NS)
    sig_method = sig.find("ds:SignedInfo/ds:SignatureMethod", NS)
    canon_method = sig.find("ds:SignedInfo/ds:CanonicalizationMethod", NS)
    references = sig.findall("ds:SignedInfo/ds:Reference", NS)
    digest_methods = [x.attrib.get("Algorithm") for x in sig.findall("ds:SignedInfo/ds:Reference/ds:DigestMethod", NS)]
    digest_values = [_text(x) for x in sig.findall("ds:SignedInfo/ds:Reference/ds:DigestValue", NS)]
    refs = [x.attrib.get("URI") for x in references]
    signature_value = _text(sig.find("ds:SignatureValue", NS))
    certs = []
    for cert in sig.findall(".//ds:X509Certificate", NS):
        value = re.sub(r"\s+", "", _text(cert) or "")
        if not value:
            continue
        try:
            der = base64.b64decode(value + "=" * ((4 - len(value) % 4) % 4), validate=False)
            fp = hashlib.sha256(der).hexdigest().upper()
            certs.append(": ".join(fp[i:i+2] for i in range(0, len(fp), 2)))
        except Exception:
            certs.append("unparseable certificate")
    return {
        "present": True,
        "signed_info_present": signed_info is not None,
        "signature_value_present": bool(signature_value),
        "signature_method": sig_method.attrib.get("Algorithm") if sig_method is not None else None,
        "canonicalization_method": canon_method.attrib.get("Algorithm") if canon_method is not None else None,
        "reference_count": len(references),
        "digest_methods": [x for x in digest_methods if x],
        "digest_value_count": sum(1 for x in digest_values if x),
        "reference_uris": [x for x in refs if x is not None],
        "x509_sha256_fingerprints": certs,
    }


def _extract_request(root) -> dict[str, Any]:
    issuer = root.find("saml:Issuer", NS)
    nameid_policy = root.find("samlp:NameIDPolicy", NS)
    rac = root.find("samlp:RequestedAuthnContext", NS)
    class_refs = [_text(x) for x in root.findall("samlp:RequestedAuthnContext/saml:AuthnContextClassRef", NS)]
    return {
        "type": "AuthnRequest",
        "id": root.attrib.get("ID"),
        "version": root.attrib.get("Version"),
        "issue_instant": root.attrib.get("IssueInstant"),
        "destination": root.attrib.get("Destination"),
        "consent": root.attrib.get("Consent"),
        "acs_url": root.attrib.get("AssertionConsumerServiceURL"),
        "acs_index": root.attrib.get("AssertionConsumerServiceIndex"),
        "attribute_consuming_service_index": root.attrib.get("AttributeConsumingServiceIndex"),
        "protocol_binding": root.attrib.get("ProtocolBinding"),
        "provider_name": root.attrib.get("ProviderName"),
        "issuer": _issuer(issuer),
        "force_authn": root.attrib.get("ForceAuthn"),
        "is_passive": root.attrib.get("IsPassive"),
        "name_id_policy": _attrs(nameid_policy, ["Format", "SPNameQualifier", "AllowCreate"]),
        "requested_authn_context": {
            "comparison": rac.attrib.get("Comparison") if rac is not None else None,
            "class_refs": [x for x in class_refs if x],
        },
        "signature": _signature_details(root),
    }


def _extract_assertion(assertion) -> dict[str, Any]:
    ass_issuer = assertion.find("saml:Issuer", NS)
    nameid_els = assertion.findall("saml:Subject/saml:NameID", NS)
    nameid = nameid_els[0] if nameid_els else None
    encrypted_id = assertion.find("saml:Subject/saml:EncryptedID", NS)
    base_id = assertion.find("saml:Subject/saml:BaseID", NS)
    subject_confirmations = []
    for sc in assertion.findall("saml:Subject/saml:SubjectConfirmation", NS):
        scd = sc.find("saml:SubjectConfirmationData", NS)
        subject_confirmations.append({
            "method": sc.attrib.get("Method"),
            "data": _attrs(scd, ["Recipient", "InResponseTo", "NotBefore", "NotOnOrAfter", "Address", "Type"]),
        })

    conditions = assertion.find("saml:Conditions", NS)
    audience_restrictions = []
    audiences: list[str] = []
    for ar in assertion.findall("saml:Conditions/saml:AudienceRestriction", NS):
        vals = [(_text(x) or "") for x in ar.findall("saml:Audience", NS)]
        vals = [x for x in vals if x]
        audience_restrictions.append(vals)
        audiences.extend(vals)

    proxy = assertion.find("saml:Conditions/saml:ProxyRestriction", NS)
    proxy_audiences = [_text(x) for x in assertion.findall("saml:Conditions/saml:ProxyRestriction/saml:Audience", NS)]

    authn_statements = []
    for authn in assertion.findall("saml:AuthnStatement", NS):
        locality = authn.find("saml:SubjectLocality", NS)
        authn_statements.append({
            **_attrs(authn, ["AuthnInstant", "SessionIndex", "SessionNotOnOrAfter"]),
            "subject_locality": _attrs(locality, ["Address", "DNSName"]),
            "authn_context_class_ref": _text(authn.find("saml:AuthnContext/saml:AuthnContextClassRef", NS)),
            "authn_context_decl_ref": _text(authn.find("saml:AuthnContext/saml:AuthnContextDeclRef", NS)),
            "authn_context_decl_present": authn.find("saml:AuthnContext/saml:AuthnContextDecl", NS) is not None,
            "authenticating_authorities": [
                _text(x) for x in authn.findall("saml:AuthnContext/saml:AuthenticatingAuthority", NS) if _text(x)
            ],
        })

    attrs = []
    for a in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        values = [_all_text(v) for v in a.findall("saml:AttributeValue", NS)]
        attrs.append({
            "name": a.attrib.get("Name"),
            "friendly_name": a.attrib.get("FriendlyName"),
            "name_format": a.attrib.get("NameFormat"),
            "values": [v for v in values if v is not None],
        })

    advice = assertion.find("saml:Advice", NS)
    advice_children = [_local(x.tag) for x in list(advice)] if advice is not None else []

    return {
        "type": "Assertion",
        "id": assertion.attrib.get("ID"),
        "version": assertion.attrib.get("Version"),
        "issue_instant": assertion.attrib.get("IssueInstant"),
        "issuer": _issuer(ass_issuer),
        "signature": _signature_details(assertion),
        "subject": {
            "name_id": _nameid_from_element(nameid) or {
                "element_present": False,
                "value": None,
                "raw_value": None,
                "empty": False,
                "format": None,
                "format_present": False,
                "name_qualifier": None,
                "name_qualifier_present": False,
                "sp_name_qualifier": None,
                "sp_name_qualifier_present": False,
                "sp_provided_id": None,
                "sp_provided_id_present": False,
            },
            "nameid_count": len(nameid_els),
            "confirmations": subject_confirmations,
            "encrypted_id_present": encrypted_id is not None,
            "base_id_present": base_id is not None,
            "subject_identifier_choice_count": (
                (1 if nameid_els else 0)
                + (1 if encrypted_id is not None else 0)
                + (1 if base_id is not None else 0)
            ),
        },
        "conditions": {
            **_attrs(conditions, ["NotBefore", "NotOnOrAfter"]),
            "audience_restrictions": audience_restrictions,
            "audiences": audiences,
            "one_time_use": assertion.find("saml:Conditions/saml:OneTimeUse", NS) is not None,
            "proxy_restriction": {
                "count": proxy.attrib.get("Count") if proxy is not None else None,
                "audiences": [x for x in proxy_audiences if x],
            } if proxy is not None else None,
        },
        "authn_statements": authn_statements,
        "attributes": attrs,
        "attribute_statement_count": len(assertion.findall("saml:AttributeStatement", NS)),
        "authz_decision_statement_count": len(assertion.findall("saml:AuthzDecisionStatement", NS)),
        "advice_children": advice_children,
    }


def _status_codes(root) -> list[str]:
    out = []
    node = root.find("samlp:Status/samlp:StatusCode", NS)
    while node is not None:
        if node.attrib.get("Value"):
            out.append(node.attrib["Value"])
        node = node.find("samlp:StatusCode", NS)
    return out


def _extract_response(root) -> dict[str, Any]:
    resp_issuer = root.find("saml:Issuer", NS)
    status_message = root.find("samlp:Status/samlp:StatusMessage", NS)
    status_detail = root.find("samlp:Status/samlp:StatusDetail", NS)
    assertions = [_extract_assertion(a) for a in root.findall("saml:Assertion", NS)]
    encrypted = root.findall("saml:EncryptedAssertion", NS)

    return {
        "type": "Response",
        "id": root.attrib.get("ID"),
        "version": root.attrib.get("Version"),
        "in_response_to": root.attrib.get("InResponseTo"),
        "issue_instant": root.attrib.get("IssueInstant"),
        "destination": root.attrib.get("Destination"),
        "consent": root.attrib.get("Consent"),
        "issuer": _issuer(resp_issuer),
        "status_codes": _status_codes(root),
        "status_message": _text(status_message),
        "status_detail_children": [_local(x.tag) for x in list(status_detail)] if status_detail is not None else [],
        "signature": _signature_details(root),
        "assertions": assertions,
        "encrypted_assertion_count": len(encrypted),
    }


def _cert_fingerprints(parent) -> list[str]:
    fps = []
    for cert in parent.findall(".//ds:X509Certificate", NS):
        value = re.sub(r"\s+", "", _text(cert) or "")
        if not value:
            continue
        try:
            der = base64.b64decode(value + "=" * ((4 - len(value) % 4) % 4), validate=False)
            fp = hashlib.sha256(der).hexdigest().upper()
            fps.append(": ".join(fp[i:i+2] for i in range(0, len(fp), 2)))
        except Exception:
            fps.append("unparseable certificate")
    return fps


def _endpoints(parent, local_name: str) -> list[dict[str, Any]]:
    out = []
    for el in parent.iter():
        if _local(el.tag) == local_name:
            out.append({
                "binding": el.attrib.get("Binding"),
                "location": el.attrib.get("Location"),
                "response_location": el.attrib.get("ResponseLocation"),
                "index": el.attrib.get("index"),
                "is_default": el.attrib.get("isDefault"),
            })
    return out


def _keys(descriptor) -> list[dict[str, Any]]:
    keys = []
    for kd in descriptor.findall("md:KeyDescriptor", NS):
        methods = [x.attrib.get("Algorithm") for x in kd.findall("xenc:EncryptionMethod", NS)]
        key_info = kd.find("ds:KeyInfo", NS)
        keys.append({
            "use": kd.attrib.get("use") or "unspecified",
            "key_info_present": key_info is not None,
            "key_names": [_text(x) for x in kd.findall("ds:KeyInfo/ds:KeyName", NS) if _text(x)],
            "x509_sha256_fingerprints": _cert_fingerprints(kd),
            "encryption_methods": [x for x in methods if x],
        })
    return keys


def _extract_entity_metadata(root) -> dict[str, Any]:
    sp = root.find("md:SPSSODescriptor", NS)
    idp = root.find("md:IDPSSODescriptor", NS)

    result: dict[str, Any] = {
        "type": "Metadata",
        "entity_id": root.attrib.get("entityID"),
        "valid_until": root.attrib.get("validUntil"),
        "cache_duration": root.attrib.get("cacheDuration"),
        "roles": [],
        "organization": None,
        "contacts": [],
    }

    if sp is not None:
        result["roles"].append("SP")
        result["sp"] = {
            "protocol_support_enumeration": sp.attrib.get("protocolSupportEnumeration"),
            "authn_requests_signed": sp.attrib.get("AuthnRequestsSigned"),
            "want_assertions_signed": sp.attrib.get("WantAssertionsSigned"),
            "assertion_consumer_services": _endpoints(sp, "AssertionConsumerService"),
            "single_logout_services": _endpoints(sp, "SingleLogoutService"),
            "name_id_formats": [_text(x) for x in sp.findall("md:NameIDFormat", NS) if _text(x)],
            "keys": _keys(sp),
            "attribute_consuming_services": [
                {
                    "index": x.attrib.get("index"),
                    "is_default": x.attrib.get("isDefault"),
                    "service_names": [_text(n) for n in x.findall("md:ServiceName", NS) if _text(n)],
                    "requested_attributes": [
                        {
                            "name": a.attrib.get("Name"),
                            "friendly_name": a.attrib.get("FriendlyName"),
                            "name_format": a.attrib.get("NameFormat"),
                            "is_required": a.attrib.get("isRequired"),
                        }
                        for a in x.findall("md:RequestedAttribute", NS)
                    ],
                }
                for x in sp.findall("md:AttributeConsumingService", NS)
            ],
        }

    if idp is not None:
        result["roles"].append("IdP")
        result["idp"] = {
            "protocol_support_enumeration": idp.attrib.get("protocolSupportEnumeration"),
            "want_authn_requests_signed": idp.attrib.get("WantAuthnRequestsSigned"),
            "single_sign_on_services": _endpoints(idp, "SingleSignOnService"),
            "single_logout_services": _endpoints(idp, "SingleLogoutService"),
            "artifact_resolution_services": _endpoints(idp, "ArtifactResolutionService"),
            "name_id_formats": [_text(x) for x in idp.findall("md:NameIDFormat", NS) if _text(x)],
            "keys": _keys(idp),
        }

    org = root.find("md:Organization", NS)
    if org is not None:
        result["organization"] = {
            "names": [_text(x) for x in org.findall("md:OrganizationName", NS) if _text(x)],
            "display_names": [_text(x) for x in org.findall("md:OrganizationDisplayName", NS) if _text(x)],
            "urls": [_text(x) for x in org.findall("md:OrganizationURL", NS) if _text(x)],
        }

    for contact in root.findall("md:ContactPerson", NS):
        result["contacts"].append({
            "type": contact.attrib.get("contactType"),
            "company": _text(contact.find("md:Company", NS)),
            "given_name": _text(contact.find("md:GivenName", NS)),
            "surname": _text(contact.find("md:SurName", NS)),
            "emails": [_text(x) for x in contact.findall("md:EmailAddress", NS) if _text(x)],
            "phones": [_text(x) for x in contact.findall("md:TelephoneNumber", NS) if _text(x)],
        })
    return result


def _extract_metadata_roots(root) -> list[dict[str, Any]]:
    if _local(root.tag) == "EntityDescriptor":
        return [_extract_entity_metadata(root)]
    if _local(root.tag) == "EntitiesDescriptor":
        return [_extract_entity_metadata(x) for x in root.findall(".//md:EntityDescriptor", NS)]
    return []


def _check(name: str, left: Any, right: Any, note: str) -> dict[str, Any]:
    if left is None or right is None or left == [] or right == []:
        return {"check": name, "status": "UNKNOWN", "left": left, "right": right, "note": note}
    return {"check": name, "status": "MATCH" if left == right else "MISMATCH", "left": left, "right": right, "note": note}


def _check_in(name: str, value: Any, choices: list[Any], note: str) -> dict[str, Any]:
    if value is None or not choices:
        return {"check": name, "status": "UNKNOWN", "left": value, "right": choices, "note": note}
    return {"check": name, "status": "MATCH" if value in choices else "MISMATCH", "left": value, "right": choices, "note": note}


def _issuer_value(obj: dict[str, Any] | None) -> str | None:
    return (obj or {}).get("value")


def _subject_recipients(assertion: dict[str, Any]) -> list[str]:
    vals = []
    for sc in (assertion.get("subject") or {}).get("confirmations") or []:
        value = (sc.get("data") or {}).get("Recipient")
        if value:
            vals.append(value)
    return vals


def _subject_in_response_to(assertion: dict[str, Any]) -> list[str]:
    vals = []
    for sc in (assertion.get("subject") or {}).get("confirmations") or []:
        value = (sc.get("data") or {}).get("InResponseTo")
        if value:
            vals.append(value)
    return vals


def _time_checks(assertion: dict[str, Any]) -> list[dict[str, Any]]:
    checks = []
    now = datetime.now(timezone.utc)
    cond = assertion.get("conditions") or {}
    nb = _parse_time(cond.get("NotBefore"))
    noa = _parse_time(cond.get("NotOnOrAfter"))
    if nb:
        checks.append({
            "check": "Assertion Conditions NotBefore",
            "status": "MATCH" if now >= nb else "MISMATCH",
            "left": now.isoformat(),
            "right": cond.get("NotBefore"),
            "note": "MATCH means the assertion is not premature at analyzer runtime. Clock skew is not applied by this validator.",
        })
    if noa:
        checks.append({
            "check": "Assertion Conditions NotOnOrAfter",
            "status": "MATCH" if now < noa else "MISMATCH",
            "left": now.isoformat(),
            "right": cond.get("NotOnOrAfter"),
            "note": "MATCH means the assertion has not expired at analyzer runtime. Clock skew is not applied by this validator.",
        })
    for idx, sc in enumerate((assertion.get("subject") or {}).get("confirmations") or [], 1):
        s_noa_s = (sc.get("data") or {}).get("NotOnOrAfter")
        s_noa = _parse_time(s_noa_s)
        if s_noa:
            checks.append({
                "check": f"SubjectConfirmation #{idx} NotOnOrAfter",
                "status": "MATCH" if now < s_noa else "MISMATCH",
                "left": now.isoformat(),
                "right": s_noa_s,
                "note": "MATCH means this subject confirmation has not expired at analyzer runtime. Clock skew is not applied.",
            })
    return checks


def looks_like_saml_input(text: str) -> bool:
    low = text.lower()
    if any(x in low for x in ("samlresponse", "samlrequest", "authnrequest", "urn:oasis:names:tc:saml", "<samlp:", "<saml:", "entitydescriptor")):
        return True
    for candidate, _source in _extract_candidates(text):
        root = _parse_xml(candidate)
        if root is not None and _local(root.tag) in SAMLISH_ROOTS:
            return True
    return False


def analyze_saml_input(text: str) -> dict[str, Any]:
    docs: list[dict[str, Any]] = []
    encodings: list[dict[str, str]] = []
    parse_failures: list[dict[str, str]] = []

    for candidate, source in _extract_candidates(text):
        root, parse_error = _parse_xml_detailed(candidate)
        if root is None:
            if parse_error:
                # A pasted bundle of several complete XML documents is expected to
                # fail as one XML document; embedded documents are extracted below.
                roots = _SAML_ROOT_RE.findall(candidate)
                if not (source == "input" and len(roots) > 1):
                    item = {"source": source, "error": parse_error}
                    if item not in parse_failures:
                        parse_failures.append(item)
            continue
        typ = _local(root.tag)
        extracted: list[dict[str, Any]] = []
        if typ == "AuthnRequest":
            extracted = [_extract_request(root)]
        elif typ == "Response":
            extracted = [_extract_response(root)]
        elif typ == "Assertion":
            extracted = [_extract_assertion(root)]
        elif typ in {"EntityDescriptor", "EntitiesDescriptor"}:
            extracted = _extract_metadata_roots(root)
        else:
            continue

        for d in extracted:
            d = dict(d)
            d["source"] = source
            # Deduplicate semantically while keeping the clearest source label.
            compare = {k: v for k, v in d.items() if k not in {"source"}}
            if not any({k: v for k, v in x.items() if k not in {"source"}} == compare for x in docs):
                docs.append(d)
                encodings.append({"document_type": d["type"], "source": source})

    requests = [d for d in docs if d["type"] == "AuthnRequest"]
    responses = [d for d in docs if d["type"] == "Response"]
    standalone_assertions = [d for d in docs if d["type"] == "Assertion"]
    metadata = [d for d in docs if d["type"] == "Metadata"]
    checks: list[dict[str, Any]] = []

    req = requests[-1] if requests else None
    resp = responses[-1] if responses else None
    assertions = (resp.get("assertions") or []) if resp else []
    if not assertions and standalone_assertions:
        assertions = standalone_assertions

    if req and resp:
        checks.append(_check("AuthnRequest ACS vs Response Destination", req.get("acs_url"), resp.get("destination"), "For SP-initiated SSO these normally identify the same ACS endpoint."))
        checks.append(_check("AuthnRequest ID vs Response InResponseTo", req.get("id"), resp.get("in_response_to"), "SP-initiated Response should correlate to the AuthnRequest when InResponseTo is present."))

    for ai, ass in enumerate(assertions, 1):
        recipients = _subject_recipients(ass)
        irts = _subject_in_response_to(ass)
        audiences = (ass.get("conditions") or {}).get("audiences") or []
        if req:
            for idx, recipient in enumerate(recipients, 1):
                checks.append(_check(f"AuthnRequest ACS vs Assertion #{ai} Recipient #{idx}", req.get("acs_url"), recipient, "SubjectConfirmationData Recipient normally identifies the receiving ACS endpoint."))
            for idx, irt in enumerate(irts, 1):
                checks.append(_check(f"AuthnRequest ID vs Assertion #{ai} SubjectConfirmation InResponseTo #{idx}", req.get("id"), irt, "Subject confirmation should correlate to the request in SP-initiated SSO."))
            req_issuer = _issuer_value(req.get("issuer"))
            if req_issuer:
                checks.append(_check_in(f"AuthnRequest Issuer / SP entityID present in Assertion #{ai} Audience", req_issuer, audiences, "The SP entityID is normally an allowed Audience for the assertion."))
        if resp:
            for idx, recipient in enumerate(recipients, 1):
                checks.append(_check(f"Response Destination vs Assertion #{ai} Recipient #{idx}", resp.get("destination"), recipient, "Both normally identify the receiving ACS endpoint."))
            checks.append(_check(f"Response Issuer vs Assertion #{ai} Issuer", _issuer_value(resp.get("issuer")), _issuer_value(ass.get("issuer")), "A mismatch is suspicious unless the deployment intentionally uses different issuers."))

    sp_metadata = [m for m in metadata if "SP" in (m.get("roles") or [])]
    idp_metadata = [m for m in metadata if "IdP" in (m.get("roles") or [])]

    # Explicitly show important checks that cannot be completed because the
    # corresponding request/metadata was not supplied. This avoids a false
    # impression that a standalone Response was fully validated.
    if resp and not req:
        checks.append({
            "check": "Response InResponseTo vs AuthnRequest ID",
            "status": "UNKNOWN",
            "left": resp.get("in_response_to"),
            "right": None,
            "note": "AuthnRequest was not supplied; correlation cannot be verified. This may also be an unsolicited IdP-initiated response.",
        })
        checks.append({
            "check": "Response Destination vs AuthnRequest ACS",
            "status": "UNKNOWN",
            "left": resp.get("destination"),
            "right": None,
            "note": "AuthnRequest was not supplied, so the requested ACS cannot be compared.",
        })
    if resp and not sp_metadata:
        checks.append({
            "check": "Response Destination / Recipient vs SP metadata ACS",
            "status": "UNKNOWN",
            "left": resp.get("destination"),
            "right": None,
            "note": "SP metadata was not supplied; registered ACS endpoints cannot be verified.",
        })
        for ai, ass in enumerate(assertions, 1):
            checks.append({
                "check": f"Assertion #{ai} Audience vs SP metadata entityID",
                "status": "UNKNOWN",
                "left": (ass.get("conditions") or {}).get("audiences") or [],
                "right": None,
                "note": "SP metadata was not supplied; the intended SP entityID cannot be verified.",
            })
    if resp and not idp_metadata:
        checks.append({
            "check": "Response / Assertion Issuer vs IdP metadata entityID",
            "status": "UNKNOWN",
            "left": _issuer_value(resp.get("issuer")),
            "right": None,
            "note": "IdP metadata was not supplied; issuer identity cannot be verified against metadata.",
        })

    for mi, md in enumerate(sp_metadata, 1):
        sp = md.get("sp") or {}
        acs_locations = [x.get("location") for x in sp.get("assertion_consumer_services", []) if x.get("location")]
        if req:
            checks.append(_check(f"SP metadata #{mi} entityID vs AuthnRequest Issuer", md.get("entity_id"), _issuer_value(req.get("issuer")), "The AuthnRequest Issuer should normally be the SP entityID."))
            checks.append(_check_in(f"AuthnRequest ACS present in SP metadata #{mi} ACS list", req.get("acs_url"), acs_locations, "The requested ACS should normally be registered in SP metadata."))
        if resp:
            checks.append(_check_in(f"Response Destination present in SP metadata #{mi} ACS list", resp.get("destination"), acs_locations, "Response Destination should normally be one of the SP ACS endpoints."))
        for ai, ass in enumerate(assertions, 1):
            audiences = (ass.get("conditions") or {}).get("audiences") or []
            checks.append(_check_in(f"SP metadata #{mi} entityID present in Assertion #{ai} Audience", md.get("entity_id"), audiences, "The assertion Audience normally includes the SP entityID."))
            for ri, recipient in enumerate(_subject_recipients(ass), 1):
                checks.append(_check_in(f"Assertion #{ai} Recipient #{ri} present in SP metadata #{mi} ACS list", recipient, acs_locations, "Recipient should normally be a registered ACS endpoint."))
            wanted = str(sp.get("want_assertions_signed") or "").lower()
            if wanted == "true":
                checks.append({
                    "check": f"SP metadata #{mi} WantAssertionsSigned vs Assertion #{ai} signature",
                    "status": "MATCH" if (ass.get("signature") or {}).get("present") else "MISMATCH",
                    "left": "WantAssertionsSigned=true",
                    "right": (ass.get("signature") or {}).get("present"),
                    "note": "This checks signature presence only, not cryptographic validity.",
                })

    for mi, md in enumerate(idp_metadata, 1):
        idp = md.get("idp") or {}
        sso_locations = [x.get("location") for x in idp.get("single_sign_on_services", []) if x.get("location")]
        if req:
            checks.append(_check_in(f"AuthnRequest Destination present in IdP metadata #{mi} SSO endpoints", req.get("destination"), sso_locations, "AuthnRequest Destination should normally be an advertised IdP SSO endpoint."))
        if resp:
            checks.append(_check(f"IdP metadata #{mi} entityID vs Response Issuer", md.get("entity_id"), _issuer_value(resp.get("issuer")), "The Response Issuer should normally identify the IdP entityID."))
        for ai, ass in enumerate(assertions, 1):
            checks.append(_check(f"IdP metadata #{mi} entityID vs Assertion #{ai} Issuer", md.get("entity_id"), _issuer_value(ass.get("issuer")), "The Assertion Issuer should normally identify the IdP entityID."))

    findings, transport = validate_saml(
        raw_input=text,
        requests=requests,
        responses=responses,
        standalone_assertions=standalone_assertions,
        metadata=metadata,
    )
    parse_findings = [
        {
            "code": "XML_NOT_WELL_FORMED",
            "severity": "ERROR",
            "scope": f"Input ({pf['source']})",
            "message": "SAML-like XML could be decoded/detected but is not well-formed XML, so semantic validation of that document cannot continue.",
            "observed": pf["error"],
            "expected": "well-formed XML",
            "standard": "XML 1.0 prerequisite for SAML 2.0",
            "note": "Fix XML syntax first; the analyzer will then apply SAML Core/profile checks.",
        }
        for pf in parse_failures
    ]
    findings = parse_findings + findings

    return {
        "kind": "saml",
        "documents_found": len(docs),
        "documents": docs,
        "detected_sources": encodings,
        "parse_failures": parse_failures,
        "transport": transport,
        "findings": findings,
        "checks": checks,
        "summary": {
            "authn_requests": len(requests),
            "responses": len(responses),
            "standalone_assertions": len(standalone_assertions),
            "assertions_inside_responses": sum(len(r.get("assertions") or []) for r in responses),
            "metadata_entities": len(metadata),
            "sp_metadata_entities": len(sp_metadata),
            "idp_metadata_entities": len(idp_metadata),
            "mismatches": sum(1 for c in checks if c.get("status") == "MISMATCH"),
            "matches": sum(1 for c in checks if c.get("status") == "MATCH"),
            "unknown_checks": sum(1 for c in checks if c.get("status") == "UNKNOWN"),
            "validation_errors": sum(1 for f in findings if f.get("severity") == "ERROR"),
            "validation_warnings": sum(1 for f in findings if f.get("severity") == "WARNING"),
            "validation_info": sum(1 for f in findings if f.get("severity") == "INFO"),
        },
        "limitations": [
            "Signature presence and algorithms are reported, but cryptographic trust validation is not performed by the current validator.",
            "A standard SAML Response contains Assertion XML directly; the analyzer decodes whole Base64 SAMLRequest/SAMLResponse payloads and standalone Base64 Assertions, but intentionally does not recursively decode arbitrary Base64 text nodes such as X509 certificates.",
            "EncryptedAssertion is detected but cannot be decrypted without the SP private key.",
            "Time validity is evaluated against the analyzer machine's current UTC time and does not apply configurable clock skew yet; historical samples will therefore correctly appear expired today.",
            "Standards validation combines SAML 2.0 Core requirements with Web Browser SSO profile rules where the supplied documents indicate an SSO Response. Binding-dependent checks are only hard errors when the binding can be inferred; otherwise they are warnings.",
        ],
    }
