from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import urllib.parse
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET

from . import saml_validation as saml_val
from .saml_validation import (
    BEARER_METHOD,
    clock_skew_assisted_note,
    instant_expired,
    instant_not_yet_valid,
    resolve_saml_timing,
    select_role_metadata,
    validate_saml,
)
from .xml_safe import decompress_limited

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


def _xmlenc_algorithm_name(uri: str | None) -> str | None:
    if not uri:
        return None
    if "#" in uri:
        return uri.rsplit("#", 1)[-1] or uri
    return uri.rsplit("/", 1)[-1] or uri


def _xmlenc_payload(container) -> dict[str, Any]:
    data = container.find("xenc:EncryptedData", NS)
    content_uri = None
    key_info_present = False
    if data is not None:
        method = data.find("xenc:EncryptionMethod", NS)
        if method is not None:
            content_uri = method.attrib.get("Algorithm")
        key_info_present = data.find("ds:KeyInfo", NS) is not None
    key_uris: list[str] = []
    seen: set[str] = set()
    missing_key_method = 0
    encrypted_keys = list(container.findall(".//xenc:EncryptedKey", NS))
    for encrypted_key in encrypted_keys:
        method = encrypted_key.find("xenc:EncryptionMethod", NS)
        uri = method.attrib.get("Algorithm") if method is not None else None
        if not uri:
            missing_key_method += 1
            continue
        if uri not in seen:
            seen.add(uri)
            key_uris.append(uri)
    return {
        "encrypted_data_present": data is not None,
        "content_encryption": _xmlenc_algorithm_name(content_uri),
        "content_encryption_uri": content_uri,
        "content_encryption_method_present": bool(content_uri),
        "key_encryption": [_xmlenc_algorithm_name(uri) for uri in key_uris],
        "key_encryption_uris": key_uris,
        "key_info_present": key_info_present,
        "encrypted_key_count": len(encrypted_keys),
        "encrypted_key_missing_encryption_method_count": missing_key_method,
    }


def _encrypted_attributes(assertion) -> list[dict[str, Any]]:
    return [_xmlenc_payload(enc) for enc in assertion.findall(".//saml:EncryptedAttribute", NS)]


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
                    inflated = decompress_limited(data, wbits)
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


def _try_json(text: str):
    body = text.lstrip("\ufeff \t\r\n")
    if not body or body[0] not in "{[":
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def _saml_form_params(obj) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for key in ("SAMLRequest", "SAMLResponse"):
            value = obj.get(key)
            if isinstance(value, str) and value:
                out[key] = value
            elif isinstance(value, (int, float)):
                continue
        params = obj.get("params")
        if isinstance(params, list):
            for item in params:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                value = item.get("value")
                if name in {"SAMLRequest", "SAMLResponse"} and value:
                    out[str(name)] = str(value)
        text = obj.get("text")
        if isinstance(text, str) and text:
            parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
            for key in ("SAMLRequest", "SAMLResponse"):
                if key not in out:
                    vals = parsed.get(key) or []
                    if vals and vals[0]:
                        out[key] = vals[0]
        return out
    if isinstance(obj, list):
        for item in obj:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if name in {"SAMLRequest", "SAMLResponse"} and value:
                out[str(name)] = str(value)
    return out


def _looks_like_saml_xml_text(value: str) -> bool:
    return "<" in value and any(name in value for name in SAMLISH_ROOTS)


def _har_payloads_from_obj(obj) -> list[tuple[str, str]]:
    if not isinstance(obj, dict):
        return []
    entries = ((obj.get("log") or {}).get("entries") or []) if isinstance(obj.get("log"), dict) else []
    if not isinstance(entries, list) or not entries:
        return []
    out: list[tuple[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        if not isinstance(req, dict):
            continue
        post = req.get("postData") or {}
        for name, value in _saml_form_params(post).items():
            out.append((value, f"HAR {name}"))
        url = req.get("url")
        if isinstance(url, str) and ("SAMLRequest=" in url or "SAMLResponse=" in url):
            out.append((url, "HAR URL"))
    return out


def _tracer_http_requests(obj) -> list[dict[str, Any]] | None:
    if isinstance(obj, list):
        rows = [item for item in obj if isinstance(item, dict)]
        if rows and any("saml" in item or "postData" in item or "get" in item for item in rows):
            return rows
        return None
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("log"), dict) and obj["log"].get("entries"):
        return None
    for key in ("requests", "entries"):
        rows = obj.get(key)
        if isinstance(rows, list) and any(
            isinstance(item, dict) and ("saml" in item or "postData" in item or "get" in item)
            for item in rows
        ):
            return [item for item in rows if isinstance(item, dict)]
    if "saml" in obj or (("method" in obj or "url" in obj) and ("postData" in obj or "get" in obj)):
        return [obj]
    return None


def _tracer_payloads_from_obj(obj) -> list[tuple[str, str]]:
    rows = _tracer_http_requests(obj)
    if not rows:
        return []
    out: list[tuple[str, str]] = []
    for index, req in enumerate(rows, 1):
        saml = req.get("saml")
        if isinstance(saml, str) and _looks_like_saml_xml_text(saml):
            out.append((saml, f"SAML-tracer saml #{index}"))
            continue
        for name, value in _saml_form_params(req.get("get")).items():
            out.append((value, f"SAML-tracer GET {name} #{index}"))
        for name, value in _saml_form_params(req.get("postData")).items():
            out.append((value, f"SAML-tracer POST {name} #{index}"))
        url = req.get("url")
        if isinstance(url, str) and ("SAMLRequest=" in url or "SAMLResponse=" in url):
            out.append((url, f"SAML-tracer URL #{index}"))
    return out


def _json_string_payloads(obj, *, _out: list[tuple[str, str]] | None = None) -> list[tuple[str, str]]:
    out = _out if _out is not None else []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in {"SAMLRequest", "SAMLResponse"} and isinstance(value, str) and value:
                out.append((value, f"JSON {key}"))
            else:
                _json_string_payloads(value, _out=out)
    elif isinstance(obj, list):
        for item in obj:
            _json_string_payloads(item, _out=out)
    elif isinstance(obj, str) and _looks_like_saml_xml_text(obj):
        out.append((obj, "JSON string"))
    return out


def _candidates_from_json(obj) -> list[tuple[str, str]]:
    har = _har_payloads_from_obj(obj)
    tracer = _tracer_payloads_from_obj(obj)
    if har or tracer:
        return har + tracer
    return _json_string_payloads(obj)


def _har_payloads(text: str) -> list[tuple[str, str]]:
    obj = _try_json(text)
    if obj is None:
        return []
    return _har_payloads_from_obj(obj)


_SAML_ARTIFACT_SEP_RE = re.compile(r"<!--\s*iddqd-artifact\s*-->")
_FILE_BANNER_RE = re.compile(r"===== FILE: .+? =====")


def _input_segments(text: str) -> list[str]:
    """Decode each Analyze artifact on its own. Base64 payloads cannot be concatenated."""
    parts = [text]
    for pat in (_SAML_ARTIFACT_SEP_RE, _FILE_BANNER_RE):
        parts = [piece for chunk in parts for piece in pat.split(chunk)]
    return [part.strip() for part in parts if part.strip()]


def _extract_xml_fragments(text: str, *, include_assertion: bool) -> list[tuple[str, str]]:
    xml_patterns = [
        ("AuthnRequest", r"(<(?:\w+:)?AuthnRequest\b.*?</(?:\w+:)?AuthnRequest>)"),
        ("Response", r"(<(?:\w+:)?Response\b.*?</(?:\w+:)?Response>)"),
        ("EntityDescriptor", r"(<(?:\w+:)?EntityDescriptor\b.*?</(?:\w+:)?EntityDescriptor>)"),
        ("EntitiesDescriptor", r"(<(?:\w+:)?EntitiesDescriptor\b.*?</(?:\w+:)?EntitiesDescriptor>)"),
    ]
    if include_assertion:
        xml_patterns.insert(2, ("Assertion", r"(<(?:\w+:)?Assertion\b.*?</(?:\w+:)?Assertion>)"))
    out: list[tuple[str, str]] = []
    for label, pat in xml_patterns:
        out.extend((m.group(1), f"embedded {label}") for m in re.finditer(pat, text, re.I | re.S))
    return out


def _extract_candidates(text: str) -> list[tuple[str, str]]:
    raw = text.strip()
    obj = _try_json(raw)
    if obj is not None:
        candidates = _candidates_from_json(obj)
    else:
        unescaped = html.unescape(raw)
        segments = _input_segments(unescaped)
        if len(segments) <= 1:
            candidates = [(unescaped, "input")]
        else:
            candidates = [(seg, f"input #{i}") for i, seg in enumerate(segments, 1)]
        for name in ("SAMLRequest", "SAMLResponse"):
            for m in re.finditer(rf"(?:^|[?&\s]){name}=([^&\s]+)", unescaped):
                candidates.append((m.group(1), name))
        candidates.extend(_extract_xml_fragments(unescaped, include_assertion=True))

    expanded: list[tuple[str, str]] = []
    for candidate, source in candidates:
        expanded.append((candidate, source))
        for decoded, chain in _decode_saml_payload(candidate):
            expanded.append((decoded, f"{source}: {chain}"))

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
    xsi_type = "{http://www.w3.org/2001/XMLSchema-instance}type"
    for a in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        value_els = a.findall("saml:AttributeValue", NS)
        values = [_all_text(v) for v in value_els]
        attrs.append({
            "name": a.attrib.get("Name"),
            "friendly_name": a.attrib.get("FriendlyName"),
            "name_format": a.attrib.get("NameFormat"),
            "name_format_present": "NameFormat" in a.attrib,
            "values": [v for v in values if v is not None],
            "xsi_types": [v.attrib.get(xsi_type) for v in value_els],
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
            "encrypted_id": _xmlenc_payload(encrypted_id) if encrypted_id is not None else None,
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
        "encrypted_attributes": _encrypted_attributes(assertion),
        "encrypted_attribute_count": len(assertion.findall(".//saml:EncryptedAttribute", NS)),
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


def _slot_finding(code: str, slot: str, message: str, *, observed: Any = None, expected: Any = None, note: str | None = None) -> dict[str, Any]:
    return {
        "code": code,
        "severity": "ERROR" if code == "METADATA_PARSE_FAILED" else "INFO",
        "scope": f"{slot.upper()} metadata",
        "message": message,
        "observed": observed,
        "expected": expected,
        "standard": "SAML Metadata 2.0",
        "note": note,
    }


def _ingest_metadata_slot(blob: str | None, slot: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    """Parse optional SP/IdP metadata XML. Failures are findings, not trace aborts."""
    text = (blob or "").strip()
    if not text:
        return [], [], None
    root, parse_error = _parse_xml_detailed(text)
    if root is None:
        for candidate, _source in _extract_candidates(text):
            root, parse_error = _parse_xml_detailed(candidate)
            if root is not None:
                break
    if root is None:
        return [], [_slot_finding(
            "METADATA_PARSE_FAILED",
            slot,
            "Optional metadata XML could not be parsed. Trace analysis continues without this metadata.",
            observed=parse_error or "not well-formed XML",
            expected="md:EntityDescriptor or md:EntitiesDescriptor",
            note="Missing or unusable metadata is not treated as a SAML protocol failure.",
        )], text
    typ = _local(root.tag)
    if typ not in {"EntityDescriptor", "EntitiesDescriptor"}:
        return [], [_slot_finding(
            "METADATA_PARSE_FAILED",
            slot,
            "Optional metadata upload is not a SAML metadata document.",
            observed=typ,
            expected="EntityDescriptor or EntitiesDescriptor",
        )], text
    extracted = _extract_metadata_roots(root)
    findings: list[dict[str, Any]] = []
    expected_role = "IdP" if slot == "idp" else "SP"
    roles = {role for d in extracted for role in (d.get("roles") or [])}
    if extracted and expected_role not in roles:
        findings.append(_slot_finding(
            "METADATA_WRONG_ROLE",
            slot,
            f"The XML in the {slot.upper()} metadata slot has no {expected_role} role descriptor.",
            observed=sorted(roles) or "no SPSSODescriptor/IDPSSODescriptor",
            expected=f"md:{'IDP' if expected_role == 'IdP' else 'SP'}SSODescriptor",
            note="This file is not used for that party's configuration checks. It is not reported as a SAML protocol mismatch.",
        ))
        for d in extracted:
            d["wrong_slot_role"] = True
    for d in extracted:
        d["metadata_slot"] = slot
        d["source"] = f"{slot} metadata upload"
    return extracted, findings, text


def _http_status_from_tracer_row(req: dict[str, Any]) -> int | None:
    for key in ("status", "statusCode", "responseStatus"):
        value = req.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    nested = req.get("response")
    if isinstance(nested, dict):
        value = nested.get("status") or nested.get("statusCode")
        if isinstance(value, int):
            return value
    for key in ("statusLine", "responseStatusLine", "statusText"):
        line = req.get(key)
        if isinstance(line, str):
            match = re.search(r"\b([1-5]\d{2})\b", line)
            if match:
                return int(match.group(1))
    return None


def _row_has_saml_response(req: dict[str, Any]) -> bool:
    saml = req.get("saml")
    if isinstance(saml, str) and "Response" in saml and "AuthnRequest" not in saml[:200]:
        return True
    post = req.get("postData")
    if isinstance(post, dict) and post.get("SAMLResponse"):
        return True
    url = req.get("url")
    if isinstance(url, str) and "SAMLResponse=" in url:
        return True
    return False


def _observed_http_from_text(text: str) -> list[dict[str, Any]]:
    obj = _try_json(text)
    if obj is None:
        return []
    rows = _tracer_http_requests(obj)
    if not rows:
        return []
    out: list[dict[str, Any]] = []
    for req in rows:
        status = _http_status_from_tracer_row(req)
        if status is None:
            continue
        row = {
            "status": status,
            "method": req.get("method"),
            "url": req.get("url"),
            "has_saml_response": _row_has_saml_response(req),
        }
        response_date = saml_val._row_response_date(req, None)
        if response_date is not None:
            row["response_date"] = saml_val._iso_z(response_date)
        out.append(row)
    return out


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


def _bearer_in_response_to(assertion: dict[str, Any]) -> list[tuple[int, str | None]]:
    rows: list[tuple[int, str | None]] = []
    bi = 0
    for sc in (assertion.get("subject") or {}).get("confirmations") or []:
        if sc.get("method") != BEARER_METHOD:
            continue
        bi += 1
        rows.append((bi, (sc.get("data") or {}).get("InResponseTo")))
    return rows


def _time_check_note(status: str, now: datetime, bound: datetime, *, lower: bool, match_plain: str, mismatch_plain: str) -> str:
    if status == "MATCH":
        assisted = clock_skew_assisted_note(now, bound, lower=lower)
        return assisted or match_plain
    return mismatch_plain


def _time_checks(assertion: dict[str, Any], timing: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    checks = []
    timing_ctx = timing or {"mode": "replay_now", "validation_time": saml_val._now_utc(), "analyzer_runtime": saml_val._now_utc()}
    mode = timing_ctx.get("mode") or "replay_now"
    validation_time = timing_ctx.get("validation_time")
    analyzer_now = timing_ctx.get("analyzer_runtime") or saml_val._now_utc()
    if mode == "incident_trace" and validation_time is None:
        checks.append({
            "check": "Assertion timing (incident trace)",
            "status": "UNKNOWN",
            "left": None,
            "right": (assertion.get("conditions") or {}).get("NotOnOrAfter"),
            "note": "ACS trace without observed event time; timing is not compared against analyzer runtime.",
        })
        return checks
    now = validation_time if mode == "incident_trace" else analyzer_now
    when = saml_val._timing_label(timing_ctx)
    left = now.isoformat() if now is not None else None
    cond = assertion.get("conditions") or {}
    nb = saml_val._parse_time(cond.get("NotBefore"))
    noa = saml_val._parse_time(cond.get("NotOnOrAfter"))
    if nb and now is not None:
        status = "MATCH" if not instant_not_yet_valid(now, nb) else "MISMATCH"
        checks.append({
            "check": "Assertion Conditions NotBefore",
            "status": status,
            "left": left,
            "right": cond.get("NotBefore"),
            "note": _time_check_note(
                status,
                now,
                nb,
                lower=True,
                match_plain=f"MATCH means the assertion is not premature at {when}.",
                mismatch_plain=f"MISMATCH means the assertion is not yet valid at {when} even after configured clock skew.",
            ),
        })
    if noa and now is not None:
        status = "MATCH" if not instant_expired(now, noa) else "MISMATCH"
        checks.append({
            "check": "Assertion Conditions NotOnOrAfter",
            "status": status,
            "left": left,
            "right": cond.get("NotOnOrAfter"),
            "note": _time_check_note(
                status,
                now,
                noa,
                lower=False,
                match_plain=f"MATCH means the assertion has not expired at {when}.",
                mismatch_plain=f"MISMATCH means the assertion has expired at {when} even after configured clock skew.",
            ),
        })
    for idx, sc in enumerate((assertion.get("subject") or {}).get("confirmations") or [], 1):
        s_noa_s = (sc.get("data") or {}).get("NotOnOrAfter")
        s_noa = saml_val._parse_time(s_noa_s)
        if s_noa and now is not None:
            status = "MATCH" if not instant_expired(now, s_noa) else "MISMATCH"
            checks.append({
                "check": f"SubjectConfirmation #{idx} NotOnOrAfter",
                "status": status,
                "left": left,
                "right": s_noa_s,
                "note": _time_check_note(
                    status,
                    now,
                    s_noa,
                    lower=False,
                    match_plain=f"MATCH means this subject confirmation has not expired at {when}.",
                    mismatch_plain=f"MISMATCH means this subject confirmation has expired at {when} even after configured clock skew.",
                ),
            })
    return checks


def looks_like_saml_input(text: str) -> bool:
    low = text.lower()
    if any(x in low for x in ("samlresponse", "samlrequest", "authnrequest", "urn:oasis:names:tc:saml", "<samlp:", "<saml:", "entitydescriptor")):
        return True
    return bool(saml_root_types(text))


def saml_root_types(text: str) -> set[str]:
    found: set[str] = set()
    for candidate, _source in _extract_candidates(text or ""):
        root = _parse_xml(candidate)
        if root is not None:
            loc = _local(root.tag)
            if loc in SAMLISH_ROOTS:
                found.add(loc)
    return found


_TRANSPORT_SOURCE_RE = re.compile(r"Base64|DEFLATE|gzip|\bzlib\b|URL-decoded", re.I)
_EXPORT_SLUG = {
    "AuthnRequest": "authnrequest",
    "Response": "response",
    "Assertion": "assertion",
    "EntityDescriptor": "metadata",
    "EntitiesDescriptor": "metadata",
    "Metadata": "metadata",
}


def _is_transport_source(source: str) -> bool:
    return bool(_TRANSPORT_SOURCE_RE.search(source or ""))


def _export_stem(source_name: str | None) -> str:
    if not source_name or source_name == "pasted text":
        return "pasted"
    stem = Path(source_name).stem
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._")
    return (stem or "pasted")[:80]


def _xml_for_export(candidate: str) -> str:
    start = candidate.find("<")
    return candidate[start:] if start >= 0 else candidate


def collect_decoded_artifacts(text: str, source_name: str | None = None) -> list[dict[str, Any]]:
    """SAML XML the analyzer unpacked from a transport encoding, with source lineage."""
    found: list[dict[str, Any]] = []
    seen_xml: set[str] = set()
    for candidate, source in _extract_candidates(text or ""):
        if not _is_transport_source(source):
            continue
        root, _error = _parse_xml_detailed(candidate)
        if root is None:
            continue
        typ = _local(root.tag)
        if typ not in SAMLISH_ROOTS:
            continue
        xml = _xml_for_export(candidate)
        if xml in seen_xml:
            continue
        seen_xml.add(xml)
        found.append({
            "source_name": source_name or "pasted text",
            "encoding": source,
            "document_type": "Metadata" if typ in {"EntityDescriptor", "EntitiesDescriptor"} else typ,
            "xml": xml,
        })
    return found


def assign_decoded_export_names(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str], int] = {}
    named: list[dict[str, Any]] = []
    for item in items:
        stem = _export_stem(item.get("source_name"))
        slug = _EXPORT_SLUG.get(str(item.get("document_type") or ""), "saml")
        key = (stem, slug)
        counts[key] = counts.get(key, 0) + 1
        row = dict(item)
        row["export_name"] = f"{stem}.{slug}_{counts[key]:02d}.xml"
        named.append(row)
    return named


def decoded_artifacts_for_named_inputs(artifacts: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Collect transport-decoded SAML per source file so lineage is not lost at join."""
    items: list[dict[str, Any]] = []
    seen_files: set[tuple[str, str]] = set()
    seen_xml: set[str] = set()
    for name, text in artifacts:
        key = (name, text)
        if key in seen_files:
            continue
        seen_files.add(key)
        for item in collect_decoded_artifacts(text, name):
            if item["xml"] in seen_xml:
                continue
            seen_xml.add(item["xml"])
            items.append(item)
    return assign_decoded_export_names(items)


def analyze_saml_input(
    text: str,
    *,
    idp_metadata: str | None = None,
    sp_metadata: str | None = None,
) -> dict[str, Any]:
    docs: list[dict[str, Any]] = []
    encodings: list[dict[str, str]] = []
    parse_failures: list[dict[str, str]] = []
    slot_findings: list[dict[str, Any]] = []
    slot_metadata_xml: list[str] = []

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

    for slot, blob in (("idp", idp_metadata), ("sp", sp_metadata)):
        extracted, extra_findings, xml_text = _ingest_metadata_slot(blob, slot)
        slot_findings.extend(extra_findings)
        if xml_text:
            slot_metadata_xml.append(xml_text)
        for d in extracted:
            compare = {k: v for k, v in d.items() if k not in {"source", "metadata_slot", "wrong_slot_role"}}
            if not any({k: v for k, v in x.items() if k not in {"source", "metadata_slot", "wrong_slot_role"}} == compare for x in docs):
                docs.append(d)
                encodings.append({"document_type": d["type"], "source": d.get("source") or f"{slot} metadata upload"})

    requests = [d for d in docs if d["type"] == "AuthnRequest"]
    responses = [d for d in docs if d["type"] == "Response"]
    standalone_assertions = [d for d in docs if d["type"] == "Assertion"]
    metadata = [d for d in docs if d["type"] == "Metadata"]
    checks: list[dict[str, Any]] = []
    observed_http = _observed_http_from_text(text)
    timing = resolve_saml_timing(text)

    req = requests[-1] if requests else None
    resp = responses[-1] if responses else None
    assertions = (resp.get("assertions") or []) if resp else []
    if not assertions and standalone_assertions:
        assertions = standalone_assertions

    if req and resp:
        checks.append(_check("AuthnRequest ACS vs Response Destination", req.get("acs_url"), resp.get("destination"), "For SP-initiated SSO these normally identify the same ACS endpoint."))
        checks.append(_check("AuthnRequest ID vs Response InResponseTo", req.get("id"), resp.get("in_response_to"), "SP-initiated Response should correlate to the AuthnRequest when InResponseTo is present."))

    for ai, ass in enumerate(assertions, 1):
        checks.extend(_time_checks(ass, timing))
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
            for bi, bearer_irt in _bearer_in_response_to(ass):
                if resp.get("in_response_to") and bearer_irt:
                    checks.append(_check(
                        f"Response InResponseTo vs Assertion #{ai} bearer SubjectConfirmation #{bi} InResponseTo",
                        resp.get("in_response_to"),
                        bearer_irt,
                        "Solicited Web Browser SSO: both MUST identify the same AuthnRequest ID. This check does not require the original request.",
                    ))
            checks.append(_check(f"Response Issuer vs Assertion #{ai} Issuer", _issuer_value(resp.get("issuer")), _issuer_value(ass.get("issuer")), "A mismatch is suspicious unless the deployment intentionally uses different issuers."))

    all_sp_metadata = [m for m in metadata if "SP" in (m.get("roles") or []) and not m.get("wrong_slot_role")]
    all_idp_metadata = [m for m in metadata if "IdP" in (m.get("roles") or []) and not m.get("wrong_slot_role")]
    req_issuer = _issuer_value(req.get("issuer")) if req else None
    resp_issuer = _issuer_value(resp.get("issuer")) if resp else None
    sp_selected, _sp_sel = select_role_metadata(all_sp_metadata, [req_issuer])
    idp_selected, _idp_sel = select_role_metadata(
        all_idp_metadata,
        [resp_issuer, *(_issuer_value(a.get("issuer")) for a in assertions)],
    )

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
    if resp and not all_sp_metadata:
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
    if resp and not all_idp_metadata:
        checks.append({
            "check": "Response / Assertion Issuer vs IdP metadata entityID",
            "status": "UNKNOWN",
            "left": _issuer_value(resp.get("issuer")),
            "right": None,
            "note": "IdP metadata was not supplied; issuer identity cannot be verified against metadata.",
        })

    for mi, md in enumerate(sp_selected, 1):
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

    for mi, md in enumerate(idp_selected, 1):
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
        timing=timing,
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
    findings = slot_findings + parse_findings + findings

    if observed_http:
        findings.append({
            "code": "HTTP_RESULT_OBSERVED",
            "severity": "INFO",
            "scope": "HTTP",
            "message": "HTTP status values were present on the SAML tracer export. They are reported as observed transport results only.",
            "observed": observed_http,
            "expected": None,
            "standard": None,
            "note": "An HTTP 401 after a successful SAML Response does not by itself prove certificate, Audience, Recipient, or signature-policy failure. The SP's internal rejection reason is not in this trace.",
        })

    idp_slot_docs = [d for d in docs if d.get("type") == "Metadata" and d.get("metadata_slot") == "idp"]
    sp_slot_docs = [d for d in docs if d.get("type") == "Metadata" and d.get("metadata_slot") == "sp"]
    validation_context = {
        "trace_present": bool(requests or responses or standalone_assertions),
        "idp_metadata": {
            "supplied": bool(all_idp_metadata) or bool(idp_slot_docs) or any(f.get("scope") == "IDP metadata" for f in slot_findings),
            "parse_failed": any(f.get("code") == "METADATA_PARSE_FAILED" and f.get("scope") == "IDP metadata" for f in slot_findings),
            "wrong_role": any(f.get("code") == "METADATA_WRONG_ROLE" and f.get("scope") == "IDP metadata" for f in slot_findings),
            "entity_ids": [m.get("entity_id") for m in all_idp_metadata],
            "selected_entity_id": (idp_selected[0].get("entity_id") if idp_selected else None),
            "selection": (_idp_sel or ("selected" if idp_selected else "none")),
        },
        "sp_metadata": {
            "supplied": bool(all_sp_metadata) or bool(sp_slot_docs) or any(f.get("scope") == "SP metadata" for f in slot_findings),
            "parse_failed": any(f.get("code") == "METADATA_PARSE_FAILED" and f.get("scope") == "SP metadata" for f in slot_findings),
            "wrong_role": any(f.get("code") == "METADATA_WRONG_ROLE" and f.get("scope") == "SP metadata" for f in slot_findings),
            "entity_ids": [m.get("entity_id") for m in all_sp_metadata],
            "selected_entity_id": (sp_selected[0].get("entity_id") if sp_selected else None),
            "selection": (_sp_sel or ("selected" if sp_selected else "none")),
        },
        "observed_http": observed_http,
        "timing": (transport.get("timing") or {}),
    }

    return {
        "kind": "saml",
        "documents_found": len(docs),
        "documents": docs,
        "detected_sources": encodings,
        "parse_failures": parse_failures,
        "slot_metadata_xml": slot_metadata_xml,
        "validation_context": validation_context,
        "decoded_artifacts": assign_decoded_export_names(
            collect_decoded_artifacts(text, "pasted text")
        ),
        "transport": transport,
        "findings": findings,
        "checks": checks,
        "summary": {
            "authn_requests": len(requests),
            "responses": len(responses),
            "standalone_assertions": len(standalone_assertions),
            "assertions_inside_responses": sum(len(r.get("assertions") or []) for r in responses),
            "metadata_entities": len(metadata),
            "sp_metadata_entities": len(all_sp_metadata),
            "idp_metadata_entities": len(all_idp_metadata),
            "mismatches": sum(1 for c in checks if c.get("status") == "MISMATCH"),
            "matches": sum(1 for c in checks if c.get("status") == "MATCH"),
            "unknown_checks": sum(1 for c in checks if c.get("status") == "UNKNOWN"),
            "validation_errors": sum(1 for f in findings if f.get("severity") == "ERROR"),
            "validation_warnings": sum(1 for f in findings if f.get("severity") == "WARNING"),
            "validation_info": sum(1 for f in findings if f.get("severity") == "INFO"),
        },
        "limitations": [
            "XML Signature cryptographic validity is evaluated when a certificate is available. Partner-key authorization is evaluated only against supplied IdP/SP metadata or an operator-supplied signing certificate; missing metadata is NOT_EVALUATED, not failure.",
            "A match against supplied metadata means the signing key is published in that file. It does not prove the metadata file was obtained from a trusted distribution channel. Public WebPKI / certificate CN is not SAML partner trust.",
            "A standard SAML Response contains Assertion XML directly; the analyzer decodes whole Base64 SAMLRequest/SAMLResponse payloads and standalone Base64 Assertions, but intentionally does not recursively decode arbitrary Base64 text nodes such as X509 certificates.",
            "EncryptedAssertion is detected but cannot be decrypted without the SP private key.",
            "EncryptedAttribute and EncryptedID are detected; XML Encryption algorithms and KeyInfo presence are reported, but plaintext is not recovered without the corresponding private key.",
            "Assertion Conditions NotBefore/NotOnOrAfter and bearer SubjectConfirmationData.NotOnOrAfter use a chosen validation_time with configurable clock skew (SAML_CLOCK_SKEW_SECONDS; IDDQD default 120): NotBefore minus skew through NotOnOrAfter plus skew (exclusive upper bound). For SAML-tracer/HAR ACS rows (incident_trace_mode) validation_time is the ACS response Date when present, else the request timestamp; analyzer runtime is not used as the primary clock. Missing event time downgrades timing to INFO, not ERROR. Raw XML without ACS transport evidence uses replay_now_mode (analyzer UTC). Bearer SubjectConfirmationData.NotBefore is forbidden and is not a skew window. Set 0 for no extra tolerance. SessionNotOnOrAfter follows the same mode. Metadata validUntil is compared against the same validation_time.",
            "Standards validation combines SAML 2.0 Core requirements with Web Browser SSO profile rules where the supplied documents indicate an SSO Response. Binding-dependent checks are only hard errors when the binding can be inferred; otherwise they are warnings.",
            "HTTP statuses copied from a tracer export are observed transport facts. They are not used to infer SAML configuration failures.",
            "XML_SIGNATURE_VALID_WITH_EMBEDDED_CERT means the signature verifies against the certificate in ds:KeyInfo. SIGNER_TRUST_NOT_EVALUATED means partner-key authorization was not compared to IdP/SP metadata; cryptographic validity is not MX/SP trust.",
        ],
    }
