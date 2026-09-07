from __future__ import annotations

import base64
import re
from typing import Any
from urllib.parse import quote_plus

from lxml import etree

from .anonymizer import (
    BASE64_TOKEN_RE,
    SAML_PARAM_RE,
    _Mapper,
    _anonymize_patterns,
    _decode_saml_payload,
    _encode_saml_payload,
)

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"

DATA_URL_ATTRS = {
    "Destination", "Recipient", "AssertionConsumerServiceURL", "Location", "ResponseLocation", "entityID"
}
IDREF_ATTRS = {"InResponseTo"}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _map_id(mapper: _Mapper, value: str) -> str:
    return mapper.map("SAML_ID", value)


def _safe_value(value: str, mapper: _Mapper, category: str) -> str:
    value = (value or "").strip()
    if not value:
        return value
    return mapper.map(category, value)


def _anonymize_saml_xml(xml: str, mapper: _Mapper) -> tuple[str, dict[str, Any]]:
    """Anonymize data-bearing SAML fields while preserving protocol/namespace URIs.

    This is deliberately XML-aware. Namespace URIs, SAML URNs, XMLDSig algorithm URIs,
    NameID Format URIs, AuthnContext URIs and binding/profile identifiers are not passed
    through the generic URL/domain anonymizer.
    """
    parser = etree.XMLParser(resolve_entities=False, no_network=True, remove_blank_text=False, recover=False)
    root = etree.fromstring(xml.encode("utf-8"), parser=parser)

    id_map: dict[str, str] = {}
    x509_redacted = 0
    attribute_values_redacted = 0

    # First pass: collect IDs so ds:Reference URI and InResponseTo remain internally coherent.
    for el in root.iter():
        value = el.get("ID")
        if value and value not in id_map:
            id_map[value] = _map_id(mapper, value)

    for el in root.iter():
        local = _local_name(el.tag)

        if el.get("ID") in id_map:
            el.set("ID", id_map[el.get("ID")])

        for attr in IDREF_ATTRS:
            value = el.get(attr)
            if value:
                el.set(attr, id_map.get(value, mapper.map("SAML_ID", value)))

        session_index = el.get("SessionIndex")
        if session_index:
            el.set("SessionIndex", mapper.map("SESSION", session_index))

        for attr in DATA_URL_ATTRS:
            value = el.get(attr)
            if value and not value.startswith("{"):
                el.set(attr, _anonymize_patterns(value, mapper))

        # SubjectLocality Address may be an IP or hostname.
        if local == "SubjectLocality" and el.get("Address"):
            el.set("Address", _anonymize_patterns(el.get("Address"), mapper))

        # ds:Reference must continue to point to the mapped signed element ID.
        if el.tag == f"{{{DS_NS}}}Reference":
            uri = el.get("URI")
            if uri and uri.startswith("#"):
                target = uri[1:]
                el.set("URI", "#" + id_map.get(target, mapper.map("SAML_ID", target)))

        # Never rewrite Algorithm/Method/Format namespace/profile URIs.
        if el.tag == f"{{{DS_NS}}}X509Certificate" and (el.text or "").strip():
            marker = mapper.map("CERTIFICATE", re.sub(r"\s+", "", el.text or ""))
            el.text = marker
            x509_redacted += 1
            continue

        if local == "Issuer" and (el.text or "").strip():
            el.text = _anonymize_patterns((el.text or "").strip(), mapper)
        elif local == "Audience" and (el.text or "").strip():
            value = (el.text or "").strip()
            el.text = value if value.startswith("{") else _anonymize_patterns(value, mapper)
        elif local == "NameID" and (el.text or "").strip():
            value = (el.text or "").strip()
            if "@" in value:
                el.text = mapper.map("EMAIL", value)
            else:
                el.text = mapper.map("NAMEID", value)
        elif local == "AttributeValue" and (el.text or "").strip():
            el.text = mapper.map("ATTRIBUTE_VALUE", (el.text or "").strip())
            attribute_values_redacted += 1

    serialized = etree.tostring(root, encoding="unicode")
    return serialized, {
        "saml_ids_anonymized": len(id_map),
        "x509_certificates_redacted": x509_redacted,
        "attribute_values_redacted": attribute_values_redacted,
    }


def _try_whole_xml(text: str, mapper: _Mapper) -> tuple[str, dict[str, Any]] | None:
    stripped = text.strip()
    if not stripped.startswith("<") or "urn:oasis:names:tc:SAML:2.0:" not in stripped:
        return None
    try:
        return _anonymize_saml_xml(stripped, mapper)
    except Exception:
        return None


def _anonymize_encoded_saml(text: str, mapper: _Mapper) -> tuple[str, int, set[str], dict[str, int]]:
    changed = 0
    transports: set[str] = set()
    stats = {"saml_ids_anonymized": 0, "x509_certificates_redacted": 0, "attribute_values_redacted": 0}

    def process(value: str) -> tuple[str, str] | None:
        decoded = _decode_saml_payload(value)
        if decoded is None:
            return None
        xml, transport = decoded
        try:
            anon_xml, local_stats = _anonymize_saml_xml(xml, mapper)
        except Exception:
            return None
        for key in stats:
            stats[key] += int(local_stats.get(key, 0))
        return _encode_saml_payload(anon_xml, transport), transport

    def named_repl(match: re.Match[str]) -> str:
        nonlocal changed
        original = match.group("value")
        processed = process(original)
        if processed is None:
            return match.group(0)
        encoded, transport = processed
        if "%" in original:
            encoded = quote_plus(encoded, safe="")
        changed += 1
        transports.add(transport)
        q = match.group("quote") or ""
        return match.group("prefix") + q + encoded + q

    out = SAML_PARAM_RE.sub(named_repl, text)

    def blob_repl(match: re.Match[str]) -> str:
        nonlocal changed
        before = out[max(0, match.start() - 48):match.start()]
        if re.search(r"SAML(?:Response|Request)\s*[=:]\s*['\"]?$", before, re.I):
            return match.group(0)
        processed = process(match.group("value"))
        if processed is None:
            return match.group("value")
        encoded, transport = processed
        changed += 1
        transports.add(transport)
        return encoded

    out = BASE64_TOKEN_RE.sub(blob_repl, out)
    return out, changed, transports, stats


def anonymize_text(text: str) -> dict[str, Any]:
    mapper = _Mapper()

    whole = _try_whole_xml(text, mapper)
    if whole is not None:
        out, stats = whole
        encoded_count = 0
        transports: set[str] = set()
    else:
        out, encoded_count, transports, stats = _anonymize_encoded_saml(text, mapper)
        # Anything outside encoded SAML is still handled as ordinary log/plaintext data.
        out = _anonymize_patterns(out, mapper)

    limitations = [
        "The anonymizer is pattern-based for generic logs and XML-aware for recognized SAML payloads; it is not a certified DLP engine.",
        "Standard SAML/XML/XMLDSig namespace, profile and algorithm URIs are preserved.",
        "SAML identifiers are pseudonymized coherently across ID, InResponseTo and ds:Reference URI fields.",
        "X.509 certificate content and SAML AttributeValue/NameID data are redacted because they may contain organization or identity information.",
        "Review the anonymized preview before sharing externally.",
    ]
    if encoded_count or whole is not None:
        limitations.append(
            "Anonymizing signed SAML changes signed content, so the original XML Signature/DigestValue is no longer cryptographically valid by design."
        )

    counts = mapper.counts()
    return {
        "text": out,
        "mapping": mapper.as_rows(),
        "counts": counts,
        "replacements": sum(counts.values()),
        "encoded_saml_payloads_anonymized": encoded_count,
        "encoded_saml_transports": sorted(transports),
        "saml_ids_anonymized": stats["saml_ids_anonymized"],
        "x509_certificates_redacted": stats["x509_certificates_redacted"],
        "attribute_values_redacted": stats["attribute_values_redacted"],
        "limitations": limitations,
    }
