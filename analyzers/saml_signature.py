from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from .saml import NS, _extract_candidates, _skip_xml_prologue
from .saml_validation import _usable_metadata, select_role_metadata
from .xml_safe import lxml_fromstring


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


def _spki_sha256_from_pem(pem: str) -> str | None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except Exception:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
        der = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(der).hexdigest().upper()
        return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
    except Exception:
        return None


def _keys_equivalent(left: dict[str, str], right: dict[str, str]) -> str | None:
    """Return how two cert dicts match: DER fingerprint, public-key, or None."""
    if left.get("fingerprint") and left.get("fingerprint") == right.get("fingerprint"):
        return "certificate SHA-256 fingerprint (DER)"
    lp = left.get("spki") or _spki_sha256_from_pem(left.get("pem") or "")
    rp = right.get("spki") or _spki_sha256_from_pem(right.get("pem") or "")
    if lp and rp and lp == rp:
        return "public key (SubjectPublicKeyInfo SHA-256)"
    return None


def _annotate_cert(item: dict[str, str]) -> dict[str, str]:
    out = dict(item)
    if "spki" not in out and out.get("pem"):
        spki = _spki_sha256_from_pem(out["pem"])
        if spki:
            out["spki"] = spki
    return out


def _fingerprint_from_b64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value or "")
    if not compact:
        return None
    try:
        der = base64.b64decode(compact + "=" * ((4 - len(compact) % 4) % 4), validate=False)
    except Exception:
        return None
    fp = hashlib.sha256(der).hexdigest().upper()
    return ":".join(fp[i : i + 2] for i in range(0, len(fp), 2))


def _pem_from_b64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value or "")
    if not compact:
        return None
    try:
        base64.b64decode(compact + "=" * ((4 - len(compact) % 4) % 4), validate=False)
    except Exception:
        return None
    lines = [compact[i : i + 64] for i in range(0, len(compact), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def _iter_result_objects(result: dict[str, Any]):
    counters = {"AuthnRequest": 0, "Response": 0, "Assertion": 0}
    for document in result.get("documents") or []:
        dtype = document.get("type")
        if dtype in {"AuthnRequest", "Response", "Assertion"}:
            counters[dtype] += 1
            prefix = "AUTHNREQUEST" if dtype == "AuthnRequest" else dtype.upper()
            yield dtype, document, f"{dtype} #{counters[dtype]}", prefix
        if dtype == "Response":
            for assertion in document.get("assertions") or []:
                counters["Assertion"] += 1
                yield "Assertion", assertion, f"Assertion #{counters['Assertion']}", "ASSERTION"


def _reference_profile_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for dtype, obj, scope, prefix in _iter_result_objects(result):
        sig = obj.get("signature") or {}
        if not sig.get("present"):
            continue

        count = int(sig.get("reference_count") or 0)
        refs = list(sig.get("reference_uris") or [])
        signed_id = obj.get("id")
        sig["reference_profile_valid"] = False

        if count != 1:
            findings.append(
                _issue(
                    f"{prefix}_SIGNATURE_REFERENCE_COUNT_INVALID",
                    "ERROR",
                    scope,
                    "The SAML XML Signature profile requires exactly one ds:Reference.",
                    observed=count,
                    expected=1,
                    standard="SAML Core 2.0 §5.4.2",
                )
            )
            continue

        if len(refs) != 1 or not refs[0]:
            findings.append(
                _issue(
                    f"{prefix}_SIGNATURE_REFERENCE_URI_MISSING",
                    "ERROR",
                    scope,
                    "The single ds:Reference must carry a same-document URI that points to the signed SAML root element ID.",
                    observed=refs,
                    expected=f"#{signed_id}" if signed_id else "#<signed-root-ID>",
                    standard="SAML Core 2.0 §5.4.2",
                    note="XML Signature generally permits other URI-reference forms, but the SAML signature profile is stricter.",
                )
            )
            continue

        if signed_id and refs[0] != f"#{signed_id}":
            findings.append(
                _issue(
                    f"{prefix}_SIGNATURE_REFERENCE_URI_INVALID",
                    "ERROR",
                    scope,
                    "Reference URI does not match the required same-document reference to the signed SAML root ID.",
                    observed=refs[0],
                    expected=f"#{signed_id}",
                    standard="SAML Core 2.0 §5.4.2",
                    note="For ID='foo', the SAML profile requires URI='#foo'; a full HTTP URL is not the expected form here.",
                )
            )
            continue

        if signed_id:
            sig["reference_profile_valid"] = True
            findings.append(
                _issue(
                    f"{prefix}_SIGNATURE_REFERENCE_URI_VALID",
                    "INFO",
                    scope,
                    "Reference URI is the required same-document reference to the signed SAML root ID.",
                    observed=refs[0],
                    expected=f"#{signed_id}",
                    standard="SAML Core 2.0 §5.4.2",
                )
            )
    return findings


def _parse_lxml_documents(text: str):
    try:
        from lxml import etree
    except Exception:
        return [], []

    saml_objects: dict[tuple[str, str], Any] = {}
    metadata_roots: list[Any] = []

    for candidate, _source in _extract_candidates(text):
        start = candidate.find("<")
        if start < 0:
            continue
        xml = _skip_xml_prologue(candidate[start:].strip())
        try:
            root = lxml_fromstring(xml)
        except Exception:
            continue

        local = etree.QName(root).localname
        if local in {"EntityDescriptor", "EntitiesDescriptor"}:
            metadata_roots.append(root)
            continue

        if local in {"AuthnRequest", "Response", "Assertion"}:
            rid = root.get("ID")
            if rid:
                saml_objects.setdefault((local, rid), root)

        if local == "Response":
            for assertion in root.xpath("./saml:Assertion", namespaces={"saml": NS["saml"]}):
                aid = assertion.get("ID")
                if aid:
                    saml_objects.setdefault(("Assertion", aid), assertion)

    return saml_objects, metadata_roots


def _metadata_signing_certs(metadata_roots: list[Any]) -> dict[tuple[str, str], list[dict[str, str]]]:
    trust: dict[tuple[str, str], list[dict[str, str]]] = {}
    ns = {"md": NS["md"], "ds": NS["ds"]}

    for root in metadata_roots:
        local = root.tag.rsplit("}", 1)[-1]
        if local == "EntityDescriptor":
            entities = [root]
        else:
            entities = root.xpath(".//md:EntityDescriptor", namespaces=ns)

        for entity in entities:
            entity_id = entity.get("entityID")
            if not entity_id:
                continue
            for role, xpath in (
                ("IdP", "./md:IDPSSODescriptor"),
                ("SP", "./md:SPSSODescriptor"),
            ):
                for descriptor in entity.xpath(xpath, namespaces=ns):
                    for kd in descriptor.xpath("./md:KeyDescriptor", namespaces=ns):
                        use = (kd.get("use") or "").strip().lower()
                        if use not in {"", "signing"}:
                            continue
                        for cert_el in kd.xpath(".//ds:X509Certificate", namespaces=ns):
                            value = "".join((cert_el.text or "").split())
                            pem = _pem_from_b64(value)
                            fp = _fingerprint_from_b64(value)
                            if not pem or not fp:
                                continue
                            item = _annotate_cert({"pem": pem, "fingerprint": fp})
                            bucket = trust.setdefault((role, entity_id), [])
                            if not any(x["fingerprint"] == fp for x in bucket):
                                bucket.append(item)
    return trust


def _embedded_certs(element: Any) -> list[dict[str, str]]:
    if element is None:
        return []
    ns = {"ds": NS["ds"]}
    signature = element.find(f"{{{NS['ds']}}}Signature")
    if signature is None:
        return []
    out: list[dict[str, str]] = []
    for cert_el in signature.xpath(".//ds:X509Certificate", namespaces=ns):
        value = "".join((cert_el.text or "").split())
        pem = _pem_from_b64(value)
        fp = _fingerprint_from_b64(value)
        if pem and fp and not any(x["fingerprint"] == fp for x in out):
            out.append(_annotate_cert({"pem": pem, "fingerprint": fp}))
    return out


def _is_sha1_algorithm(uri: str | None) -> bool:
    if not uri:
        return False
    return "sha1" in uri.lower()


def _algorithm_quality_findings(obj: dict[str, Any], scope: str, prefix: str) -> list[dict[str, Any]]:
    """Warn about weak algorithms without treating them as cryptographic failure."""
    findings: list[dict[str, Any]] = []
    sig = obj.get("signature") or {}
    method = sig.get("signature_method")
    if _is_sha1_algorithm(method):
        findings.append(
            _issue(
                f"{prefix}_SIGNATURE_ALGORITHM_WEAK",
                "WARNING",
                scope,
                "SHA-1 based signature algorithms are deprecated/weak for modern deployments.",
                observed=method,
                expected="rsa-sha256 or stronger",
                standard="Security hardening (not a cryptographic signature failure)",
                note="This does not mean the SignatureValue failed verification.",
            )
        )
    for digest in sig.get("digest_methods") or []:
        if _is_sha1_algorithm(digest):
            findings.append(
                _issue(
                    f"{prefix}_DIGEST_ALGORITHM_WEAK",
                    "WARNING",
                    scope,
                    "SHA-1 digest algorithms are deprecated/weak for modern deployments.",
                    observed=digest,
                    expected="sha256 or stronger",
                    standard="Security hardening (not a cryptographic signature failure)",
                    note="This does not mean the DigestValue failed verification.",
                )
            )
            break
    return findings


def _signature_config_for_crypto_check():
    """Permit observed legacy SHA-1 only so cryptographic validity can be measured.

    SignXML's default SignatureConfiguration rejects SHA-1. That is a policy
    decision, not a proof that SignatureValue/DigestValue are wrong.
    """
    from signxml import DigestAlgorithm, SignatureConfiguration, SignatureMethod

    default = SignatureConfiguration()
    sha1_methods = frozenset(method for method in SignatureMethod if "SHA1" in method.name)
    sha1_digests = frozenset(digest for digest in DigestAlgorithm if "SHA1" in digest.name)
    return SignatureConfiguration(
        require_x509=True,
        location="./",
        expect_references=1,
        signature_methods=default.signature_methods | sha1_methods,
        digest_algorithms=default.digest_algorithms | sha1_digests,
        ignore_ambiguous_key_info=default.ignore_ambiguous_key_info,
        default_reference_c14n_method=default.default_reference_c14n_method,
    )


def _is_algorithm_policy_error(exc: BaseException) -> bool:
    message = str(exc).lower()
    return (
        "forbidden by configuration" in message
        or "sha1-based algorithms are not supported" in message
    )


def _verify_with_cert(element: Any, cert_pem: str) -> tuple[bool, str | None]:
    try:
        from signxml import InvalidDigest, InvalidSignature, XMLVerifier
    except Exception as exc:
        return False, f"signxml unavailable: {exc}"

    try:
        XMLVerifier().verify(
            element,
            x509_cert=cert_pem,
            id_attribute="ID",
            validate_schema=False,
            expect_config=_signature_config_for_crypto_check(),
        )
        return True, None
    except (InvalidSignature, InvalidDigest) as exc:
        return False, str(exc)
    except Exception as exc:
        if _is_algorithm_policy_error(exc):
            return False, f"algorithm_policy: {exc}"
        return False, str(exc)


def _remove_obsolete_findings(result: dict[str, Any]) -> None:
    cleaned = []
    for finding in result.get("findings") or []:
        code = str(finding.get("code") or "")
        if code.endswith("_SIGNATURE_REFERENCE_SUSPICIOUS"):
            continue
        cleaned.append(finding)
    result["findings"] = cleaned


def _remove_crypto_warning(result: dict[str, Any], prefix: str, scope: str) -> None:
    code = f"{prefix}_SIGNATURE_NOT_CRYPTO_VERIFIED"
    result["findings"] = [
        f
        for f in result.get("findings") or []
        if not (f.get("code") == code and f.get("scope") == scope)
    ]


def _signature_parse_text(text: str, result: dict[str, Any]) -> str:
    extras = [x for x in (result.get("slot_metadata_xml") or []) if x]
    if not extras:
        return text
    return "\n\n".join([text, *extras])


def _metadata_role_for_document(dtype: str) -> str:
    return "SP" if dtype == "AuthnRequest" else "IdP"


def _selected_metadata_certs(
    trust: dict[tuple[str, str], list[dict[str, str]]],
    result: dict[str, Any],
    dtype: str,
    issuer: str | None,
) -> tuple[list[dict[str, str]], str | None, str | None]:
    """Return (certs, entity_id, selection_state). selection_state is none/selected/ambiguous/not_selected."""
    role = _metadata_role_for_document(dtype)
    docs = _usable_metadata(result.get("documents") or [], role)
    if not docs:
        return [], None, "none"
    selected, issue = select_role_metadata(docs, [issuer] if issuer else [])
    if issue:
        return [], None, "ambiguous" if issue == "METADATA_ENTITY_AMBIGUOUS" else "not_selected"
    entity_id = selected[0].get("entity_id") if selected else None
    if not entity_id:
        return [], None, "not_selected"
    return list(trust.get((role, entity_id)) or []), entity_id, "selected"


def _verify_any(element: Any, certs: list[dict[str, str]]) -> tuple[dict[str, str] | None, str | None]:
    last_error = None
    for cert in certs:
        ok, error = _verify_with_cert(element, cert["pem"])
        if ok:
            return cert, None
        last_error = error
    return None, last_error


def _crypto_findings(text: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    saml_objects, metadata_roots = _parse_lxml_documents(_signature_parse_text(text, result))
    trust = _metadata_signing_certs(metadata_roots)

    for dtype, obj, scope, prefix in _iter_result_objects(result):
        sig = obj.get("signature") or {}
        if not sig.get("present"):
            continue

        signed_id = obj.get("id")
        element = saml_objects.get((dtype, signed_id)) if signed_id else None
        issuer = ((obj.get("issuer") or {}).get("value"))
        role = _metadata_role_for_document(dtype)
        trusted, selected_entity_id, selection = _selected_metadata_certs(trust, result, dtype, issuer)
        embedded = _embedded_certs(element)
        trusted_fps = [x["fingerprint"] for x in trusted]
        embedded_fps = [x["fingerprint"] for x in embedded]

        sig["metadata_signing_cert_fingerprints"] = trusted_fps
        sig["embedded_signing_cert_fingerprints"] = embedded_fps
        sig["crypto_verification"] = "NOT_CHECKED"
        findings.extend(_algorithm_quality_findings(obj, scope, prefix))

        if element is None:
            findings.append(
                _issue(
                    f"{prefix}_SIGNATURE_CRYPTO_NOT_CHECKED_XML_UNAVAILABLE",
                    "WARNING",
                    scope,
                    "Cryptographic verification was not run because the exact signed XML element could not be reconstructed from the supplied input.",
                    standard="XML Signature validation",
                )
            )
            continue

        verified_cert = None
        last_error = None
        verified_via_metadata = False
        if trusted:
            verified_cert, last_error = _verify_any(element, trusted)
            verified_via_metadata = verified_cert is not None
        if verified_cert is None and embedded:
            verified_cert, last_error = _verify_any(element, embedded)

        if verified_cert:
            match_kind = None
            if trusted:
                for meta_cert in trusted:
                    match_kind = _keys_equivalent(verified_cert, meta_cert)
                    if match_kind:
                        verified_via_metadata = True
                        break
            _remove_crypto_warning(result, prefix, scope)
            if verified_via_metadata and trusted:
                sig["crypto_verification"] = "VALID_TRUSTED_METADATA"
                sig["verified_signing_cert_fingerprint"] = verified_cert["fingerprint"]
                findings.append(
                    _issue(
                        f"{prefix}_XML_SIGNATURE_VALID",
                        "INFO",
                        scope,
                        "XML Signature and referenced digest verified successfully.",
                        observed=verified_cert["fingerprint"],
                        expected=trusted_fps,
                        standard="SAML Core 2.0 §5 + XML Signature",
                    )
                )
                match_code = (
                    f"{prefix}_SIGNING_KEY_MATCHES_SP_METADATA"
                    if role == "SP"
                    else f"{prefix}_SIGNING_KEY_MATCHES_IDP_METADATA"
                )
                findings.append(
                    _issue(
                        match_code,
                        "INFO",
                        scope,
                        f"The signing key matches a signing key published in the supplied {role} metadata.",
                        observed=verified_cert["fingerprint"],
                        expected=trusted_fps,
                        standard="SAML metadata KeyDescriptor comparison",
                        note=f"Match method: {match_kind or 'certificate SHA-256 fingerprint (DER)'}. This is not a claim that the metadata file itself was obtained from a trusted distribution channel.",
                    )
                )
                if embedded_fps and not any(_keys_equivalent(verified_cert, e) for e in embedded):
                    findings.append(
                        _issue(
                            f"{prefix}_EMBEDDED_CERT_NOT_METADATA_SIGNING_CERT",
                            "WARNING",
                            scope,
                            "The signature verifies with a signing key from supplied metadata, but the certificate embedded in ds:KeyInfo is a different key.",
                            observed=embedded_fps,
                            expected=verified_cert["fingerprint"],
                            standard="SAML metadata key comparison",
                            note="An embedded ds:KeyInfo certificate is not automatically an authorized partner key.",
                        )
                    )
            elif selection in {"ambiguous", "not_selected"}:
                _remove_crypto_warning(result, prefix, scope)
                sig["crypto_verification"] = "VALID_EMBEDDED_CERT"
                sig["verified_signing_cert_fingerprint"] = verified_cert["fingerprint"]
                findings.append(
                    _issue(
                        f"{prefix}_XML_SIGNATURE_VALID",
                        "INFO",
                        scope,
                        "XML Signature and referenced digest verified successfully with the certificate embedded in ds:KeyInfo.",
                        observed=verified_cert["fingerprint"],
                        standard="XML Signature",
                    )
                )
                findings.append(
                    _issue(
                        f"{prefix}_SIGNER_TRUST_NOT_EVALUATED",
                        "INFO",
                        scope,
                        f"Signer metadata comparison was not evaluated because the {role} metadata entity was not uniquely selected.",
                        observed=verified_cert["fingerprint"],
                        expected="a unique metadata entityID matching the message Issuer",
                        standard="SAML metadata trust model",
                        note="Missing or ambiguous metadata is not a signature failure.",
                    )
                )
            elif selection == "selected":
                _remove_crypto_warning(result, prefix, scope)
                sig["crypto_verification"] = "VALID_EMBEDDED_CERT"
                sig["verified_signing_cert_fingerprint"] = verified_cert["fingerprint"]
                findings.append(
                    _issue(
                        f"{prefix}_XML_SIGNATURE_VALID",
                        "INFO",
                        scope,
                        "XML Signature and referenced digest verified successfully with the certificate embedded in ds:KeyInfo.",
                        observed=verified_cert["fingerprint"],
                        standard="XML Signature",
                    )
                )
                mismatch_code = (
                    f"{prefix}_SIGNING_KEY_NOT_IN_SP_METADATA"
                    if role == "SP"
                    else f"{prefix}_SIGNING_KEY_NOT_IN_IDP_METADATA"
                )
                findings.append(
                    _issue(
                        mismatch_code,
                        "ERROR",
                        scope,
                        f"The signing certificate does not match any signing key in the supplied {role} metadata.",
                        observed=verified_cert["fingerprint"],
                        expected=trusted_fps or f"{role} metadata signing keys for {selected_entity_id}",
                        standard="SAML metadata KeyDescriptor comparison",
                        note=f"Compared {len(trusted)} published signing key(s) using certificate SHA-256 fingerprints and public-key equality. This is not a public WebPKI trust decision.",
                    )
                )
            else:
                _remove_crypto_warning(result, prefix, scope)
                sig["crypto_verification"] = "VALID_EMBEDDED_CERT"
                sig["verified_signing_cert_fingerprint"] = verified_cert["fingerprint"]
                findings.append(
                    _issue(
                        f"{prefix}_XML_SIGNATURE_VALID",
                        "INFO",
                        scope,
                        "XML Signature and referenced digest verified successfully with the certificate embedded in ds:KeyInfo.",
                        observed=verified_cert["fingerprint"],
                        standard="XML Signature",
                    )
                )
                findings.append(
                    _issue(
                        f"{prefix}_SIGNER_TRUST_NOT_EVALUATED",
                        "INFO",
                        scope,
                        f"Signer trust against {role} metadata was not evaluated: no matching {role} metadata or explicit trusted signing key was supplied.",
                        observed=verified_cert["fingerprint"],
                        expected=f"optional {role} metadata signing KeyDescriptor(s) or an operator-supplied signing certificate",
                        standard="SAML metadata trust model",
                        note="Cryptographic validity of the signature is not the same as partner-key authorization.",
                    )
                )
            continue

        policy_blocked = str(last_error or "").startswith("algorithm_policy:")
        if policy_blocked:
            _remove_crypto_warning(result, prefix, scope)
            sig["crypto_verification"] = "NOT_CHECKED_ALGORITHM_POLICY"
            findings.append(
                _issue(
                    f"{prefix}_SIGNATURE_CRYPTO_NOT_CHECKED_ALGORITHM_UNSUPPORTED",
                    "WARNING",
                    scope,
                    "Cryptographic verification was not completed because the signature uses an algorithm the verifier cannot evaluate. This is not classified as a cryptographic signature failure.",
                    observed=last_error,
                    standard="XML Signature validation",
                )
            )
            continue

        if trusted or embedded:
            _remove_crypto_warning(result, prefix, scope)
            sig["crypto_verification"] = "INVALID_TRUSTED_METADATA" if trusted else "INVALID_EMBEDDED_CERT"
            findings.append(
                _issue(
                    f"{prefix}_XML_SIGNATURE_INVALID",
                    "ERROR",
                    scope,
                    "XML Signature could not be verified with the available signing certificates.",
                    observed=last_error,
                    expected=trusted_fps or embedded_fps,
                    standard="SAML Core 2.0 §5 + XML Signature",
                )
            )
            continue

        sig["crypto_verification"] = "NOT_CHECKED_NO_CERT"
        findings.append(
            _issue(
                f"{prefix}_SIGNATURE_NO_VERIFICATION_CERT",
                "WARNING",
                scope,
                "No usable signing certificate was available from matching metadata or ds:KeyInfo, so cryptographic verification could not be performed.",
                expected="metadata signing certificate or embedded ds:KeyInfo certificate",
                standard="SAML Core 2.0 §5 + XML Signature",
            )
        )

    return findings


def enhance_saml_signature_validation(text: str, result: dict[str, Any]) -> dict[str, Any]:
    """Add SAML XML Signature profile and cryptographic checks without private keys.

    Signature verification uses public X.509 certificates. A private key is not
    needed to verify XML signatures; it is only relevant to later optional
    decryption of encrypted SAML content.
    """
    _remove_obsolete_findings(result)

    additions = _reference_profile_findings(result)
    try:
        additions.extend(_crypto_findings(text, result))
    except Exception as exc:
        additions.append(
            _issue(
                "XML_SIGNATURE_VERIFICATION_ENGINE_ERROR",
                "WARNING",
                "Signature verification",
                "The additional cryptographic verification layer could not complete.",
                observed=str(exc),
                note="Base SAML parsing and protocol validation results are still available.",
            )
        )

    result.setdefault("findings", []).extend(additions)
    summary = result.setdefault("summary", {})
    summary["validation_errors"] = sum(1 for f in result["findings"] if f.get("severity") == "ERROR")
    summary["validation_warnings"] = sum(1 for f in result["findings"] if f.get("severity") == "WARNING")
    summary["validation_info"] = sum(1 for f in result["findings"] if f.get("severity") == "INFO")
    summary["signature_crypto_valid_trusted"] = sum(
        1
        for _dtype, obj, _scope, _prefix in _iter_result_objects(result)
        if (obj.get("signature") or {}).get("crypto_verification") == "VALID_TRUSTED_METADATA"
    )
    return result
