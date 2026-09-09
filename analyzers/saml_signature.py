from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from .saml import NS, _extract_candidates, _skip_xml_prologue
from .xml_safe import lxml_fromstring

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"


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
            for assertion in root.xpath("./saml:Assertion", namespaces={"saml": SAML_NS}):
                aid = assertion.get("ID")
                if aid:
                    saml_objects.setdefault(("Assertion", aid), assertion)

    return saml_objects, metadata_roots


def _metadata_signing_certs(metadata_roots: list[Any]) -> dict[tuple[str, str], list[dict[str, str]]]:
    trust: dict[tuple[str, str], list[dict[str, str]]] = {}
    ns = {"md": MD_NS, "ds": DS_NS}

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
                            item = {"pem": pem, "fingerprint": fp}
                            bucket = trust.setdefault((role, entity_id), [])
                            if not any(x["fingerprint"] == fp for x in bucket):
                                bucket.append(item)
    return trust


def _embedded_certs(element: Any) -> list[dict[str, str]]:
    if element is None:
        return []
    ns = {"ds": DS_NS}
    signature = element.find(f"{{{DS_NS}}}Signature")
    if signature is None:
        return []
    out: list[dict[str, str]] = []
    for cert_el in signature.xpath(".//ds:X509Certificate", namespaces=ns):
        value = "".join((cert_el.text or "").split())
        pem = _pem_from_b64(value)
        fp = _fingerprint_from_b64(value)
        if pem and fp and not any(x["fingerprint"] == fp for x in out):
            out.append({"pem": pem, "fingerprint": fp})
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


def _crypto_findings(text: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    saml_objects, metadata_roots = _parse_lxml_documents(text)
    trust = _metadata_signing_certs(metadata_roots)

    for dtype, obj, scope, prefix in _iter_result_objects(result):
        sig = obj.get("signature") or {}
        if not sig.get("present"):
            continue

        signed_id = obj.get("id")
        element = saml_objects.get((dtype, signed_id)) if signed_id else None
        issuer = ((obj.get("issuer") or {}).get("value"))
        role = "SP" if dtype == "AuthnRequest" else "IdP"
        trusted = trust.get((role, issuer), []) if issuer else []
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

        if trusted:
            verified_cert = None
            last_error = None
            for cert in trusted:
                ok, error = _verify_with_cert(element, cert["pem"])
                if ok:
                    verified_cert = cert
                    break
                last_error = error

            _remove_crypto_warning(result, prefix, scope)
            if verified_cert:
                sig["crypto_verification"] = "VALID_TRUSTED_METADATA"
                sig["verified_signing_cert_fingerprint"] = verified_cert["fingerprint"]
                findings.append(
                    _issue(
                        f"{prefix}_XML_SIGNATURE_VALID",
                        "INFO",
                        scope,
                        "XML Signature and referenced digest verified successfully with a signing certificate from matching SAML metadata.",
                        observed=verified_cert["fingerprint"],
                        expected=f"trusted {role} signing certificate",
                        standard="SAML Core 2.0 §5 + XML Signature",
                    )
                )
                if embedded_fps:
                    if verified_cert["fingerprint"] in embedded_fps:
                        findings.append(
                            _issue(
                                f"{prefix}_SIGNING_CERT_MATCHES_METADATA",
                                "INFO",
                                scope,
                                "The certificate embedded in ds:KeyInfo matches the metadata signing certificate that verified the signature.",
                                observed=verified_cert["fingerprint"],
                                standard="SAML metadata trust comparison",
                            )
                        )
                    else:
                        findings.append(
                            _issue(
                                f"{prefix}_EMBEDDED_CERT_NOT_METADATA_SIGNING_CERT",
                                "WARNING",
                                scope,
                                "The signature verifies with trusted metadata, but the certificate embedded in ds:KeyInfo does not match that trusted signing certificate.",
                                observed=embedded_fps,
                                expected=verified_cert["fingerprint"],
                                standard="SAML metadata trust comparison",
                                note="Trust is established by the configured metadata certificate, not by an arbitrary embedded certificate.",
                            )
                        )
            else:
                policy_blocked = str(last_error or "").startswith("algorithm_policy:")
                if policy_blocked:
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
                else:
                    sig["crypto_verification"] = "INVALID_TRUSTED_METADATA"
                    findings.append(
                        _issue(
                            f"{prefix}_XML_SIGNATURE_INVALID",
                            "ERROR",
                            scope,
                            "XML Signature could not be verified with any signing certificate from matching SAML metadata.",
                            observed=last_error,
                            expected=trusted_fps,
                            standard="SAML Core 2.0 §5 + XML Signature",
                        )
                    )
            continue

        if embedded:
            verified_cert = None
            last_error = None
            for cert in embedded:
                ok, error = _verify_with_cert(element, cert["pem"])
                if ok:
                    verified_cert = cert
                    break
                last_error = error

            _remove_crypto_warning(result, prefix, scope)
            if verified_cert:
                sig["crypto_verification"] = "VALID_EMBEDDED_CERT_UNTRUSTED"
                sig["verified_signing_cert_fingerprint"] = verified_cert["fingerprint"]
                findings.append(
                    _issue(
                        f"{prefix}_XML_SIGNATURE_VALID_EMBEDDED_CERT_ONLY",
                        "WARNING",
                        scope,
                        "The XML Signature is cryptographically valid with the certificate embedded in ds:KeyInfo, but signer trust is not established because matching SAML metadata was not supplied.",
                        observed=verified_cert["fingerprint"],
                        expected="matching trusted SP/IdP metadata signing certificate",
                        standard="XML Signature + SAML metadata trust model",
                    )
                )
            else:
                policy_blocked = str(last_error or "").startswith("algorithm_policy:")
                if policy_blocked:
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
                else:
                    sig["crypto_verification"] = "INVALID_EMBEDDED_CERT"
                    findings.append(
                        _issue(
                            f"{prefix}_XML_SIGNATURE_INVALID",
                            "ERROR",
                            scope,
                            "XML Signature could not be verified with the certificate embedded in ds:KeyInfo.",
                            observed=last_error,
                            expected=embedded_fps,
                            standard="XML Signature",
                        )
                    )
            continue

        # Keep the base SIGNATURE_NOT_CRYPTO_VERIFIED warning in this case.
        sig["crypto_verification"] = "NOT_CHECKED_NO_CERT"
        findings.append(
            _issue(
                f"{prefix}_SIGNATURE_NO_VERIFICATION_CERT",
                "WARNING",
                scope,
                "No usable signing certificate was available from matching metadata or ds:KeyInfo, so cryptographic verification could not be performed.",
                expected="trusted metadata signing certificate",
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
    summary["signature_crypto_valid_trusted"] = sum(
        1
        for _dtype, obj, _scope, _prefix in _iter_result_objects(result)
        if (obj.get("signature") or {}).get("crypto_verification") == "VALID_TRUSTED_METADATA"
    )
    return result
