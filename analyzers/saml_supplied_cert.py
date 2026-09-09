from __future__ import annotations

import re
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .saml_signature import (
    _issue,
    _iter_result_objects,
    _parse_lxml_documents,
    _remove_crypto_warning,
    _verify_with_cert,
)

_PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.*?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)


def extract_pem_certificates_from_text(text: str) -> bytes | None:
    """Return PEM certificate blocks found in pasted/uploaded text, if any."""
    if not text:
        return None
    raw = text.encode("utf-8", errors="ignore")
    blocks = _PEM_CERT_RE.findall(raw)
    if not blocks:
        return None
    return b"\n".join(blocks) + b"\n"


def _colon_sha256(cert: x509.Certificate) -> str:
    raw = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


def _dt_iso(value) -> str | None:
    if value is None:
        return None
    try:
        return value.isoformat()
    except Exception:
        return str(value)


def load_supplied_certificates(data: bytes | str | None) -> tuple[list[dict[str, str]], str | None]:
    """Load one DER certificate or one/more PEM X.509 certificates.

    Returns normalized PEM certificates plus display metadata. Bare PUBLIC KEY
    files are intentionally rejected because the SAML verifier's trust input is
    an X.509 signing certificate, matching normal SAML metadata semantics.
    """
    if data is None:
        return [], None
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if not raw.strip():
        return [], None

    if b"BEGIN PUBLIC KEY" in raw or b"BEGIN RSA PUBLIC KEY" in raw or b"BEGIN EC PUBLIC KEY" in raw:
        return [], "A bare public key was supplied. Upload an X.509 certificate (.pem/.crt/.cer) instead."
    if b"BEGIN PRIVATE KEY" in raw or b"BEGIN RSA PRIVATE KEY" in raw or b"BEGIN EC PRIVATE KEY" in raw:
        return [], "A private key was supplied. Private keys are not accepted by signature verification. Upload the public X.509 certificate instead."

    certs: list[x509.Certificate] = []
    pem_blocks = _PEM_CERT_RE.findall(raw)
    if pem_blocks:
        for block in pem_blocks:
            try:
                certs.append(x509.load_pem_x509_certificate(block))
            except Exception as exc:
                return [], f"Could not parse PEM X.509 certificate: {exc}"
    else:
        try:
            certs.append(x509.load_der_x509_certificate(raw))
        except Exception as exc:
            return [], f"Could not parse X.509 certificate as PEM or DER: {exc}"

    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for cert in certs:
        fp = _colon_sha256(cert)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(
            {
                "pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                "fingerprint": fp,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": format(cert.serial_number, "X"),
                "not_valid_before": _dt_iso(getattr(cert, "not_valid_before_utc", cert.not_valid_before)),
                "not_valid_after": _dt_iso(getattr(cert, "not_valid_after_utc", cert.not_valid_after)),
            }
        )
    return out, None


def _remove_no_cert_warning(result: dict[str, Any], prefix: str, scope: str) -> None:
    codes = {
        f"{prefix}_SIGNATURE_NOT_CRYPTO_VERIFIED",
        f"{prefix}_SIGNATURE_NO_VERIFICATION_CERT",
    }
    result["findings"] = [
        f
        for f in result.get("findings") or []
        if not (f.get("scope") == scope and f.get("code") in codes)
    ]


def _recount(result: dict[str, Any]) -> None:
    findings = result.get("findings") or []
    summary = result.setdefault("summary", {})
    summary["validation_errors"] = sum(1 for f in findings if f.get("severity") == "ERROR")
    summary["validation_warnings"] = sum(1 for f in findings if f.get("severity") == "WARNING")
    summary["signature_crypto_valid_supplied_cert"] = sum(
        1
        for _dtype, obj, _scope, _prefix in _iter_result_objects(result)
        if (obj.get("signature") or {}).get("crypto_verification") == "VALID_SUPPLIED_CERT"
    )


def verify_with_supplied_certificate(
    text: str,
    result: dict[str, Any],
    certificate_data: bytes | str | None,
) -> dict[str, Any]:
    certs, parse_error = load_supplied_certificates(certificate_data)
    if parse_error:
        result.setdefault("findings", []).append(
            _issue(
                "SUPPLIED_SIGNING_CERTIFICATE_INVALID",
                "ERROR",
                "Signing certificate",
                parse_error,
                expected="X.509 certificate in PEM or DER format",
                note="Private keys are neither required nor accepted for XML Signature verification.",
            )
        )
        _recount(result)
        return result
    if not certs:
        return result

    result["supplied_signing_certificates"] = [
        {k: v for k, v in cert.items() if k != "pem"} for cert in certs
    ]

    saml_objects, _metadata_roots = _parse_lxml_documents(text)
    additions: list[dict[str, Any]] = []

    for dtype, obj, scope, prefix in _iter_result_objects(result):
        sig = obj.get("signature") or {}
        if not sig.get("present"):
            continue

        signed_id = obj.get("id")
        element = saml_objects.get((dtype, signed_id)) if signed_id else None
        supplied_fps = [c["fingerprint"] for c in certs]
        sig["supplied_signing_cert_fingerprints"] = supplied_fps

        if element is None:
            additions.append(
                _issue(
                    f"{prefix}_SUPPLIED_CERT_NOT_CHECKED_XML_UNAVAILABLE",
                    "WARNING",
                    scope,
                    "A signing certificate was supplied, but the exact signed XML element could not be reconstructed for verification.",
                    observed=supplied_fps,
                )
            )
            continue

        current = sig.get("crypto_verification")
        metadata_fps = list(sig.get("metadata_signing_cert_fingerprints") or [])
        embedded_fps = list(sig.get("embedded_signing_cert_fingerprints") or [])

        # Metadata remains the primary trust source. If it already verified the
        # signature, only compare the operator-supplied certificate with it.
        if current == "VALID_TRUSTED_METADATA":
            verified_fp = sig.get("verified_signing_cert_fingerprint")
            if verified_fp in supplied_fps:
                additions.append(
                    _issue(
                        f"{prefix}_SUPPLIED_CERT_MATCHES_METADATA",
                        "INFO",
                        scope,
                        "The supplied signing certificate matches the metadata certificate that verified the XML Signature.",
                        observed=verified_fp,
                        standard="SAML metadata trust comparison",
                    )
                )
            else:
                additions.append(
                    _issue(
                        f"{prefix}_SUPPLIED_CERT_DIFFERS_FROM_VERIFIED_METADATA",
                        "WARNING",
                        scope,
                        "The XML Signature is valid with trusted metadata, but the separately supplied certificate is different.",
                        observed=supplied_fps,
                        expected=verified_fp,
                        note="This may be intentional during certificate rollover; verify which certificate is currently configured as trusted.",
                    )
                )
            continue

        verified = None
        last_error = None
        for cert in certs:
            ok, error = _verify_with_cert(element, cert["pem"])
            if ok:
                verified = cert
                break
            last_error = error

        if verified:
            _remove_crypto_warning(result, prefix, scope)
            _remove_no_cert_warning(result, prefix, scope)
            sig["crypto_verification"] = "VALID_SUPPLIED_CERT"
            sig["verified_signing_cert_fingerprint"] = verified["fingerprint"]
            additions.append(
                _issue(
                    f"{prefix}_XML_SIGNATURE_VALID_SUPPLIED_CERT",
                    "INFO",
                    scope,
                    "XML Signature and referenced digest verified successfully with the explicitly supplied X.509 certificate.",
                    observed=verified["fingerprint"],
                    expected="operator-supplied signing certificate",
                    standard="SAML Core 2.0 §5 + XML Signature",
                    note="Cryptographic validity is proven. The certificate's identity/provenance must be trusted out of band unless it is also present in trusted SAML metadata.",
                )
            )

            if metadata_fps:
                if verified["fingerprint"] in metadata_fps:
                    additions.append(
                        _issue(
                            f"{prefix}_SUPPLIED_CERT_MATCHES_METADATA",
                            "INFO",
                            scope,
                            "The supplied certificate is also present as a signing certificate in matching SAML metadata.",
                            observed=verified["fingerprint"],
                            standard="SAML metadata trust comparison",
                        )
                    )
                else:
                    additions.append(
                        _issue(
                            f"{prefix}_SUPPLIED_CERT_NOT_IN_METADATA",
                            "WARNING",
                            scope,
                            "The signature verifies with the supplied certificate, but that certificate is not present among the matching metadata signing certificates.",
                            observed=verified["fingerprint"],
                            expected=metadata_fps,
                            note="This commonly indicates stale metadata, certificate rollover, or a certificate supplied for a different trust configuration.",
                        )
                    )

            if embedded_fps and verified["fingerprint"] not in embedded_fps:
                additions.append(
                    _issue(
                        f"{prefix}_SUPPLIED_CERT_DIFFERS_FROM_EMBEDDED_CERT",
                        "WARNING",
                        scope,
                        "The supplied certificate verifies the signature, but it differs from the certificate embedded in ds:KeyInfo.",
                        observed=embedded_fps,
                        expected=verified["fingerprint"],
                        note="An embedded certificate is not automatically trusted, but a difference is useful troubleshooting evidence.",
                    )
                )
            continue

        # Do not replace a previously proven embedded-certificate signature with
        # an error. The supplied cert may simply belong to the opposite SAML role.
        severity = "WARNING" if str(current or "").startswith("VALID_") else "ERROR"
        additions.append(
            _issue(
                f"{prefix}_SUPPLIED_CERT_DOES_NOT_VERIFY_SIGNATURE",
                severity,
                scope,
                "The supplied certificate does not verify this XML Signature.",
                observed=supplied_fps,
                expected="certificate matching the signer",
                standard="XML Signature",
                note=f"Last verification error: {last_error}" if last_error else None,
            )
        )
        if severity == "ERROR":
            sig["crypto_verification"] = "INVALID_SUPPLIED_CERT"

    result.setdefault("findings", []).extend(additions)
    _recount(result)
    return result
