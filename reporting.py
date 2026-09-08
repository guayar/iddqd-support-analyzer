from __future__ import annotations

import json
from typing import Any


def _severity_icon(level: str) -> str:
    lv = (level or "").upper()
    if lv in {"ERROR", "FATAL", "SEVERE", "CRITICAL"}:
        return "❌"
    if lv in {"WARN", "WARNING"}:
        return "⚠️"
    if lv == "INFO":
        return "ℹ️"
    if lv == "DEBUG":
        return "🔍"
    if lv == "TRACE":
        return "▫️"
    return "•"


def _severity_sort_key(level: str) -> tuple[int, str]:
    order = {
        "FATAL": 0,
        "CRITICAL": 1,
        "SEVERE": 2,
        "ERROR": 3,
        "WARN": 4,
        "INFO": 5,
        "DEBUG": 6,
        "TRACE": 7,
    }
    lv = (level or "").upper()
    return (order.get(lv, 50), lv)


def _fmt(value: Any) -> str:
    if value is None or value == "" or value == [] or value == {}:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _bullet(label: str, value: Any, indent: int = 0) -> str:
    pad = "  " * indent
    return f"{pad}- **{label}:** `{_fmt(value)}`"


def _md_signature(sig: dict[str, Any] | None, indent: int = 0) -> list[str]:
    sig = sig or {}
    out = [_bullet("Signature present", sig.get("present"), indent)]
    if sig.get("present"):
        out.append(_bullet("SignatureMethod", sig.get("signature_method"), indent))
        out.append(_bullet("CanonicalizationMethod", sig.get("canonicalization_method"), indent))
        out.append(_bullet("Digest method(s)", sig.get("digest_methods"), indent))
        out.append(_bullet("Reference URI(s)", sig.get("reference_uris"), indent))
        out.append(_bullet("X509 SHA-256 fingerprint(s)", sig.get("x509_sha256_fingerprints"), indent))
        if sig.get("crypto_verification"):
            out.append(_bullet("Cryptographic verification", sig.get("crypto_verification"), indent))
        if sig.get("verified_signing_cert_fingerprint"):
            out.append(_bullet("Verified signing certificate", sig.get("verified_signing_cert_fingerprint"), indent))
        if sig.get("metadata_signing_cert_fingerprints"):
            out.append(_bullet("Metadata signing certificate(s)", sig.get("metadata_signing_cert_fingerprints"), indent))
        if sig.get("supplied_signing_cert_fingerprints"):
            out.append(_bullet("Supplied signing certificate(s)", sig.get("supplied_signing_cert_fingerprints"), indent))
    return out


def _md_assertion(a: dict[str, Any], index: int | None = None) -> list[str]:
    title = f"### Assertion #{index}" if index is not None else "## Standalone Assertion"
    out = [title]
    issuer = a.get("issuer") or {}
    subject = a.get("subject") or {}
    nameid = subject.get("name_id") or {}
    conditions = a.get("conditions") or {}

    out += [
        _bullet("ID", a.get("id")),
        _bullet("Version", a.get("version")),
        _bullet("IssueInstant", a.get("issue_instant")),
        _bullet("Issuer / typically IdP entityID", issuer.get("value")),
        _bullet("Issuer Format", issuer.get("format")),
    ]
    out += _md_signature(a.get("signature"))

    out += [
        "\n#### Subject",
        _bullet("NameID", nameid.get("value")),
        _bullet("NameID Format", nameid.get("format")),
        _bullet("NameQualifier", nameid.get("name_qualifier")),
        _bullet("SPNameQualifier", nameid.get("sp_name_qualifier")),
        _bullet("SPProvidedID", nameid.get("sp_provided_id")),
        _bullet("EncryptedID present", subject.get("encrypted_id_present")),
    ]
    confirmations = subject.get("confirmations") or []
    if confirmations:
        for i, sc in enumerate(confirmations, 1):
            out.append(f"\n**SubjectConfirmation #{i}**")
            out.append(_bullet("Method", sc.get("method"), 1))
            data = sc.get("data") or {}
            for key in ("Recipient", "InResponseTo", "NotBefore", "NotOnOrAfter", "Address", "Type"):
                if data.get(key) is not None:
                    out.append(_bullet(key, data.get(key), 1))
    else:
        out.append("- **SubjectConfirmation:** —")

    out += [
        "\n#### Conditions / Audience",
        _bullet("NotBefore", conditions.get("NotBefore")),
        _bullet("NotOnOrAfter", conditions.get("NotOnOrAfter")),
        _bullet("Audience(s)", conditions.get("audiences")),
        _bullet("AudienceRestriction groups", conditions.get("audience_restrictions")),
        _bullet("OneTimeUse", conditions.get("one_time_use")),
        _bullet("ProxyRestriction", conditions.get("proxy_restriction")),
    ]

    authn = a.get("authn_statements") or []
    out.append("\n#### Authentication statement(s)")
    if not authn:
        out.append("- —")
    for i, st in enumerate(authn, 1):
        out.append(f"**AuthnStatement #{i}**")
        for key, label in (
            ("AuthnInstant", "AuthnInstant"),
            ("SessionIndex", "SessionIndex"),
            ("SessionNotOnOrAfter", "SessionNotOnOrAfter"),
            ("authn_context_class_ref", "AuthnContextClassRef"),
            ("authn_context_decl_ref", "AuthnContextDeclRef"),
            ("authn_context_decl_present", "AuthnContextDecl present"),
            ("subject_locality", "SubjectLocality"),
            ("authenticating_authorities", "AuthenticatingAuthority"),
        ):
            out.append(_bullet(label, st.get(key), 1))

    attrs = a.get("attributes") or []
    out.append(f"\n#### Attributes ({len(attrs)})")
    if not attrs:
        out.append("- —")
    for i, attr in enumerate(attrs, 1):
        name = attr.get("friendly_name") or attr.get("name") or f"Attribute #{i}"
        out.append(f"- **{name}**")
        out.append(_bullet("Name", attr.get("name"), 1))
        out.append(_bullet("FriendlyName", attr.get("friendly_name"), 1))
        out.append(_bullet("NameFormat", attr.get("name_format"), 1))
        out.append(_bullet("Value(s)", attr.get("values"), 1))

    out += [
        _bullet("AttributeStatement count", a.get("attribute_statement_count")),
        _bullet("AuthzDecisionStatement count", a.get("authz_decision_statement_count")),
        _bullet("Advice child elements", a.get("advice_children")),
    ]
    return out


def _md_metadata(d: dict[str, Any], index: int) -> list[str]:
    out = [f"## Metadata entity #{index}"]
    out += [
        _bullet("entityID", d.get("entity_id")),
        _bullet("Role(s)", d.get("roles")),
        _bullet("validUntil", d.get("valid_until")),
        _bullet("cacheDuration", d.get("cache_duration")),
    ]

    sp = d.get("sp")
    if sp:
        out.append("\n### SPSSODescriptor")
        out += [
            _bullet("protocolSupportEnumeration", sp.get("protocol_support_enumeration")),
            _bullet("AuthnRequestsSigned", sp.get("authn_requests_signed")),
            _bullet("WantAssertionsSigned", sp.get("want_assertions_signed")),
            _bullet("NameIDFormat(s)", sp.get("name_id_formats")),
        ]
        out.append("\n**AssertionConsumerService endpoints**")
        for i, ep in enumerate(sp.get("assertion_consumer_services") or [], 1):
            out.append(f"- **ACS #{i}** `{ep.get('location')}`")
            out.append(_bullet("Binding", ep.get("binding"), 1))
            out.append(_bullet("index", ep.get("index"), 1))
            out.append(_bullet("isDefault", ep.get("is_default"), 1))
        out.append("\n**SingleLogoutService endpoints**")
        for i, ep in enumerate(sp.get("single_logout_services") or [], 1):
            out.append(f"- **SLO #{i}** `{ep.get('location')}` — `{ep.get('binding')}`")
        out.append("\n**Keys / certificates**")
        for i, key in enumerate(sp.get("keys") or [], 1):
            out.append(f"- **Key #{i}** use=`{key.get('use')}`")
            out.append(_bullet("X509 SHA-256 fingerprint(s)", key.get("x509_sha256_fingerprints"), 1))
            out.append(_bullet("Encryption methods", key.get("encryption_methods"), 1))
        if sp.get("attribute_consuming_services"):
            out.append("\n**AttributeConsumingService**")
            for svc in sp.get("attribute_consuming_services") or []:
                out.append(f"- index=`{svc.get('index')}` default=`{svc.get('is_default')}` names=`{_fmt(svc.get('service_names'))}`")
                for attr in svc.get("requested_attributes") or []:
                    out.append(f"  - `{attr.get('friendly_name') or attr.get('name')}` required=`{attr.get('is_required')}`")

    idp = d.get("idp")
    if idp:
        out.append("\n### IDPSSODescriptor")
        out += [
            _bullet("protocolSupportEnumeration", idp.get("protocol_support_enumeration")),
            _bullet("WantAuthnRequestsSigned", idp.get("want_authn_requests_signed")),
            _bullet("NameIDFormat(s)", idp.get("name_id_formats")),
        ]
        out.append("\n**SingleSignOnService endpoints**")
        for i, ep in enumerate(idp.get("single_sign_on_services") or [], 1):
            out.append(f"- **SSO #{i}** `{ep.get('location')}` — `{ep.get('binding')}`")
        out.append("\n**SingleLogoutService endpoints**")
        for i, ep in enumerate(idp.get("single_logout_services") or [], 1):
            out.append(f"- **SLO #{i}** `{ep.get('location')}` — `{ep.get('binding')}`")
        out.append("\n**Keys / certificates**")
        for i, key in enumerate(idp.get("keys") or [], 1):
            out.append(f"- **Key #{i}** use=`{key.get('use')}`")
            out.append(_bullet("X509 SHA-256 fingerprint(s)", key.get("x509_sha256_fingerprints"), 1))
            out.append(_bullet("Encryption methods", key.get("encryption_methods"), 1))

    if d.get("organization"):
        out += ["\n### Organization", f"```json\n{json.dumps(d['organization'], indent=2, ensure_ascii=False)}\n```"]
    if d.get("contacts"):
        out += ["\n### Contacts", f"```json\n{json.dumps(d['contacts'], indent=2, ensure_ascii=False)}\n```"]
    return out


def render_saml_report(result: dict[str, Any]) -> str:
    summary = result.get("summary") or {}
    out = [
        "# SAML / SSO analysis",
        f"**Documents detected:** {result.get('documents_found', 0)}  ",
        f"**AuthnRequest:** {summary.get('authn_requests', 0)} · **Response:** {summary.get('responses', 0)} · "
        f"**Assertions:** {summary.get('assertions_inside_responses', 0) + summary.get('standalone_assertions', 0)} · "
        f"**Metadata entities:** {summary.get('metadata_entities', 0)}  ",
        f"**Standards/profile validation:** ❌ {summary.get('validation_errors', 0)} error(s) · ⚠️ {summary.get('validation_warnings', 0)} warning(s)  ",
        f"**Cross-checks:** ✅ {summary.get('matches', 0)} · ❌ {summary.get('mismatches', 0)} · ⚪ {summary.get('unknown_checks', 0)}",
    ]

    if result.get("supplied_signing_certificates"):
        out.append("\n## Supplied signing certificate")
        for cert in result["supplied_signing_certificates"]:
            out += [
                _bullet("SHA-256 fingerprint", cert.get("fingerprint")),
                _bullet("Subject", cert.get("subject")),
                _bullet("Issuer", cert.get("issuer")),
                _bullet("Valid from", cert.get("not_valid_before")),
                _bullet("Valid until", cert.get("not_valid_after")),
            ]

    if result.get("detected_sources"):
        out.append("\n## Input decoding / detection")
        for src in result["detected_sources"]:
            out.append(f"- **{src.get('document_type')}** — `{src.get('source')}`")

    if result.get("decoded_artifacts"):
        out.append("\n## Decoded artifacts")
        for item in result["decoded_artifacts"]:
            out.append(
                f"- **{item.get('document_type')}** — `{item.get('export_name')}` · "
                f"source `{item.get('source_name')}` · `{item.get('encoding')}`"
            )
        out.append("Download the raw decoded XML from **Decoded SAML artifacts** (not pretty-printed, not anonymized).")

    transport = result.get("transport") or {}
    if any(transport.get(k) for k in ("request_binding", "response_binding", "inferred_response_binding", "redirect_signature_present", "evidence")):
        out.append("\n## Transport / binding detection")
        out += [
            _bullet("Request binding", transport.get("request_binding")),
            _bullet("Response binding", transport.get("response_binding")),
            _bullet("Inferred response binding", transport.get("inferred_response_binding")),
            _bullet("Request HTTP method", transport.get("request_http_method")),
            _bullet("Response HTTP method", transport.get("response_http_method")),
            _bullet("HTTP-Redirect signature detected", transport.get("redirect_signature_present")),
            _bullet("SigAlg", transport.get("redirect_sigalg")),
            _bullet("RelayState value(s)", transport.get("relaystate_values")),
            _bullet("Evidence", transport.get("evidence")),
        ]

    metadata_index = 0
    for d in result.get("documents") or []:
        if d["type"] == "AuthnRequest":
            issuer = d.get("issuer") or {}
            out += [
                "\n## AuthnRequest",
                _bullet("ID", d.get("id")),
                _bullet("Version", d.get("version")),
                _bullet("IssueInstant", d.get("issue_instant")),
                _bullet("Issuer / SP entityID", issuer.get("value")),
                _bullet("Issuer Format", issuer.get("format")),
                _bullet("Destination / IdP SSO URL", d.get("destination")),
                _bullet("AssertionConsumerServiceURL", d.get("acs_url")),
                _bullet("AssertionConsumerServiceIndex", d.get("acs_index")),
                _bullet("ProtocolBinding", d.get("protocol_binding")),
                _bullet("ProviderName", d.get("provider_name")),
                _bullet("ForceAuthn", d.get("force_authn")),
                _bullet("IsPassive", d.get("is_passive")),
                _bullet("NameIDPolicy", d.get("name_id_policy")),
                _bullet("RequestedAuthnContext", d.get("requested_authn_context")),
            ]
            out += _md_signature(d.get("signature"))
        elif d["type"] == "Response":
            issuer = d.get("issuer") or {}
            out += [
                "\n## SAML Response",
                _bullet("ID", d.get("id")),
                _bullet("Version", d.get("version")),
                _bullet("IssueInstant", d.get("issue_instant")),
                _bullet("Issuer / typically IdP entityID", issuer.get("value")),
                _bullet("Issuer Format", issuer.get("format")),
                _bullet("Destination / SP ACS", d.get("destination")),
                _bullet("InResponseTo", d.get("in_response_to")),
                _bullet("Consent", d.get("consent")),
                _bullet("StatusCode chain", d.get("status_codes")),
                _bullet("StatusMessage", d.get("status_message")),
                _bullet("StatusDetail children", d.get("status_detail_children")),
                _bullet("EncryptedAssertion count", d.get("encrypted_assertion_count")),
            ]
            out += _md_signature(d.get("signature"))
            for i, assertion in enumerate(d.get("assertions") or [], 1):
                out += ["\n"] + _md_assertion(assertion, i)
        elif d["type"] == "Assertion":
            out += ["\n"] + _md_assertion(d)
        elif d["type"] == "Metadata":
            metadata_index += 1
            out += ["\n"] + _md_metadata(d, metadata_index)

    if result.get("findings"):
        out.append("\n## Standards / SSO validation findings")
        for f in result["findings"]:
            severity = f.get("severity")
            icon = _severity_icon(severity)
            line = f"- {icon} **{f.get('code')}** — `{severity}` — **{f.get('scope')}**\n  - {f.get('message')}"
            if f.get("observed") is not None:
                line += f"\n  - observed: `{_fmt(f.get('observed'))}`"
            if f.get("expected") is not None:
                line += f"\n  - expected: `{_fmt(f.get('expected'))}`"
            if f.get("standard"):
                line += f"\n  - basis: {f.get('standard')}"
            if f.get("note"):
                line += f"\n  - note: {f.get('note')}"
            out.append(line)

    if result.get("checks"):
        out.append("\n## Mapping / consistency checks")
        for c in result["checks"]:
            icon = "✅" if c["status"] == "MATCH" else ("❌" if c["status"] == "MISMATCH" else "⚪")
            out.append(
                f"- {icon} **{c['check']}** — `{c['status']}`\n"
                f"  - left: `{_fmt(c.get('left'))}`\n"
                f"  - right: `{_fmt(c.get('right'))}`\n"
                f"  - note: {c.get('note')}"
            )

    if result.get("limitations"):
        out.append("\n## Limitations")
        out.extend(f"- {x}" for x in result["limitations"])
    return "\n".join(out)


def render_log_report(result: dict[str, Any]) -> str:
    tr = result["time_range"]
    out = [
        "# Log analysis",
        f"**File:** `{result.get('filename') or 'pasted text'}`  ",
        f"**Lines:** {result['line_count']:,}  ",
        f"**Timestamp range:** `{tr.get('from') or 'not detected'}` → `{tr.get('to') or 'not detected'}`",
        "\n## Severity counts",
    ]
    if result["levels"]:
        out.extend(
            f"- {_severity_icon(k)} **{k}:** {v}"
            for k, v in sorted(result["levels"].items(), key=lambda kv: _severity_sort_key(kv[0]))
        )
    else:
        out.append("- No standard severity markers detected")
    out.append("\n## Error / status codes")
    if result["error_codes"]:
        out.extend(f"- `{k}` — {v} occurrence(s)" for k, v in list(result["error_codes"].items())[:40])
    else:
        out.append("- No explicit codes detected")
    groups = result.get("incidents") or result.get("error_groups") or []
    out.append(f"\n## Incidents ({len(groups)} unique; {result['error_event_count']} events)")
    if not groups:
        out.append("No explicit ERROR/FATAL/SEVERE/CRITICAL events detected.")
    for i, g in enumerate(groups[:30], 1):
        title = g.get("signature") or "Unknown error"
        out.append(f"\n### {i}. {title}")
        out.append(f"- **Severity:** {_severity_icon(g['level'])} {g['level']}")
        out.append(f"- **Occurrences:** {g['count']}")
        out.append(f"- **First occurrence line:** {g['first_line']}")
        if g.get("exit_code") is not None:
            out.append(f"- **Exit code:** {g['exit_code']}")
        if g.get("root_cause"):
            out.append(f"- **Root cause:** `{g['root_cause']}`")
        codes = g.get("codes") or {}
        out.append(f"- **Codes:** {', '.join('`'+x+'`' for x in codes) or '—'}")
        chain = g.get("exception_chain") or []
        if len(chain) >= 2:
            short = [c.rsplit(".", 1)[-1] for c in chain]
            out.append("\n**Exception chain**\n")
            out.append("\n".join([f"`{short[0]}`"] + [f"→ `{c}`" for c in short[1:]]))
        sample = (g.get("sample") or "")[:50_000]
        out.append(
            "\n<details>\n<summary>Relevant log</summary>\n\n"
            f"```text\n{sample}\n```\n\n</details>"
        )
        causes = g.get("causes") or []
        if causes:
            out.append(f"\n**Caused by ({len(causes)})**\n")
            out.extend(f"{n}. `{cause}`" for n, cause in enumerate(causes, 1))
    return "\n".join(out)


def render_saml_multi_sections(result: dict[str, Any]) -> str:
    parts: list[str] = []
    for item in result.get("analyses") or []:
        name = item.get("name") or "artifact"
        body = render_saml_report(item.get("result") or {}).replace(
            "# SAML / SSO analysis", f"## SAML analysis — `{name}`", 1
        )
        parts.append(body)
    return "\n\n".join(parts)


def render_saml_output(result: dict[str, Any]) -> str:
    if result.get("kind") == "saml_multi":
        lines = ["# Analysis", "", "SAML artifacts:"]
        for item in result.get("analyses") or []:
            lines.append(f"- `{item.get('name')}`")
        if result.get("decoded_artifacts"):
            lines.append("")
            lines.append("## Decoded artifacts")
            for item in result["decoded_artifacts"]:
                lines.append(
                    f"- **{item.get('document_type')}** — `{item.get('export_name')}` · "
                    f"source `{item.get('source_name')}` · `{item.get('encoding')}`"
                )
            lines.append("Download the raw decoded XML from **Decoded SAML artifacts** (not pretty-printed, not anonymized).")
        lines.append("")
        lines.append(render_saml_multi_sections(result))
        return "\n".join(lines)
    return render_saml_report(result)


def render_mixed_report(result: dict[str, Any]) -> str:
    lines = ["# Analysis", "", "Files/artifacts detected:"]
    for item in result.get("artifacts") or []:
        lines.append(f"- {item.get('name')} — {item.get('kind')}")
    saml = result.get("saml")
    if saml:
        lines.append("")
        if saml.get("decoded_artifacts") and saml.get("kind") == "saml_multi":
            lines.append("## Decoded artifacts")
            for item in saml["decoded_artifacts"]:
                lines.append(
                    f"- **{item.get('document_type')}** — `{item.get('export_name')}` · "
                    f"source `{item.get('source_name')}` · `{item.get('encoding')}`"
                )
            lines.append("Download the raw decoded XML from **Decoded SAML artifacts** (not pretty-printed, not anonymized).")
            lines.append("")
        if saml.get("kind") == "saml_multi":
            lines.append(render_saml_multi_sections(saml))
        else:
            lines.append(render_saml_report(saml).replace("# SAML / SSO analysis", "## SAML analysis", 1))
    log = result.get("log")
    if log:
        lines.append("")
        lines.append(render_log_report(log).replace("# Log analysis", "## Log analysis", 1))
    return "\n".join(lines)


def render_anonymize_summary(result: dict[str, Any]) -> str:
    counts = result["counts"]
    summary = ["# Anonymized log", f"**Unique values anonymized:** {result['replacements']}"]
    if counts:
        summary.append("\n## Replacements")
        summary.extend(f"- **{k}:** {v}" for k, v in sorted(counts.items()))
    else:
        summary.append("\nNo supported sensitive patterns were detected.")
    residual = result.get("residual_findings") or []
    summary.append("\n## Residual leaks")
    if residual:
        summary.append(
            f"❌ **{len(residual)}** leftover match(es) after anonymization. Do not share until reviewed."
        )
        for i, hit in enumerate(residual[:40], 1):
            summary.append(f"{i}. `{hit.get('kind')}` line {hit.get('line')} — `{hit.get('value')}`")
        if len(residual) > 40:
            summary.append(f"- … {len(residual) - 40} more")
    else:
        summary.append("No leftover email / IP / token / domain matches from the residual scan.")
    summary.append(
        "\n> Stable pseudonyms are used within this run, e.g. the same IP always maps to the same `IP_###`. "
        "Review the preview before external sharing; this tool is not a certified DLP engine."
    )
    return "\n".join(summary)
