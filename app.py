from __future__ import annotations

import ipaddress
import json
import os
import socket
import tempfile
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import gradio as gr
import requests
from ddgs import DDGS

from analyzers import analyze_log_text, analyze_saml_input, anonymize_text
from analyzers.saml import looks_like_saml_input

APP_TITLE = "IDDQD Support Analyzer"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.6:27b")
ALLOW_REMOTE_LLM = os.getenv("ALLOW_REMOTE_LLM", "false").lower() == "true"
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "150"))
APP_PORT = int(os.getenv("APP_PORT", "7860"))
WEB_SEARCH_RESULTS = int(os.getenv("WEB_SEARCH_RESULTS", "6"))
WEB_FETCH_RESULTS = int(os.getenv("WEB_FETCH_RESULTS", "3"))
WEB_FETCH_CHARS = int(os.getenv("WEB_FETCH_CHARS", "16000"))
WEB_SEARCH_REGION = os.getenv("WEB_SEARCH_REGION", "wt-wt")


def _endpoint_is_local(url: str) -> bool:
    host = urlparse(url).hostname
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    if not host:
        return False
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if not (ip.is_loopback or ip.is_private):
                return False
        return True
    except Exception:
        return False


def _llm(messages: list[dict[str, str]], temperature: float = 0.2) -> str:
    if not ALLOW_REMOTE_LLM and not _endpoint_is_local(OLLAMA_URL):
        raise RuntimeError("Remote LLM endpoint blocked. Set ALLOW_REMOTE_LLM=true only if you intentionally want it.")
    r = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={"model": OLLAMA_MODEL, "messages": messages, "stream": False, "options": {"temperature": temperature}},
        timeout=600,
    )
    r.raise_for_status()
    return r.json()["message"]["content"]


def _read_files(files) -> tuple[str, list[str]]:
    if not files:
        return "", []
    if not isinstance(files, list):
        files = [files]
    chunks = []
    names = []
    for f in files:
        p = Path(getattr(f, "name", f))
        if p.stat().st_size > MAX_FILE_MB * 1024 * 1024:
            raise gr.Error(f"{p.name}: file exceeds {MAX_FILE_MB} MB limit")
        data = p.read_bytes()
        text = data.decode("utf-8", errors="replace")
        names.append(p.name)
        chunks.append(f"\n===== FILE: {p.name} =====\n{text}")
    return "\n".join(chunks), names


def _looks_saml(text: str) -> bool:
    return looks_like_saml_input(text)


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


def _md_saml(result: dict[str, Any]) -> str:
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

    if result.get("detected_sources"):
        out.append("\n## Input decoding / detection")
        for src in result["detected_sources"]:
            out.append(f"- **{src.get('document_type')}** — `{src.get('source')}`")

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
            icon = "❌" if severity == "ERROR" else ("⚠️" if severity == "WARNING" else "ℹ️")
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


def _md_log(result: dict[str, Any]) -> str:
    tr = result["time_range"]
    out = [
        "# Log analysis",
        f"**File:** `{result.get('filename') or 'pasted text'}`  ",
        f"**Lines:** {result['line_count']:,}  ",
        f"**Timestamp range:** `{tr.get('from') or 'not detected'}` → `{tr.get('to') or 'not detected'}`",
        "\n## Severity counts",
    ]
    if result["levels"]:
        out.extend(f"- **{k}:** {v}" for k, v in sorted(result["levels"].items()))
    else:
        out.append("- No standard severity markers detected")
    out.append("\n## Error / status codes")
    if result["error_codes"]:
        out.extend(f"- `{k}` — {v} occurrence(s)" for k, v in list(result["error_codes"].items())[:40])
    else:
        out.append("- No explicit codes detected")
    out.append(f"\n## Error groups ({len(result['error_groups'])} unique; {result['error_event_count']} events)")
    if not result["error_groups"]:
        out.append("No explicit ERROR/FATAL/SEVERE/CRITICAL events detected.")
    for i, g in enumerate(result["error_groups"][:30], 1):
        out.append(f"\n### {i}. {g['signature']}\n- **Count:** {g['count']}\n- **Level:** {g['level']}\n- **Caused by:** `{g.get('root_cause') or 'not explicitly present'}`\n- **Codes:** {', '.join('`'+x+'`' for x in g.get('codes', {})) or '—'}\n- **First occurrence line:** {g['first_line']}\n\n```text\n{g['sample'][:5000]}\n```")
    return "\n".join(out)


def analyze(files, pasted, mode):
    file_text, names = _read_files(files)
    text = (file_text + "\n" + (pasted or "")).strip()
    if not text:
        raise gr.Error("Upload a log/SAML tracer or paste text first.")
    chosen = mode
    if mode == "Auto-detect":
        chosen = "SAML" if _looks_saml(text) else "Log"
    if chosen == "SAML":
        result = analyze_saml_input(text)
        md = _md_saml(result)
    else:
        result = analyze_log_text(text, filename=", ".join(names) if names else None)
        md = _md_log(result)
    return md, json.dumps(result, indent=2, ensure_ascii=False), result


def anonymize(file, pasted):
    text = (pasted or "")
    filename = None
    if file:
        p = Path(getattr(file, "name", file))
        if p.stat().st_size > MAX_FILE_MB * 1024 * 1024:
            raise gr.Error(f"{p.name}: file exceeds {MAX_FILE_MB} MB limit")
        text = p.read_bytes().decode("utf-8", errors="replace") + ("\n" + text if text else "")
        filename = p.name
    if not text.strip():
        raise gr.Error("Upload a log or paste text first.")

    result = anonymize_text(text)
    counts = result["counts"]
    summary = ["# Anonymized log", f"**Unique values anonymized:** {result['replacements']}"]
    if counts:
        summary.append("\n## Replacements")
        summary.extend(f"- **{k}:** {v}" for k, v in sorted(counts.items()))
    else:
        summary.append("\nNo supported sensitive patterns were detected.")
    summary.append("\n> Stable pseudonyms are used within this run, e.g. the same IP always maps to the same `IP_###`. Review the preview before external sharing; this tool is not a certified DLP engine.")

    base = Path(filename or "pasted-log.txt")
    safe_name = f"{base.stem}.anonymized{base.suffix or '.txt'}"
    out_dir = Path(tempfile.mkdtemp(prefix="support_anonymized_"))
    out_path = out_dir / safe_name
    out_path.write_text(result["text"], encoding="utf-8")

    mapping_json = json.dumps({"counts": counts, "mapping": result["mapping"], "limitations": result["limitations"]}, indent=2, ensure_ascii=False)
    return "\n".join(summary), result["text"], mapping_json, str(out_path)


SYSTEM = """You are a senior enterprise support/escalation engineer assistant running LOCALLY.
You receive deterministic analyzer output generated from customer-provided material.
Never invent values, completed checks, root causes, dates, error codes, or customer actions.
Clearly distinguish observed facts from hypotheses and recommendations.
If asked for an email, write concise, natural professional English suitable for enterprise support. Do not expose internal notes or implementation details.
If asked for a report, produce a structured technical report with: Scope, Time range (if available), Findings, Error groups/codes, Caused-by chains, Assessment, Recommended next checks.
For SAML, preserve exact URLs/Entity IDs/Audience/Destination/Recipient values and explicitly call out MATCH/MISMATCH/UNKNOWN checks.
The system has no web-search tool. Do not claim to have checked external documentation.
"""


def chat(message, history, analysis_state):
    if not analysis_state:
        return "Najpierw wrzuć plik/SAML tracer i kliknij **Analyze**."
    compact = json.dumps(analysis_state, ensure_ascii=False)[:120_000]
    msgs = [{"role": "system", "content": SYSTEM + "\n\nANALYZER OUTPUT:\n" + compact}]
    for h in (history or [])[-12:]:
        if isinstance(h, dict) and h.get("role") in {"user", "assistant"}:
            c = h.get("content")
            if isinstance(c, str):
                msgs.append({"role": h["role"], "content": c[:12000]})
    msgs.append({"role": "user", "content": message})
    try:
        return _llm(msgs)
    except requests.RequestException as e:
        return f"LLM unavailable: `{e}`\n\nThe deterministic analyzer still works. Check that Ollama is running and `{OLLAMA_MODEL}` is installed."
    except Exception as e:
        return f"LLM error: `{e}`"


GENERAL_SYSTEM = """You are a private local technical assistant running on the user's Ubuntu workstation.
You have no web-search tool and must never claim to have checked the internet or current external documentation.
Be concise, technically precise, and practical. If uncertain, say what is uncertain.
For programming questions, prioritize Java, TypeScript, Python and Playwright when relevant.
Do not invent APIs, command results, files, logs, or execution results.
"""

MAIL_SYSTEM = """You are a senior enterprise technical support writing assistant running LOCALLY.
Turn rough notes, Polish/English drafts, or technical findings into concise, natural professional English.
Preserve the user's meaning and technical facts. Do not invent completed checks, root causes, customer actions, dates, or results.
Avoid robotic phrasing and unnecessary corporate filler.
When useful, structure the message as: context/findings, what was verified, next step/request.
Do not expose implementation details.
"""

CODE_SYSTEM = """You are a senior software engineering assistant running LOCALLY.
Primary stack: Java, TypeScript, Python and Playwright.
Help write, review, debug and explain code. Prefer production-quality, readable solutions and point out assumptions.
Do not claim code was executed unless execution output was actually provided.
You have no web-search tool, so do not claim to have checked current documentation. If an API/version detail may have changed, flag it.
"""

WEB_SYSTEM = """You are a web-enabled general assistant. The language model itself runs locally, but for this chat the application deliberately searches the public web.
Use the supplied search results as external evidence. Current date: {today}.
Answer in the user's language unless asked otherwise.
For technical questions, prefer official documentation, vendor documentation, release notes and primary sources over blogs.
Do not fabricate facts or sources. If the search evidence is insufficient or conflicting, say so.
Cite factual web-derived claims inline using source markers like [S1], [S2]. Do not invent markers that are not in the supplied material.
This General Chat is intentionally separate from the private Analyzer/Assistant. Never imply you can see content from those tabs.
"""


def general_chat(message, history, mode):
    systems = {
        "General": GENERAL_SYSTEM,
        "Support Mail": MAIL_SYSTEM,
        "Code": CODE_SYSTEM,
    }
    msgs = [{"role": "system", "content": systems.get(mode, GENERAL_SYSTEM)}]
    for h in (history or [])[-20:]:
        if isinstance(h, dict) and h.get("role") in {"user", "assistant"}:
            c = h.get("content")
            if isinstance(c, str):
                msgs.append({"role": h["role"], "content": c[:20000]})
    msgs.append({"role": "user", "content": message})
    try:
        return _llm(msgs)
    except requests.RequestException as e:
        return f"LLM unavailable: `{e}`\n\nCheck that Ollama is running and `{OLLAMA_MODEL}` is installed."
    except Exception as e:
        return f"LLM error: `{e}`"


def _history_text(history, limit: int = 6) -> str:
    items = []
    for h in (history or [])[-limit:]:
        if isinstance(h, dict) and h.get("role") in {"user", "assistant"} and isinstance(h.get("content"), str):
            items.append(f"{h['role'].upper()}: {h['content'][:2500]}")
    return "\n".join(items)


def _search_queries(message: str, history) -> list[str]:
    """Ask the local model for focused search queries. Only the resulting query strings leave the machine."""
    prompt = f"""Create 1 to 3 concise web-search queries for the user's latest request.
Preserve important product names, versions, error codes and technical terms. Prefer English queries for technical documentation when useful.
For a follow-up question, use the short conversation context to make the query self-contained.
Return ONLY a JSON array of strings, no markdown.

RECENT CONTEXT:
{_history_text(history)}

LATEST REQUEST:
{message}
"""
    try:
        raw = _llm([{"role": "system", "content": "You generate precise web search queries."}, {"role": "user", "content": prompt}], temperature=0.0).strip()
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.lower().startswith("json"):
                raw = raw[4:].strip()
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            queries = [str(x).strip() for x in parsed if str(x).strip()]
            if queries:
                return queries[:3]
    except Exception:
        pass
    return [message.strip()]


def _web_search(message: str, history) -> tuple[list[dict[str, str]], list[str]]:
    queries = _search_queries(message, history)
    merged: list[dict[str, str]] = []
    seen: set[str] = set()
    ddgs = DDGS(timeout=10)

    for query in queries:
        try:
            results = ddgs.text(query, region=WEB_SEARCH_REGION, safesearch="moderate", max_results=WEB_SEARCH_RESULTS, backend="auto")
        except Exception:
            results = []
        for item in results or []:
            url = str(item.get("href") or item.get("url") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            merged.append({
                "title": str(item.get("title") or url).strip(),
                "url": url,
                "snippet": str(item.get("body") or item.get("snippet") or "").strip(),
                "content": "",
            })
            if len(merged) >= WEB_SEARCH_RESULTS:
                break
        if len(merged) >= WEB_SEARCH_RESULTS:
            break

    for item in merged[:WEB_FETCH_RESULTS]:
        try:
            extracted = ddgs.extract(item["url"], fmt="text_plain")
            content = extracted.get("content", "") if isinstance(extracted, dict) else ""
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            item["content"] = str(content)[:WEB_FETCH_CHARS]
        except Exception:
            item["content"] = ""

    return merged, queries


def _web_context(results: list[dict[str, str]]) -> str:
    blocks = []
    for idx, item in enumerate(results, 1):
        blocks.append(
            f"[S{idx}] {item['title']}\nURL: {item['url']}\n"
            f"SEARCH SNIPPET: {item['snippet']}\n"
            f"PAGE CONTENT:\n{item.get('content') or '(page not fetched; use snippet only)'}"
        )
    return "\n\n---\n\n".join(blocks)


def _source_footer(results: list[dict[str, str]], queries: list[str]) -> str:
    lines = ["\n\n---\n**Web sources used by this chat**"]
    for idx, item in enumerate(results, 1):
        safe_title = item["title"].replace("[", "\\[").replace("]", "\\]")
        lines.append(f"- [S{idx}] [{safe_title}]({item['url']})")
    if queries:
        lines.append("\n<details><summary>Search queries sent to the web</summary>\n\n" + "\n".join(f"- `{q}`" for q in queries) + "\n</details>")
    return "\n".join(lines)


def web_chat(message, history):
    if not (message or "").strip():
        return "Wpisz pytanie do wyszukania."
    try:
        results, queries = _web_search(message, history)
    except Exception as e:
        results, queries = [], [message]
        search_error = str(e)
    else:
        search_error = ""

    msgs = [{"role": "system", "content": WEB_SYSTEM.format(today=date.today().isoformat())}]
    for h in (history or [])[-10:]:
        if isinstance(h, dict) and h.get("role") in {"user", "assistant"}:
            c = h.get("content")
            if isinstance(c, str):
                msgs.append({"role": h["role"], "content": c[:12000]})

    if results:
        msgs.append({"role": "system", "content": "WEB SEARCH RESULTS:\n\n" + _web_context(results)[:100_000]})
        msgs.append({"role": "user", "content": message})
        try:
            answer = _llm(msgs)
            return answer + _source_footer(results, queries)
        except Exception as e:
            return f"Local LLM error after successful web search: `{e}`" + _source_footer(results, queries)

    # Search failed or returned nothing. Keep the separation honest and fall back to local knowledge explicitly.
    msgs.append({"role": "system", "content": "The web search returned no usable results. Make clear that live search was unavailable/empty and answer only from local model knowledge if useful."})
    msgs.append({"role": "user", "content": message})
    try:
        answer = _llm(msgs)
    except Exception as e:
        return f"Web search failed and local LLM is unavailable: `{search_error or e}`"
    detail = f"\n\n> Web search returned no usable results{': ' + search_error if search_error else ''}. The answer above is therefore based only on the local model."
    return answer + detail


CSS = """
.gradio-container {
    max-width: 1240px !important;
    margin: 0 auto !important;
    padding: 18px 28px 42px !important;
}
#hero {
    max-width: 1180px !important;
    margin: 0 auto 8px auto !important;
    padding: 0 !important;
}
.psa-shell {
    width: 100% !important;
    max-width: 1180px !important;
    margin: 0 auto !important;
    padding: 0 !important;
    background: transparent !important;
}
.psa-note {
    padding: 4px 0 10px 0 !important;
    margin: 0 !important;
    background: transparent !important;
    border: 0 !important;
}
#analysis {
    min-height: 210px !important;
    padding: 14px 16px !important;
    background: white !important;
    border: 1px solid var(--border-color-primary) !important;
    border-radius: 8px !important;
    overflow: auto !important;
}
#analysis-chat, #assistant-chat, #web-chat {
    min-height: 500px !important;
}
#anon-preview textarea, #paste-input textarea, #anon-paste textarea {
    background: white !important;
}
.psa-shell .form,
.psa-shell .panel,
.psa-shell .group {
    background: transparent !important;
}
.psa-shell > div {
    background: transparent;
}
"""

with gr.Blocks(title=APP_TITLE, delete_cache=(3600, 3600)) as demo:
    state = gr.State(None)
    gr.Markdown(
        "# IDDQD Support Analyzer\n"
        "**Local SAML + `*.log` analysis · private local assistant · separate web-enabled general chat · log anonymizer**",
        elem_id="hero",
    )

    with gr.Tabs():
        with gr.Tab("Analyze"):
            with gr.Column(elem_classes=["psa-shell"]):
                with gr.Row(equal_height=True):
                    files = gr.File(
                        label="Upload SAML tracer / metadata XML / HAR / *.log",
                        file_count="multiple",
                        height=235,
                        scale=1,
                    )
                    pasted = gr.Textbox(
                        label="or paste SAML / log text",
                        lines=10,
                        placeholder="Paste SAML tracer, metadata XML, Base64 SAMLRequest/SAMLResponse, Assertion, stack trace or *.log fragment…",
                        scale=1,
                        elem_id="paste-input",
                    )

                with gr.Row(equal_height=True):
                    mode = gr.Radio(
                        ["Auto-detect", "SAML", "Log"],
                        value="Auto-detect",
                        label="Analyzer",
                        scale=4,
                    )
                    run = gr.Button("Analyze", variant="primary", scale=1, min_width=180)

                report = gr.Markdown(elem_id="analysis")

                with gr.Accordion("Structured analyzer output (JSON)", open=False):
                    raw = gr.Code(label="JSON", language="json")

                gr.Markdown(
                    "### Ask about this analysis\n"
                    "Examples: **napisz maila do supportu po angielsku**, **zrób raport techniczny**, "
                    "**który błąd jest root cause?**, **porównaj metadata/ACS/Audience/Destination/Issuer**"
                )
                analysis_chatbot = gr.Chatbot(height=500, label="Chat", elem_id="analysis-chat")
                gr.ChatInterface(
                    fn=chat,
                    chatbot=analysis_chatbot,
                    additional_inputs=[state],
                    save_history=False,
                )
                run.click(analyze, inputs=[files, pasted, mode], outputs=[report, raw, state])

        with gr.Tab("Anonymize log"):
            with gr.Column(elem_classes=["psa-shell"]):
                gr.Markdown(
                    "### Local log anonymizer\n"
                    "Creates a shareable pseudonymized copy while preserving timestamps, error codes and stack-trace "
                    "structure. The mapping stays local and is not embedded in the output file.",
                    elem_classes=["psa-note"],
                )
                with gr.Row(equal_height=True):
                    anon_file = gr.File(
                        label="Drop a log/text file",
                        file_count="single",
                        height=235,
                        scale=1,
                    )
                    anon_pasted = gr.Textbox(
                        label="or paste text",
                        lines=10,
                        placeholder="Paste a log fragment…",
                        scale=1,
                        elem_id="anon-paste",
                    )

                anon_run = gr.Button("Anonymize", variant="primary")
                anon_summary = gr.Markdown()
                anon_preview = gr.Textbox(
                    label="Anonymized preview",
                    lines=20,
                    elem_id="anon-preview",
                )
                anon_download = gr.File(label="Download anonymized copy", interactive=False)

                with gr.Accordion("Local replacement map — do NOT share this with the anonymized log", open=False):
                    anon_mapping = gr.Code(label="Mapping JSON", language="json")

                anon_run.click(
                    anonymize,
                    inputs=[anon_file, anon_pasted],
                    outputs=[anon_summary, anon_preview, anon_mapping, anon_download],
                )
        with gr.Tab("Assistant"):
            with gr.Column(elem_classes=["psa-shell"]):
                gr.Markdown(
                    "### 🔒 Local Assistant\n"
                    "Everything in this tab stays between the browser, this application and the local Ollama model. "
                    "**No web search.** Use it for sensitive analysis, support mail and coding.",
                    elem_classes=["psa-note"],
                )
                assistant_mode = gr.Radio(
                    ["General", "Support Mail", "Code"],
                    value="General",
                    label="Mode",
                )
                assistant_chatbot = gr.Chatbot(height=500, label="Chat", elem_id="assistant-chat")
                gr.ChatInterface(
                    fn=general_chat,
                    chatbot=assistant_chatbot,
                    additional_inputs=[assistant_mode],
                    save_history=False,
                )

        with gr.Tab("General Chat 🌐"):
            with gr.Column(elem_classes=["psa-shell"]):
                gr.Markdown(
                    "### 🌐 Web-enabled General Chat\n"
                    "This tab is deliberately separate. It may send **search queries** to public search providers. "
                    "It receives **no Analyzer or Assistant context**. Do not paste customer logs, credentials or other "
                    "sensitive data here; use **Assistant** for that.",
                    elem_classes=["psa-note"],
                )
                web_chatbot = gr.Chatbot(height=500, label="Chat", elem_id="web-chat")
                gr.ChatInterface(fn=web_chat, chatbot=web_chatbot, save_history=False)


if __name__ == "__main__":
    auth = None
    if os.getenv("BASIC_AUTH_USER") and os.getenv("BASIC_AUTH_PASS"):
        auth = (os.environ["BASIC_AUTH_USER"], os.environ["BASIC_AUTH_PASS"])
    demo.launch(
        server_name="127.0.0.1",
        server_port=APP_PORT,
        auth=auth,
        show_error=True,
        footer_links=["settings"],
        css=CSS,
        max_file_size=f"{MAX_FILE_MB}mb",
    )
