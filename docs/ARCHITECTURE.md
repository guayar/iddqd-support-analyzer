# Architecture

## Design goal

Short landing page: [../README.md](../README.md). User guide: [USER.md](USER.md).

The core Analyzer is deterministic first. Protocol parsing, required-field checks, identifier comparisons, timestamps, endpoint mappings and validation findings are produced by code rather than delegated to the language model.

```text
Gradio UI (app.py)
  │
  ├─ Analyze (always) ──> actions.analyze ──> analyzers/saml,logs ──> reporting
  │         └── Auto-detect routes each artifact; SAML files stay one correlated bundle
  │         └── log incidents: multiline records + Java exception chains
  │
  ├─ Anonymize (optional module) ──> actions.anonymize (lazy) ──> analyzers/anonymizer
  │
  ├─ Assistant (optional module) ──> chats.assistant_chat ──> vision.py (scope=assistant) ──> llm.py
  │         └── latest Analyze result + optional PNG/JPEG/WEBP; no websearch
  │         └── pixels to Ollama when /api/show lists vision; OCR is auxiliary
  │         └── muted OLLAMA_MODEL env tag next to analysis-context status (not in the app header)
  │
  ├─ General Chat (optional module) ──> chats.web_chat ──> vision.py (scope=general_chat) ──> llm.py
  │         └── local by default; plan_web_search may call websearch.execute_web_search
  │         └── never receives Analyze or Assistant context; no OCR/image dumps to search
  │
  └─ Config (always) ──> modules.py ──> .iddqd-modules.json + process restart

Input
  │
  ├─ SAML / metadata ──> decode ──> XML parse ──> extract ──> validate ──> report
  │                                      │
  │                                      └─ XMLDSig ──> Reference profile checks
  │                                                   ├─ metadata public-cert verification
  │                                                   ├─ optional supplied X.509 certificate
  │                                                   └─ metadata / embedded-cert comparison
  │
  ├─ *.log ───────> parse ──> group errors / codes / stacks ─────────> report
  │
  └─ log anonymizer ──> deterministic pseudonymization ──> anonymized copy
            └── optional SAML XML audit: exact decoded XML (sensitive) + post-transform XML
```

## Security boundaries

- Analyzer does not invoke web search or require Ollama.
- Assistant (optional) does not invoke web search. It receives the latest Analyze result and optional local screenshots plus OCR. **Clear analysis context** can detach it.
- General Chat (optional) does not inherit Analyzer or Assistant context, screenshots or OCR. Local by default. Public search only after a per-turn plan; queries are minimal text, never image bytes or OCR dumps.
- Optional modules are off by default and enabled independently. Enabling them in Config requires a process restart. Tab order: Analyze → Anonymize → Assistant → General Chat → Config. A legacy `.iddqd-modules.json` value `llm` still turns on both chat modules.
- `OLLAMA_MODEL` is the process env tag (default `qwen3.6:27b` if unset). Chats display that string; they do not parse model-file metadata or `ollama list`.
- Model endpoints must be loopback or RFC1918 unless `ALLOW_REMOTE_LLM=true`.
- Screenshot/photo uploads are local files only (type/size/pixel limits, no URLs). Original pixels are sent to Ollama; OCR runs on a derived copy via local Tesseract. Assistant and General Chat use separate OCR caches and never copy attachments between tabs.
- `.env`, local logs, generated mappings and credential material are excluded from version control.
- Local certificate/key formats (`*.pem`, `*.crt`, `*.cer`, `*.der`, `*.key`, `*.p12`, `*.pfx`, keystores) are excluded from version control.
- The standalone signing-certificate input accepts public X.509 certificates only; private keys are rejected.
- The anonymizer is pattern-based and should not be treated as a certified DLP control. A residual leak scan runs on the anonymized text. Original decoded SAML XML offered for QA contains source data and is not for external sharing.

## SAML validation model

Validation is separated into four layers:

1. **Transport decoding** — raw XML, Base64, URL encoding and Redirect-binding DEFLATE.
2. **Document and protocol structure** — well-formed XML, document type, required fields and profile rules.
3. **Signature and trust validation** — SAML XML Signature profile checks, same-document Reference validation, cryptographic signature/digest verification with public X.509 certificates, and comparison with matching metadata signing certificates.
4. **Cross-document consistency** — comparisons between Request, Response, Assertion and supplied SP/IdP metadata.

### XML Signature trust model

A private key is not required to verify an XML Signature. Verification uses the signer's public X.509 certificate.

When matching metadata is supplied, its `KeyDescriptor` entries with `use="signing"` (or unspecified use) are treated as the preferred trust source. The analyzer verifies the signature and referenced digest against those certificates. A certificate embedded in `ds:KeyInfo` is compared with metadata but is not automatically trusted merely because it is embedded in the signed message.

An operator may also supply a standalone X.509 signing certificate in PEM or DER form. If it verifies the XML Signature, the analyzer reports cryptographic validity and the certificate fingerprint, while keeping identity/provenance distinct from metadata-backed trust. If both metadata and a standalone certificate are available, metadata remains the primary trust source and the supplied certificate is compared against it. Differences are surfaced as troubleshooting evidence, including certificate-rollover scenarios.

If metadata is unavailable but an embedded certificate is present, the analyzer may prove that the signature is cryptographically self-consistent with that certificate, while reporting that signer trust is not established.

For SAML assertions and protocol messages, SAML Core 2.0 §5.4.2 is applied strictly: the signature must contain exactly one `ds:Reference`, and its URI must be the same-document fragment `#<ID>` of the signed SAML root element.

Encrypted SAML content is a separate concern. `EncryptedAssertion` is detected, but decryption is not performed. Decryption would require the SP private key and is intentionally outside the signature-verification path.

Untrusted SAML and metadata XML on the signature and anonymizer paths is parsed with entity resolution, DTDs and network access disabled. Transport inflation (Redirect DEFLATE / zlib / gzip) is capped at `MAX_FILE_MB`.
