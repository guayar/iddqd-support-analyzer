# Architecture

## Design goal

Short landing page: [../README.md](../README.md). User guide: [USER.md](USER.md). Third-party test data: [THIRD_PARTY_TEST_DATA.md](THIRD_PARTY_TEST_DATA.md).

The core Analyzer is deterministic first. Protocol parsing, required-field checks, identifier comparisons, timestamps, endpoint mappings and validation findings are produced by code rather than delegated to the language model.

```text
Gradio UI (app.py)
  │
  ├─ Analyze (always) ──> actions.analyze ──> analyzers/saml,logs ──> reporting
  │         └── Auto-detect routes each artifact; SAML files stay one correlated bundle
  │         └── log scan: optional slash-date policy, then one sequential pass (prefix once; vendor/levels/events; `LINE_FAMILY_TYPES` correlators, OpenSSH first). Stored groups/vendor details/family sessions are capped; unique/event counts stay exact. `LOG_ANALYZE_MAX_SECONDS` can abort a hang. Whole file is in RAM (`splitlines`). New stateful family: implement `LogFamily`, append to the registry.
  │         └── optional fetched third-party corpora stay under testdata/external (not required to run Analyze)
  │         └── Clear resets uploads, paste, cert, report; mode and Assistant chat stay
  │
  ├─ Anonymize (optional module) ──> actions.anonymize (lazy) ──> analyzers/anonymizer
  │
  ├─ Assistant (optional module) ──> chats.assistant_chat ──> vision.py (scope=assistant) ──> llm.py
  │         └── latest Analyze result + optional PNG/JPEG/WEBP; no websearch
  │         └── pixels to Ollama when /api/show lists vision; OCR is auxiliary
  │         └── Clear conversation resets this chat and OCR cache; analysis stays attached
  │         └── muted OLLAMA_MODEL env tag next to analysis-context status (not in the app header)
  │
  ├─ General Chat (optional module) ──> chats.web_chat ──> vision.py (scope=general_chat) ──> llm.py
  │         └── local by default; plan_web_search may call websearch.execute_web_search
  │         └── never receives Analyze or Assistant context; no OCR/image dumps to search
  │         └── Clear conversation resets this chat and OCR cache only
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
  ├─ *.log ───────> one scan + hint-gated correlators ──> bounded groups / report
  │
  └─ log anonymizer ──> deterministic pseudonymization ──> anonymized copy
            └── optional SAML XML audit: exact decoded XML (sensitive) + post-transform XML
```

## Security boundaries

- Analyzer does not invoke web search or require Ollama.
- Assistant (optional) does not invoke web search. It receives the latest Analyze result, every Analyze tab source file and pasted text (local only; large bodies may be truncated but all names stay listed), and optional local screenshots plus OCR. **Clear conversation** resets the transcript without detaching analysis. **Clear analysis context** can detach it.
- General Chat (optional) does not inherit Analyzer or Assistant context, Analyze source files, screenshots or OCR. Local by default. Public search only after a per-turn plan; queries are minimal text, never image bytes or OCR dumps.
- Optional modules are off by default on the **full** edition and enabled independently. Enabling them in Config requires a process restart. Tab order: Analyze → Anonymize → Assistant → General Chat → Config. A legacy `.iddqd-modules.json` value `llm` still turns on both chat modules.
- **Light edition** (`IDDQD Support Analyzer Light`; `IDDQD_EDITION=light`, alias `core`; `./run-light.sh`; or a `LIGHT_EDITION` marker in the Light zip): Analyze + Anonymize only. Chat modules are not loaded and are omitted from the exported zip. Analyzer and anonymizer code is shared; LLM files stay on the full tree.
- `OLLAMA_MODEL` is the process env tag (default `qwen3.6:27b` if unset). Chats display that string; they do not parse model-file metadata or `ollama list`. Light edition does not use it.
- Model endpoints must be loopback or RFC1918 unless `ALLOW_REMOTE_LLM=true`.
- Screenshot/photo uploads are local files only (type/size/pixel limits, no URLs). Pixels sent to Ollama are downscaled; OCR runs on a derived copy via local Tesseract. If a vision request returns HTTP 400, `llm.complete` retries without images (OCR text remains). Assistant and General Chat use separate OCR caches and never copy attachments between tabs.
- Gradio Screen Studio (browser-tab recording) is disabled. Run history is off so Analyze/Anonymize payloads are not stored in the Gradio runs UI.
- `.env`, local logs, generated mappings and credential material are excluded from version control.
- Local certificate/key formats (`*.pem`, `*.crt`, `*.cer`, `*.der`, `*.key`, `*.p12`, `*.pfx`, keystores) are excluded from version control.
- The standalone signing-certificate input accepts public X.509 certificates only; private keys are rejected.
- The anonymizer is pattern-based and should not be treated as a certified DLP control. A residual leak scan runs on the anonymized text. Original decoded SAML XML offered for QA contains source data and is not for external sharing.

## SAML validation model

Validation is separated into four layers:

1. **Transport decoding** — JSON (SAML-tracer / HAR) is parsed structurally first; then raw XML, Base64, URL encoding and Redirect-binding DEFLATE from decoded values. XML is not scraped from JSON-escaped source text.
2. **Document and protocol structure** — well-formed XML, document type, required fields and profile rules.
3. **Signature and trust validation** — SAML XML Signature profile checks, same-document Reference validation, cryptographic signature/digest verification with public X.509 certificates, and comparison with matching metadata signing certificates.
4. **Cross-document consistency** — comparisons between Request, Response, Assertion and supplied SP/IdP metadata.

Time validity for assertion Conditions `NotBefore`/`NotOnOrAfter` and bearer `SubjectConfirmationData.NotOnOrAfter` uses a chosen `validation_time` with `SAML_CLOCK_SKEW_SECONDS` (IDDQD default 120; not a SAML-mandated value). SAML-tracer/HAR ACS posts use `incident_trace_mode` (ACS response `Date`, else request timestamp; never analyzer runtime as the primary clock). Raw XML without ACS transport evidence uses `replay_now_mode` (analyzer UTC). `SessionNotOnOrAfter` follows the same mode. Metadata `validUntil` uses the same validation time.

### XML Signature trust model

A private key is not required to verify an XML Signature. Verification uses the signer's public X.509 certificate.

When matching metadata is supplied, `KeyDescriptor` entries with `use="signing"` or with no `use` (usable for signing and encryption per SAML metadata) are the published signing keys. The analyzer verifies the XML Signature cryptographically, then compares the actual signer to those keys (certificate SHA-256 / public key). A match is reported as a deterministic metadata comparison, not as “certificate trusted.” Encryption-only `KeyDescriptor`s are not used for signer comparison. Multiple signing keys are normal during rollover; any matching key is sufficient.

An operator may also supply a standalone X.509 signing certificate in PEM or DER form. That is an explicit trust input, separate from metadata. If both are present, metadata remains the primary comparison source and the supplied certificate is compared against it.

If IdP metadata is unavailable, a valid embedded signature is cryptographic validity plus `SIGNER_TRUST_NOT_EVALUATED`. Missing metadata is not a failure and is not reported as an untrusted certificate.

Optional SP and IdP metadata uploads are independent. Entity selection among `EntitiesDescriptor` members uses AuthnRequest Issuer (SP) and Response/Assertion Issuer (IdP). If selection is ambiguous, dependent checks are not evaluated and the analyzer does not guess. Metadata XML is parsed with the same safe XML settings as SAML messages; metadata URLs are not fetched.

For SAML assertions and protocol messages, SAML Core 2.0 §5.4.2 is applied strictly: the signature must contain exactly one `ds:Reference`, and its URI must be the same-document fragment `#<ID>` of the signed SAML root element.

Encrypted SAML content is a separate concern. `EncryptedAssertion` is detected, but decryption is not performed. Decryption would require the SP private key and is intentionally outside the signature-verification path.

Untrusted SAML and metadata XML on the signature and anonymizer paths is parsed with entity resolution, DTDs and network access disabled. Transport inflation (Redirect DEFLATE / zlib / gzip) is capped at `MAX_FILE_MB`.
