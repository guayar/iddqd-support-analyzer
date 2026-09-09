# User guide

Short landing page: [README](../README.md). Architecture: [ARCHITECTURE.md](ARCHITECTURE.md). Changelog: [../CHANGELOG.md](../CHANGELOG.md). Version: [../VERSION](../VERSION).

## Why this exists

Built to learn SAML and support-style log analysis by implementing the checks, including awkward real-world edge cases rather than only happy-path traces. Coding is AI-assisted; requirements, tests, and spec interpretation stay with the author. Private workstation tool for work: paste a trace or a log, get a structured read. Not something to drop onto a customer network as a supported product.

## Features

### SAML / SSO analysis

- raw `AuthnRequest`, `Response` and standalone `Assertion` XML
- HTTP-POST Base64 decoding
- HTTP-Redirect URL decoding, Base64 decoding and raw-DEFLATE decompression (output capped at `MAX_FILE_MB`)
- download of each transport-decoded SAML document (raw XML, source filename preserved)
- SP and IdP metadata parsing (`EntityDescriptor` / `EntitiesDescriptor`)
- full Response and Assertion field extraction
- Subject / NameID / SubjectConfirmation analysis
- AudienceRestriction and Conditions analysis
- AuthnStatement, session and AuthnContext extraction
- attribute extraction, including multi-valued attributes; duplicate `Name`+`NameFormat` and conflicting `xsi:type` on `AttributeValue`
- XML Signature structure inspection
- SAML XML Signature profile validation, including the single same-document `Reference URI="#ID"` rule
- cryptographic XML Signature and digest verification with public X.509 certificates
- trust comparison against matching SP / IdP metadata signing certificates
- optional standalone X.509 signing certificate upload (`.pem`, `.crt`, `.cer`; PEM or DER)
- certificate fingerprints from SAML messages, metadata and supplied certificates
- protocol/profile validation with structured error codes
- copy the rendered Analyze report to the clipboard
- cross-document checks across Request ↔ Response ↔ Assertion ↔ SP metadata ↔ IdP metadata

Examples of validator findings:

```text
RESPONSE_ID_MISSING
RESPONSE_STATUS_MISSING
NAMEID_EMAIL_FORMAT_INVALID
NAMEID_EMAIL_FORMAT_NOT_FULLY_CHECKED
NAMEID_ENCRYPTED_FORMAT_PLAINTEXT
ENCRYPTED_ID_PRESENT
ENCRYPTED_ID_ENCRYPTION_METHOD_MISSING
ENCRYPTED_ID_KEY_ENCRYPTION_METHOD_MISSING
ENCRYPTED_ID_KEYINFO_MISSING
NAMEID_ENTITY_URI_INVALID
NAMEID_PERSISTENT_NAMEQUALIFIER_NOT_CHECKED
NAMEIDPOLICY_RETURNED_FORMAT_MISMATCH
SUBJECT_IDENTIFIER_CHOICE_INVALID
SESSION_NOTONORAFTER_EXPIRED
RESPONSE_BEARER_INRESPONSETO_MISMATCH
BEARER_INRESPONSETO_UNSOLICITED
BEARER_RECIPIENT_ACS_MISMATCH
AUDIENCE_SP_ENTITYID_MISMATCH
DUPLICATE_SAML_ID
ATTRIBUTE_NAME_DUPLICATE
ATTRIBUTE_VALUE_TYPE_MISMATCH
ENCRYPTED_ATTRIBUTE_PRESENT
XML_NOT_WELL_FORMED
RESPONSE_SIGNATURE_REFERENCE_URI_INVALID
RESPONSE_XML_SIGNATURE_INVALID
RESPONSE_DESTINATION_EMPTY
RESPONSE_DESTINATION_MISMATCH
RESPONSE_DESTINATION_MATCH
RESPONSE_XML_SIGNATURE_VALID
RESPONSE_XML_SIGNATURE_VALID_SUPPLIED_CERT
ASSERTION_SIGNATURE_ALGORITHM_WEAK
ASSERTION_DIGEST_ALGORITHM_WEAK
RESPONSE_SIGNING_CERT_MATCHES_METADATA
```

XML Signature verification does **not** require a private key. When matching SAML metadata is supplied, the analyzer verifies the signature using the trusted public signing certificate from that metadata. If metadata is unavailable, the Analyze tab accepts an optional standalone X.509 signing certificate and can use it to verify the signature and referenced digest. The report still distinguishes cryptographic validity from metadata-backed signer trust.

A bare `-----BEGIN PUBLIC KEY-----` file is not accepted in this path; upload the corresponding X.509 certificate instead. Private keys are neither required nor accepted for signature verification.

If only a certificate embedded in `ds:KeyInfo` is available, the analyzer can verify the cryptographic signature but explicitly reports that signer trust is not established by metadata.

`EncryptedAssertion`, `EncryptedAttribute` and `EncryptedID` are detected, but decryption is not implemented. Decryption would require the SP private key and is intentionally kept separate from signature verification. XML Encryption algorithms and KeyInfo presence are reported. Missing EncryptionMethod or KeyInfo on EncryptedID is a warning: XML Encryption allows the omission, typical SP libraries do not.

### Log analysis

- timestamp range detection
- severity counts from recognized log-record prefixes
- error/status code extraction
- multiline incidents with Java exception chains and Maven `[ERROR]` blocks
- root-cause extraction from `Caused by:` (not a separate incident)
- first occurrence, numbered `Caused by` list, and a collapsible raw log sample

Auto-detect classifies each uploaded file (and pasted text as one extra artifact). Independent SAML Responses get separate reports. AuthnRequest + Response + metadata stay one correlated analysis. Each Base64 artifact is decoded on its own. Log files go to the log analyzer. A mixed upload produces one report with both sections. Explicit **SAML** / **Log** modes still send the whole bundle to that analyzer, except multiple standalone SAML Responses are split the same way.

### Anonymize (optional module)

Enable **Anonymize** on the Config tab, then restart. Drop a file **or** paste text — not both; choosing one source clears the other. Local deterministic pseudonymization for logs and SAML traces, including:

- IPv4 / IPv6
- hostnames and domains
- e-mail addresses
- MAC addresses
- UUIDs
- JWTs and Authorization headers
- passwords, tokens, API keys and session identifiers
- sensitive URL query parameters and RelayState
- Base64-encoded SAMLRequest / SAMLResponse payloads
- HTTP-Redirect SAMLRequest payloads using URL-encoded Base64 + raw DEFLATE
- raw standalone SAML XML, tracer bundles and SAML XML embedded in logs

For encoded SAML, the anonymizer follows the transport rather than treating Base64 as opaque text:

```text
Base64 / Redirect SAML
        ↓
decode (+ DEFLATE when required)
        ↓
parse SAML XML safely
        ↓
structure-aware anonymization
        ↓
recompress when required
        ↓
Base64 / URL encode again
```

After a run you can download three layers for QA:

- the **full anonymized copy** (re-encoded Base64/Redirect when that was the input)
- **original decoded XML** — exact bytes inspected before transformation; **contains source data, not for external sharing**
- **anonymized XML** after the tree transform, before re-encoding

Files are named `{source}.{type}_{nn}.decoded.xml` / `.anonymized.xml`. Multiple documents come as a zip. Original decoded files are labeled in the UI as sensitive.

SAML is anonymized structurally rather than by applying generic domain regexes to the XML. This means standard protocol identifiers remain intact, including SAML URNs, XML namespaces, XML Schema URLs, XMLDSig namespaces, algorithms, bindings, NameID formats and AuthnContext values.

The SAML-aware layer pseudonymizes values such as:

- Request / Response / Assertion `ID`
- `InResponseTo` and same-document `ds:Reference URI="#..."` values using the same mapping
- Issuer, Audience, Destination, Recipient and metadata endpoints
- NameID and NameID qualifiers
- AttributeValue contents
- SessionIndex
- SubjectLocality Address
- selected metadata organization/contact fields

Embedded X.509 certificates are replaced with valid synthetic certificates so the anonymized XML remains structurally parseable without exposing certificate subject/issuer information. `SignatureValue` and `DigestValue` are also replaced with harmless Base64 placeholders.

Pre-existing SAML inconsistencies are preserved. For example, if a Signature references the wrong Assertion ID before anonymization, the anonymized copy still references the corresponding wrong pseudonymized ID rather than silently repairing the trace.

Unrelated Base64 blobs are left unchanged unless they decode to recognizable SAML XML. Stable pseudonyms are used within a single run so repeated values remain correlatable across plaintext logs and decoded SAML.

Anonymizing fields inside signed SAML changes the signed bytes and therefore invalidates the original XML Signature. This is expected for a shareable anonymized copy; do not use the anonymized copy to verify the original signature.

The anonymizer is not a certified DLP product; generated output should still be reviewed before external sharing, especially when custom SAML extension elements contain free-form business data. After each run a **residual leak scan** lists leftover emails, IPs, tokens, domains and user home paths that the first pass did not replace. Java/Maven logs also replace customer packages, project roots, process user names, Spring app names and Maven artifact names; stack frames from Spring/Apache and `*.java` / `*.jar` names stay intact.

### Assistant (optional module)

Enable **Assistant** on the Config tab, then restart. Requires local Ollama. Independent of General Chat.

The Assistant has no web-search path and no Mode switch. Ask it for technical help, a support-mail draft, or code in the same chat. Attach **local PNG/JPEG/WEBP screenshots** (terminal, stack traces, admin consoles; up to three per message). Original pixels go to Ollama when the model reports `vision`; a **local Tesseract OCR** extract is extra evidence and is labeled as imperfect. Follow-up turns without a new file re-send the last screenshot plus OCR. The latest Analyze result is available here automatically. A muted **Model:** line next to the analysis-context status shows the configured `OLLAMA_MODEL` tag (startup only; no in-app switcher). **Clear analysis context** removes that report, screenshot OCR cache and resets the Assistant chat. General Chat never receives the report, images or OCR.

Ubuntu OCR (Assistant and General Chat, optional): `sudo apt install tesseract-ocr tesseract-ocr-eng tesseract-ocr-pol`. Without Tesseract, images still go to a vision-capable Ollama model. Without vision, OCR text can still be sent.

### General Chat (optional module)

Enable **General Chat** on the Config tab, then restart. Requires local Ollama. Independent of Assistant.

A deliberately separate web-enabled chat. It receives **no** Analyzer or Assistant context. Local by default: a planning step (local model, JSON) decides whether this turn needs the public web. Search only when the user asked to look something up or the task needs current/external facts. Simple “what is this?” on a photo stays local. Queries are short and never include OCR dumps, screenshots, logs or Analyzer JSON. The sources footer appears only when search actually ran.

## Known limitations

- Local Gradio app on `127.0.0.1` for a private workstation, not a packaged or multi-user product. Reports are heuristics plus spec-backed SAML checks, not a substitute for an IdP/SP vendor’s own validator. Unexpected runtime errors are in the process terminal; validation messages (empty input, oversize file) are a timed toast.
- `EncryptedAssertion` is detected, not decrypted. The anonymizer is useful, not DLP; shareable output still needs a human pass.
- Log timestamps are treated as record boundaries when the shape is recognizable; numeric dates such as `09/01/26` do not get a calendar `time_range` unless the same log makes day/month order unambiguous.
- Optional chats need local Ollama. Assistant and General Chat are independent Config modules. The displayed model name is the `OLLAMA_MODEL` env tag, not a label from the weight file and not `ollama list`. Coverage grows from real traces and failing cases, not from claiming a complete SAML or logging catalogue.
- Local OCR is imperfect. Prefer the image when OCR and pixels disagree. Cloud OCR is not used. OCR text from General Chat may be used to build public search queries.
- Chat transcripts are height-capped so they scroll in-pane; the prompt does not grow the page. Analyze still page-scrolls.

## Privacy model

| Area | Local model | Web access | Intended data |
|---|---:|---:|---|
| Analyze | No | No | Logs, SAML traces, metadata, public signing certificates |
| Anonymize (optional) | No | No | Sensitive logs and SAML traces |
| Assistant (optional) | Yes | No | Technical/support material, screenshots, local OCR, plus the latest Analyze result |
| General Chat (optional) | Yes | Yes | Non-sensitive public questions; optional local photos (pixels stay local; text queries may go to search) |
| Config | No | No | Which optional modules to load after restart |

The application binds to `127.0.0.1` by default and blocks non-local model endpoints unless explicitly enabled. Loopback and RFC1918 Ollama URLs count as local; public cloud endpoints need `ALLOW_REMOTE_LLM=true`.

Default UI is **Analyze** and **Config** only. Optional tabs appear only after they are enabled and the application is restarted. Tab order with modules on: Analyze → Anonymize → Assistant → General Chat → Config.

## Requirements

Install order: OS packages → `./run.sh` (creates `.venv` and installs `requirements.txt`) → optional Ollama/Tesseract only for the chat modules you enable in Config.

### Always — Analyze and Config

| Need | Install |
|---|---|
| Ubuntu / Linux, Python 3.12+ | distro packages (`python3`, `python3-venv`) |
| Python libraries | `./run.sh` (includes SAML/XML, Gradio, and also chat extras such as `ddgs`, `pillow`, `pytesseract` even when those tabs are off) |

No GPU, no Ollama, no Tesseract. Binding defaults to `http://127.0.0.1:7860`.

### Anonymize (optional Config module)

Nothing extra beyond Analyze. Enable the checkbox, restart, refresh. No language model.

### Assistant (optional Config module)

| Need | Install |
|---|---|
| Ollama running locally | [ollama.com](https://ollama.com) |
| A pulled model | `ollama pull <tag>` then set `OLLAMA_MODEL` to **that exact tag** and restart. If unset, the process uses `qwen3.6:27b` even if you pulled something else |
| Screenshots (PNG/JPEG/WEBP) | already in the Python venv (`pillow`) |
| OCR text on those screenshots | `sudo apt install tesseract-ocr tesseract-ocr-eng tesseract-ocr-pol` |

Without Tesseract, screenshots still go to a vision-capable model. Without `vision` on the model, OCR text can still be sent. No web search.

Tested inference: `qwen3.6:27b` on an **AMD Radeon AI PRO R9700** (desktop graphics on the iGPU).

### General Chat (optional Config module)

Same Ollama + `OLLAMA_MODEL` as Assistant if you enable both (one process, one tag). Independent checkbox — you can enable this tab without Assistant.

| Need | Install |
|---|---|
| Ollama + pulled tag | same as Assistant |
| Outbound HTTPS | public search via `ddgs` (queries only) |
| Local product photos | venv `pillow`; optional Tesseract as above |

Image bytes stay local. Search providers receive text queries (your question plus OCR), not the file.

### Out of scope for every module

Do not install cloud OCR, a remote LLM (unless you set `ALLOW_REMOTE_LLM=true`), or extra search CLIs. Switching models is `.env` / `OLLAMA_MODEL` plus restart, not an in-app menu.

## Standalone signing certificate

In **Analyze**, use **Signing certificate (optional)** when you have the signing certificate separately from SAML metadata. Supported input:

```text
.pem   PEM X.509 certificate
.crt   PEM or DER X.509 certificate
.cer   PEM or DER X.509 certificate
```

The certificate is read for the current analysis only. It is not copied into the repository or persisted by the analyzer. Matching metadata remains the preferred trust source when available.

## Configuration

Use the **Config** tab to enable optional modules independently (**Anonymize**, **Assistant**, **General Chat**). Changes are saved immediately to a local `.iddqd-modules.json` file (gitignored). A red notice appears until you click **Restart application** and refresh the browser. Default UI is **Analyze** and **Config**. A previously saved combined `llm` plugin still enables both chat tabs.

`config.example.env` contains the supported environment variables. Common settings:

```text
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen3.6:27b
ALLOW_REMOTE_LLM=false
APP_PORT=7860
MAX_FILE_MB=150
UI_THEME=system
```

`MAX_FILE_MB` also caps decompressed SAML from Redirect/Base64 (zlib, raw DEFLATE, gzip), including pasted text, not only uploaded files. Signature and anonymizer XML parsing disables DTDs, entity expansion and network fetches.

`UI_THEME` is `light`, `dark` or `system` (default). Choosing Light/Dark/System in Settings is stored in the browser and restored after a process restart. Gradio Screen Studio (tab recording) is disabled.

`OLLAMA_*` settings apply only when Assistant or General Chat is enabled. `OLLAMA_MODEL` is the exact Ollama tag sent to `/api/chat` and shown on those tabs. It is not Qwen-only and is not read from the model file.

Web-enabled General Chat:

```text
WEB_SEARCH_RESULTS=6
WEB_FETCH_RESULTS=3
WEB_FETCH_CHARS=16000
WEB_SEARCH_REGION=wt-wt
WEB_SEARCH_BACKEND=auto
```

Assistant and General Chat screenshots/photos (never shared across those tabs):

```text
ASSISTANT_IMAGE_MAX_MB=8
ASSISTANT_IMAGE_MAX_PIXELS=12000000
ASSISTANT_IMAGES_PER_MESSAGE=3
OCR_TIMEOUT_SECONDS=5
```

Optional basic authentication can be enabled with `BASIC_AUTH_USER` and `BASIC_AUTH_PASS`.

## Updating

```bash
cd ~/Praca/iddqd-support-analyzer
./update.sh
```

The update script refuses to overwrite tracked local changes. Commit or stash them first if you intentionally modify project files locally.

## Running tests

```bash
source .venv/bin/activate
PYTHONPATH=. python tests/test_analyzers.py
PYTHONPATH=. python tests/test_signature_validation.py
PYTHONPATH=. python tests/test_anonymizer_saml.py
PYTHONPATH=. python tests/test_anonymize_xml_audit.py
PYTHONPATH=. python tests/test_saml_anonymizer.py
PYTHONPATH=. python tests/test_layers.py
PYTHONPATH=. python tests/test_nameid.py
PYTHONPATH=. python tests/test_modules.py
PYTHONPATH=. python tests/test_assistant_handoff.py
PYTHONPATH=. python tests/test_chat_history.py
PYTHONPATH=. python tests/test_vision.py
```

The tests use synthetic SAML and log data only. Signature and anonymization tests generate ephemeral synthetic keys/certificates at runtime; no private key material is stored in the repository.

## Project structure

```text
.
├── analyzers/          # deterministic SAML and log engines; anonymizer is optional
├── docs/               # user guide and architecture (landing README stays short)
├── tests/
├── actions.py          # Analyze use-case; Anonymize imported lazily
├── reporting.py        # markdown reports from analyzer JSON
├── modules.py          # optional-module registry and restart
├── llm.py              # local Ollama client and endpoint policy
├── vision.py           # screenshot/photo validation and local OCR (separate caches per chat)
├── chats.py            # Assistant / General Chat
├── websearch.py        # General Chat search/fetch only
├── uploads.py          # file size limits and text reads
├── config.py           # environment settings
├── app.py              # Gradio UI shell
├── config.example.env
├── requirements.txt
├── run.sh
├── start-analyzer.sh
├── update.sh
├── CHANGELOG.md
└── VERSION
```

## Versioning

The project uses semantic versioning while it is pre-1.0. New functionality normally increments the minor version; compatibility fixes and focused improvements to an existing feature increment the patch version.

When behavior, UI, modules, env vars or security boundaries change, update docs in the same change:

1. `VERSION`
2. `CHANGELOG.md` — new heading matching `VERSION`
3. `README.md` — short GitHub landing page only (`**Current version:**`, purpose, capability summary, start command, links into `docs/`). Finding-code catalogues, env dumps and install tables belong in this guide, not on the landing README.
4. This file for user-facing detail. `docs/ARCHITECTURE.md` and `config.example.env` when architecture or env vars changed.

The README `**Current version:**` string must equal `VERSION`. The latest changelog heading must equal `VERSION`. Do not bump the version for a docs-only follow-up of a change that already shipped that version; still fix stale wording.

The GitHub About box has no version number. Refresh it only when user-facing functionality changes (new or removed modules, privacy/search/vision boundaries, what the tool is). Skip About for patch-only or docs-only version bumps.
