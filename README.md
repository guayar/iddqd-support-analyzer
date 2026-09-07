# IDDQD Support Analyzer

[![Tests](https://github.com/guayar/iddqd-support-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/guayar/iddqd-support-analyzer/actions/workflows/tests.yml)

Local troubleshooting toolkit for SAML/SSO, protocol validation, metadata analysis, log files, anonymization, support writing and coding assistance.

**Current version:** `0.10.6`

The project is designed for local-first technical support workflows. Deterministic parsers and validators handle protocol checks and structured extraction; local inference can be used for explanation, report drafting and coding assistance. Web access is isolated in a separate General Chat tab and is never used automatically by the Analyzer or local Assistant.

## Features

### SAML / SSO analysis

- raw `AuthnRequest`, `Response` and standalone `Assertion` XML
- HTTP-POST Base64 decoding
- HTTP-Redirect URL decoding, Base64 decoding and raw-DEFLATE decompression
- SP and IdP metadata parsing (`EntityDescriptor` / `EntitiesDescriptor`)
- full Response and Assertion field extraction
- Subject / NameID / SubjectConfirmation analysis
- AudienceRestriction and Conditions analysis
- AuthnStatement, session and AuthnContext extraction
- attribute extraction, including multi-valued attributes
- XML Signature structure inspection
- SAML XML Signature profile validation, including the single same-document `Reference URI="#ID"` rule
- cryptographic XML Signature and digest verification with public X.509 certificates
- trust comparison against matching SP / IdP metadata signing certificates
- optional standalone X.509 signing certificate upload (`.pem`, `.crt`, `.cer`; PEM or DER)
- certificate fingerprints from SAML messages, metadata and supplied certificates
- protocol/profile validation with structured error codes
- cross-document checks across Request ↔ Response ↔ Assertion ↔ SP metadata ↔ IdP metadata

Examples of validator findings:

```text
RESPONSE_ID_MISSING
RESPONSE_STATUS_MISSING
NAMEID_EMAIL_FORMAT_INVALID
BEARER_RECIPIENT_ACS_MISMATCH
AUDIENCE_SP_ENTITYID_MISMATCH
DUPLICATE_SAML_ID
XML_NOT_WELL_FORMED
RESPONSE_SIGNATURE_REFERENCE_URI_INVALID
RESPONSE_XML_SIGNATURE_INVALID
RESPONSE_XML_SIGNATURE_VALID
RESPONSE_XML_SIGNATURE_VALID_SUPPLIED_CERT
RESPONSE_SIGNING_CERT_MATCHES_METADATA
```

XML Signature verification does **not** require a private key. When matching SAML metadata is supplied, the analyzer verifies the signature using the trusted public signing certificate from that metadata. If metadata is unavailable, the Analyze tab accepts an optional standalone X.509 signing certificate and can use it to verify the signature and referenced digest. The report still distinguishes cryptographic validity from metadata-backed signer trust.

A bare `-----BEGIN PUBLIC KEY-----` file is not accepted in this path; upload the corresponding X.509 certificate instead. Private keys are neither required nor accepted for signature verification.

If only a certificate embedded in `ds:KeyInfo` is available, the analyzer can verify the cryptographic signature but explicitly reports that signer trust is not established by metadata.

`EncryptedAssertion` is detected, but decryption is not implemented. Decryption would require the SP private key and is intentionally kept separate from signature verification.

### Log analysis

- timestamp range detection
- severity counts
- error/status code extraction
- grouped error events and stack traces
- `Caused by` chain extraction
- first occurrence and representative samples

### Anonymization

Local deterministic pseudonymization for logs and SAML traces, including:

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

The anonymizer is not a certified DLP product; generated output should still be reviewed before external sharing, especially when custom SAML extension elements contain free-form business data.

### Local Assistant

Separate local modes for:

- general technical assistance
- enterprise support mail drafting
- Java / TypeScript / Python / Playwright coding help

The Assistant has no web-search path.

### General Chat

A deliberately separate web-enabled chat. It receives no Analyzer or local Assistant context. Search queries are generated locally, sent to public search providers through `ddgs`, and the returned pages are summarized by the local model.

## Privacy model

| Area | Local model | Web access | Intended data |
|---|---:|---:|---|
| Analyze | Yes | No | Logs, SAML traces, metadata, public signing certificates |
| Anonymize log | No model required | No | Sensitive logs and SAML traces |
| Assistant | Yes | No | Technical/support material |
| General Chat | Yes | Yes | Non-sensitive public questions |

The application binds to `127.0.0.1` by default and blocks non-local model endpoints unless explicitly enabled.

## Requirements

- Ubuntu / Linux
- Python 3.12+
- Ollama
- a locally installed text model (default configuration: `qwen3.6:27b`)

## Quick start

```bash
git clone https://github.com/guayar/iddqd-support-analyzer.git
cd iddqd-support-analyzer
cp config.example.env .env
./run.sh
```

`run.sh` creates a local `.venv`, installs dependencies there and starts the application.

For desktop use, `start-analyzer.sh` opens the local UI in the browser and keeps the application attached to the terminal. To update an existing checkout safely, run `./update.sh`; it performs a fast-forward-only pull and refreshes dependencies when a local virtual environment exists.

Default UI:

```text
http://127.0.0.1:7860
```

## Standalone signing certificate

In **Analyze**, use **Signing certificate (optional)** when you have the signing certificate separately from SAML metadata. Supported input:

```text
.pem   PEM X.509 certificate
.crt   PEM or DER X.509 certificate
.cer   PEM or DER X.509 certificate
```

The certificate is read for the current analysis only. It is not copied into the repository or persisted by the analyzer. Matching metadata remains the preferred trust source when available.

## Configuration

`config.example.env` contains the supported environment variables. Common settings:

```text
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen3.6:27b
ALLOW_REMOTE_LLM=false
APP_PORT=7860
MAX_FILE_MB=150
```

Web-enabled General Chat settings:

```text
WEB_SEARCH_RESULTS=6
WEB_FETCH_RESULTS=3
WEB_FETCH_CHARS=16000
WEB_SEARCH_REGION=wt-wt
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
PYTHONPATH=. python tests/test_saml_anonymizer.py
PYTHONPATH=. python tests/test_layers.py
```

The tests use synthetic SAML and log data only. Signature and anonymization tests generate ephemeral synthetic keys/certificates at runtime; no private key material is stored in the repository.

## Project structure

```text
.
├── analyzers/          # deterministic SAML, log and anonymizer engines
├── tests/
├── actions.py          # Analyze / Anonymize use-cases (no Gradio)
├── reporting.py        # markdown reports from analyzer JSON
├── llm.py              # local Ollama client and endpoint policy
├── chats.py            # Assistant / analysis / web chat
├── websearch.py        # General Chat search/fetch
├── uploads.py          # file size limits and text reads
├── config.py           # environment settings
├── app.py              # Gradio UI only
├── config.example.env
├── requirements.txt
├── run.sh
├── start-analyzer.sh
├── update.sh
├── CHANGELOG.md
└── VERSION
```

## Versioning

The project uses semantic versioning while it is pre-1.0. New functionality normally increments the minor version; compatibility fixes and focused improvements to an existing feature increment the patch version (`0.10.5` → `0.10.6`).
