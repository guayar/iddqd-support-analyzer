# Changelog

All notable changes to this project are documented here.

## [0.17.0] - 2026-09-10

### Added

- Log records may have a bracketed level after a timestamp (`[Sun Dec 04 04:47:44 2005] [error] …`). Repeated messages group on the text after the level; `[client …]` and `child <digits>` are context, not identity. Apache `notice` counts as INFO and is not an incident

### Changed

- Correlated-incidents empty state: 0 incidents does not mean the log is empty; vendor codes stay a separate list
- Versioning (user guide): no bump for cosmetics/docs; patch for small work on existing modules; minor only for new capabilities
- version bumped to `0.17.0`

## [0.16.1] - 2026-09-10

### Changed

- Log report incidents heading is **Correlated incidents**. Empty state does not imply the whole log was empty when vendor codes are listed
- Vendor codes state that occurrence count is not importance; the list says how many of the unique codes are shown. HTTP/SQLSTATE tokens are not mixed into vendor unique totals
- Unique vendor-code and per-code counts stay exact; first/last/example storage stays capped
- version bumped to `0.16.1`

## [0.16.0] - 2026-09-10

### Added

- Oracle-style alert timestamps (`Wed Jul 01 15:00:00 2026`, including a weekday and a year) are calendar `time_range` values. RFC3164 stamps without a year are still shown as written
- Log report **Vendor codes** lists record-start `PREFIX-NUMBER` families (ORA, RMAN, TNS, …) with counts and first/last line; embedded tokens such as `SP2-0552` in a message body are ignored. Codes are identifiers, not incidents

### Changed

- English `error:` / `WARNING:` inside an Oracle vendor-code message is not counted as a source ERROR/WARN
- Log scan skips slash-date policy and OpenSSH correlation when those shapes are absent; unique vendor-code lists are capped
- version bumped to `0.16.0`

## [0.15.2] - 2026-09-09

### Changed

- Signature validation uses the shared SAML namespace map from `analyzers/saml.py` instead of a local copy. Dead import and unused walrus assignment cleaned up
- version bumped to `0.15.2`

## [0.15.1] - 2026-09-09

### Changed

- Log report lists explicit FATAL/CRITICAL/SEVERE source markers under **Notable line findings** (source line, marker, PID context) before Incidents, independently of the incident-detail cap. `fatal:` is still not a CRITICAL incident. FATAL uses a distinct icon from ERROR
- version bumped to `0.15.1`

## [0.15.0] - 2026-09-09

### Added

- Optional third-party regression corpora (Loghub 2k samples, python3-saml fixtures) via a pinned manifest and `scripts/fetch_regression_data.py`. Files stay gitignored under `testdata/external`; unit tests do not require them. Attribution: `docs/THIRD_PARTY_TEST_DATA.md`
- version bumped to `0.15.0`

## [0.14.1] - 2026-09-09

### Changed

- Log SSH incidents use correlated severity, not `max(line rule)`: reverse-DNS mismatch alone is WARN; the same `sshd` PID with failed authentication is ERROR; `fatal:` still counts as a source FATAL line and is not a CRITICAL incident
- Brute-force clusters keep the 15-minute gap and no global IP merge. Five to nine slower attempts are suspected (WARN); ten or more, or five or more inside a 60-second window (`BRUTE_FORCE_RAPID_WINDOW_SECONDS`), are ERROR
- Log report **Detected line severities** (source markers plus per-line classification) is separate from incident severity; incident unique counts are computed before the display cap
- version bumped to `0.14.1`

## [0.14.0] - 2026-09-09

### Added

- Log analyzer recognizes RFC3164/syslog stamps (`MMM d HH:mm:ss` / `MMM dd HH:mm:ss`) in the timestamp range without inventing a year
- Case-insensitive `error:` / `fatal:` (and other `LEVEL:`) markers, plus OpenSSH/auth patterns (`Failed password`, `Invalid user`, `POSSIBLE BREAK-IN ATTEMPT`, and related). Lines for one `sshd[pid]` become one authentication attempt; repeated attempts from the same IP in a short window can raise a brute-force incident. A lone `Connection closed` is not an error

### Changed

- Analyze certificate note sits directly under the input fields, above Analyze / Clear
- version bumped to `0.14.0`

## [0.13.11] - 2026-09-09

### Added

- Analyze **Clear** resets uploads, paste, optional signing certificate, report, decoded artifacts and JSON. Analyzer mode is left unchanged. If Assistant is on, the attached analysis is dropped; the chat transcript is not.

### Changed

- version bumped to `0.13.11`

## [0.13.10] - 2026-09-09

### Changed

- Display theme (Light / Dark / System) is remembered across application restarts (`UI_THEME` default plus browser storage). Gradio Screen Studio recording is disabled; run history is off.
- version bumped to `0.13.10`

## [0.13.9] - 2026-09-09

### Fixed

- Empty Analyze/Anonymize no longer hides the whole page. The timed toast stays; only the per-output Error overlay is suppressed.

### Changed

- version bumped to `0.13.9`

## [0.13.8] - 2026-09-09

### Added

- Anonymize can download the exact decoded SAML XML inspected before transformation (sensitive, not for sharing) and the post-transform XML before re-encoding, named like `stem.response_01.decoded.xml`

### Changed

- version bumped to `0.13.8`

## [0.13.7] - 2026-09-09

### Fixed

- Analyze/Anonymize paste fields, report pane, copy button and Analyzer radio chips follow the Gradio theme instead of a forced white background (dark layout)

### Changed

- version bumped to `0.13.7`

## [0.13.6] - 2026-09-09

### Changed

- Validation errors are only the timed top-right toast. The per-component Error pills (report, decoded files, anonymizer) are hidden.
- version bumped to `0.13.6`

## [0.13.5] - 2026-09-09

### Changed

- Unexpected Gradio exceptions stay in the process terminal. Validation still uses in-app `gr.Error` (empty input, file too large).
- version bumped to `0.13.5`

## [0.13.4] - 2026-09-09

### Fixed

- Signature-path SAML/metadata XML is parsed with the same hardened lxml settings as the anonymizer (no entity expansion, no network, no DTD, no huge trees)
- Redirect/Base64 DEFLATE, zlib and gzip inflation is capped at `MAX_FILE_MB` (paste included), including the anonymizer decode path

### Changed

- version bumped to `0.13.4`

## [0.13.3] - 2026-09-09

### Fixed

- Assistant and General Chat no longer stretch a full-viewport column with a huge empty gap. Only the transcript is height-capped; the prompt stays under the chat box.

### Changed

- version bumped to `0.13.3`

## [0.13.2] - 2026-09-09

### Fixed

- General Chat no longer searches the web on every message. A local model decides per turn (JSON); default is local. Queries are minimal and never OCR/image dumps. Footer only when search ran.

### Changed

- version bumped to `0.13.2`

## [0.13.1] - 2026-09-09

### Fixed

- Assistant and General Chat stay inside the viewport: the transcript scrolls, the prompt does not grow the page under the input bar

### Changed

- version bumped to `0.13.1`

## [0.13.0] - 2026-09-09

### Added

- Assistant and General Chat are separate Config modules (legacy saved `llm` still enables both)
- General Chat accepts local PNG/JPEG/WEBP on its own path: pixels and OCR stay on this tab; only text search queries go to the public web

### Changed

- version bumped to `0.13.0`

### Docs

- README, architecture and `config.example.env` match 0.13.0: independent Assistant / General Chat modules, General Chat local photos with text-only web queries, separate OCR caches
- README Requirements are grouped per module (always / Anonymize / Assistant / General Chat) with what to apt-install vs Ollama vs `./run.sh`
- README is a short landing page (purpose, modules, start); full user docs live in `docs/USER.md`

## [0.12.1] - 2026-09-09

### Added

- Assistant and General Chat show the configured `OLLAMA_MODEL` tag as muted secondary text (next to analysis-context status, and with a web-search hint in General Chat). Informational only; switching still happens at startup. The Analyze header does not show the model.

### Changed

- version bumped to `0.12.1`

### Docs

- README, architecture and `config.example.env` describe any Ollama tag via `OLLAMA_MODEL`, Assistant screenshot/OCR limits, and that the UI label is the env string rather than a Qwen-only or file-embedded name

## [0.12.0] - 2026-09-09

### Added

- Assistant accepts local PNG/JPEG/WEBP screenshots. Original pixels go to a vision-capable Ollama model; Tesseract OCR is extra local evidence and is labeled as imperfect
- Screenshots, OCR and Analyzer JSON stay in Assistant only; General Chat remains text-only and cannot receive them
- Image validation (type, size, pixels, no remote URLs); OCR cache; previous-screenshot follow-up; graceful OCR/vision absence

### Changed

- version bumped to `0.12.0`

## [0.11.23] - 2026-09-09

### Added

- General Chat search backends are configurable via `WEB_SEARCH_BACKEND` (`auto` or a comma list of ddgs text engines: Brave, DuckDuckGo, Google, Grokipedia, Mojeek, Startpage, Wikipedia, Yahoo). Default `auto` already queries that set. The reply footer lists the engines used.

### Changed

- version bumped to `0.11.23`

## [0.11.22] - 2026-09-08

### Added

- `RESPONSE_BEARER_INRESPONSETO_MISMATCH` (ERROR) when Response `InResponseTo` and bearer `SubjectConfirmationData/@InResponseTo` are both present and differ; solicited SSO requires both to name the same AuthnRequest ID (Core §3.2.2 + Profiles §4.1.4.2/§4.1.4.3), without needing the original request
- Mapping check `Response InResponseTo vs Assertion #n bearer SubjectConfirmation #k InResponseTo`
- `BEARER_INRESPONSETO_MISSING` also when the Response itself claims to be solicited (has `InResponseTo`) even if AuthnRequest was not supplied
- `BEARER_INRESPONSETO_UNSOLICITED` (ERROR) when an unsolicited Response (no Response `InResponseTo`, no AuthnRequest) still carries bearer `InResponseTo` (Profiles §4.1.4.3 / §4.1.5)

### Changed

- version bumped to `0.11.22`

## [0.11.21] - 2026-09-08

### Added

- `SESSION_NOTONORAFTER_EXPIRED` (WARNING) when AuthnStatement `SessionNotOnOrAfter` has passed. Core OS “MUST consider session ended” was loosened by Approved Errata E79; Web Browser SSO Profiles §4.1.4.3 only SHOULD discard the derived security context. Independent of `SessionIndex` syntax and of Conditions `NotOnOrAfter`.

### Changed

- version bumped to `0.11.21`

## [0.11.20] - 2026-09-08

### Fixed

- Analyze copy-to-clipboard actually copies the report; Gradio 6 ignores `launch(js=...)`, so the handler is bound on page load instead

### Changed

- version bumped to `0.11.20`

## [0.11.19] - 2026-09-08

### Added

- Analyze report window has a copy-to-clipboard control for the rendered report text

### Changed

- version bumped to `0.11.19`

## [0.11.18] - 2026-09-08

### Added

- `ENCRYPTED_ID_PRESENT` (INFO) when Subject contains `EncryptedID`; reports content/key algorithms and KeyInfo without decrypting
- `ENCRYPTED_ID_KEY_ENCRYPTION_METHOD_MISSING` and `ENCRYPTED_ID_ENCRYPTION_METHOD_MISSING` (WARNING) when EncryptionMethod is omitted (XML Encryption allows this; python3-saml `encrypted_nameID_without_EncMethod` fails)
- `ENCRYPTED_ID_KEYINFO_MISSING` (WARNING) when EncryptedData has neither KeyInfo nor EncryptedKey (XML Encryption allows this; python3-saml `encrypted_nameID_without_keyinfo` fails)

### Changed

- version bumped to `0.11.18`

## [0.11.17] - 2026-09-08

### Added

- `ENCRYPTED_ATTRIBUTE_PRESENT` (INFO) when an assertion contains `EncryptedAttribute`; reports XML Encryption content and key algorithms and does not decrypt without the SP private key

### Changed

- version bumped to `0.11.17`

## [0.11.16] - 2026-09-08

### Added

- Analyze can download each SAML document unpacked from Base64 / Redirect / DEFLATE (and tracer/HAR fields), as separate XML files named from the source file; the bytes are the raw decode, not pretty-printed or anonymized

### Changed

- version bumped to `0.11.16`

## [0.11.15] - 2026-09-08

### Fixed

- log timestamps inside brackets, two-digit years, and extra tokens after the clock (for example `[09/01/26 14:04:46 healthCheck]`) are recognized as record boundaries; `time_range` is filled only when day/month order is unambiguous
- Assistant and General Chat prompt stay in the viewport instead of sitting below a fixed 480px transcript

### Changed

- version bumped to `0.11.15`

## [0.11.14] - 2026-09-08

### Fixed

- Assistant and General Chat keep prior turns in a session; Gradio 6 history uses text blocks, which were previously dropped before the Ollama request

### Changed

- version bumped to `0.11.14`

## [0.11.13] - 2026-09-08

### Added

- `ATTRIBUTE_NAME_DUPLICATE` when the same SAML attribute identity (`Name` + `NameFormat`, defaulting omitted format to unspecified) appears more than once in an assertion; this is not forbidden in AttributeStatement (Core recommends multiple `AttributeValue` children instead). `AttributeQuery` MUST NOT repeat that pair. Same `Name` with different `NameFormat` is not a duplicate
- `ATTRIBUTE_VALUE_TYPE_MISMATCH` when `xsi:type` is set on some but not all `AttributeValue` children, or the types differ

### Changed

- version bumped to `0.11.13`

## [0.11.12] - 2026-09-08

### Changed

- independent SAML Responses (file + paste, or multiple files) each get their own report; AuthnRequest + Response + metadata stay one correlated analysis
- version bumped to `0.11.12`

## [0.11.11] - 2026-09-08

### Fixed

- Analyze no longer Base64-decodes a file and a paste as one payload, so two SAML Base64 artifacts are each detected

### Changed

- version bumped to `0.11.11`

## [0.11.10] - 2026-09-08

### Fixed

- Anonymize uses one input source (uploaded file or pasted text), not a silent concatenation of both
- Analyze Auto-detect classifies each file/paste separately so a mixed log + SAML upload is not forced into a single analyzer

### Changed

- version bumped to `0.11.10`

## [0.11.9] - 2026-09-08

### Added

- anonymizer maps customer Java packages (`com.` / `net.` that are not known vendors), Windows project roots, Spring Boot `started by` / `[AppName]` / `Starting ClassName`, and Maven artifact / `Building` names

### Changed

- domain matching uses an allowlisted TLD set so logger names like `org.springframework.boot` are not treated as hostnames
- version bumped to `0.11.9`

## [0.11.8] - 2026-09-08

### Fixed

- anonymizer no longer treats Java stack frames, logger abbreviations, `*.java`/`*.jar`/`pom.xml` or `::` as customer domains/IPs

### Changed

- version bumped to `0.11.8`

## [0.11.7] - 2026-09-08

### Added

- residual leak scan after Anonymize (leftover email / IP / token / domain / user-home matches in the summary)
- Windows/Unix user-home path and `jwt.secret=` replacements

### Changed

- version bumped to `0.11.7`

## [0.11.6] - 2026-09-08

### Changed

- log severity counts use the same attention icons as SAML findings (`❌` / `⚠️` / `ℹ️` / `🔍`)
- version bumped to `0.11.6`

## [0.11.5] - 2026-09-08

### Changed

- log incident report keeps the raw sample in a collapsible **Relevant log** block and lists each `Caused by` under it as a numbered list with a count
- version bumped to `0.11.5`

## [0.11.4] - 2026-09-08

### Changed

- log analyzer treats Java stack traces as one incident with an exception chain; Maven `[ERROR]` advisory lines stay in the same failure; the word `Error` in message text is not a severity prefix
- version bumped to `0.11.4`

## [0.11.3] - 2026-09-08

### Removed

- Assistant Mode switch (General / Support Mail / Code); one local assistant prompt covers those tasks from the user message

### Changed

- version bumped to `0.11.3`

## [0.11.2] - 2026-09-08

### Changed

- Assistant receives the latest Analyze result automatically; General Chat remains the isolated web-enabled tab
- version bumped to `0.11.2`

### Removed

- **Attach latest analysis** (redundant once Analyze already has a result)

## [0.11.1] - 2026-09-08

### Fixed

- Assistant receives an Analyze result only through explicit **Attach latest analysis** on the Assistant tab; a later Analyze does not replace an already attached case
- **Clear analysis context** and attaching a different analysis both reset Assistant chat history
- Config copy states the default UI is Analyze + Config

### Changed

- version bumped to `0.11.1`

## [0.11.0] - 2026-09-08

### Added

- optional Anonymize and LLM modules enabled from the Config tab (default UI: Analyze + Config)
- Restart application control after module changes; refresh the browser after the UI disconnects
- Assistant can receive an Analyze result; General Chat never receives that report

### Removed

- Analyze-tab chat ("Ask about this analysis")

### Changed

- version bumped to `0.11.0`

## [0.10.11] - 2026-09-07

### Fixed

- plaintext `NameID` with `Format=encrypted` is `ERROR` (`NAMEID_ENCRYPTED_FORMAT_PLAINTEXT`); EncryptedID is not interchangeable with that Format (Approved Errata E6/E15)
- explicit empty `Format=""` is an invalid URI, not unspecified omission
- empty or whitespace-only NameID content is `NAMEID_EMPTY` even when the parser would strip it
- entity NameID forbids qualifiers even when the attributes are present but empty
- persistent/transient `NameQualifier` / `SPNameQualifier` no longer `ERROR` against the current Issuer/SP entityID (original generator and affiliations are not provable from one paste)
- NameIDPolicy Format comparison uses the AuthnRequest correlated by `InResponseTo`, not the last request in the paste
- `Subject` `NameID`+`EncryptedID`/`BaseID` combinations are reported as schema `ERROR`
- quoted RFC 2822 addr-spec forms are no longer false `ERROR`s of the reduced email checker
- Windows DQN no longer rejects spaces that SAML Core does not forbid
- transient non-`xs:ID` syntax is `WARNING`, not a proven `ERROR`
- `AllowCreate="TRUE"` is rejected as invalid `xs:boolean`

### Changed

- version bumped to `0.10.11`

## [0.10.10] - 2026-09-07

### Added

- format-aware SAML NameID validation for all Core §8.3 formats, including unspecified, emailAddress, X509SubjectName, Windows DQN, Kerberos, entity, persistent, transient and custom URI formats

### Changed

- version bumped to `0.10.10`

## [0.10.9] - 2026-09-07

### Fixed

- `Destination=""` is reported as `RESPONSE_DESTINATION_EMPTY` instead of being treated as an absent optional attribute

### Changed

- version bumped to `0.10.9`

## [0.10.8] - 2026-09-07

### Fixed

- cryptographically valid legacy RSA-SHA1 / SHA-1 XML Signatures are no longer reported as `XML_SIGNATURE_INVALID`; they verify as valid and emit separate weak-algorithm warnings

### Changed

- version bumped to `0.10.8`

## [0.10.7] - 2026-09-07

### Fixed

- Auto-detect no longer treats Base64 SAML with an XML declaration as a log file

### Changed

- version bumped to `0.10.7`

## [0.10.6] - 2026-09-07

### Added

- application version is shown next to Settings in the Gradio footer

### Fixed

- desktop launcher no longer reinstalls Python packages on every start
- start script keeps the terminal open after a failure so the error is visible

### Changed

- version bumped to `0.10.6`

## [0.10.5] - 2026-09-07

### Changed

- Gradio UI, analyzer actions, markdown reports, Ollama client and web search are split into separate modules; Analyze / Anonymize behavior is unchanged
- version bumped to `0.10.5`

## [0.10.4] - 2026-09-07

### Fixed

- SAML tracer bundles and SAML XML embedded in logs are anonymized structurally even when the whole paste is not one well-formed XML document
- SAML `ID` / `InResponseTo` values in those pastes are no longer left in clear text after a failed whole-input XML parse

### Changed

- version bumped to `0.10.4`

## [0.10.3] - 2026-09-07

### Fixed

- decoded SAML is now anonymized as an XML tree instead of by generic URL/domain regexes
- standard XML, SAML and XMLDSig namespace/algorithm URIs such as `www.w3.org` are preserved
- SAML `ID`, `InResponseTo` and XMLDSig same-document `Reference URI="#..."` values are pseudonymized consistently without repairing pre-existing mismatches
- `NameID`, `AttributeValue`, endpoints, `SessionIndex` and `SubjectLocality` values are anonymized structurally
- identifying X.509 certificates embedded in SAML are replaced with parseable synthetic certificates rather than being leaked or replaced by invalid text
- `SignatureValue` and `DigestValue` are replaced in the anonymized copy because modification of signed SAML invalidates the original signature by design

### Added

- structure-aware anonymization for raw standalone SAML XML as well as Base64/Redirect payloads
- RelayState pseudonymization
- regression tests covering standard URI preservation, SAML ID/reference correlation, attributes, certificates, signature/digest values and raw/Base64 SAML

### Changed

- direct `lxml` and `cryptography` dependencies are declared explicitly because the anonymizer now parses XML safely and generates synthetic X.509 certificates
- version bumped to `0.10.3`

## [0.10.2] - 2026-09-07

### Fixed

- Base64-encoded `SAMLResponse` and `SAMLRequest` values are now decoded, anonymized as XML, and encoded again
- HTTP-Redirect SAML payloads using URL-encoded Base64 + raw DEFLATE are decompressed, anonymized, recompressed and re-encoded
- unrelated Base64 blobs are left unchanged unless they decode to recognizable SAML XML
- anonymization remains deterministic across plaintext and encoded SAML content in the same run

### Added

- encoded SAML transport diagnostics in anonymizer output
- explicit warning that anonymizing signed SAML content invalidates the original XML Signature/DigestValue
- regression coverage for standalone Base64 SAMLResponse, URL/form SAMLResponse and Redirect-binding SAMLRequest

### Changed

- version bumped to `0.10.2`

## [0.10.1] - 2026-09-07

### Added

- optional standalone X.509 signing certificate upload in the Analyze tab
- PEM and DER certificate parsing for `.pem`, `.crt` and `.cer` inputs
- cryptographic signature verification with an explicitly supplied certificate when trusted metadata is unavailable
- supplied-certificate fingerprint, subject, issuer and validity reporting
- diagnostics for supplied certificates that differ from metadata or embedded `ds:KeyInfo` certificates
- explicit rejection of bare public keys and private keys in the certificate upload path
- regression tests for standalone PEM, DER and bundled certificate verification

### Changed

- signature reports now show cryptographic verification state and the certificate fingerprint used for verification
- version bumped to `0.10.1`

## [0.10.0] - 2026-09-07

### Added

- cryptographic SAML XML Signature verification using public X.509 certificates
- signature verification against matching SP / IdP metadata signing certificates
- fallback cryptographic verification with an embedded `ds:KeyInfo` certificate, explicitly marked as untrusted when metadata is unavailable
- strict SAML Core §5.4.2 `ds:Reference` validation: exactly one Reference and `URI="#<signed-root-ID>"`
- certificate fingerprint comparison between signed messages and SAML metadata
- synthetic signature, tampering and Reference URI regression tests

### Changed

- signature presence is no longer treated as equivalent to successful verification
- version bumped to `0.10.0`

## [0.9.0] - 2026-09-07

### Added

- SAML 2.0 AuthnRequest, Response and Assertion parsing
- HTTP-POST Base64 and HTTP-Redirect DEFLATE decoding
- SP and IdP metadata parsing
- structured SAML protocol/profile validation findings
- required field and identifier validation
- Response status validation
- bearer SubjectConfirmation validation
- NameID semantic validation
- Conditions and time-window validation
- Audience, ACS, Recipient, Issuer and InResponseTo cross-checks
- metadata endpoint and signing-policy checks
- duplicate SAML ID detection
- malformed decoded XML diagnostics
- XML Signature presence and structure inspection
- generic application log analysis
- local pattern-based log anonymization
- local Assistant with general, support-mail and coding modes
- isolated web-enabled General Chat
- automated analyzer tests
