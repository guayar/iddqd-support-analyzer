# Changelog

All notable changes to this project are documented here.

## [0.11.1] - 2026-09-08

### Fixed

- Assistant receives an Analyze result only through explicit **Open in Assistant**; a later Analyze does not replace an already attached case
- **Clear analysis context** and attaching a different analysis both reset Assistant chat history
- Config copy states the default UI is Analyze + Config

### Changed

- version bumped to `0.11.1`

## [0.11.0] - 2026-09-08

### Added

- optional Anonymize and LLM modules enabled from the Config tab (default UI: Analyze + Config)
- Restart application control after module changes; refresh the browser after the UI disconnects
- Assistant can receive an Analyze result through Open in Assistant; General Chat never receives that report

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
