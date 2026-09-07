# Changelog

All notable changes to this project are documented here.

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
