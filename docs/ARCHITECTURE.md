# Architecture

## Design goal

The core Analyzer is deterministic first. Protocol parsing, required-field checks, identifier comparisons, timestamps, endpoint mappings and validation findings are produced by code rather than delegated to the language model.

```text
Input
  │
  ├─ SAML / metadata ──> decode ──> XML parse ──> extract ──> validate ──> report
  │
  ├─ *.log ───────> parse ──> group errors / codes / stacks ─────────> report
  │
  └─ log anonymizer ──> deterministic pseudonymization ───────────────────> output

Optional local model
  └─ consumes deterministic analyzer output for explanation/report drafting

General Chat
  └─ separate path with explicit public web search
```

## Security boundaries

- Analyzer and Assistant do not invoke web search.
- General Chat does not inherit Analyzer or Assistant context.
- Model endpoints are restricted to loopback by default.
- `.env`, local logs, generated mappings and credential material are excluded from version control.
- The anonymizer is pattern-based and should not be treated as a certified DLP control.

## SAML validation model

Validation is separated into three layers:

1. **Transport decoding** — raw XML, Base64, URL encoding and Redirect-binding DEFLATE.
2. **Document and protocol structure** — well-formed XML, document type, required fields and profile rules.
3. **Cross-document consistency** — comparisons between Request, Response, Assertion and supplied SP/IdP metadata.

Signature verification is currently limited to presence and XML Signature structure checks. Cryptographic trust validation is planned separately.
