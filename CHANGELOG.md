# Changelog

All notable changes to this project are documented here.

Version numbering: **MAJOR.MINOR.PATCH** (Semantic Versioning)
- MAJOR: Breaking API changes
- MINOR: New features, improvements
- PATCH: Bug fixes, performance tweaks

---

## [0.22.0] - 2026-10-03

### ⚠️ Status: EARLY STAGE (EXPERIMENTAL)

Root Cause Analysis and Multi-File correlation features added, but marked experimental. See [EXPERIMENTAL_FEATURES.md](EXPERIMENTAL_FEATURES.md) for important limitations and terminology.

### Added

- **Experimental Root Cause Hints** (`analyzers/root_cause.py`)
  - Detects temporal + pattern-based causality chains
  - NOT proven root cause, only investigation hints
  - Supports 10+ known patterns (deadlock → connection exhaustion, etc.)
  - Pattern match strength scored 0.0-1.0 (heuristic, not probability)

- **Multi-File Correlation** (`analyzers/multi_file_analyzer.py`)
  - Analyzes related log files together (PostgreSQL + Nginx + Docker)
  - Correlation strength: WEAK / MODERATE / STRONG
  - Cross-analyzer cascade detection with time deltas
  - Only when real timestamps allow cross-file comparison

- **Analyze Export Formats** (JSON, Markdown, CSV)
  - `export_analysis_as_json()` - Complete analysis with schema versioning
  - `export_analysis_as_markdown()` - Human-readable report
  - `export_analysis_as_csv()` - Finding rows for Excel/spreadsheets
  - Stable JSON schema with version header

- **Docker Light Edition** (new `docker-light-edition` branch)
  - Container-based deployment for Light Edition
  - Dockerfile + docker-compose.yml + volume mapping
  - No Python installation required on end system

### Changed

- version bumped to `0.22.0`
- Terminology: "confidence" in RCA renamed to "pattern_match_strength" to avoid implying statistical probability (See EXPERIMENTAL_FEATURES.md)
- Analyze reports now include time ranges for all inputs at a glance

### Known Issues / Limitations

- EncryptedAssertion decryption still not implemented
- RCA patterns are heuristic only; manual verification required
- Docker support for Light Edition only (Full Edition remains local install)

### Tests

- 362 total tests passing (317 original + 45 new export tests)
- New: test_analyze_export_json.py, test_analyze_export_markdown.py, test_analyze_export_csv.py
- All tests in Light Edition pass without LLM dependencies

---

## [0.21.0] - 2026-10-03

### ⚠️ Status: EARLY STAGE

Configuration system and enhanced export capabilities added.

### Added

- **Configuration System** (`analyzers/config.py`)
  - Custom pattern injection without code changes
  - Per-analyzer time windows for correlation
  - Config file loading/saving

- **Finding Deduplication** (`analyzers/deduplication.py`)
  - Automatic grouping of related findings
  - Reduces alert fatigue
  - Preserves root cause traceability

- **Base Class Refactor** - Common analyzer patterns extracted
  - BaseCorrelator parent class reduces boilerplate
  - Consistent finding assembly across analyzers

### Changed

- version bumped to `0.21.0`
- Analyzer implementations use shared base patterns

### Tests

- 22 new tests for config, deduplication, base class

---

## [0.20.0] - 2026-01-15

### Status: PRODUCTION READY (at the time)

⚠️ *Note: This release was marked "production ready" in Jan 2026. Current project is early-stage (Oct 2026).*

Complete set of 20 log analyzer families with deterministic core.

### Added

- 20 complete log analyzer families (SSH, Nginx, PostgreSQL, Docker, etc.)
- Full SAML/SSO analysis (AuthnRequest, Response, Assertion, metadata)
- Knowledge Base with SQLite + FTS5
- Anonymization module
- Optional Assistant (Ollama local)
- Optional General Chat (with optional web search)
- Light Edition (SAML + Log + Anonymize + KB, no LLM)

### Tests

- 180+ unit + integration tests, 100% passing
- All 20 analyzers covered

### Documentation

- API.md - LogFamily protocol
- ARCHITECTURE.md - System design
- EXTENDING.md - How to add analyzers
- EXAMPLES.md - Real-world scenarios
- USER.md - User guide

---

## [0.19.3] - 2026-09-24

### Fixed

- Assistant screenshot + Analyze context no longer hard-fails with `LLM unavailable: 400`: Ollama vision requests fall back to OCR text when the image payload is rejected, screenshots are downscaled for the model, and Analyze source text is kept smaller on image turns

### Changed

- version bumped to `0.19.3`

---

## [0.19.2] - 2026-09-24

### Fixed

- Assistant Analyze context now includes every uploaded source file and the pasted text, not only a truncated single-file slice of the analyzer JSON. General Chat still receives none of that material

### Changed

- version bumped to `0.19.2`

---

## [0.19.1] - 2026-09-24

### Added

- SAML report shows observed time range and assertion Conditions validity window in UTC, so ACS traces can be compared with log windows
- Log `time_range` keeps timezone when ISO stamps include `Z` or an offset (`UTC`, `+02:00`, or `mixed`); naive stamps note that timezone was not in the source
- Analyze report opens with **Time ranges at a glance**: every log file (and SAML) listed with its date range before the detailed sections

### Changed

- version bumped to `0.19.1`

---

## [0.19.0] - 2026-09-24

### Fixed

- SAML incident traces no longer treat Conditions / bearer expiry against analyzer runtime as ERROR when an ACS POST Date (or request timestamp) shows the assertion was still valid at the SP
- SAML-tracer JSON ACS POST rows now populate Response HTTP method, HTTP-POST binding, and Response POST target in the transport report

### Changed

- Timing splits `incident_trace_mode` (validate at observed ACS event time) from `replay_now_mode` (raw XML / paste evaluated at analyzer UTC). Missing event time on a tracer downgrades timing to INFO, not ERROR
- Embedded-certificate crypto result renamed to `XML_SIGNATURE_VALID_WITH_EMBEDDED_CERT` to avoid implying partner trust; `SIGNER_TRUST_NOT_EVALUATED` remains the trust gap signal
- version bumped to `0.19.0`

---

## Earlier Versions

See git history for v0.18 and earlier releases.

---

## How to Read This Changelog

- **Status line** at each major release indicates maturity level
- **Added** = new features or capabilities
- **Changed** = modifications to existing behavior
- **Fixed** = bug fixes
- **⚠️ EXPERIMENTAL** features are documented in [EXPERIMENTAL_FEATURES.md](EXPERIMENTAL_FEATURES.md) and require manual verification
- **Early-stage** project status is declared in [README.md](README.md)
