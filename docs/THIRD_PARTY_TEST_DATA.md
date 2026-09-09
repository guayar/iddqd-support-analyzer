# Third-party test data

IDDQD uses selected **public** third-party files as interoperability and regression
input. Those files are not authored by IDDQD. Upstream projects remain the source
of truth. External corpora are fetched onto a developer machine and are **not**
shipped in the IDDQD git tree.

The deterministic analyzers (and IDDQD-authored expectation files) are developed
against that input. Minimized fixtures under `tests/fixtures/` are separate and
are written by IDDQD.

Machine-readable pins: [`third_party_testdata.yml`](../third_party_testdata.yml).

```bash
python scripts/fetch_regression_data.py
python scripts/run_regression_corpus.py
```

Normal use of the Analyze UI does not require these files.

External fixtures are never mixed with user-uploaded production traces. Do not
commit customer logs, real SAML assertions, tokens, cookies, or production keys.

## Loghub

| | |
|---|---|
| Project | [Loghub](https://github.com/logpai/loghub) |
| Upstream | `logpai/loghub` |
| Pinned commit | `dd61d0952749ee7963bde24220d1be5ede023033` (2026-09-09) |
| Purpose in IDDQD | Heterogeneous log samples (starting with OpenSSH, Apache, Linux 2k-line GitHub copies) |
| License / terms | Custom dataset terms, **not** MIT/Apache/CC. GitHub SPDX: `NOASSERTION`. The upstream LICENSE (same commit) says the datasets are freely available for **research or academic work**; copies must include that notice; usage or distribution should refer to https://github.com/logpai/loghub and cite the ISSRE 2023 Loghub paper where applicable. |
| What IDDQD downloads | `LICENSE`, `CITATION`, selected `*_2k.log` files and their upstream READMEs. Not Zenodo full archives (tens of GB). |
| In git? | No. Local only under `testdata/external/loghub/`. |

`SoftManiaTech/sample_log_files` is a GitHub **fork** of `logpai/loghub` (parent confirmed via the GitHub API). IDDQD does not fetch that fork; it would duplicate the same datasets.

## python3-saml

| | |
|---|---|
| Project | [python3-saml](https://github.com/SAML-Toolkits/python3-saml) |
| Upstream | `SAML-Toolkits/python3-saml` |
| Pinned commit | `52d2ac8da3f35262755f6e1c32ba7c62a6011fe1` (2026-09-09) |
| Purpose in IDDQD | AuthnRequest, Response, invalid, and metadata XML/Base64 for parser/regression |
| License / terms | **MIT**. Copyright (c) 2010-2022 OneLogin, Inc.; Copyright (c) 2023 IAM Digital Services, SL. License text: [LICENSE](https://github.com/SAML-Toolkits/python3-saml/blob/52d2ac8da3f35262755f6e1c32ba7c62a6011fe1/LICENSE). |
| What IDDQD downloads | Upstream `LICENSE` plus a small explicit list of files under `tests/data/` (requests, one unsigned response, one invalid Base64 fixture, IdP metadata). **Not** `tests/certs` and **not** private keys. |
| In git? | No. Local only under `testdata/external/python3-saml/`. |

If a subset is ever vendored into this repository, the MIT copyright and permission notice must stay with those files. That is not the default.

## IDDQD-authored files (committed)

- `third_party_testdata.yml` — pins and fetch list
- `tests/regression/expectations/` — invariants we review (not golden dumps of analyzer JSON)
- `tests/fixtures/` — minimized synthetic cases we write
- `scripts/fetch_regression_data.py`, `scripts/run_regression_corpus.py`

Expectation files name the upstream path. They do not claim IDDQD wrote the input.

Updating a pin is an explicit corpus-version change: new commit SHA in the manifest, then re-fetch with `--force` after reviewing diffs.
