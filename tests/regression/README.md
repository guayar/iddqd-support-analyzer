# Regression corpora and IDDQD expectations

This directory holds **IDDQD-authored** expectation files. It does not contain
Loghub or python3-saml source data.

| Path | Authorship |
|---|---|
| `tests/regression/expectations/` | IDDQD (invariants we review) |
| `tests/fixtures/` | IDDQD minimized cases, when we add them |
| `testdata/external/` | third-party files fetched locally, gitignored |

External files are named as upstream names them (`OpenSSH_2k.log`, `authn_request.xml`).
Do not rename them as if IDDQD wrote them.

Fetch (optional, not required to run the analyzer or unit tests):

```bash
python scripts/fetch_regression_data.py
python scripts/fetch_regression_data.py --source loghub
python scripts/fetch_regression_data.py --source python3-saml
python scripts/run_regression_corpus.py
```

Provenance, licenses, and pinned commits: [docs/THIRD_PARTY_TEST_DATA.md](../../docs/THIRD_PARTY_TEST_DATA.md) and [third_party_testdata.yml](../../third_party_testdata.yml).
