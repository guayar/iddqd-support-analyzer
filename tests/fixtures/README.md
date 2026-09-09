# IDDQD-authored fixtures

Minimized cases we write ourselves for unit/regression tests. They are not copies
of Loghub or python3-saml corpora.

If a third-party sample exposes a bug, add a short synthetic fixture here and
record provenance in a comment or in `docs/THIRD_PARTY_TEST_DATA.md`. Do not
paste large upstream chunks.

Existing analyzer tests mostly embed synthetic snippets in `tests/test_*.py`.
That remains valid.
