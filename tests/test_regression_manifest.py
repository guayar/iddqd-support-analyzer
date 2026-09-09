from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from regression_manifest import iter_sources, load_manifest  # noqa: E402


def test_manifest_sources_and_pins():
    data = load_manifest()
    assert data["version"] == 1
    sources = dict(iter_sources(data))
    assert set(sources) == {"loghub", "python3-saml"}
    loghub = sources["loghub"]
    assert loghub["github_repo"] == "logpai/loghub"
    assert loghub["source_commit"] == "dd61d0952749ee7963bde24220d1be5ede023033"
    assert loghub["license_spdx"] == "NOASSERTION"
    assert loghub["redistribution_policy"] == "local-only"
    assert any(f["upstream_path"] == "OpenSSH/OpenSSH_2k.log" for f in loghub["files"])
    saml = sources["python3-saml"]
    assert saml["license_spdx"] == "MIT"
    assert saml["source_commit"] == "52d2ac8da3f35262755f6e1c32ba7c62a6011fe1"
    paths = {f["upstream_path"] for f in saml["files"]}
    assert "LICENSE" in paths
    assert "tests/data/requests/authn_request.xml" in paths
    assert not any("tests/certs" in p for p in paths)
    assert not any(p.endswith(".key") for p in paths)


def test_fetch_list_and_runner_without_corpus():
    listed = subprocess.check_output(
        [sys.executable, str(ROOT / "scripts" / "fetch_regression_data.py"), "--list"],
        cwd=ROOT,
        text=True,
    )
    assert "loghub:" in listed
    assert "python3-saml:" in listed
    assert "OpenSSH/OpenSSH_2k.log" in listed
    rc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_regression_corpus.py")],
        cwd=ROOT,
        check=False,
    )
    assert rc.returncode == 0


if __name__ == "__main__":
    test_manifest_sources_and_pins()
    test_fetch_list_and_runner_without_corpus()
    print("REGRESSION MANIFEST TESTS OK")
