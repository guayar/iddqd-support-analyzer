#!/usr/bin/env python3
"""Fetch pinned third-party regression files into testdata/external (gitignored)."""
from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from regression_manifest import (  # noqa: E402
    MAX_DOWNLOAD_BYTES,
    ROOT,
    destination_for,
    github_raw_url,
    iter_sources,
    load_manifest,
)

UA = "iddqd-support-analyzer-regression-fetch/0.15"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Network error fetching {url}: {exc.reason}") from exc
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise SystemExit(f"Refusing download larger than {MAX_DOWNLOAD_BYTES} bytes: {url}")
    return data


def fetch_one(source_id: str, source: dict, entry: dict, force: bool) -> str:
    upstream_path = entry["upstream_path"]
    dest = destination_for(source_id, source, upstream_path)
    url = github_raw_url(source["github_repo"], source["source_commit"], upstream_path)
    expected = entry.get("sha256")
    print(f"  {source['name']}")
    print(f"    upstream: {source['upstream_repository']}")
    print(f"    commit:   {source['source_commit']}")
    print(f"    path:     {upstream_path}")
    print(f"    license:  {source.get('license_name') or source.get('license')}")
    print(f"    url:      {url}")
    print(f"    dest:     {dest.relative_to(ROOT)}")
    if dest.exists() and not force:
        local = dest.read_bytes()
        digest = sha256_bytes(local)
        if expected and digest != expected:
            raise SystemExit(
                f"Local file {dest} SHA-256 {digest} does not match manifest {expected}. "
                "Refusing to replace. Pass --force to overwrite."
            )
        print(f"    skip:     exists (sha256={digest})")
        return "skipped"
    data = download(url)
    digest = sha256_bytes(data)
    if expected and digest != expected:
        raise SystemExit(f"Downloaded {url} SHA-256 {digest} does not match manifest {expected}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    print(f"    wrote:    {len(data)} bytes sha256={digest}")
    return "fetched"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", help="Fetch only this source id (e.g. loghub, python3-saml)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing local files")
    parser.add_argument("--list", action="store_true", help="List configured sources and files")
    args = parser.parse_args(argv)
    manifest = load_manifest()
    pairs = iter_sources(manifest, args.source)
    if args.list:
        for source_id, source in pairs:
            print(f"{source_id}: {source['name']} @ {source['source_commit']}")
            for entry in source["files"]:
                print(f"  {entry['upstream_path']}")
        return 0
    print("External corpora stay under testdata/external and are not part of the IDDQD tree.")
    print("They are not required to run the analyzer.\n")
    for source_id, source in pairs:
        print(f"== {source_id} ==")
        for entry in source["files"]:
            fetch_one(source_id, source, entry, args.force)
            print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
