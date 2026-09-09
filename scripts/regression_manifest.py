from __future__ import annotations

from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "third_party_testdata.yml"
EXTERNAL_ROOT = ROOT / "testdata" / "external"
MAX_DOWNLOAD_BYTES = 8 * 1024 * 1024


def load_simple_yaml(text: str) -> Any:
    """Load a restricted YAML subset: maps, lists, scalars, comments. No tags or anchors."""
    lines = text.splitlines()
    idx = 0

    def skip_empty() -> None:
        nonlocal idx
        while idx < len(lines):
            raw = lines[idx]
            stripped = raw.split("#", 1)[0].rstrip()
            if stripped.strip():
                return
            idx += 1

    def indent_of(i: int) -> int:
        line = lines[i]
        return len(line) - len(line.lstrip(" "))

    def parse_scalar(raw: str) -> Any:
        raw = raw.strip()
        if raw in {"", "~", "null", "Null", "NULL"}:
            return None
        if raw in {"true", "True", "TRUE"}:
            return True
        if raw in {"false", "False", "FALSE"}:
            return False
        if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
            return raw[1:-1]
        try:
            if raw.startswith("0") and raw != "0" and not raw.startswith("0."):
                return raw
            if "." in raw:
                return float(raw)
            return int(raw)
        except ValueError:
            return raw

    def parse_block(min_indent: int) -> Any:
        nonlocal idx
        skip_empty()
        if idx >= len(lines):
            return {}
        first = lines[idx].split("#", 1)[0].rstrip()
        if not first.strip():
            return {}
        if first.lstrip().startswith("- "):
            return parse_list(min_indent)
        return parse_map(min_indent)

    def parse_list(min_indent: int) -> list[Any]:
        nonlocal idx
        out: list[Any] = []
        while idx < len(lines):
            skip_empty()
            if idx >= len(lines):
                break
            ind = indent_of(idx)
            if ind < min_indent:
                break
            body = lines[idx].split("#", 1)[0].rstrip()
            if not body.lstrip().startswith("- "):
                break
            item = body.lstrip()[2:]
            idx += 1
            if item.endswith(":") or (":" in item and not item.startswith("{")):
                key, _, rest = item.partition(":")
                mapping: dict[str, Any] = {}
                rest = rest.strip()
                if rest:
                    mapping[key.strip()] = parse_scalar(rest)
                skip_empty()
                if idx < len(lines) and indent_of(idx) > ind:
                    nested = parse_block(ind + 1)
                    if isinstance(nested, dict):
                        mapping.update(nested)
                    else:
                        mapping[key.strip()] = nested
                elif not rest and item.endswith(":"):
                    skip_empty()
                    if idx < len(lines) and indent_of(idx) > ind:
                        mapping[key.strip()] = parse_block(ind + 1)
                out.append(mapping)
            elif item == "" or item.endswith(":"):
                skip_empty()
                out.append(parse_block(ind + 1) if idx < len(lines) and indent_of(idx) > ind else {})
            else:
                out.append(parse_scalar(item))
        return out

    def parse_map(min_indent: int) -> dict[str, Any]:
        nonlocal idx
        out: dict[str, Any] = {}
        while idx < len(lines):
            skip_empty()
            if idx >= len(lines):
                break
            ind = indent_of(idx)
            if ind < min_indent:
                break
            body = lines[idx].split("#", 1)[0].rstrip()
            if body.lstrip().startswith("- "):
                break
            if ":" not in body:
                raise ValueError(f"YAML parse error at line {idx + 1}: {lines[idx]!r}")
            key, _, rest = body.lstrip().partition(":")
            key = key.strip()
            if (key.startswith('"') and key.endswith('"')) or (key.startswith("'") and key.endswith("'")):
                key = key[1:-1]
            rest = rest.strip()
            idx += 1
            if rest:
                out[key] = parse_scalar(rest)
                continue
            skip_empty()
            if idx >= len(lines) or indent_of(idx) <= ind:
                out[key] = {}
                continue
            out[key] = parse_block(ind + 1)
        return out

    result = parse_block(0)
    skip_empty()
    if idx < len(lines):
        leftover = lines[idx].split("#", 1)[0].strip()
        if leftover:
            raise ValueError(f"YAML parse error: leftover at line {idx + 1}")
    return result


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    p = path or MANIFEST_PATH
    data = load_simple_yaml(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "sources" not in data:
        raise ValueError(f"{p} must contain a top-level 'sources' mapping")
    return data


def iter_sources(manifest: dict[str, Any], only: str | None = None) -> list[tuple[str, dict[str, Any]]]:
    sources = manifest["sources"]
    if not isinstance(sources, dict):
        raise ValueError("sources must be a mapping")
    items = list(sources.items())
    if only:
        if only not in sources:
            known = ", ".join(sorted(sources))
            raise SystemExit(f"Unknown source {only!r}. Configured: {known}")
        return [(only, sources[only])]
    return items


def github_raw_url(repo: str, commit: str, upstream_path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{commit}/{upstream_path.lstrip('/')}"


def destination_for(source_id: str, source: dict[str, Any], upstream_path: str) -> Path:
    dest_root = ROOT / str(source["local_destination"])
    dest = (dest_root / upstream_path).resolve()
    external = EXTERNAL_ROOT.resolve()
    if external not in dest.parents and dest != external:
        raise ValueError(f"Refusing path outside testdata/external: {dest}")
    expected_prefix = (external / source_id).resolve()
    if expected_prefix not in dest.parents and dest != expected_prefix:
        raise ValueError(f"Refusing path outside {expected_prefix}: {dest}")
    return dest
