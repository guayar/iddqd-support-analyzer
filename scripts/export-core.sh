#!/usr/bin/env bash
# Build a no-LLM tree (Analyze + Anonymize) as dist/iddqd-support-analyzer-light-$VERSION.zip
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
NAME="iddqd-support-analyzer-light-${VERSION}"
DEST="$ROOT/dist/${NAME}"
ZIP="$ROOT/dist/${NAME}.zip"

rm -rf "$DEST"
mkdir -p "$DEST"

should_skip() {
  local rel="${1#"$ROOT"/}"
  case "$rel" in
    .git|.git/*|.venv|.venv/*|.env|dist|dist/*|testdata|testdata/*) return 0 ;;
    __pycache__|*/__pycache__|*.pyc) return 0 ;;
    .iddqd-modules.json|docs/assets|docs/assets/*) return 0 ;;
    chats.py|llm.py|vision.py|websearch.py) return 0 ;;
    tests/test_assistant_handoff.py|tests/test_chat_history.py|tests/test_vision.py|tests/test_llm.py|tests/test_layers.py) return 0 ;;
    scripts/record_readme_gifs.py) return 0 ;;
  esac
  return 1
}

while IFS= read -r -d '' path; do
  rel="${path#"$ROOT"/}"
  if should_skip "$path"; then
    continue
  fi
  if [[ -d "$path" ]]; then
    mkdir -p "$DEST/$rel"
  else
    mkdir -p "$DEST/$(dirname "$rel")"
    cp -a "$path" "$DEST/$rel"
  fi
done < <(find "$ROOT" -mindepth 1 \( \
    -name .git -o -name .venv -o -name dist -o -name testdata -o -name __pycache__ -o -path "$ROOT/docs/assets" \
  \) -prune -o -print0)

printf 'light\n' > "$DEST/LIGHT_EDITION"

rm -f "$ZIP"
(cd "$ROOT/dist" && zip -qr "$NAME.zip" "$NAME")
rm -rf "$DEST"
echo "$ZIP"
