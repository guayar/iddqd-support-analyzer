from __future__ import annotations

import tempfile
from pathlib import Path

from actions import anonymize
from uploads import InputError, read_text_file_and_paste, should_clear_file_for_paste, should_clear_paste_for_file


def _file(content: str, name: str = "error.txt") -> str:
    path = Path(tempfile.mkdtemp()) / name
    path.write_text(content, encoding="utf-8")
    return str(path)


PASTE = "pasted-only 10.9.8.7 leftover"
FILE_BODY = "file-only 1.1.1.1 leftover"


# 1. file only
file_only = _file(FILE_BODY)
text, filename = read_text_file_and_paste(file_only, None)
assert filename == "error.txt"
assert "1.1.1.1" in text
assert "10.9.8.7" not in text
md, out, _mapping, _path = anonymize(file_only, "")
assert "1.1.1.1" not in out
assert "IP_" in out

# 2. pasted text only
text, filename = read_text_file_and_paste(None, PASTE)
assert filename is None
assert "10.9.8.7" in text
md, out, _mapping, _path = anonymize(None, PASTE)
assert "10.9.8.7" not in out

# 3. paste then file — UI clears paste when a file is chosen
assert should_clear_paste_for_file(file_only) is True
assert should_clear_file_for_paste("") is False
text, filename = read_text_file_and_paste(file_only, "")
assert "1.1.1.1" in text
assert "10.9.8.7" not in text

# 4. file then paste — UI clears file when paste is non-empty
assert should_clear_file_for_paste(PASTE) is True
assert should_clear_paste_for_file(None) is False
text, filename = read_text_file_and_paste(None, PASTE)
assert "10.9.8.7" in text
assert "1.1.1.1" not in text

# 5. both unexpectedly supplied to backend
both_failed = False
try:
    read_text_file_and_paste(file_only, PASTE)
except InputError as e:
    both_failed = True
    assert "not both" in str(e)
assert both_failed
anon_both_failed = False
try:
    anonymize(file_only, PASTE)
except InputError:
    anon_both_failed = True
assert anon_both_failed

# 6. no input
empty_failed = False
try:
    anonymize(None, "   ")
except InputError:
    empty_failed = True
assert empty_failed

print("ANONYMIZE SOURCE TESTS OK")
