"""Prints one version's section of CHANGELOG.md: `python .github/release_notes.py 0.7.0`."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def notes(changelog: str, version: str) -> str:
    match = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", changelog, re.S | re.M)
    if not match:
        raise SystemExit(f"no section for {version} in CHANGELOG.md")
    return match.group(1).strip() + "\n"


if __name__ == "__main__":
    text = Path(__file__).resolve().parent.parent.joinpath("CHANGELOG.md").read_text(encoding="utf-8")
    sys.stdout.write(notes(text, sys.argv[1]))
