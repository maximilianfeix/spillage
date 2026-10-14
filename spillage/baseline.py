"""A baseline for CI: the secrets a repository already had when the check was turned on.

`spillage repo --write-baseline FILE` records them, `spillage repo --baseline FILE` fails only
on the ones that are not in it. A secret is known by its fingerprint, so one that was accepted
stays accepted when it moves to another file; rotating it is what makes it go away.

The file never holds a secret or a piece of one: a fingerprint, the rule, and file:line so a
reviewer can see what was accepted. It is sorted and has no dates in it, so writing it again
over an unchanged repository gives the same bytes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Iterable, List, Set, Tuple

from .models import Finding

VERSION = 1
_FINGERPRINT = re.compile(r"[0-9a-f]{12}")


def parse(text: str, name: str) -> Set[str]:
    """The fingerprints in a baseline file's text. ValueError says what is wrong with it."""
    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError(f"the baseline {name} is not valid JSON") from None
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(f"the baseline {name} has no list of findings; write it with --write-baseline")
    if data.get("version", VERSION) != VERSION:
        raise ValueError(f"the baseline {name} is version {data.get('version')!r}, this spillage reads {VERSION}")
    fps = set()
    for entry in data["findings"]:
        fp = entry.get("fingerprint") if isinstance(entry, dict) else None
        if not isinstance(fp, str) or not _FINGERPRINT.fullmatch(fp):
            raise ValueError(f"the baseline {name} has an entry without a valid fingerprint: {str(fp)[:40]!r}")
        fps.add(fp)
    return fps


def load(path: Path) -> Set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"can't read the baseline {path}: {exc.strerror or exc}") from None
    return parse(text, str(path))


def render(findings: Iterable[Finding], rel: Callable[[str], str]) -> str:
    entries = [
        {
            "fingerprint": f.fingerprint,
            "rule": f.rule_id,
            "locations": sorted(({"file": rel(loc.file), "line": loc.line} for loc in f.locations),
                                key=lambda loc: (loc["file"], loc["line"])),
        }
        for f in findings
    ]
    entries.sort(key=lambda e: e["fingerprint"])
    return json.dumps({"version": VERSION, "findings": entries}, indent=2, ensure_ascii=False) + "\n"


def write(path: Path, text: str) -> None:
    try:
        path.write_text(text, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ValueError(f"can't write the baseline {path}: {exc.strerror or exc}") from None


def split(findings: List[Finding], accepted: Set[str]) -> Tuple[List[Finding], int, int]:
    """(new findings, how many the baseline accepted, how many of its entries are gone)."""
    new = [f for f in findings if f.fingerprint not in accepted]
    seen = {f.fingerprint for f in findings}
    return new, len(seen & accepted), len(accepted - seen)
