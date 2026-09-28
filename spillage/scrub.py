"""Remove found secrets from the log files, in place.

The rules run again over each file's raw text and every match whose fingerprint is on the
list gets replaced by a marker. Working on the raw text (instead of parsing and re-dumping
JSON) means untouched bytes stay exactly as they were, and because a match never ends in the
middle of a JSON escape, every line that was valid JSON stays valid JSON. That is checked
anyway before anything is written.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import Finding, fingerprint
from .rules import Rule, get_rules
from .scanner import find_in_text
from .sources import decode_json_fragment

ACTIVE_SECONDS = 60


def marker(rule_id: str, fp: str) -> str:
    return f"[REDACTED:{rule_id}:{fp}]"


@dataclass
class ScrubReport:
    files_changed: List[str] = field(default_factory=list)
    replacements: int = 0
    skipped_active: List[str] = field(default_factory=list)
    failed: List[Tuple[str, str]] = field(default_factory=list)
    dry_run: bool = False


def plan(findings: Iterable[Finding]) -> Dict[str, Set[str]]:
    """file -> fingerprints to remove from it."""
    todo: Dict[str, Set[str]] = {}
    for f in findings:
        for loc in f.locations:
            todo.setdefault(loc.file, set()).add(f.fingerprint)
    return todo


def redact_text(text: str, targets: Set[str], rules: Sequence[Rule], is_json: bool) -> Tuple[str, int]:
    """Replace every match whose fingerprint is in `targets`. Returns (new text, count)."""
    pieces = []
    last = 0
    count = 0
    for rule, match in find_in_text(text, rules):
        secret = decode_json_fragment(match.secret) if is_json else match.secret
        fp = fingerprint(secret)
        if fp not in targets:
            continue
        pieces.append(text[last : match.start])
        pieces.append(marker(rule.id, fp))
        last = match.end
        count += 1
    pieces.append(text[last:])
    return "".join(pieces), count


def _still_valid(original: str, redacted: str, kind: str) -> bool:
    if kind == "jsonl":
        before = original.splitlines()
        after = redacted.splitlines()
        if len(before) != len(after):
            return False
        for old, new in zip(before, after):
            if old != new and old.strip():
                try:
                    json.loads(old)
                except ValueError:
                    continue  # was already broken, don't hold that against us
                try:
                    json.loads(new)
                except ValueError:
                    return False
        return True
    if kind == "json":
        try:
            json.loads(original)
        except ValueError:
            return True
        try:
            json.loads(redacted)
        except ValueError:
            return False
    return True


def read_exact(path: Path) -> Optional[str]:
    """Text with line endings untouched, so a rewrite changes nothing but the secrets."""
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            return fh.read()
    except UnicodeDecodeError:
        return None


def write_atomic(path: Path, text: str) -> None:
    """Write via a temp file in the same folder and rename, keeping mode and timestamps.

    Keeping the mtime matters: agents sort their session lists by it (`claude --resume`)."""
    st = path.stat()
    fd, tmp = tempfile.mkstemp(prefix=".spillage-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        shutil.copymode(str(path), tmp)
        os.utime(tmp, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_in_place(path: Path, text: str) -> None:
    """Overwrite the same inode instead of replacing the file.

    For files an agent may still hold open (Codex keeps its rollout file open for the whole
    session): after a rename its later writes would go to the old, unlinked file."""
    st = path.stat()
    data = text.encode("utf-8")
    with open(path, "r+b") as fh:
        fh.write(data)
        fh.truncate(len(data))
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))


def scrub_file(
    path: Path, ignore: Iterable[str] = (), rules: Optional[Sequence[Rule]] = None, in_place: bool = False
) -> int:
    """Redact every secret in one file. Used when a session ends, so no scan result needed."""
    rules = list(rules) if rules is not None else get_rules()
    text = read_exact(path)
    if not text:
        return 0
    kind = {".jsonl": "jsonl", ".json": "json"}.get(path.suffix.lower(), "text")
    is_json = kind != "text"
    skip = set(ignore)
    targets = set()
    for _, match in find_in_text(text, rules):
        fp = fingerprint(decode_json_fragment(match.secret) if is_json else match.secret)
        if fp not in skip:
            targets.add(fp)
    if not targets:
        return 0
    new, count = redact_text(text, targets, rules, is_json)
    if count and _still_valid(text, new, kind):
        (write_in_place if in_place else write_atomic)(path, new)
        return count
    return 0


def scrub(
    findings: Sequence[Finding],
    rules: Optional[Sequence[Rule]] = None,
    only: Optional[Iterable[str]] = None,
    dry_run: bool = False,
    include_active: bool = False,
    now: Optional[float] = None,
) -> ScrubReport:
    rules = list(rules) if rules is not None else get_rules()
    wanted = set(only) if only else None
    targets = [f for f in findings if wanted is None or f.fingerprint in wanted]
    report = ScrubReport(dry_run=dry_run)
    now = time.time() if now is None else now
    for file, fps in sorted(plan(targets).items()):
        path = Path(file)
        if path.suffix == ".vscdb":
            report.failed.append((file, "Cursor's database can't be scrubbed yet, delete the chat in Cursor instead"))
            continue
        try:
            if not include_active and now - path.stat().st_mtime < ACTIVE_SECONDS:
                report.skipped_active.append(file)
                continue
            text = read_exact(path)
        except OSError as exc:
            report.failed.append((file, str(exc)))
            continue
        if text is None:
            report.failed.append((file, "could not read it as text"))
            continue
        kind = {".jsonl": "jsonl", ".json": "json"}.get(path.suffix.lower(), "text")
        new, count = redact_text(text, fps, rules, kind != "text")
        if not count:
            continue
        if not _still_valid(text, new, kind):
            report.failed.append((file, "redacting would have broken the JSON, left it alone"))
            continue
        report.replacements += count
        report.files_changed.append(file)
        if not dry_run:
            try:
                write_atomic(path, new)
            except OSError as exc:
                report.failed.append((file, str(exc)))
                report.files_changed.pop()
                report.replacements -= count
    return report

