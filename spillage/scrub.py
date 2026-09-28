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
from .sources import Source, decode_json_fragment, get_source, read_text_exact

ACTIVE_SECONDS = 60


def marker(rule_id: str, fp: str) -> str:
    return f"[REDACTED:{rule_id}:{fp}]"


@dataclass
class ScrubReport:
    files_changed: List[str] = field(default_factory=list)
    replacements: int = 0
    signed: int = 0  # left inside signed thinking blocks, see redact_text
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


def redact_text(
    text: str, targets: Set[str], rules: Sequence[Rule], is_json: bool, doc=None, stats: Optional[dict] = None
) -> Tuple[str, int]:
    """Replace every match whose fingerprint is in `targets`. Returns (new text, count).

    With a Document, matches the scan ignored (inside base64 blobs) are left alone too, and so
    is text in a signed thinking block: the API checks those signatures on `--resume`, so an
    edited block would break the session. Those are counted in stats["signed"]."""
    pieces = []
    last = 0
    count = 0
    for rule, match in find_in_text(text, rules):
        secret = decode_json_fragment(match.secret) if is_json else match.secret
        fp = fingerprint(secret)
        if fp not in targets:
            continue
        if doc is not None:
            location = doc.locate(match.start, secret)
            if location is None:
                continue
            if _in_signed_block(location.json_path):
                if stats is not None:
                    stats["signed"] = stats.get("signed", 0) + 1
                continue
        pieces.append(text[last : match.start])
        pieces.append(marker(rule.id, fp))
        last = match.end
        count += 1
    pieces.append(text[last:])
    return "".join(pieces), count


def _in_signed_block(json_path: str) -> bool:
    return json_path.endswith(".thinking") or ".thinking[" in json_path or json_path.endswith(".redacted_thinking")


def _still_valid(original: str, redacted: str, kind: str) -> bool:
    if kind == "jsonl":
        # split on \n only: str.splitlines() also breaks on U+2028, which JSON may hold raw
        before = original.split("\n")
        after = redacted.split("\n")
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
    """The same text the scanner saw, so a rewrite changes nothing but the secrets."""
    return read_text_exact(path)


def _encode(text: str) -> bytes:
    return text.encode("utf-8", errors="surrogateescape")


def write_atomic(path: Path, text: str) -> None:
    """Write via a temp file in the same folder and rename, keeping mode and timestamps.

    Keeping the mtime matters: agents sort their session lists by it (`claude --resume`)."""
    path = path.resolve()  # a symlink: rewrite what it points to, keep the link
    st = path.stat()
    fd, tmp = tempfile.mkstemp(prefix=".spillage-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(_encode(text))
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
    path = path.resolve()
    st = path.stat()
    data = _encode(text)
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
    new, count = redact_text(text, targets, rules, is_json, doc=Source().document(path, text))
    if count and _still_valid(text, new, kind):
        (write_in_place if in_place else write_atomic)(path, new)
        return count
    return 0


def _source_for(agent: str) -> Source:
    """The adapter that produced a finding, so the file is read the same way again."""
    try:
        return get_source(agent)()
    except ValueError:
        return Source()


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
    agents = {loc.file: loc.agent for f in targets for loc in f.locations}
    for file, fps in sorted(plan(targets).items()):
        path = Path(file)
        if path.suffix in (".vscdb", ".db"):
            report.failed.append((file, "can't scrub a database yet, delete the chat in the agent instead"))
            continue
        try:
            before = path.stat()
            if not include_active and now - before.st_mtime < ACTIVE_SECONDS:
                report.skipped_active.append(file)
                continue
        except OSError as exc:
            report.failed.append((file, str(exc)))
            continue
        text = read_exact(path)
        if text is None:
            report.failed.append((file, "could not read it as text"))
            continue
        source = _source_for(agents.get(file, ""))
        doc = source.document(path, text)
        stats: dict = {}
        new, count = redact_text(text, fps, rules, doc.is_json, doc=doc, stats=stats)
        report.signed += stats.get("signed", 0)
        if not count:
            if not stats.get("signed"):
                report.failed.append((file, "didn't find it again; did the file change since the scan?"))
            continue
        if not _still_valid(text, new, doc.kind):
            report.failed.append((file, "redacting would have broken the JSON, left it alone"))
            continue
        if dry_run:
            report.replacements += count
            report.files_changed.append(file)
            continue
        try:
            now_st = path.stat()
            if (now_st.st_size, now_st.st_mtime_ns) != (before.st_size, before.st_mtime_ns):
                report.failed.append((file, "it changed while being scrubbed, run scrub again"))
                continue
            write_atomic(path, new)
        except OSError as exc:
            report.failed.append((file, str(exc)))
            continue
        report.replacements += count
        report.files_changed.append(file)
    return report

