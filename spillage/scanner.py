"""The scan pipeline: sources -> files -> rules -> deduplicated findings.

Files are independent, so big scans fan out over a process pool. Each worker returns plain
tuples and the parent merges them into one Finding per distinct secret.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import Finding, Location, Severity, fingerprint
from .rules import Match, Rule, get_rules
from .sources import Source

ProgressFn = Callable[[int, int, str], None]  # jobs done, jobs total, current agent

# Below this many bytes a process pool costs more than it saves.
PARALLEL_THRESHOLD = 24 * 1024 * 1024
# JSONL files bigger than this are cut into parts (at line breaks) that run on different cores.
SPLIT_BYTES = 8 * 1024 * 1024


@dataclass
class ScanStats:
    files: int = 0
    bytes: int = 0
    seconds: float = 0.0
    per_agent: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    ignored: int = 0


@dataclass
class ScanResult:
    findings: List[Finding]
    stats: ScanStats

    def by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def worst(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict:
        from . import __version__

        return {
            "version": __version__,
            "summary": {
                "findings": len(self.findings),
                "critical": len(self.by_severity(Severity.CRITICAL)),
                "high": len(self.by_severity(Severity.HIGH)),
                "medium": len(self.by_severity(Severity.MEDIUM)),
                "low": len(self.by_severity(Severity.LOW)),
                "files": self.stats.files,
                "bytes": self.stats.bytes,
                "seconds": round(self.stats.seconds, 3),
                "ignored": self.stats.ignored,
                "agents": self.stats.per_agent,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


def find_in_text(text: str, rules: Sequence[Rule]) -> List[Tuple[Rule, Match]]:
    """(rule, match) pairs for one string, in text order. Where two rules claim overlapping
    text the one listed first wins, so specific rules beat the generic one."""
    taken: List[Tuple[int, int]] = []
    hits = []
    for rule in rules:
        for match in rule.find(text):
            if any(match.start < end and start < match.end for start, end in taken):
                continue
            taken.append((match.start, match.end))
            hits.append((rule, match))
    hits.sort(key=lambda h: h[1].start)
    return hits


# (rule id, secret, location)
Hit = Tuple[str, str, Location]


def read_part(path: Path, part: int, parts: int) -> Tuple[str, int, str]:
    """(text of this part, byte offset where it starts, the file's first line).

    Only this part's bytes are read. Cuts land on line breaks, so no JSON line is split."""
    size = path.stat().st_size
    with open(path, "rb") as fh:
        first = fh.readline()

        def cut(pos: int) -> int:
            if pos <= 0:
                return 0
            if pos >= size:
                return size
            fh.seek(pos - 1)
            fh.readline()  # finish the line we landed in
            return fh.tell()

        start, end = cut(size * part // parts), cut(size * (part + 1) // parts)
        fh.seek(start)
        data = fh.read(end - start)
    return data.decode("utf-8", errors="replace"), start, first.decode("utf-8", errors="replace")


def _lines_before(path: Path, offset: int) -> int:
    count = 0
    with open(path, "rb") as fh:
        while offset > 0:
            block = fh.read(min(offset, 8 * 1024 * 1024))
            if not block:
                break
            count += block.count(b"\n")
            offset -= len(block)
    return count


def scan_file(source: Source, path: Path, rules: Sequence[Rule], part: int = 0, parts: int = 1) -> List[Hit]:
    if parts > 1:
        text, byte_start, first_line = read_part(path, part, parts)
        doc = source.document(path, text)
        doc.first_line = first_line
        if byte_start:
            doc.line_offset = _lines_before(path, byte_start)
    else:
        loaded = source.load(path)
        if not loaded:
            return []
        text = loaded
        doc = source.document(path, text)
    hits: List[Hit] = []
    for rule, match in find_in_text(text, rules):
        secret = doc.decode(match.secret)
        location = doc.locate(match.start, secret)
        if location is not None:
            hits.append((rule.id, secret, location))
    return hits


# One unit of work: a whole file, or one part of a big JSONL file.
Job = Tuple[Source, Path, int, int]


def _scan_job(args: Tuple[Job, List[str]]) -> Tuple[List[Hit], List[str], str]:
    (source, path, part, parts), rule_ids = args
    try:
        return scan_file(source, path, _rules_for(tuple(rule_ids)), part, parts), [], source.name
    except Exception as exc:  # one broken file must not end the scan
        return [], [f"{path}: {exc}"], source.name


_RULE_CACHE: Dict[tuple, list] = {}


def _rules_for(rule_ids: tuple) -> list:
    if rule_ids not in _RULE_CACHE:
        _RULE_CACHE[rule_ids] = get_rules(only=list(rule_ids))
    return _RULE_CACHE[rule_ids]


class Scanner:
    def __init__(
        self,
        rules: Optional[Sequence[Rule]] = None,
        ignore: Iterable[str] = (),
        since: Optional[float] = None,
        min_severity: Severity = Severity.LOW,
        progress: Optional[ProgressFn] = None,
        workers: Optional[int] = None,
    ) -> None:
        self.rules = list(rules) if rules is not None else get_rules()
        self.ignore = set(ignore)
        self.since = since
        self.min_severity = min_severity
        self.progress = progress
        self.workers = workers

    def collect(self, sources: Iterable[Source], stats: ScanStats) -> List[Tuple[Source, Path, int]]:
        jobs = []
        for source in sources:
            for path in source.discover():
                try:
                    st = path.stat()
                except OSError as exc:
                    stats.errors.append(f"{path}: {exc}")
                    continue
                if self.since and st.st_mtime < self.since:
                    continue
                jobs.append((source, path, st.st_size))
                stats.files += 1
                stats.bytes += st.st_size
                stats.per_agent[source.name] = stats.per_agent.get(source.name, 0) + 1
        return jobs

    def scan(self, sources: Iterable[Source]) -> ScanResult:
        started = time.perf_counter()
        stats = ScanStats()
        jobs = self.collect(sources, stats)
        hits = self._run(jobs, stats)
        findings = self._merge(hits, stats)
        stats.seconds = time.perf_counter() - started
        return ScanResult(findings, stats)

    def _run(self, jobs: List[Tuple[Source, Path, int]], stats: ScanStats) -> List[Hit]:
        workers = self.workers if self.workers is not None else min(8, os.cpu_count() or 1)
        rule_ids = [r.id for r in self.rules]
        parallel = workers > 1 and stats.bytes >= PARALLEL_THRESHOLD and len(jobs) >= 2
        units: List[Job] = []
        # Biggest first, so the long jobs start early and the small ones fill the gaps.
        for source, path, size in sorted(jobs, key=lambda j: -j[2]):
            parts = 1
            if parallel and path.suffix == ".jsonl" and size > SPLIT_BYTES:
                parts = min(64, -(-size // SPLIT_BYTES))
            units.extend((source, path, i, parts) for i in range(parts))
        total = len(units)
        hits: List[Hit] = []
        if not parallel:
            results = (_scan_job((unit, rule_ids)) for unit in units)
            return self._collect(results, total, hits, stats)
        with ProcessPoolExecutor(max_workers=workers) as pool:
            results = pool.map(_scan_job, [(unit, rule_ids) for unit in units], chunksize=1)
            return self._collect(results, total, hits, stats)

    def _collect(self, results, total: int, hits: List[Hit], stats: ScanStats) -> List[Hit]:
        for done, (unit_hits, errors, agent) in enumerate(results, 1):
            hits.extend(unit_hits)
            stats.errors.extend(errors)
            if self.progress:
                self.progress(done, total, agent)
        return hits

    def _merge(self, hits: List[Hit], stats: ScanStats) -> List[Finding]:
        rules = {r.id: r for r in self.rules}
        found: Dict[str, Finding] = {}
        ignored = set()
        for rule_id, secret, location in hits:
            fp = fingerprint(secret)
            if fp in self.ignore:
                ignored.add(fp)
                continue
            finding = found.get(fp)
            if finding is None:
                rule = rules[rule_id]
                finding = found[fp] = Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    provider=rule.provider,
                    severity=rule.severity_for(secret),
                    secret=secret,
                    rotate_url=rule.rotate_url,
                )
            if location not in finding.locations:
                finding.locations.append(location)
        stats.ignored = len(ignored)
        for finding in found.values():
            finding.locations.sort(key=lambda loc: (loc.timestamp or "~", loc.file, loc.line))
        return sorted(
            (f for f in found.values() if f.severity >= self.min_severity),
            key=lambda f: (-f.severity, -len(f.sessions), -len(f.locations), f.rule_id),
        )


def scan_text(text: str, rules: Optional[Sequence[Rule]] = None) -> List[Finding]:
    """Scan one string. Used by the agent hooks and handy from Python."""
    rules = list(rules) if rules is not None else get_rules()
    by_id = {r.id: r for r in rules}
    found: Dict[str, Finding] = {}
    for rule, match in find_in_text(text, rules):
        fp = fingerprint(match.secret)
        if fp not in found:
            rule = by_id[rule.id]
            found[fp] = Finding(
                rule.id, rule.name, rule.provider, rule.severity_for(match.secret), match.secret, rule.rotate_url
            )
    return sorted(found.values(), key=lambda f: -f.severity)


def default_ignore_file() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "spillage" / "ignore"


def load_ignore(path: Optional[Path] = None) -> set:
    """Fingerprints to skip, one per line. Anything after a # is a comment."""
    path = path or default_ignore_file()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return set()
    return {line.split("#", 1)[0].strip() for line in lines if line.split("#", 1)[0].strip()}


def add_ignore(fingerprints: Iterable[str], note: str = "", path: Optional[Path] = None) -> Path:
    path = path or default_ignore_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = load_ignore(path)
    with open(path, "a", encoding="utf-8") as fh:
        for fp in fingerprints:
            if fp not in existing:
                fh.write(f"{fp}  # {note}\n" if note else f"{fp}\n")
    return path
