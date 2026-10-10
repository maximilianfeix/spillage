"""The scan pipeline: sources -> files -> rules -> deduplicated findings.

Files are independent, so big scans fan out over a process pool. Each worker returns plain
tuples and the parent merges them into one Finding per distinct secret.
"""

from __future__ import annotations

import os
import pickle
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import Finding, Hider, Location, Severity, fingerprint
from .rules import Match, Rule, get_rules, rule_spec, rules_from_spec
from .sources import MAX_FILE_BYTES, Source, is_database, kind_of

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
    # secrets the scan saw but doesn't report: the ones below --min-severity. Not the ones you
    # ignored by fingerprint, since you said those aren't secrets.
    seen: frozenset = field(default_factory=frozenset, repr=False)
    _hider: Optional[Hider] = field(default=None, init=False, repr=False, compare=False)

    def hide(self, text: str) -> str:
        """`text` without any full secret in it, see models.Hider."""
        if self._hider is None:
            self._hider = Hider(self.seen.union(f.secret for f in self.findings))
        return self._hider(text)

    def by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    @property
    def worst(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict:
        from . import __version__

        return self._hidden({
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
                "errors": self.stats.errors,
            },
            "findings": [f.to_dict() for f in self.findings],
        })

    def _hidden(self, node):
        if isinstance(node, str):
            return self.hide(node)
        if isinstance(node, dict):
            return {key: self._hidden(value) for key, value in node.items()}
        if isinstance(node, list):
            return [self._hidden(value) for value in node]
        return node


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
    # same decoding as Source.load / read_text_exact, so fingerprints don't depend on splitting
    return data.decode("utf-8", errors="surrogateescape"), start, first.decode("utf-8", errors="surrogateescape")


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
            doc.line_offset = lambda: _lines_before(path, byte_start)  # only counted if this part has a hit
    else:
        loaded = source.load(path)
        if not loaded:
            return []
        text = loaded
        doc = source.document(path, text)
    return [(rule.id, secret, location) for rule, secret, location in hits_in(doc, text, rules)]


def hits_in(doc, text: str, rules: Sequence[Rule]) -> List[Tuple[Rule, str, Location]]:
    """(rule, secret, location) for every match in `text`, which `doc` describes."""
    hits = []
    for rule, match in find_in_text(text, rules):
        secret = doc.decode(match.secret)
        location = doc.locate(match.start, secret)
        if location is not None:
            hits.append((rule, secret, location))
    return hits


# One unit of work: a whole file, or one part of a big JSONL file.
Job = Tuple[Source, Path, int, int]


_WORKER_RULES: list = []


def _init_worker(spec: tuple) -> None:
    """Runs once per worker process: the rules (and any .env values) arrive once, not per job."""
    _WORKER_RULES[:] = rules_from_spec(spec)


def _scan_job(unit: Job, rules: Optional[Sequence[Rule]] = None) -> Tuple[List[Hit], List[str], str]:
    source, path, part, parts = unit
    try:
        return scan_file(source, path, rules if rules is not None else _WORKER_RULES, part, parts), [], source.name
    except Exception as exc:  # one broken file must not end the scan
        return [], [f"{path}: {exc}"], source.name


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
        seen = frozenset(secret for _, secret, _ in hits if fingerprint(secret) not in self.ignore)
        return ScanResult(findings, stats, seen=seen)

    def _run(self, jobs: List[Tuple[Source, Path, int]], stats: ScanStats) -> List[Hit]:
        workers = self.workers if self.workers is not None else min(8, os.cpu_count() or 1)
        parallel = workers > 1 and stats.bytes >= PARALLEL_THRESHOLD and bool(jobs)
        if parallel:
            try:
                pickle.dumps(rule_spec(self.rules))
            except Exception:  # custom rules with lambdas: run them here instead
                parallel = False
        units: List[Job] = []
        # Biggest first, so the long jobs start early and the small ones fill the gaps.
        for source, path, size in sorted(jobs, key=lambda j: -j[2]):
            parts = 1
            if kind_of(path) == "jsonl" and (size > MAX_FILE_BYTES or (parallel and size > SPLIT_BYTES)):
                # huge files are always read in parts, even without a pool
                parts = max(-(-size // (MAX_FILE_BYTES // 2)), min(64, -(-size // SPLIT_BYTES)) if parallel else 1)
            elif size > MAX_FILE_BYTES and not is_database(path):  # a database is read row by row
                stats.errors.append(f"{path}: skipped, larger than {MAX_FILE_BYTES // 2**20} MB")
            units.extend((source, path, i, parts) for i in range(parts))
        total = len(units)
        hits: List[Hit] = []
        if not parallel:
            results = (_scan_job(unit, self.rules) for unit in units)
            return self._collect(results, total, hits, stats)
        with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker,
                                 initargs=(rule_spec(self.rules),)) as pool:
            results = pool.map(_scan_job, units, chunksize=1)
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
        order = {r.id: i for i, r in enumerate(self.rules)}
        found: Dict[str, Finding] = {}
        ignored = set()
        for rule_id, secret, location in hits:
            fp = fingerprint(secret)
            if fp in self.ignore:
                ignored.add(fp)
                continue
            finding = found.get(fp)
            if finding is not None and order[rule_id] < order[finding.rule_id]:
                # a more specific rule saw it too: "AWS secret key" beats "Value of AWS_SECRET"
                rule = rules[rule_id]
                finding.rule_id, finding.rule_name, finding.provider = rule.id, rule.name_for(secret), rule.provider
                finding.severity, finding.rotate_url = rule.severity_for(secret), rule.rotate_url
            if finding is None:
                rule = rules[rule_id]
                finding = found[fp] = Finding(
                    rule_id=rule.id,
                    rule_name=rule.name_for(secret),
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
            secret = match.secret
            found[fp] = Finding(
                rule.id, rule.name_for(secret), rule.provider, rule.severity_for(secret), secret, rule.rotate_url
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
