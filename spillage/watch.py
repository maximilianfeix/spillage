"""Watch agent logs and report secrets the moment they land.

Polling, not fsevents/inotify: it keeps spillage dependency-free. Each round is a stat() per
known log file; the list of files is refreshed every 5 seconds (60 for the agents whose logs
live in project folders). Appended JSONL is read
from where the last look stopped, other files (JSON, Markdown, SQLite) are rescanned when they
change.

"New" means new since `watch` started: a baseline scan at startup records every secret already
in the logs, and those are never reported again. That's `spillage scan`'s job.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import Finding, Location, fingerprint
from .rules import Rule, get_rules
from .scanner import Scanner, _lines_before, hits_in
from .scrub import scrub_file
from .sources import Source

TAIL = 64  # bytes before the read offset that must stay the same, or the file was rewritten
NOT_SCRUBBABLE = (".vscdb", ".db")


@dataclass
class Event:
    finding: Finding
    location: Location


@dataclass
class _FileState:
    source: Source
    ino: int = 0
    size: int = 0
    mtime: float = 0.0
    offset: int = 0  # JSONL: bytes already scanned, always at a line break
    tail: bytes = b""  # JSONL: the bytes right before `offset`
    lines: Optional[int] = None  # line breaks before `offset`, counted when first needed
    first_line: Optional[str] = None  # only set once it's complete


def _last_line_end(path: Path, size: int) -> int:
    """Offset just past the last line break, so a half-written last line is read later."""
    with open(path, "rb") as fh:
        pos = size
        while pos > 0:
            start = max(0, pos - 65536)
            fh.seek(start)
            block = fh.read(pos - start)
            nl = block.rfind(b"\n")
            if nl != -1:
                return start + nl + 1
            pos = start
    return 0


def _read_range(path: Path, start: int, end: int) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(start)
        return fh.read(max(0, end - start))


def _first_line(path: Path) -> Optional[str]:
    with open(path, "rb") as fh:
        line = fh.readline()
    return line.decode("utf-8", errors="replace") if line.endswith(b"\n") else None


@dataclass
class Watcher:
    sources: Sequence[Source]
    rules: Sequence[Rule] = field(default_factory=get_rules)
    ignore: Set[str] = field(default_factory=set)
    scrub_after: Optional[float] = None  # seconds a file must be quiet before it's scrubbed
    clock: Callable[[], float] = time.time
    rediscover: float = 5.0  # seconds between refreshing the list of log files
    rediscover_slow: float = 60.0  # the same for sources that have to search project folders
    baseline: Set[str] = field(default_factory=set)  # secrets already there at startup
    files: Dict[Path, _FileState] = field(default_factory=dict)
    reported: Set[str] = field(default_factory=set)
    pending: Dict[Path, float] = field(default_factory=dict)  # file -> when it last got a new secret
    errors: List[str] = field(default_factory=list)
    _paths: Dict[int, List[Path]] = field(default_factory=dict)
    _discovered_at: Dict[int, float] = field(default_factory=dict)

    # ---- startup ----------------------------------------------------------------------------
    def prime(self, baseline: bool = True) -> int:
        """Remember what's there now: every secret already in the logs, and where each file ends."""
        if baseline:
            result = Scanner(rules=self.rules).scan(self.sources)
            self.baseline = {f.fingerprint for f in result.findings}
        for source, path in self._discover(force=True):
            try:
                self.files[path] = self._state_now(source, path)
            except OSError:
                continue
        return len(self.files)

    def _state_now(self, source: Source, path: Path) -> _FileState:
        st = path.stat()
        state = _FileState(source, st.st_ino, st.st_size, st.st_mtime)
        if path.suffix == ".jsonl":
            state.offset = _last_line_end(path, st.st_size)
            state.tail = _read_range(path, max(0, state.offset - TAIL), state.offset)
            state.first_line = _first_line(path)
        return state

    def _discover(self, force: bool = False) -> List[Tuple[Source, Path]]:
        """Cached file lists. Sources that look through project folders (Aider, SpecStory,
        Crush) read the head of every session to find them, so they refresh less often."""
        from .sources import Crush, ProjectSource

        now = self.clock()
        out = []
        for i, source in enumerate(self.sources):
            every = self.rediscover_slow if isinstance(source, (ProjectSource, Crush)) else self.rediscover
            last = self._discovered_at.get(i)
            if force or last is None or now - last >= every:
                self._paths[i] = list(source.discover())
                self._discovered_at[i] = now
            out += [(source, p) for p in self._paths[i]]
        return out

    # ---- polling ----------------------------------------------------------------------------
    def tick(self) -> List[Event]:
        events: List[Event] = []
        for source, path in self._discover():
            try:
                events += self._check(source, path)
            except (OSError, ValueError) as exc:  # vanished, locked, half-written: try again next round
                self.errors.append(f"{path}: {exc}")
        return events

    def _check(self, source: Source, path: Path) -> List[Event]:
        try:
            st = path.stat()
        except FileNotFoundError:
            self.files.pop(path, None)
            return []
        state = self.files.get(path)
        if state is None:
            state = self.files[path] = _FileState(source)
        if (st.st_ino, st.st_size, st.st_mtime) == (state.ino, state.size, state.mtime):
            return []
        if path.suffix == ".jsonl":
            hits = self._appended(source, path, state, st.st_ino, st.st_size)
        else:
            text = source.load(path)
            hits = hits_in(source.document(path, text), text, self.rules) if text else []
        state.ino, state.size, state.mtime = st.st_ino, st.st_size, st.st_mtime
        return self._events(path, hits)

    def _appended(self, source: Source, path: Path, state: _FileState, ino: int, size: int) -> list:
        rewritten = (
            (state.ino and ino != state.ino)
            or size < state.offset
            or (state.tail and _read_range(path, state.offset - len(state.tail), state.offset) != state.tail)
        )
        if rewritten:  # scrubbed, truncated or replaced: read it again from the top
            state.offset, state.tail, state.lines, state.first_line = 0, b"", 0, None
        data = _read_range(path, state.offset, size)
        cut = data.rfind(b"\n") + 1  # leave a half-written last line for next time
        if not cut:
            return []
        chunk = data[:cut]
        if state.first_line is None:
            state.first_line = _first_line(path)
        if state.lines is None:
            state.lines = _lines_before(path, state.offset)
        text = chunk.decode("utf-8", errors="replace")
        doc = source.document(path, text)
        doc.first_line = state.first_line
        doc.line_offset = state.lines
        hits = hits_in(doc, text, self.rules)
        state.offset += cut
        state.lines += chunk.count(b"\n")
        state.tail = (state.tail + chunk)[-TAIL:]
        return hits

    def _events(self, path: Path, hits: Iterable) -> List[Event]:
        events = []
        for rule, secret, location in hits:
            fp = fingerprint(secret)
            if fp in self.ignore or fp in self.baseline:
                continue
            self.pending[path] = self.clock()  # any file holding a new secret gets scrubbed
            if fp in self.reported:
                continue
            self.reported.add(fp)
            finding = Finding(rule.id, rule.name_for(secret), rule.provider, rule.severity_for(secret), secret,
                              rule.rotate_url, [location])
            events.append(Event(finding, location))
        return events

    # ---- scrubbing --------------------------------------------------------------------------
    def scrub_quiet(self) -> List[Tuple[Path, int]]:
        """Scrub files that got a new secret and haven't changed for `scrub_after` seconds.

        Written in place, not replaced: an agent that still holds the file open keeps writing
        into the same file instead of an unlinked copy."""
        if self.scrub_after is None:
            return []
        done = []
        now = self.clock()
        for path, stamp in list(self.pending.items()):
            state = self.files.get(path)
            if now - max(stamp, state.mtime if state else 0) < self.scrub_after:
                continue
            del self.pending[path]
            if path.suffix in NOT_SCRUBBABLE or (state and not state.source.scrubbable):
                continue
            try:
                count = scrub_file(path, ignore=self.ignore, rules=self.rules, in_place=True)
                if count and state:
                    self.files[path] = self._state_now(state.source, path)
            except (OSError, ValueError) as exc:
                self.errors.append(f"{path}: {exc}")
                continue
            if count:
                done.append((path, count))
        return done


def notify(title: str, message: str) -> bool:
    """A desktop notification, if the OS has a way to show one without extra packages."""
    system = platform.system()
    try:
        if system == "Darwin" and shutil.which("osascript"):
            script = f"display notification {_applescript(message)} with title {_applescript(title)}"
            subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
            return True
        if system == "Linux" and shutil.which("notify-send"):
            subprocess.run(["notify-send", "--urgency=critical", title, message], capture_output=True, timeout=5)
            return True
    except (OSError, subprocess.SubprocessError):
        pass
    return False


def _applescript(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
