"""Watch agent logs and report secrets the moment they land.

Polling, not fsevents/inotify: it keeps spillage dependency-free, and a stat() per log file
every couple of seconds is cheap. Appended JSONL is read from where the last look stopped,
other files are rescanned when they change. Each secret is reported once per run.
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
from .scanner import find_in_text
from .scrub import scrub_file
from .sources import Source


@dataclass
class Event:
    finding: Finding
    location: Location


@dataclass
class _FileState:
    offset: int = 0  # bytes of JSONL already scanned
    mtime: float = 0.0
    size: int = 0
    lines: int = 0  # line breaks before `offset`
    first_line: Optional[str] = None


@dataclass
class Watcher:
    sources: Sequence[Source]
    rules: Sequence[Rule] = field(default_factory=get_rules)
    ignore: Set[str] = field(default_factory=set)
    scrub_after: Optional[float] = None  # seconds a file must be quiet before it's scrubbed
    clock: Callable[[], float] = time.time
    files: Dict[Path, _FileState] = field(default_factory=dict)
    seen: Set[str] = field(default_factory=set)
    pending: Dict[Path, float] = field(default_factory=dict)  # file -> when it last had a new secret

    def prime(self) -> int:
        """Remember where every file is now, so only new writes get reported."""
        for _source, path in self._discover():
            try:
                st = path.stat()
            except OSError:
                continue
            state = _FileState(offset=st.st_size, mtime=st.st_mtime, size=st.st_size)
            if path.suffix == ".jsonl":
                state.lines, state.first_line = _count_lines(path, st.st_size)
            self.files[path] = state
        return len(self.files)

    def _discover(self) -> Iterable[Tuple[Source, Path]]:
        for source in self.sources:
            for path in source.discover():
                yield source, path

    def tick(self) -> List[Event]:
        events: List[Event] = []
        for source, path in self._discover():
            try:
                st = path.stat()
            except OSError:
                continue
            state = self.files.get(path)
            if state is None:
                state = self.files[path] = _FileState()
            if st.st_mtime == state.mtime and st.st_size == state.size:
                continue
            if path.suffix == ".jsonl":
                events += self._read_appended(source, path, state, st.st_size)
            else:
                events += self._rescan(source, path)
            state.mtime, state.size = st.st_mtime, st.st_size
        if events:
            now = self.clock()
            for event in events:
                self.pending[Path(event.location.file)] = now
        return events

    def scrub_quiet(self) -> List[Tuple[Path, int]]:
        """Scrub files that had a new secret and haven't changed for `scrub_after` seconds."""
        if self.scrub_after is None:
            return []
        done = []
        now = self.clock()
        for path, stamp in list(self.pending.items()):
            state = self.files.get(path)
            last_write = max(stamp, state.mtime if state else 0)
            if now - last_write < self.scrub_after:
                continue
            del self.pending[path]
            if path.suffix == ".vscdb":
                continue
            try:
                count = scrub_file(path, ignore=self.ignore, rules=self.rules)
            except OSError:
                continue
            if count:
                st = path.stat()
                if state:
                    state.mtime, state.size, state.offset = st.st_mtime, st.st_size, st.st_size
                    state.lines, _ = _count_lines(path, st.st_size)
                done.append((path, count))
        return done

    def _read_appended(self, source: Source, path: Path, state: _FileState, size: int) -> List[Event]:
        if size < state.offset:  # rewritten or truncated: start over
            state.offset, state.lines, state.first_line = 0, 0, None
        with open(path, "rb") as fh:
            if state.first_line is None:
                state.first_line = fh.readline().decode("utf-8", errors="replace")
            fh.seek(state.offset)
            data = fh.read(size - state.offset)
        cut = data.rfind(b"\n") + 1  # leave a half-written last line for next time
        if not cut:
            return []
        chunk = data[:cut]
        text = chunk.decode("utf-8", errors="replace")
        doc = source.document(path, text)
        doc.first_line = state.first_line
        doc.line_offset = state.lines
        events = self._events(doc, text)
        state.offset += cut
        state.lines += chunk.count(b"\n")
        return events

    def _rescan(self, source: Source, path: Path) -> List[Event]:
        text = source.load(path)
        if not text:
            return []
        return self._events(source.document(path, text), text)

    def _events(self, doc, text: str) -> List[Event]:
        events = []
        for rule, match in find_in_text(text, self.rules):
            secret = doc.decode(match.secret)
            fp = fingerprint(secret)
            if fp in self.seen or fp in self.ignore:
                continue
            location = doc.locate(match.start, secret)
            if location is None:
                continue
            self.seen.add(fp)
            finding = Finding(rule.id, rule.name_for(secret), rule.provider, rule.severity_for(secret), secret,
                              rule.rotate_url, [location])
            events.append(Event(finding, location))
        return events


def _count_lines(path: Path, size: int) -> Tuple[int, Optional[str]]:
    count = 0
    first = None
    with open(path, "rb") as fh:
        first = fh.readline().decode("utf-8", errors="replace")
        fh.seek(0)
        remaining = size
        while remaining > 0:
            block = fh.read(min(remaining, 8 * 1024 * 1024))
            if not block:
                break
            count += block.count(b"\n")
            remaining -= len(block)
    return count, first


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
