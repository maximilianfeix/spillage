"""A scan that could not read everything must not look like a clean one.

Before, a file that could not be opened and a database that would not open were dropped
without a word, and a scan that listed some files as "could not be scanned" still exited 0,
the same as "nothing spilled". Exit code 3 says: nothing found in what could be read.
"""

from __future__ import annotations

from pathlib import Path

import fakes
import pytest

from spillage.cli import EXIT_INCOMPLETE, main
from spillage.scanner import Scanner
from spillage.sources import Codex as CodexCLI
from spillage.sources import Cursor, Source


def run(capsys, *args):
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def unreadable(monkeypatch):
    """Make chosen files fail to read the way a locked or permission-denied file does."""
    blocked = set()
    real = Path.read_bytes

    def read_bytes(self):
        if self.name in blocked:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    return blocked


def test_a_file_that_cant_be_read_is_an_error_not_a_clean_file(home, unreadable):
    path = home.claude_session(records=[{"type": "user", "message": {"content": fakes.github()}}])
    unreadable.add(path.name)
    result = Scanner(workers=1).scan([_claude()])
    assert not result.findings
    assert any(path.name in error for error in result.stats.errors)


def _claude():
    from spillage.sources import get_source

    return get_source("claude")()


def test_a_broken_database_is_an_error(home):
    db = home.root / ".codex" / "state_5.sqlite"
    db.parent.mkdir(parents=True)
    db.write_bytes(b"this is not a database at all " * 200)
    with pytest.raises(OSError):
        CodexCLI(home.root).load(db)


def test_a_broken_cursor_database_is_an_error(tmp_path):
    db = tmp_path / "state.vscdb"
    db.write_bytes(b"garbage " * 1000)
    with pytest.raises(OSError):
        Cursor(tmp_path).load(db)


def test_a_binary_file_is_skipped_without_an_error(home, tmp_path):
    blob = tmp_path / "logs" / "image.log"
    blob.parent.mkdir()
    blob.write_bytes(b"\0\1\2" * 100)
    assert Source(tmp_path).load(blob) is None


def test_exit_code_3_when_nothing_was_found_but_something_could_not_be_read(home, unreadable, capsys):
    clean = home.claude_session(name="ok", records=[{"type": "user", "message": {"content": "hello"}}])
    broken = home.claude_session(name="locked", records=[{"type": "user", "message": {"content": "hi"}}])
    unreadable.add(broken.name)
    code, out, _ = run(capsys, "scan", "--workers", "1", "--no-color")
    assert code == EXIT_INCOMPLETE == 3
    assert "could not be scanned" in out and "Nothing spilled" not in out
    assert clean.exists()


def test_exit_zero_still_means_zero(home, unreadable, capsys):
    broken = home.claude_session(name="locked", records=[{"type": "user", "message": {"content": "hi"}}])
    unreadable.add(broken.name)
    code, _, _ = run(capsys, "scan", "--workers", "1", "--exit-zero")
    assert code == 0


def test_findings_still_exit_1_when_something_else_could_not_be_read(home, unreadable, capsys):
    home.claude_session(name="leak", records=[{"type": "user", "message": {"content": fakes.github()}}])
    broken = home.claude_session(name="locked", records=[{"type": "user", "message": {"content": "hi"}}])
    unreadable.add(broken.name)
    code, _, _ = run(capsys, "scan", "--workers", "1")
    assert code == 1


def test_json_says_the_scan_is_incomplete(home, unreadable, capsys):
    import json

    broken = home.claude_session(name="locked", records=[{"type": "user", "message": {"content": "hi"}}])
    unreadable.add(broken.name)
    code, out, _ = run(capsys, "scan", "--workers", "1", "-f", "json")
    data = json.loads(out)
    assert code == 3
    assert data["summary"]["complete"] is False and data["summary"]["errors"]
