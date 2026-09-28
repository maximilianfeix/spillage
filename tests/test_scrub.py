from __future__ import annotations

import io
import json
import os
import stat
import sys
import time

import fakes
import pytest
from conftest import write_json

from spillage.cli import main
from spillage.models import fingerprint
from spillage.rules import get_rules
from spillage.scanner import Scanner
from spillage.scrub import marker, redact_text, scrub
from spillage.sources import build_sources

LONG_AGO = time.time() + 3600  # "now" an hour ahead, so no test file counts as active


def scan():
    return Scanner(workers=1).scan(build_sources())


def all_text(home) -> str:
    return "".join(p.read_text(encoding="utf-8") for p in home.root.rglob("*") if p.is_file())


def test_scrub_removes_everything_and_keeps_json_valid(leaky_home):
    result = scan()
    report = scrub(result.findings, now=LONG_AGO)
    assert report.replacements >= 6 and not report.failed
    text = all_text(leaky_home)
    for secret in leaky_home.secrets.values():
        assert secret not in text
        assert json.dumps(secret)[1:-1] not in text
    for path in leaky_home.root.rglob("*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            json.loads(line)
    assert scan().findings == []


def test_markers_name_rule_and_fingerprint(leaky_home):
    gh = leaky_home.secrets["github"]
    scrub(scan().findings, now=LONG_AGO)
    assert marker("github-token", fingerprint(gh)) in all_text(leaky_home)


def test_only_some_fingerprints(leaky_home):
    gh = leaky_home.secrets["github"]
    report = scrub(scan().findings, only=[fingerprint(gh)], now=LONG_AGO)
    assert report.replacements == 2
    text = all_text(leaky_home)
    assert gh not in text
    assert leaky_home.secrets["sendgrid"] in text


def test_dry_run_changes_nothing(leaky_home):
    before = all_text(leaky_home)
    report = scrub(scan().findings, dry_run=True, now=LONG_AGO)
    assert report.replacements and report.dry_run
    assert all_text(leaky_home) == before


def test_active_files_are_skipped(leaky_home):
    report = scrub(scan().findings)  # files were just written
    assert report.replacements == 0 and len(report.skipped_active) == 2
    report = scrub(scan().findings, include_active=True)
    assert report.replacements > 0


def test_mode_and_mtime_survive(leaky_home):
    path = next(leaky_home.root.rglob("s1.jsonl"))
    os.chmod(path, 0o600)
    old = time.time() - 7200
    os.utime(path, (old, old))
    scrub(scan().findings)
    st = path.stat()
    if sys.platform != "win32":
        assert stat.S_IMODE(st.st_mode) == 0o600
    assert abs(st.st_mtime - old) < 1


def test_line_endings_are_kept(home):
    gh = fakes.github()
    path = home.root / ".claude/projects/p/s.jsonl"
    path.parent.mkdir(parents=True)
    line = json.dumps({"type": "user", "message": {"content": gh}})
    path.write_bytes((line + "\r\n" + line + "\r\n").encode())
    scrub(scan().findings, now=LONG_AGO)
    raw = path.read_bytes()
    assert raw.count(b"\r\n") == 2 and gh.encode() not in raw


def test_indented_json_file(home):
    key = fakes.google()
    home.gemini_chat([{"type": "user", "content": f"key {key}"}])
    scrub(scan().findings, now=LONG_AGO)
    path = next(home.root.rglob("session-1.json"))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert key not in json.dumps(data)
    assert "\n  " in path.read_text(encoding="utf-8")  # still indented


def test_refuses_to_break_json(home, monkeypatch):
    import spillage.scrub as mod

    gh = fakes.github()
    write_json(home.root / ".gemini/tmp/x/chats/session-1.json", {"messages": [{"content": gh}]})
    monkeypatch.setattr(mod, "marker", lambda rule, fp: '"broken')
    report = scrub(scan().findings, now=LONG_AGO)
    assert report.replacements == 0 and report.failed
    assert gh in all_text(home)


def test_redact_text_ignores_other_secrets():
    a, b = fakes.github(), fakes.npm()
    text, n = redact_text(f"{a} {b}", {fingerprint(a)}, get_rules(), False)
    assert n == 1 and a not in text and b in text


def test_scrub_twice_is_a_noop(leaky_home):
    scrub(scan().findings, now=LONG_AGO)
    before = all_text(leaky_home)
    report = scrub(scan().findings, now=LONG_AGO)
    assert report.replacements == 0 and all_text(leaky_home) == before


# ---- CLI --------------------------------------------------------------------------------

@pytest.fixture
def old_files(leaky_home):
    old = time.time() - 7200
    for p in leaky_home.root.rglob("*.jsonl"):
        os.utime(p, (old, old))
    return leaky_home


def test_cli_scrub_yes(old_files, capsys):
    assert main(["scrub", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "Redacted" in out and "Rotate" in out
    assert main(["scan"]) == 0


def test_cli_scrub_dry_run(old_files, capsys):
    assert main(["scrub", "--dry-run"]) == 0
    assert "Would redact" in capsys.readouterr().out
    assert main(["scan", "--exit-zero"]) == 0
    assert "4 secrets" in capsys.readouterr().out


def test_cli_scrub_needs_yes_without_a_terminal(old_files, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert main(["scrub"]) == 2
    assert "--yes" in capsys.readouterr().err


def test_cli_scrub_asks(old_files, capsys, monkeypatch):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr("sys.stdin", Tty("n\n"))
    assert main(["scrub"]) == 0
    assert "Nothing changed" in capsys.readouterr().out
    monkeypatch.setattr("sys.stdin", Tty("y\n"))
    assert main(["scrub"]) == 0
    assert "Redacted" in capsys.readouterr().out


def test_cli_scrub_only(old_files, capsys):
    gh = old_files.secrets["github"]
    assert main(["scrub", "-y", "--only", fingerprint(gh)]) == 0
    assert "1 secret," in capsys.readouterr().out


def test_cli_scrub_nothing(home, capsys):
    assert main(["scrub", "-y"]) == 0
    assert "nothing to scrub" in capsys.readouterr().out
