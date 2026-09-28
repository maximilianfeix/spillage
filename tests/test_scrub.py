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


# ---- review fixes -------------------------------------------------------------------------

def test_crlf_private_key_in_a_text_log(home):
    pk = fakes.private_key().replace("\n", "\r\n")
    log = home.root / ".codex/log/codex-tui.log"
    log.parent.mkdir(parents=True)
    log.write_bytes(("started\r\n" + pk + "\r\ndone\r\n").encode())
    report = scrub(scan().findings, now=LONG_AGO)
    assert report.replacements == 1 and not report.failed
    assert b"PRIVATE KEY-----\r\n" not in log.read_bytes() and log.read_bytes().endswith(b"\r\ndone\r\n")


def test_symlink_target_is_scrubbed(home, tmp_path):
    from spillage.scanner import Scanner as S
    from spillage.sources import PathSource

    real = tmp_path / "real.jsonl"
    key = fakes.npm()
    real.write_text(json.dumps({"content": key}) + "\n")
    link = tmp_path / "link.jsonl"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("no symlinks")
    result = S(workers=1).scan([PathSource([link])])
    report = scrub(result.findings, now=LONG_AGO)
    assert report.replacements == 1
    assert link.is_symlink() and key not in real.read_text()


def test_invalid_byte_elsewhere_in_the_file(home):
    gh = fakes.github()
    path = home.root / ".claude/projects/p/s.jsonl"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"type":"user","message":{"content":"caf\xff"}}\n'
                     + json.dumps({"type": "user", "message": {"content": gh}}).encode() + b"\n")
    report = scrub(scan().findings, now=LONG_AGO)
    assert report.replacements == 1 and not report.failed
    raw = path.read_bytes()
    assert b"caf\xff" in raw and gh.encode() not in raw


def test_file_changed_since_the_scan_is_reported(leaky_home):
    result = scan()
    for p in leaky_home.root.rglob("*.jsonl"):
        p.write_text('{"type":"user","message":{"content":"all gone"}}\n')
    report = scrub(result.findings, now=LONG_AGO)
    assert report.replacements == 0
    assert any("didn't find it again" in why for _, why in report.failed)


def test_signed_thinking_blocks_are_left_alone(home):
    key = fakes.npm()
    home.claude_session(records=[
        {"type": "assistant", "message": {"content": [
            {"type": "thinking", "thinking": f"the user gave {key}", "signature": "x" * 300}]}},
        {"type": "user", "message": {"content": f"here {key}"}},
    ])
    report = scrub(scan().findings, now=LONG_AGO)
    assert report.replacements == 1 and report.signed == 1
    text = next(home.root.rglob("s1.jsonl")).read_text()
    assert f"the user gave {key}" in text and f"here {key}" not in text


def test_u2028_inside_a_line_is_still_validated():
    from spillage.scrub import _still_valid

    old = json.dumps({"a": "x y", "k": "v"}, ensure_ascii=False)
    new = old.replace('"v"', '"broken')
    assert not _still_valid(old, new, "jsonl")


def test_ctrl_d_at_the_prompt(old_files, capsys, monkeypatch):
    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr("sys.stdin", Tty(""))
    assert main(["scrub"]) == 0
    assert "Nothing changed" in capsys.readouterr().out


def test_session_end_scrub_skips_thinking_too(home):
    from spillage.scrub import scrub_file

    key = fakes.npm()
    path = home.claude_session(records=[
        {"type": "assistant", "message": {"content": [{"type": "thinking", "thinking": key, "signature": "s" * 300}]}},
        {"type": "user", "message": {"content": key}},
    ])
    assert scrub_file(path) == 1
    assert path.read_text().count(key) == 1
