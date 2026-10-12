"""What a second review turned up outside the guard: secrets that were missed, a file name that
carried a key out, and a scrub that could lose what an agent wrote in the meantime."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess

import fakes
import pytest

from spillage import cli, watch
from spillage.cli import main
from spillage.rules import KnownValueRule, get_rules
from spillage.scanner import scan_file
from spillage.scrub import read_exact, scrub_file, write_in_place
from spillage.sources import Source, SQLiteSource, build_sources
from spillage.watch import Watcher


def record(text: str) -> str:
    return json.dumps({"type": "user", "message": {"content": text}}) + "\n"


# ---- scrub ------------------------------------------------------------------------------

def test_scrubbing_in_place_keeps_what_was_appended_meanwhile(tmp_path):
    key = fakes.github()
    path = tmp_path / "rollout.jsonl"
    path.write_bytes(record(f"use {key}").encode())
    original = read_exact(path)
    redacted = original.replace(key, "[REDACTED]")
    later = record("the agent wrote this while the scrub was running")
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(later)
    write_in_place(path, redacted, original=original)
    assert read_exact(path) == redacted + later


def test_scrubbing_in_place_leaves_a_rewritten_file_alone(tmp_path):
    path = tmp_path / "rollout.jsonl"
    path.write_bytes(record("something else entirely").encode())
    with pytest.raises(OSError):
        write_in_place(path, "new text\n", original=record("what the scrub started from"))
    assert read_exact(path) == record("something else entirely")


def test_scrub_file_in_place_still_redacts(tmp_path):
    key = fakes.github()
    path = tmp_path / "rollout.jsonl"
    path.write_bytes(record(f"use {key}").encode())
    assert scrub_file(path, in_place=True) == 1
    assert key not in read_exact(path) and json.loads(read_exact(path))


def test_a_signed_thinking_block_in_a_json_file_is_left_alone(tmp_path):
    key = fakes.anthropic()
    path = tmp_path / "session.json"
    data = {"content": [{"type": "text", "text": key}, {"type": "thinking", "thinking": key, "signature": "sig"}]}
    path.write_text(json.dumps(data), encoding="utf-8")
    assert scrub_file(path) == 1
    after = json.loads(path.read_text(encoding="utf-8"))
    assert key not in after["content"][0]["text"]
    assert after["content"][1] == data["content"][1]  # an edited block would break --resume


# ---- scan -------------------------------------------------------------------------------

def test_a_key_in_a_very_long_string_is_found(tmp_path):
    key = fakes.anthropic()
    path = tmp_path / "big.json"
    path.write_text(json.dumps({"content": "x" * 2_000_001 + " " + key}), encoding="utf-8")
    (hit,) = scan_file(Source(), path, get_rules())
    assert hit[1] == key
    line = tmp_path / "big.jsonl"
    line.write_text(json.dumps({"message": {"content": "y" * 2_000_001 + " " + key}}) + "\n", encoding="utf-8")
    (hit,) = scan_file(Source(), line, get_rules())
    assert hit[1] == key


def test_a_file_that_is_one_json_string(tmp_path):
    key = fakes.github()
    path = tmp_path / "note.json"
    path.write_text(json.dumps(f"token {key}"), encoding="utf-8")
    (hit,) = scan_file(Source(), path, get_rules())
    assert hit[1] == key


def test_a_known_value_is_found_where_the_log_escapes_non_ascii():
    value = "P4ss-é-X9#long"
    rule = KnownValueRule({value: "DB_PASSWORD from ~/app/.env"})
    for text in (json.dumps({"content": value}), json.dumps({"content": value}, ensure_ascii=False)):
        assert len(list(rule.find(text))) == 1, text


def test_one_broken_row_does_not_hide_the_rows_after_it(tmp_path):
    key = fakes.github()
    path = tmp_path / "sessions.db"
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE messages (content TEXT)")
    conn.execute("INSERT INTO messages VALUES (CAST(x'80' AS TEXT))")
    conn.execute("INSERT INTO messages VALUES (?)", (f"token {key}",))
    conn.commit()
    conn.close()
    assert key in (SQLiteSource().load(path) or "")


# ---- output -----------------------------------------------------------------------------

@pytest.fixture
def named_after_the_key(tmp_path, home):
    """A repository with a transcript whose file name is the key that is in it."""
    root = tmp_path / "shop"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    key = fakes.github()
    (root / ".claude").mkdir()
    (root / ".claude" / f"{key}.jsonl").write_text(record(f"use {key}"), encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", ".claude"], check=True)
    return root, key


@pytest.mark.parametrize("fmt", ["text", "json", "markdown", "github", "sarif"])
def test_a_file_named_after_a_key_does_not_carry_it_out(named_after_the_key, capsys, tmp_path, monkeypatch, fmt):
    root, key = named_after_the_key
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(root))
    sarif = tmp_path / "out.sarif"
    assert main(["repo", str(root), "-f", fmt, "--strict", "--sarif", str(sarif)]) == 1
    out = capsys.readouterr()
    assert key not in out.out and key not in out.err
    assert "GitHub" in out.out  # the finding itself is still reported
    assert key not in sarif.read_text(encoding="utf-8")
    if fmt == "github":
        assert key not in summary.read_text(encoding="utf-8")


def test_watch_does_not_print_a_project_folder_named_after_the_key(home, capsys, monkeypatch):
    import argparse

    key = fakes.npm()
    session = home.claude_session(records=[])
    leak = json.dumps({"type": "user", "cwd": f"/work/{key}", "message": {"content": f"k {key}"}}) + "\n"

    def write(_seconds):
        with open(session, "a", encoding="utf-8") as fh:
            fh.write(leak)
        st = session.stat()
        os.utime(session, (st.st_atime, st.st_mtime + 1))

    monkeypatch.setattr(cli.time, "sleep", write)
    args = argparse.Namespace(agent=["claude"], scrub=False, quiet=90, interval=0.01, no_notify=True)
    assert cli.cmd_watch(args, max_ticks=2) == 0
    out = capsys.readouterr().out
    assert "npm access token" in out and key not in out


# ---- watch ------------------------------------------------------------------------------

def test_a_database_counts_as_changed_when_its_wal_file_grows(tmp_path):
    db = tmp_path / "sessions.db"
    db.write_bytes(b"x" * 10)
    before = watch._stamp(db, db.stat())
    assert before == (db.stat().st_ino, 10, db.stat().st_mtime)
    (tmp_path / "sessions.db-wal").write_bytes(b"y" * 7)
    assert watch._stamp(db, db.stat())[1] == 17 and watch._stamp(db, db.stat()) != before
    log = tmp_path / "session.jsonl"
    log.write_bytes(b"{}\n")
    (tmp_path / "session.jsonl-wal").write_bytes(b"zzz")
    assert watch._stamp(log, log.stat())[1] == 3  # only databases have one


def test_what_is_written_while_watch_starts_up_is_not_lost(home, monkeypatch):
    session = home.claude_session(records=[{"type": "user", "message": {"content": "hello"}}])
    key = fakes.npm()

    class SlowScan:
        """Stands in for the scan at startup; an agent writes a key while it runs."""

        def __init__(self, rules=None):
            pass

        def scan(self, sources):
            with open(session, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"type": "user", "message": {"content": f"k {key}"}}) + "\n")
            return type("Result", (), {"findings": []})()

    monkeypatch.setattr(watch, "Scanner", SlowScan)
    w = Watcher(build_sources(["claude"]))
    w.prime()
    st = session.stat()
    os.utime(session, (st.st_atime, st.st_mtime + 1))
    (event,) = w.tick()
    assert event.finding.secret == key
