from __future__ import annotations

import json
import os
import time

import fakes

from spillage.models import Origin
from spillage.sources import build_sources
from spillage.watch import Watcher, _applescript


def append(path, record):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    st = path.stat()
    os.utime(path, (st.st_atime, st.st_mtime + 1))  # make sure the change is visible


def test_only_new_secrets_are_reported(leaky_home):
    w = Watcher(build_sources())
    assert w.prime() == 2
    assert w.tick() == []  # what was already there doesn't count
    session = next(leaky_home.root.rglob("s1.jsonl"))
    key = fakes.npm()
    append(session, {"type": "user", "sessionId": "s1", "cwd": "/work/app", "message": {"content": f"k {key}"}})
    (event,) = w.tick()
    assert event.finding.secret == key
    assert event.location.origin == Origin.PROMPT
    assert event.location.line == 5 and event.location.session == "s1"
    append(session, {"type": "user", "sessionId": "s1", "message": {"content": f"again {key}"}})
    assert w.tick() == []  # reported once per run


def test_half_written_line_waits(home):
    session = home.claude_session(records=[{"type": "user", "message": {"content": "hi"}}])
    w = Watcher(build_sources(["claude"]))
    w.prime()
    key = fakes.github()
    line = json.dumps({"type": "user", "message": {"content": key}})
    with open(session, "a", encoding="utf-8") as fh:
        fh.write(line[:20])
    os.utime(session, (time.time(), time.time() + 5))
    assert w.tick() == []
    with open(session, "a", encoding="utf-8") as fh:
        fh.write(line[20:] + "\n")
    os.utime(session, (time.time(), time.time() + 10))
    (event,) = w.tick()
    assert event.finding.secret == key


def test_new_files_and_codex_session_meta(home):
    w = Watcher(build_sources())
    w.prime()
    key = fakes.stripe()
    home.codex_session(records=[{"type": "response_item", "payload": {"type": "function_call_output", "output": key}}])
    (event,) = w.tick()
    assert event.location.session == "rollout-1" and event.location.origin == Origin.TOOL


def test_scrub_after_quiet(leaky_home):
    now = [1000.0]
    w = Watcher(build_sources(), scrub_after=60, clock=lambda: now[0])
    w.prime()
    session = next(leaky_home.root.rglob("s1.jsonl"))
    key = fakes.npm()
    append(session, {"type": "user", "message": {"content": key}})
    assert len(w.tick()) == 1
    w.files[session].mtime = 1000.0
    now[0] = 1030.0
    assert w.scrub_quiet() == []  # still too fresh
    now[0] = 1100.0
    ((path, count),) = w.scrub_quiet()
    assert path == session and count >= 2  # the new key and the old ones in that file
    assert key not in session.read_text()
    append(session, {"type": "user", "message": {"content": "hello"}})
    assert w.tick() == []  # our own rewrite doesn't trigger anything


def test_truncated_file_starts_over(home):
    session = home.claude_session(records=[{"type": "user", "message": {"content": "x" * 500}}])
    w = Watcher(build_sources(["claude"]))
    w.prime()
    key = fakes.npm()
    session.write_text(json.dumps({"type": "user", "message": {"content": key}}) + "\n", encoding="utf-8")
    os.utime(session, (time.time(), time.time() + 5))
    (event,) = w.tick()
    assert event.location.line == 1


def test_ignored_fingerprints(home):
    from spillage.models import fingerprint

    key = fakes.npm()
    session = home.claude_session(records=[])
    w = Watcher(build_sources(["claude"]), ignore={fingerprint(key)})
    w.prime()
    append(session, {"type": "user", "message": {"content": key}})
    assert w.tick() == []


def test_applescript_quoting():
    assert _applescript('say "hi" \\ bye') == '"say \\"hi\\" \\\\ bye"'


def test_cli_watch(home, capsys, monkeypatch):
    import argparse

    from spillage import cli

    session = home.claude_session(records=[])
    calls = []
    monkeypatch.setattr("spillage.watch.notify", lambda t, m: calls.append((t, m)))
    new_leak = {"type": "user", "message": {"content": fakes.npm()}}
    monkeypatch.setattr(cli.time, "sleep", lambda s: append(session, new_leak))
    args = argparse.Namespace(agent=["claude"], scrub=False, quiet=90, interval=0.01, no_notify=False)
    assert cli.cmd_watch(args, max_ticks=2) == 0
    out = capsys.readouterr().out
    assert "npm access token" in out and "1 log files" in out
    assert calls and "npm access token" in calls[0][0]
