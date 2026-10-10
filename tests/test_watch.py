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
    now = [0.0]
    w = Watcher(build_sources(), clock=lambda: now[0])
    w.prime()
    now[0] = 6
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


def test_old_keys_in_rewritten_json_are_not_new(home):
    """Gemini rewrites its whole chat file on every message; a key from last week isn't news."""
    old = fakes.google()
    path = home.gemini_chat([{"type": "user", "content": f"old {old}"}])
    w = Watcher(build_sources(["gemini"]))
    w.prime()
    home.gemini_chat([{"type": "user", "content": f"old {old}"}, {"type": "user", "content": "hi"}])
    os.utime(path, (time.time(), time.time() + 5))
    assert w.tick() == []
    new = fakes.npm()
    home.gemini_chat([{"type": "user", "content": f"old {old}"}, {"type": "user", "content": f"new {new}"}])
    os.utime(path, (time.time(), time.time() + 10))
    (event,) = w.tick()
    assert event.finding.secret == new


def test_a_repeat_in_another_file_still_gets_scrubbed(home):
    now = [1000.0]
    a = home.claude_session(name="a", records=[])
    b = home.claude_session(name="b", records=[])
    w = Watcher(build_sources(["claude"]), scrub_after=10, clock=lambda: now[0])
    w.prime()
    key = fakes.npm()
    append(a, {"type": "user", "message": {"content": key}})
    assert len(w.tick()) == 1
    append(b, {"type": "user", "message": {"content": key}})
    assert w.tick() == []  # reported once
    assert b in w.pending
    for p in (a, b):
        w.files[p].mtime = 1000.0
    now[0] = 2000.0
    assert {p for p, _ in w.scrub_quiet()} == {a, b}
    assert key not in b.read_text()


def test_half_written_line_at_startup(home):
    session = home.claude_session(records=[{"type": "user", "message": {"content": "hi"}}])
    key = fakes.github()
    line = json.dumps({"type": "user", "sessionId": "s1", "message": {"content": f"x {key}"}})
    cut = line.index(key) + 10  # stop in the middle of the key
    with open(session, "a", encoding="utf-8") as fh:
        fh.write(line[:cut])
    w = Watcher(build_sources(["claude"]))
    w.prime()
    with open(session, "a", encoding="utf-8") as fh:
        fh.write(line[cut:] + "\n")
    os.utime(session, (time.time(), time.time() + 5))
    (event,) = w.tick()
    assert event.finding.secret == key and event.location.origin == Origin.PROMPT and event.location.line == 2


def test_in_place_rewrite_that_grows_is_noticed(home):
    key1 = fakes.npm()
    session = home.claude_session(records=[{"type": "user", "message": {"content": key1}}])
    w = Watcher(build_sources(["claude"]))
    w.prime()
    text = session.read_text().replace(key1, "[REDACTED:npm-token:0123456789ab]")
    key2 = fakes.github()
    text += json.dumps({"type": "user", "message": {"content": key2}}) + "\n"
    session.write_text(text)
    os.utime(session, (time.time(), time.time() + 5))
    (event,) = w.tick()
    assert event.finding.secret == key2 and event.location.line == 2


def test_vanished_file_doesnt_crash(home):
    session = home.claude_session(records=[])
    w = Watcher(build_sources(["claude"]))
    w.prime()
    session.unlink()
    assert w.tick() == []
    assert session not in w.files


def test_discovery_is_cached(home, monkeypatch):
    now = [0.0]
    w = Watcher(build_sources(["claude"]), clock=lambda: now[0], rediscover=30)
    w.prime(baseline=False)
    calls = []
    real = w.sources[0].discover
    monkeypatch.setattr(w.sources[0], "discover", lambda: calls.append(1) or real())
    w.tick()
    now[0] = 10
    w.tick()
    assert calls == []
    now[0] = 40
    w.tick()
    assert calls == [1]


def test_scrub_keeps_the_inode(home):
    now = [1000.0]
    session = home.claude_session(records=[])
    w = Watcher(build_sources(["claude"]), scrub_after=1, clock=lambda: now[0])
    w.prime()
    ino = session.stat().st_ino
    append(session, {"type": "user", "message": {"content": fakes.npm()}})
    w.tick()
    w.files[session].mtime = 1000.0
    now[0] = 1100.0
    assert w.scrub_quiet()
    assert session.stat().st_ino == ino


def test_windows_toast_gets_the_text_through_the_environment(monkeypatch):
    """A key name or a path with a quote or a `$(...)` in it must never become PowerShell code."""
    from spillage import watch

    seen = {}

    def run(cmd, **kwargs):
        seen["cmd"], seen["env"] = cmd, kwargs["env"]

    monkeypatch.setattr(watch.platform, "system", lambda: "Windows")
    monkeypatch.setattr(watch.shutil, "which", lambda name: name)
    monkeypatch.setattr(watch.subprocess, "Popen", run)
    assert watch.notify('a "title"', "$(calc) `whoami`") is True
    assert seen["env"]["SPILLAGE_TITLE"] == 'a "title"'
    assert seen["env"]["SPILLAGE_MESSAGE"] == "$(calc) `whoami`"
    assert "calc" not in " ".join(seen["cmd"]) and "title" not in " ".join(seen["cmd"])


def test_no_notification_without_a_way_to_show_one(monkeypatch):
    from spillage import watch

    monkeypatch.setattr(watch.shutil, "which", lambda name: None)
    assert watch.notify("t", "m") is False
