"""Places the agents started to keep conversations in after their adapters were written."""

from __future__ import annotations

import json
import os
import sqlite3

import fakes
import pytest
from conftest import write_json, write_jsonl

from spillage.models import Origin
from spillage.scanner import Scanner
from spillage.scrub import scrub
from spillage.sources import build_sources


def scan(agents):
    return {f.secret: f for f in Scanner(workers=1).scan(build_sources(agents)).findings}


def database(path, script, rows=()):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.executescript(script)
    for sql, values in rows:
        conn.execute(sql, values)
    conn.commit()
    conn.close()
    return path


def test_claude_tool_output_that_was_too_big_for_the_transcript(home):
    key = fakes.stripe()
    session = home.root / ".claude" / "projects" / "-work-app" / "s1"
    (session / "tool-results").mkdir(parents=True)
    (session / "tool-results" / "toolu_01.txt").write_text(f"STRIPE_SECRET_KEY={key}\nDEBUG=1\n", encoding="utf-8")
    (f,) = scan(["claude"]).values()
    assert f.secret == key and f.origins == [Origin.TOOL]


def test_claude_superseded_session_memory_and_plans(home):
    old, memory, plan = fakes.github(), fakes.npm(), fakes.sendgrid()
    project = home.root / ".claude" / "projects" / "-work-app"
    write_jsonl(project / "s1.jsonl.superseded-1760000000", [
        {"type": "user", "sessionId": "s1", "message": {"role": "user", "content": f"use {old}"}}])
    (project / "memory").mkdir()
    (project / "memory" / "deploy.md").write_text(f"The deploy token is {memory}\n", encoding="utf-8")
    (home.root / ".claude" / "plans").mkdir()
    (home.root / ".claude" / "plans" / "ship.md").write_text(f"1. curl with {plan}\n", encoding="utf-8")
    found = scan(["claude"])
    assert set(found) == {old, memory, plan}
    assert found[old].origins == [Origin.PROMPT] and found[old].locations[0].session == "s1"


def test_codex_databases_next_to_the_rollouts(home):
    prompt, output, logged = fakes.github(), fakes.anthropic(), fakes.npm()
    codex = home.root / ".codex"
    database(codex / "state_5.sqlite",
             "CREATE TABLE threads (id TEXT, cwd TEXT, title TEXT, first_user_message TEXT, preview TEXT);",
             [("INSERT INTO threads VALUES (?, ?, ?, ?, ?)", ("t1", "/work/api", "deploy", f"use {prompt}", ""))])
    item = {"type": "function_call_output", "call_id": "c1", "output": f"ANTHROPIC_API_KEY={output}"}
    database(codex / "thread_history_1.sqlite",
             "CREATE TABLE thread_items (thread_id TEXT, item_id TEXT, item_type TEXT, item_json TEXT);",
             [("INSERT INTO thread_items VALUES (?, ?, ?, ?)", ("t1", "i1", "function_call_output", json.dumps(item)))])
    # Codex's own log holds the tokens of its own login, which nobody leaked
    database(codex / "logs_2.sqlite", "CREATE TABLE logs (ts INTEGER, feedback_log_body TEXT);",
             [("INSERT INTO logs VALUES (?, ?)", (1, f"authorization: Bearer {logged}"))])
    found = scan(["codex"])
    assert set(found) == {prompt, output}
    assert found[prompt].origins == [Origin.PROMPT] and found[prompt].locations[0].project == "/work/api"
    assert found[output].origins == [Origin.TOOL] and found[output].locations[0].session == "t1"


def test_scrub_says_that_a_database_keeps_its_copy(home):
    key = fakes.github()
    home.codex_session(records=[{"type": "response_item", "payload": {
        "type": "message", "role": "user", "content": [{"type": "input_text", "text": f"use {key}"}]}}])
    db = database(home.root / ".codex" / "state_5.sqlite", "CREATE TABLE threads (id TEXT, first_user_message TEXT);",
                  [("INSERT INTO threads VALUES (?, ?)", ("t1", f"use {key}"))])
    result = Scanner(workers=1).scan(build_sources(["codex"]))
    report = scrub(result.findings, include_active=True)
    assert report.replacements == 1
    assert [file for file, _ in report.failed] == [str(db)]
    (row,) = sqlite3.connect(str(db)).execute("SELECT first_user_message FROM threads").fetchall()
    assert key in row[0]  # untouched: the report says so instead of pretending


def test_gemini_sessions_as_jsonl_and_subagents(home):
    key, sub = fakes.google(), fakes.github()
    chats = home.root / ".gemini" / "tmp" / "abc123" / "chats"
    write_jsonl(chats / "session-2026-10-01.jsonl", [
        {"sessionId": "g2", "projectHash": "abc123def4567890"}, {"type": "user", "content": f"key {key}"}])
    write_jsonl(chats / "sub" / "session-agent.jsonl", [{"type": "gemini", "content": f"I will use {sub}"}])
    found = scan(["gemini"])
    assert set(found) == {key, sub}
    assert found[key].origins == [Origin.PROMPT] and found[key].locations[0].session == "g2"


def test_qwen_new_folder(home):
    key = fakes.openrouter()
    write_jsonl(home.root / ".qwen" / "projects" / "app" / "chats" / "s.jsonl", [{"type": "user", "content": key}])
    assert set(scan(["qwen"])) == {key}


def test_opencode_database(home):
    key = fakes.anthropic()
    part = {"type": "tool", "state": {"output": f"ANTHROPIC_API_KEY={key}"}}
    database(home.root / ".local" / "share" / "opencode" / "opencode.db",
             "CREATE TABLE session (id TEXT, directory TEXT); CREATE TABLE part (id TEXT, session_id TEXT, data TEXT);",
             [("INSERT INTO session VALUES (?, ?)", ("ses_1", "/work/app")),
              ("INSERT INTO part VALUES (?, ?, ?)", ("prt_1", "ses_1", json.dumps(part)))])
    (f,) = scan(["opencode"]).values()
    assert f.secret == key and f.origins == [Origin.TOOL] and f.locations[0].session == "ses_1"


def test_copilot_cli_events_and_its_search_database(home, monkeypatch):
    prompt, answer, stored = fakes.github(), fakes.npm(), fakes.sendgrid()
    copilot = home.root / "copilot-home"
    monkeypatch.setenv("COPILOT_HOME", str(copilot))
    write_jsonl(copilot / "session-state" / "s1" / "events.jsonl", [
        {"type": "user.message", "data": {"content": f"use {prompt}"}},
        {"type": "assistant.message", "data": {"content": f"ok, {answer}"}}])
    database(copilot / "session-store.db",
             "CREATE TABLE turns (session_id TEXT, turn_index INTEGER, user_message TEXT, assistant_response TEXT);",
             [("INSERT INTO turns VALUES (?, ?, ?, ?)", ("s1", 0, f"send with {stored}", "done"))])
    found = scan(["copilot"])
    assert set(found) == {prompt, answer, stored}
    assert found[prompt].origins == [Origin.PROMPT] and found[answer].origins == [Origin.ASSISTANT]
    assert found[stored].origins == [Origin.PROMPT]


def test_copilot_chat_in_vs_code(home):
    key, empty = fakes.github(), fakes.stripe()
    user = home.root / "AppData" / "Code" / "User"
    write_jsonl(user / "workspaceStorage" / "0a1b" / "chatSessions" / "c1.jsonl", [
        {"kind": 0, "v": {"requests": []}},
        {"kind": 2, "k": ["requests"], "v": [{"message": {"text": f"why does {key} not work"}}]}])
    write_jsonl(user / "globalStorage" / "emptyWindowChatSessions" / "c2.jsonl", [{"kind": 1, "k": ["x"], "v": empty}])
    found = scan(["copilot-chat"])
    assert set(found) == {key, empty}
    assert found[key].agents == ["copilot-chat"] and found[key].locations[0].session == "c1"


def test_cursor_agent_transcripts(home):
    key = fakes.anthropic()
    write_jsonl(home.root / ".cursor" / "projects" / "work-app" / "agent-transcripts" / "a1" / "a1.jsonl",
                [{"role": "user", "message": {"content": [{"type": "text", "text": f"use {key}"}]}}])
    (f,) = scan(["cursor"]).values()
    assert f.secret == key and f.origins == [Origin.PROMPT]


@pytest.mark.skipif(os.name != "nt", reason="the Microsoft Store only exists on Windows")
def test_claude_desktop_from_the_microsoft_store(home):
    """Store apps get a private copy of %APPDATA% under %LOCALAPPDATA%\\Packages."""
    import spillage.sources as sources

    key = fakes.github()
    roaming = home.root / "AppData" / "Local" / "Packages" / "Claude_abc" / "LocalCache" / "Roaming"
    write_json(roaming / "Claude" / "claude_desktop_config.json",
               {"mcpServers": {"github": {"command": "npx", "env": {"GITHUB_TOKEN": key}}}})
    assert roaming in sources._app_support()
    (f,) = scan(["config"]).values()
    assert f.secret == key and f.origins == [Origin.CONFIG]


def test_a_superseded_session_is_scrubbed_as_the_jsonl_it_is(home):
    """Same care as for a live session: JSON stays valid and a signed thinking block is left alone."""
    from spillage.scrub import scrub_file

    key = fakes.github()
    path = write_jsonl(home.root / ".claude" / "projects" / "-work-app" / "s1.jsonl.superseded-1760000000", [
        {"type": "assistant", "message": {"content": [
            {"type": "thinking", "thinking": f"the key is {key}", "signature": "x" * 300},
            {"type": "text", "text": f"I use {key} and a line\nbreak"}]}}])
    assert scrub_file(path) == 1
    (record,) = (json.loads(line) for line in path.read_text(encoding="utf-8").splitlines())
    assert record["message"]["content"][0]["thinking"] == f"the key is {key}"
    assert key not in record["message"]["content"][1]["text"]


def test_each_database_row_gets_its_own_session(home):
    first, second = fakes.github(), fakes.npm()
    database(home.root / ".codex" / "state_5.sqlite",
             "CREATE TABLE other (thread_id TEXT, note TEXT); CREATE TABLE threads (id TEXT, first_user_message TEXT);",
             [("INSERT INTO other VALUES (?, ?)", ("unrelated", "nothing")),
              ("INSERT INTO threads VALUES (?, ?)", ("t1", f"use {first}")),
              ("INSERT INTO threads VALUES (?, ?)", ("t2", f"use {second}"))])
    found = scan(["codex"])
    assert found[first].locations[0].session == "t1" and found[second].locations[0].session == "t2"


def test_a_table_that_cant_be_read_does_not_hide_the_others(home):
    key = fakes.github()
    try:
        db = database(home.root / ".copilot" / "session-store.db",
                      "CREATE TABLE turns (session_id TEXT, user_message TEXT);"
                      "CREATE VIRTUAL TABLE search_index USING fts5(content, tokenize='porter');",
                      [("INSERT INTO turns VALUES (?, ?)", ("s1", f"use {key}"))])
    except sqlite3.OperationalError:
        pytest.skip("this SQLite has no FTS5")
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA writable_schema=ON")
    conn.execute("UPDATE sqlite_master SET sql = 'CREATE VIRTUAL TABLE search_index USING nosuchmodule(x)' "
                 "WHERE name = 'search_index'")
    conn.commit()
    conn.close()
    assert set(scan(["copilot"])) == {key}


def test_watch_leaves_the_databases_that_repeat_a_jsonl_file(home):
    from spillage.watch import Watcher

    home.codex_session(records=[])
    database(home.root / ".codex" / "state_5.sqlite", "CREATE TABLE threads (id TEXT);")
    database(home.root / ".local" / "share" / "opencode" / "opencode.db", "CREATE TABLE session (id TEXT);")
    watcher = Watcher(build_sources(["codex", "opencode"]))
    watcher.prime()
    names = sorted(path.name for path in watcher.files)
    assert names == ["opencode.db", "rollout-1.jsonl"]
