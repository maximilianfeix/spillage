from __future__ import annotations

import json
import sqlite3

import fakes
from conftest import write_json, write_jsonl

from spillage.models import Origin
from spillage.scanner import Scanner
from spillage.sources import build_sources


def scan(agents):
    return {f.secret: f for f in Scanner(workers=1).scan(build_sources(agents)).findings}


def test_qwen_code(home):
    key = fakes.openrouter()
    write_json(home.root / ".qwen/tmp/abc/chats/session-1.json",
               {"sessionId": "q1", "messages": [{"type": "user", "content": f"key {key}"}]})
    (f,) = scan(["qwen"]).values()
    assert f.secret == key and f.origins == [Origin.PROMPT] and f.agents == ["qwen"]


def test_goose_sqlite(home):
    key, sk = fakes.anthropic(), fakes.stripe()
    db = home.root / ".local/share/goose/sessions/sessions.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE sessions (id TEXT, working_dir TEXT, description TEXT)")
    conn.execute("CREATE TABLE messages (session_id TEXT, role TEXT, content_json TEXT, blob BLOB)")
    conn.execute("INSERT INTO sessions VALUES ('20260920_1', '/work/app', 'deploy')")
    conn.execute("INSERT INTO messages VALUES (?, ?, ?, ?)",
                 ("20260920_1", "user", json.dumps([{"type": "text", "text": f"use {key}"}]), b"\x00\xff\xfe"))
    conn.execute("INSERT INTO messages VALUES (?, ?, ?, ?)",
                 ("20260920_1", "user", json.dumps([{"type": "toolResponse", "toolResult": {"output": sk}}]), None))
    conn.commit()
    conn.close()
    found = scan(["goose"])
    assert found[key].origins == [Origin.PROMPT]
    assert found[key].locations[0].session == "20260920_1"
    assert Origin.TOOL in found[sk].origins or Origin.PROMPT in found[sk].origins


def test_goose_jsonl(home):
    key = fakes.npm()
    write_jsonl(home.root / ".config/goose/sessions/20250921_143022.jsonl",
                [{"working_dir": "/w"}, {"role": "user", "content": [{"type": "text", "text": key}]}])
    (f,) = scan(["goose"]).values()
    assert f.secret == key and f.origins == [Origin.PROMPT]


def test_crush_per_project(home, tmp_path, monkeypatch):
    proj = tmp_path / "api"
    (proj / ".crush").mkdir(parents=True)
    reg = home.root / ".local/share/crush/projects.json"
    reg.parent.mkdir(parents=True)
    reg.write_text(json.dumps({"projects": [{"path": str(proj)}]}))
    monkeypatch.chdir(home.root)
    key = fakes.github()
    conn = sqlite3.connect(str(proj / ".crush/crush.db"))
    conn.execute("CREATE TABLE messages (session_id TEXT, role TEXT, parts TEXT)")
    parts = json.dumps([{"type": "text", "data": {"text": key}}])
    conn.execute("INSERT INTO messages VALUES ('s9', 'user', ?)", (parts,))
    conn.commit()
    conn.close()
    (f,) = scan(["crush"]).values()
    assert f.secret == key and f.locations[0].session == "s9" and f.locations[0].project == str(proj)
