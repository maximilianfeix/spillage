from __future__ import annotations

import json
import sqlite3
import sys

import fakes
import pytest

from spillage.models import Origin
from spillage.scanner import Scanner
from spillage.scrub import scrub
from spillage.sources import Cursor, build_sources


def app_support(root):
    if sys.platform == "darwin":
        return root / "Library/Application Support"
    if sys.platform == "win32":
        return root / "AppData"
    return root / ".config"


def make_db(path, kv=(), items=()):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
    conn.execute("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
    conn.executemany("INSERT INTO cursorDiskKV VALUES (?, ?)", [(k, json.dumps(v)) for k, v in kv])
    conn.executemany("INSERT INTO ItemTable VALUES (?, ?)", [(k, json.dumps(v)) for k, v in items])
    conn.commit()
    conn.close()
    return path


@pytest.fixture
def cursor_home(home):
    gh, ak, sk = fakes.github(), fakes.anthropic(), fakes.stripe()
    home.secrets = {"github": gh, "anthropic": ak, "stripe": sk}
    make_db(app_support(home.root) / "Cursor/User/globalStorage/state.vscdb", kv=[
        ("composerData:c1", {"composerId": "c1", "blobEncryptionKey": "A" + fakes.rand(43),
                             "name": "deploy"}),
        ("bubbleId:c1:b1", {"type": 1, "text": f"use {gh} to push"}),
        ("bubbleId:c1:b2", {"type": 2, "text": "ok", "toolResults": [{"result": f"KEY={ak}"}]}),
        ("bubbleId:c1:b3", {"type": 2, "text": f"your stripe key is {sk}"}),
        ("cursorAuth/accessToken", "x" + fakes.jwt()),
    ])
    make_db(app_support(home.root) / "Cursor/User/workspaceStorage/abc/state.vscdb",
            items=[("aiService.prompts", [{"text": f"again {gh}", "commandType": 4}])])
    return home


def by_secret(result):
    return {f.secret: f for f in result.findings}


def test_cursor_chats(cursor_home):
    result = Scanner(workers=1).scan(build_sources(["cursor"]))
    found = by_secret(result)
    s = cursor_home.secrets
    assert set(found) == set(s.values())
    assert Origin.PROMPT in found[s["github"]].origins
    assert found[s["anthropic"]].origins == [Origin.TOOL]
    assert found[s["stripe"]].origins == [Origin.ASSISTANT]
    assert "c1" in found[s["github"]].sessions
    assert result.stats.files == 2


def test_only_chat_rows_are_read(cursor_home):
    text = Cursor().load(next(Cursor().discover()))
    assert "cursorAuth" not in text and "EncryptionKey" not in text


def test_broken_database_is_skipped(home):
    path = app_support(home.root) / "Cursor/User/globalStorage/state.vscdb"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"not a database at all")
    result = Scanner(workers=1).scan(build_sources(["cursor"]))
    assert result.findings == []


def test_scrub_leaves_cursor_alone(cursor_home):
    result = Scanner(workers=1).scan(build_sources(["cursor"]))
    report = scrub(result.findings, include_active=True)
    assert report.replacements == 0
    assert any("Cursor" in why for _, why in report.failed)
