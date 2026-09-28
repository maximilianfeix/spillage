from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import fakes


def write_jsonl(path: Path, records) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    return path


def write_json(path: Path, data, indent=2) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=indent), encoding="utf-8")
    return path


class FakeHome:
    """A throwaway home directory with agent logs laid out the way the real agents do it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.secrets: dict = {}

    def claude_session(self, name="s1", project="/work/app", records=None) -> Path:
        path = self.root / ".claude" / "projects" / project.replace("/", "-") / f"{name}.jsonl"
        base = {"sessionId": name, "cwd": project, "timestamp": "2026-09-20T10:00:00Z"}
        return write_jsonl(path, [dict(base, **r) for r in (records or [])])

    def codex_session(self, name="rollout-1", cwd="/work/api", records=()) -> Path:
        path = self.root / ".codex" / "sessions" / "2026" / "09" / "20" / f"{name}.jsonl"
        meta = {"timestamp": "2026-09-20T11:00:00Z", "type": "session_meta", "payload": {"id": name, "cwd": cwd}}
        return write_jsonl(path, [meta] + list(records))

    def gemini_chat(self, records) -> Path:
        path = self.root / ".gemini" / "tmp" / "abc123" / "chats" / "session-1.json"
        return write_json(path, {"sessionId": "g1", "projectHash": "abc123def4567890", "messages": records})


@pytest.fixture
def home(tmp_path, monkeypatch) -> FakeHome:
    root = tmp_path / "home"
    root.mkdir()
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.setenv("USERPROFILE", str(root))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(root / ".local" / "share"))
    monkeypatch.setenv("APPDATA", str(root / "AppData"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: root))
    return FakeHome(root)


@pytest.fixture
def leaky_home(home: FakeHome) -> FakeHome:
    """A home with one secret per origin across three agents."""
    gh, ak, sg = fakes.github(), fakes.anthropic(), fakes.sendgrid()
    pk = fakes.private_key()
    home.secrets = {"github": gh, "anthropic": ak, "sendgrid": sg, "private_key": pk}
    home.claude_session(records=[
        {"type": "user", "message": {"role": "user", "content": f"deploy with token {gh} please"}},
        {"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/work/app/.env"}}]}},
        {"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": f"ANTHROPIC_API_KEY={ak}\nDEBUG=1"}]},
         "toolUseResult": {"file": {"content": f"ANTHROPIC_API_KEY={ak}\nDEBUG=1"}}},
        {"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "text", "text": "I found your key and the deploy key:\n" + pk}]}},
    ])
    home.codex_session(records=[
        {"timestamp": "2026-09-20T11:01:00Z", "type": "response_item",
         "payload": {"type": "function_call_output", "call_id": "c1", "output": f"SENDGRID={sg}"}},
        {"timestamp": "2026-09-20T11:02:00Z", "type": "response_item",
         "payload": {"type": "message", "role": "user",
                     "content": [{"type": "input_text", "text": f"why is {gh} not working"}]}},
    ])
    return home
