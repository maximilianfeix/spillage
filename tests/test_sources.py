from __future__ import annotations

import base64

import fakes
import pytest
from conftest import write_json, write_jsonl

from spillage.models import Origin
from spillage.scanner import Scanner
from spillage.sources import PathSource, all_sources, build_sources, get_source


def scan(home, agents=None, paths=None):
    return Scanner(workers=1).scan(build_sources(agents, paths, home.root))


def by_secret(result):
    return {f.secret: f for f in result.findings}


def test_every_agent_is_registered():
    names = [cls.name for cls in all_sources()]
    assert names[:3] == ["claude", "codex", "gemini"]
    assert len(names) == len(set(names))
    with pytest.raises(ValueError, match="unknown agent"):
        get_source("nope")


def test_claude_origins(leaky_home):
    found = by_secret(scan(leaky_home, ["claude"]))
    s = leaky_home.secrets
    assert found[s["github"]].origins == [Origin.PROMPT]
    assert found[s["anthropic"]].origins == [Origin.TOOL]
    assert found[s["private_key"]].origins == [Origin.ASSISTANT]
    loc = found[s["github"]].locations[0]
    assert (loc.agent, loc.session, loc.project, loc.line) == ("claude", "s1", "/work/app", 1)
    assert loc.json_path == "message.content"
    assert loc.timestamp.startswith("2026-09-20")


def test_codex_origins_and_session_meta(leaky_home):
    found = by_secret(scan(leaky_home, ["codex"]))
    sg = found[leaky_home.secrets["sendgrid"]]
    assert sg.origins == [Origin.TOOL]
    assert sg.locations[0].session == "rollout-1"
    assert sg.locations[0].project == "/work/api"
    assert found[leaky_home.secrets["github"]].origins == [Origin.PROMPT]


def test_same_secret_across_agents_is_one_finding(leaky_home):
    result = scan(leaky_home)
    gh = by_secret(result)[leaky_home.secrets["github"]]
    assert gh.agents == ["claude", "codex"]
    assert len(gh.sessions) == 2
    assert len(result.findings) == 4


def test_gemini_chat(home):
    key = fakes.google()
    home.gemini_chat([
        {"type": "user", "content": f"use {key}"},
        {"type": "gemini", "content": "ok", "toolCalls": [{"name": "shell", "result": "nothing"}]},
    ])
    (f,) = scan(home, ["gemini"]).findings
    assert f.secret == key
    assert f.origins == [Origin.PROMPT]
    assert f.locations[0].session == "g1"


def test_opencode_and_cline_and_continue(home):
    tok = fakes.npm()
    write_json(home.root / ".local/share/opencode/storage/part/ses_1/msg_1/prt_1.json",
               {"sessionID": "ses_1", "type": "tool", "state": {"output": f"//registry/:_authToken={tok}"}})
    cline_task = home.root / "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/42"
    write_json(cline_task / "api_conversation_history.json",
               [{"role": "user", "content": [{"type": "text", "text": f"npm token {tok}"}]}])
    write_json(home.root / ".continue/sessions/abc.json", {"history": [{"message": {"role": "user", "content": tok}}]})
    import sys
    if sys.platform == "darwin":
        (f,) = scan(home, ["opencode", "cline", "continue"]).findings
        assert f.agents == ["cline", "continue", "opencode"]
        assert "42" in f.sessions
    else:
        (f,) = scan(home, ["opencode", "continue"]).findings
        assert f.agents == ["continue", "opencode"]
    assert Origin.TOOL in f.origins


def test_base64_images_and_signatures_are_skipped(home):
    blob = base64.b64encode(("AKIA" + "Q" * 16 + " ").encode() * 30).decode()
    fake_key = "AKIA" + fakes.rand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    home.claude_session(records=[
        {"type": "user", "message": {"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": fake_key + blob}}]}},
        {"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "hm", "signature": fake_key + blob}]}},
    ])
    assert scan(home, ["claude"]).findings == []


def test_broken_json_lines_still_get_scanned(home):
    gh = fakes.github()
    path = home.root / ".claude/projects/x/s.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text('{"type": "user", "message": {"content": "' + gh + '"', encoding="utf-8")  # cut off
    (f,) = scan(home, ["claude"]).findings
    assert f.origins == [Origin.OTHER]


def test_claude_file_history_and_paste_cache(home):
    key = fakes.stripe()
    fh = home.root / ".claude/file-history/sess-9/abc123@v2"
    fh.parent.mkdir(parents=True)
    fh.write_text(f"STRIPE_KEY={key}\n", encoding="utf-8")
    (f,) = scan(home, ["claude"]).findings
    assert f.origins == [Origin.FILE]
    assert f.locations[0].line == 1


def test_claude_history_file(home):
    key = fakes.huggingface()
    write_jsonl(home.root / ".claude/history.jsonl", [{"display": f"login with {key}", "pastedContents": {}}])
    (f,) = scan(home, ["claude"]).findings
    assert f.origins == [Origin.HISTORY]


def test_claude_config_dir_env(home, tmp_path, monkeypatch):
    other = tmp_path / "elsewhere"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(other))
    write_jsonl(other / "projects/p/s.jsonl", [{"type": "user", "message": {"content": fakes.npm()}}])
    assert len(scan(home, ["claude"]).findings) == 1


def test_path_source_scans_any_file_or_folder(home, tmp_path):
    folder = tmp_path / "logs"
    folder.mkdir()
    (folder / "notes.md").write_text(f"token {fakes.github()}", encoding="utf-8")
    write_jsonl(folder / "chat.jsonl", [{"role": "user", "content": fakes.npm()}])
    (folder / "image.png").write_bytes(b"\x89PNG\x00\x00" + fakes.github().encode())
    result = Scanner(workers=1).scan([PathSource([folder])])
    assert len(result.findings) == 2
    assert {f.agents[0] for f in result.findings} == {"path"}


def test_no_logs_at_all(home):
    result = scan(home)
    assert result.findings == [] and result.stats.files == 0


def test_symlinks_are_not_followed(home, tmp_path):
    outside = tmp_path / "outside.jsonl"
    write_jsonl(outside, [{"content": fakes.github()}])
    link = home.root / ".claude/projects/p/link.jsonl"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("no symlinks here")
    assert scan(home, ["claude"]).stats.files == 0
