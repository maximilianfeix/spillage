from __future__ import annotations

import json
import subprocess

import fakes

from spillage.cli import main


def checks(capsys) -> dict:
    return {c["check"]: c for c in json.loads(capsys.readouterr().out)["checks"]}


def test_clean_machine_without_agents_has_nothing_to_fix(home, capsys):
    assert main(["doctor", "-f", "json"]) == 0
    found = checks(capsys)
    assert found["logs"]["state"] == "info"
    assert found["leaks"]["state"] == "ok"
    assert found["guard"]["state"] == "info"
    assert "repo" not in found  # not inside a git repository


def test_leaks_and_missing_hooks_are_listed_with_their_fix(leaky_home, capsys):
    assert main(["doctor", "-f", "json"]) == 1
    found = checks(capsys)
    assert found["logs"]["state"] == "ok" and "Claude Code" in found["logs"]["text"]
    assert found["leaks"]["state"] == "todo" and found["leaks"]["text"].startswith("4 secrets in the logs")
    assert found["guard"] == {"check": "guard", "state": "todo", "text": "hooks are off for Claude Code, Codex CLI",
                              "fix": "spillage guard install"}


def test_text_output_never_shows_a_secret(leaky_home, capsys):
    assert main(["doctor", "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "✗ leaks" in out and "→ spillage guard install" in out and "2 to fix." in out
    for secret in leaky_home.secrets.values():
        assert secret not in out


def test_all_good_after_scrub_and_guard_install(leaky_home, capsys):
    assert main(["scrub", "--yes", "--include-active"]) == 0
    assert main(["guard", "install"]) == 0
    capsys.readouterr()
    assert main(["doctor", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "All good." in out and "✗" not in out


def test_keys_in_agent_settings_are_their_own_point(home, capsys):
    token = fakes.github()
    (home.root / ".claude.json").write_text(json.dumps(
        {"mcpServers": {"github": {"command": "npx", "env": {"GITHUB_TOKEN": token}}}}), encoding="utf-8")
    assert main(["doctor", "-f", "json"]) == 1
    found = checks(capsys)
    assert found["settings"]["state"] == "todo" and found["settings"]["text"].startswith("1 key in plain text")
    assert found["leaks"]["state"] == "ok"


def test_committed_transcript_in_the_current_repository(home, tmp_path, monkeypatch, capsys):
    repo = tmp_path / "project"
    (repo / ".specstory" / "history").mkdir(parents=True)
    (repo / ".specstory" / "history" / "chat.md").write_text("# a chat\n", encoding="utf-8")
    for cmd in (["init", "-q"], ["add", "-A"]):
        subprocess.run(["git", *cmd], cwd=repo, check=True, capture_output=True)
    monkeypatch.chdir(repo)
    assert main(["doctor", "-f", "json"]) == 1
    assert checks(capsys)["repo"]["text"] == "1 agent transcript committed in this repository"
