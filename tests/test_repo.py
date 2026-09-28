from __future__ import annotations

import json
import subprocess

import fakes
import pytest

from spillage.cli import main
from spillage.repo import scan_repo, transcript_agent


@pytest.fixture
def repo(tmp_path, home):
    root = tmp_path / "shop"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    key, gh = fakes.anthropic(), fakes.github()
    hist = root / ".specstory" / "history"
    hist.mkdir(parents=True)
    (hist / "2026-09-20_fix.md").write_text(f"_**User**_\n\nkey: {key}\n", encoding="utf-8")
    (root / ".aider.chat.history.md").write_text("#### hello\n\nhi!\n", encoding="utf-8")
    (root / "app.py").write_text(f'TOKEN = "{gh}"\n', encoding="utf-8")
    (root / "untracked.aider.chat.history.md").write_text(f"#### {gh}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", ".specstory", ".aider.chat.history.md", "app.py"], check=True)
    return root, key, gh


@pytest.mark.parametrize("path,agent", [
    (".specstory/history/2026-09-20_fix.md", "specstory"),
    ("packages/web/.specstory/history/a.md", "specstory"),
    (".aider.chat.history.md", "aider"),
    ("sub/.aider.input.history", "aider"),
    (".claude/transcript.jsonl", "claude"),
    ("logs/rollout-2026-09-20T10-00-00-abc.jsonl", "codex"),
    ("src/main.py", None),
    ("docs/specstory.md", None),
])
def test_transcript_patterns(path, agent):
    assert transcript_agent(path) == agent


def test_scan_repo(repo):
    root, key, _gh = repo
    result = scan_repo(root)
    assert result.transcripts == {".specstory/history/2026-09-20_fix.md": "specstory",
                                  ".aider.chat.history.md": "aider"}
    assert [f.secret for f in result.findings] == [key]
    assert result.findings[0].origins == ["prompt"]


def test_all_files(repo):
    root, key, gh = repo
    secrets = {f.secret for f in scan_repo(root, all_files=True).findings}
    assert secrets == {key, gh}


def test_only_given_files(repo, monkeypatch):
    root, _, _ = repo
    monkeypatch.chdir(root)
    result = scan_repo(root, files=[".aider.chat.history.md"])
    assert list(result.transcripts) == [".aider.chat.history.md"] and result.findings == []


def test_not_a_repo(tmp_path, capsys):
    assert main(["repo", str(tmp_path)]) == 2
    assert "not a git repository" in capsys.readouterr().err


def test_cli_text(repo, capsys):
    root, key, _ = repo
    assert main(["repo", str(root), "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "2 agent transcripts are committed" in out and "Anthropic API key" in out
    assert "git history" in out and key not in out


def test_cli_github_format(repo, capsys, tmp_path, monkeypatch):
    root, key, _ = repo
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(root))
    assert main(["repo", str(root), "-f", "github", "--strict"]) == 1
    out = capsys.readouterr().out
    assert "::error file=.specstory/history/2026-09-20_fix.md,line=3,title=spillage: Anthropic API key::" in out
    assert "::warning file=.aider.chat.history.md" in out
    assert key not in out
    assert "| critical | Anthropic API key |" in summary.read_text()


def test_cli_json(repo, capsys):
    root, _, _ = repo
    main(["repo", str(root), "-f", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["transcripts"][".aider.chat.history.md"] == "aider"
    assert data["findings"][0]["locations"][0]["file"] == ".specstory/history/2026-09-20_fix.md"


def test_strict_fails_on_clean_transcripts(repo, capsys, monkeypatch):
    root, _, _ = repo
    monkeypatch.chdir(root)
    assert main(["repo", "--files", ".aider.chat.history.md"]) == 0
    assert main(["repo", "--strict", "--files", ".aider.chat.history.md"]) == 1


def test_clean_repo(tmp_path, home, capsys):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    assert main(["repo", str(tmp_path)]) == 0
    assert "No agent transcripts committed" in capsys.readouterr().out


def test_precommit_regex_matches_the_code():
    from pathlib import Path

    from spillage.repo import HOOK_REGEX, TRANSCRIPT_REGEX

    text = (Path(__file__).parent.parent / ".pre-commit-hooks.yaml").read_text()
    hooks = text.split("\n- id: ")
    assert "  files: '" + HOOK_REGEX.replace("'", "''") + "'" in hooks[1]  # spillage: transcripts + settings
    assert "  files: '" + TRANSCRIPT_REGEX.replace("'", "''") + "'" in hooks[2]  # no-agent-transcripts


@pytest.mark.parametrize("path", [
    "data/rollout-metrics-2026.jsonl",
    "docs/cline_task_template.md",
    "x/specstory/history/a.md",
    "notes/.aider.chat.history.md.bak",
])
def test_lookalikes_are_not_transcripts(path):
    assert transcript_agent(path) is None


@pytest.mark.parametrize("path,agent", [
    ("pkg/.claude/session.jsonl", "claude"),
    ("sessions/rollout-2026-09-20T10-00-00-01a0e697-162b-7503.jsonl", "codex"),
    ("tasks/api_conversation_history.json", "cline"),
    ("cline_task_sep-28-2026_10-00-00-am.md", "cline"),
    (".codex/history.jsonl", "codex"),
])
def test_more_transcripts(path, agent):
    assert transcript_agent(path) == agent


def test_files_outside_the_repo_are_skipped(repo, tmp_path, monkeypatch):
    root, _, _ = repo
    outside = tmp_path / ".aider.chat.history.md"
    outside.write_text("#### hi\n")
    monkeypatch.chdir(tmp_path)
    result = scan_repo(root, files=[".aider.chat.history.md"])
    assert result.transcripts == {}


def test_repo_ignore_file(repo, capsys):
    from spillage.models import fingerprint

    root, key, _ = repo
    (root / ".spillageignore").write_text(fingerprint(key) + "  # test fixture\n")
    assert main(["repo", str(root)]) == 0


def test_github_paths_relative_to_workspace(repo, capsys, tmp_path, monkeypatch):
    root, _, _ = repo
    monkeypatch.setenv("GITHUB_WORKSPACE", str(root.parent))
    out_file = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    main(["repo", str(root), "-f", "github", "--all-files"])
    out = capsys.readouterr().out
    assert f"::error file={root.name}/.specstory/history/2026-09-20_fix.md" in out
    assert "is in a committed file" in out and "app.py" in out
    assert out_file.read_text() == "transcripts=2\nsecrets=2\n"


def test_git_error_is_explained(tmp_path, capsys, monkeypatch):
    import subprocess as sp

    from spillage import repo as repo_mod

    def fake_run(*a, **k):
        return sp.CompletedProcess(a, 128, b"", b"fatal: detected dubious ownership in repository")

    monkeypatch.setattr(repo_mod.subprocess, "run", fake_run)
    assert main(["repo", str(tmp_path)]) == 2
    assert "dubious ownership" in capsys.readouterr().err


def test_strict_explains_itself(repo, capsys, monkeypatch):
    root, _, _ = repo
    monkeypatch.chdir(root)
    assert main(["repo", "--strict", "--files", ".aider.chat.history.md", "--no-color"]) == 1
    assert "--strict" in capsys.readouterr().out


@pytest.mark.parametrize("path,hit", [
    (".mcp.json", True), ("packages/api/.mcp.json", True), (".claude/settings.json", True),
    (".claude/settings.local.json", True), (".cursor/mcp.json", True), (".vscode/mcp.json", True),
    ("opencode.json", True), ("docs/mcp.json", False), (".claude/settings.yaml", False),
])
def test_settings_patterns(path, hit):
    from spillage.repo import is_settings

    assert is_settings(path) is hit


def test_committed_mcp_json_is_scanned_but_not_a_transcript(tmp_path, home):
    root = tmp_path / "tool"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    gh = fakes.github()
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": gh}}}}), encoding="utf-8")
    (root / ".claude").mkdir()
    (root / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"allow": ["Bash(npm test)"]}}),
                                                     encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    result = scan_repo(root)
    assert result.transcripts == {}
    assert [f.secret for f in result.findings] == [gh]
    assert result.findings[0].locations[0].origin == "config"
    # a clean committed settings file is fine, even with --strict
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}),
                                    encoding="utf-8")
    assert main(["repo", "--strict", str(root)]) == 0
