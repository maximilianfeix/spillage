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
    assert "isn't a git repository" in capsys.readouterr().err


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
