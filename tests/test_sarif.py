"""SARIF output for code scanning (#48)."""

from __future__ import annotations

import json
import subprocess

import fakes
import pytest

from spillage import __version__
from spillage.cli import main


def sarif_of(capsys, *argv):
    code = main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def test_scan_sarif_is_valid_shape_and_masked(leaky_home, capsys):
    code, data = sarif_of(capsys, "scan", "-f", "sarif")
    assert code == 1 and data["version"] == "2.1.0" and "sarif-2.1.0" in data["$schema"]
    run = data["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "spillage" and driver["version"] == __version__
    ids = {r["id"] for r in driver["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= ids
    for rule in driver["rules"]:
        assert float(rule["properties"]["security-severity"]) > 0
        assert rule["defaultConfiguration"]["level"] in ("error", "warning", "note")
    for result in run["results"]:
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].startswith("file://")
        assert loc["region"]["startLine"] >= 1
        assert result["partialFingerprints"]["spillageSecret/v1"]
    text = json.dumps(data)
    for secret in leaky_home.secrets.values():
        assert secret not in text


def test_one_result_per_place_with_how_it_got_there(leaky_home, capsys):
    _, data = sarif_of(capsys, "scan", "-f", "sarif")
    gh = [r for r in data["runs"][0]["results"] if r["ruleId"].startswith("github")]
    assert len(gh) == 2  # pasted into a Claude prompt and into a Codex prompt
    assert all("you pasted it into a prompt" in r["message"]["text"] for r in gh)


def test_nothing_found_is_an_empty_run(home, capsys):
    code, data = sarif_of(capsys, "scan", "-f", "sarif")
    assert code == 0 and data["runs"][0]["results"] == []


@pytest.fixture
def repo(tmp_path, home):
    root = tmp_path / "shop"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    key = fakes.anthropic()
    hist = root / "app" / ".specstory" / "history"
    hist.mkdir(parents=True)
    (hist / "2026-09-20_fix.md").write_text(f"_**User**_\n\nkey: {key}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    return root, key


def test_repo_sarif_uses_paths_relative_to_the_checkout(repo, capsys, monkeypatch):
    root, key = repo
    monkeypatch.setenv("GITHUB_WORKSPACE", str(root))
    code, data = sarif_of(capsys, "repo", str(root), "-f", "sarif")
    assert code == 1
    uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "app/.specstory/history/2026-09-20_fix.md"
    assert key not in json.dumps(data)


def test_repo_sarif_file_next_to_github_annotations(repo, capsys, monkeypatch, tmp_path):
    root, key = repo
    monkeypatch.setenv("GITHUB_WORKSPACE", str(root))
    out_file = tmp_path / "spillage.sarif"
    assert main(["repo", str(root), "-f", "github", "--sarif", str(out_file)]) == 1
    assert "::error file=app/.specstory/history/2026-09-20_fix.md" in capsys.readouterr().out
    data = json.loads(out_file.read_text())
    assert len(data["runs"][0]["results"]) == 1 and key not in out_file.read_text()


def test_action_passes_the_sarif_input():
    from pathlib import Path

    action = (Path(__file__).parent.parent / "action.yml").read_text()
    assert "sarif:" in action and '--sarif "$SPILLAGE_SARIF"' in action


def test_a_test_key_is_not_rated_like_a_live_one(home, capsys):
    live, test = fakes.stripe(live=True), fakes.stripe(live=False)
    home.claude_session(records=[{"type": "user", "message": {"role": "user", "content": f"{live} or {test}"}}])
    _, data = sarif_of(capsys, "scan", "-f", "sarif")
    rules = {r["id"]: r for r in data["runs"][0]["tool"]["driver"]["rules"]}
    by_rule = {r["ruleId"]: r["level"] for r in data["runs"][0]["results"]}
    assert len(rules) == 2 and len(by_rule) == 2
    severities = sorted(float(r["properties"]["security-severity"]) for r in rules.values())
    assert severities[0] < 4 < severities[1]
    assert sorted(by_rule.values()) == ["error", "note"]


def test_strict_sarif_explains_the_failure(tmp_path, home, capsys, monkeypatch):
    root = tmp_path / "clean"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / ".aider.chat.history.md").write_text("#### hello\n\nhi!\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(root))
    code, data = sarif_of(capsys, "repo", str(root), "--strict", "-f", "sarif")
    results = data["runs"][0]["results"]
    assert code == 1 and [r["ruleId"] for r in results] == ["committed-transcript"]
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".aider.chat.history.md"
    # without --strict a clean transcript isn't a failure, and not an alert either
    code, data = sarif_of(capsys, "repo", str(root), "-f", "sarif")
    assert code == 0 and data["runs"][0]["results"] == []
