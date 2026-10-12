from __future__ import annotations

import json
import os
import subprocess

import fakes
import pytest

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


posix_only = pytest.mark.skipif(os.name != "posix", reason="file modes mean something else on Windows")


@posix_only
def test_log_files_other_users_can_read_are_a_point_with_the_chmod(home, capsys):
    session = home.claude_session(records=[{"type": "user", "message": {"role": "user", "content": "hi"}}])
    folder = home.root / ".claude"
    home.root.chmod(0o755)
    for path in (folder, folder / "projects", session.parent):
        path.chmod(0o755)
    session.chmod(0o644)
    assert main(["doctor", "-f", "json"]) == 1
    assert checks(capsys)["perms"] == {
        "check": "perms", "state": "todo", "text": "1 log file can be read by other users on this machine",
        "fix": "chmod -R go-rwx ~/.claude"}


@posix_only
def test_a_closed_folder_on_the_way_keeps_the_files_private(home, capsys):
    session = home.claude_session(records=[{"type": "user", "message": {"role": "user", "content": "hi"}}])
    home.root.chmod(0o755)
    session.chmod(0o644)
    (home.root / ".claude").chmod(0o700)
    main(["doctor", "-f", "json"])
    assert checks(capsys)["perms"]["state"] == "ok"


@posix_only
def test_a_private_file_in_an_open_folder_is_fine(home, capsys):
    session = home.claude_session(records=[{"type": "user", "message": {"role": "user", "content": "hi"}}])
    home.root.chmod(0o755)
    session.chmod(0o600)
    main(["doctor", "-f", "json"])
    assert checks(capsys)["perms"]["state"] == "ok"


def test_a_folder_with_a_space_is_quoted_whole_so_the_shell_finds_it():
    from spillage import doctor

    path = "/Users/me/Library/Application Support/Code"
    assert doctor._for_shell(path) == f'"{path}"'


def test_exposure_is_decided_from_the_file_and_every_folder_above_it(tmp_path):
    from spillage import doctor

    modes = {"home": 0o755, "home/.claude": 0o755, "home/.claude/s.jsonl": 0o644}
    stat = lambda path: os.stat_result((modes[path.relative_to(tmp_path).as_posix()],) + (0,) * 9)  # noqa: E731
    log, home_dir = tmp_path / "home" / ".claude" / "s.jsonl", tmp_path / "home"
    assert doctor.readable_by_others(log, home_dir, stat)
    modes["home/.claude/s.jsonl"] = 0o640  # your own group may read it: that is not "other users"
    assert not doctor.readable_by_others(log, home_dir, stat)
    modes.update({"home/.claude/s.jsonl": 0o644, "home/.claude": 0o750})
    assert not doctor.readable_by_others(log, home_dir, stat)
    modes.update({"home/.claude": 0o755, "home": 0o750})  # Ubuntu's default home
    assert not doctor.readable_by_others(log, home_dir, stat)


def test_retention_shows_claude_codes_default_and_where_to_change_it(home, capsys):
    home.claude_session(records=[{"type": "user", "message": {"role": "user", "content": "hi"}}])
    main(["doctor", "-f", "json"])
    found = checks(capsys)["retention"]
    assert found["state"] == "info" and found["text"] == "Claude Code keeps transcripts for 30 days (its default)"
    assert "cleanupPeriodDays" in found["fix"]


def test_retention_reads_the_value_from_claude_codes_settings(home, capsys):
    home.claude_session(records=[{"type": "user", "message": {"role": "user", "content": "hi"}}])
    (home.root / ".claude" / "settings.json").write_text(json.dumps({"cleanupPeriodDays": 7}), encoding="utf-8")
    main(["doctor", "-f", "json"])
    assert checks(capsys)["retention"] == {
        "check": "retention", "state": "ok", "text": "Claude Code keeps transcripts for 7 days", "fix": ""}


def test_retention_longer_than_the_default_is_pointed_out_but_not_a_failure(home, capsys):
    home.claude_session(records=[{"type": "user", "message": {"role": "user", "content": "hi"}}])
    (home.root / ".claude" / "settings.json").write_text(json.dumps({"cleanupPeriodDays": 3650}), encoding="utf-8")
    assert main(["guard", "install"]) == 0
    capsys.readouterr()
    assert main(["doctor", "-f", "json"]) == 0
    found = checks(capsys)["retention"]
    assert found["state"] == "info" and found["text"] == "Claude Code keeps transcripts for 3650 days"


def test_no_retention_line_without_claude_code(home, capsys):
    main(["doctor", "-f", "json"])
    assert "retention" not in checks(capsys)
