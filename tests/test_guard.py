from __future__ import annotations

import io
import json
import subprocess
import sys

import fakes
import pytest

from spillage import guard
from spillage.cli import main

# ---- deciding ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    ".env", "/app/.env", "/app/.env.local", "/app/.env.production", "prod.env", "~/.aws/credentials",
    "/home/me/.ssh/id_ed25519", "C:\\Users\\me\\.ssh\\id_rsa", "server.pem", "tls.key", ".npmrc",
    ".git-credentials", "/app/secrets.yaml", "service-account-prod.json", "prod.tfvars",
    "/Users/me/.docker/config.json", ".kube/config",
])
def test_secret_files(path):
    assert guard.is_secret_file(path)


@pytest.mark.parametrize("path", [
    ".env.example", ".env.sample", "/app/.env.template", "id_ed25519.pub", "README.md", "src/env.py",
    "environment.ts", "keys.py", "/app/config.json", "credentials_test.go", ".envrc.example",
])
def test_not_secret_files(path):
    assert not guard.is_secret_file(path)


@pytest.mark.parametrize("command", [
    "cat .env", "cat /app/.env.local | grep KEY", "head -5 ~/.aws/credentials", "less config/secrets.yml",
    "printenv", "env", "env | sort", "export -p", "gh auth token", "sudo cat /etc/ssl/private/server.key",
    "grep API .env", "rg -n TOKEN .env.production", "source .env && echo $KEY",
    "security find-generic-password -s github -w", "aws configure get aws_secret_access_key",
    "cat /proc/self/environ", "echo $(cat .env)", "python3 -c 'print(1)' < .env",
    "printenv OPENAI_API_KEY", "echo $STRIPE_SECRET_KEY", 'echo "token: ${GITHUB_TOKEN}"', "cat .ENV", "cat<.env",
    """python -c "print(open('.env').read())\"""", "xargs cat < .env", "Get-Content .env", "gci env:",
    "Get-ChildItem Env:", "Write-Output $env:OPENAI_API_KEY", "$env:ANTHROPIC_API_KEY",
])
def test_risky_commands(command):
    assert guard.risky_command(command)


@pytest.mark.parametrize("command", [
    "ls -la", "cat README.md", "env FOO=1 npm test", "set -euo pipefail", "cp .env.example .env",
    "git status", "printenv HOME", "grep -r TODO src", "echo 'API_KEY=' >> .env.example", "npm run dev",
    "grep -rn credentials src/", "rg secrets.json", "echo $HOME", "printenv PATH", "python manage.py migrate",
    'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user', "python -c 'import json'",
    "$env:PATH", "ls env/",
])
def test_harmless_commands(command):
    assert guard.risky_command(command) is None


def test_prompt_with_secret_is_blocked():
    code, msg = guard.handle("prompt", {"prompt": f"use {fakes.github()} for the api"})
    assert code == 2
    assert "GitHub token" in msg and "environment variable" in msg


def test_prompt_message_is_masked():
    key = fakes.anthropic()
    _, msg = guard.handle("prompt", {"prompt": key})
    assert key not in msg and key[:6] in msg


def test_prompt_allow_word():
    assert guard.handle("prompt", {"prompt": f"{fakes.github()} {guard.ALLOW_WORD}"}) == (0, "")


def test_clean_prompt_passes():
    assert guard.handle("prompt", {"prompt": "refactor the login page"}) == (0, "")


@pytest.mark.parametrize("tool,tool_input,blocked", [
    ("Read", {"file_path": "/app/.env"}, True),
    ("Read", {"file_path": "/app/.env.example"}, False),
    ("Read", {"file_path": "/app/main.py"}, False),
    ("Grep", {"pattern": "KEY", "path": "/app/.env"}, True),
    ("Grep", {"pattern": "KEY", "glob": "*.pem"}, True),
    ("Grep", {"pattern": "KEY", "path": "/app/src"}, False),
    ("Bash", {"command": "cat .env"}, True),
    ("Bash", {"command": "pytest -q"}, False),
    ("Edit", {"file_path": "/app/.env"}, False),
    ("Read", "not a dict", False),
])
def test_tool_decisions(tool, tool_input, blocked):
    code, msg = guard.handle("tool", {"tool_name": tool, "tool_input": tool_input})
    assert (code == 2) is blocked
    assert bool(msg) is blocked


def test_unknown_event():
    with pytest.raises(ValueError):
        guard.handle("other", {})


def test_run_hook_tolerates_garbage():
    assert guard.run_hook("prompt", io.StringIO("not json"), io.StringIO()) == 0
    assert guard.run_hook("prompt", io.StringIO("[1,2]"), io.StringIO()) == 0
    assert guard.run_hook("tool", io.StringIO(""), io.StringIO()) == 0


def test_run_hook_as_a_real_process():
    """The way Claude Code calls it: JSON on stdin, exit code 2 and a reason on stderr."""
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cat .env"}}
    proc = subprocess.run(
        [sys.executable, "-m", "spillage", "hook", "tool"],
        input=json.dumps(event), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 2
    assert "spillage blocked" in proc.stderr


# ---- installing -------------------------------------------------------------------------

def test_install_into_empty_settings(tmp_path):
    path = tmp_path / "settings.json"
    assert guard.install(path)
    data = json.loads(path.read_text())
    command = data["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
    assert guard.is_hook_command(command) and command.endswith("hook prompt")
    assert data["hooks"]["PreToolUse"][0]["matcher"] == guard.TOOL_MATCHER
    assert guard.status(path) == {"UserPromptSubmit": True, "PreToolUse": True, "SessionEnd": True}
    assert "session-end" in data["hooks"]["SessionEnd"][0]["hooks"][0]["command"]


def test_install_keeps_other_settings_and_hooks(tmp_path):
    path = tmp_path / "settings.json"
    other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}
    path.write_text(json.dumps({"model": "opus", "hooks": {"PreToolUse": [other]}}))
    guard.install(path)
    data = json.loads(path.read_text())
    assert data["model"] == "opus"
    assert data["hooks"]["PreToolUse"][0] == other and len(data["hooks"]["PreToolUse"]) == 2
    assert (tmp_path / "settings.json.spillage-backup").exists()


def test_install_is_idempotent(tmp_path):
    path = tmp_path / "settings.json"
    assert guard.install(path)
    before = path.read_text()
    assert not guard.install(path)
    assert path.read_text() == before


def test_uninstall_leaves_the_rest(tmp_path):
    path = tmp_path / "settings.json"
    other = {"hooks": [{"type": "command", "command": "notify-me"}]}
    path.write_text(json.dumps({"theme": "dark", "hooks": {"UserPromptSubmit": [other]}}))
    guard.install(path)
    assert guard.uninstall(path)
    data = json.loads(path.read_text())
    assert data == {"theme": "dark", "hooks": {"UserPromptSubmit": [other]}}
    assert not guard.uninstall(path)


def test_uninstall_removes_empty_hooks(tmp_path):
    path = tmp_path / "settings.json"
    guard.install(path)
    guard.uninstall(path)
    assert json.loads(path.read_text()) == {}


def test_broken_settings_are_not_touched(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{ nope")
    with pytest.raises(ValueError, match="not valid JSON"):
        guard.install(path)
    assert path.read_text() == "{ nope"


def test_settings_scopes(tmp_path, home):
    assert guard.settings_path("user") == home.root / ".claude" / "settings.json"
    assert guard.settings_path("project", tmp_path) == tmp_path / ".claude" / "settings.json"
    assert guard.settings_path("local", tmp_path) == tmp_path / ".claude" / "settings.local.json"
    with pytest.raises(ValueError):
        guard.settings_path("global")


def test_cli_guard_roundtrip(home, capsys):
    assert main(["guard", "status"]) == 1
    assert main(["guard", "install"]) == 0  # nothing installed: falls back to Claude Code
    assert "Claude Code  guard installed" in capsys.readouterr().out
    assert main(["guard", "install", "--agent", "claude"]) == 0
    assert "already installed" in capsys.readouterr().out
    assert main(["guard", "status", "--agent", "claude"]) == 0
    assert main(["guard", "uninstall"]) == 0
    assert "guard removed" in capsys.readouterr().out


def test_cli_guard_installs_every_agent_it_finds(home, capsys):
    (home.root / ".codex").mkdir()
    (home.root / ".gemini").mkdir()
    assert main(["guard", "install"]) == 0
    out = capsys.readouterr().out
    assert "Codex CLI" in out and "Gemini CLI" in out and "Claude Code" not in out
    codex = json.loads((home.root / ".codex/hooks.json").read_text())
    assert set(codex["hooks"]) == {"UserPromptSubmit", "PreToolUse", "SessionEnd"}
    gemini = json.loads((home.root / ".gemini/settings.json").read_text())
    assert set(gemini["hooks"]) == {"BeforeAgent", "BeforeTool", "SessionEnd"}
    assert "run_shell_command" in gemini["hooks"]["BeforeTool"][0]["matcher"]
    assert main(["guard", "status", "--agent", "codex,gemini"]) == 0


def test_cli_guard_unknown_agent(home, capsys):
    assert main(["guard", "install", "--agent", "cursor"]) == 2
    assert "guard supports" in capsys.readouterr().err


def test_gemini_keeps_its_other_settings(home):
    path = home.root / ".gemini/settings.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"theme": "GitHub", "selectedAuthType": "oauth-personal"}))
    guard.install(guard.settings_path(agent="gemini"), "gemini")
    data = json.loads(path.read_text())
    assert data["theme"] == "GitHub" and "BeforeAgent" in data["hooks"]
    guard.uninstall(path)
    assert json.loads(path.read_text()) == {"theme": "GitHub", "selectedAuthType": "oauth-personal"}


@pytest.mark.parametrize("tool,tool_input", [
    ("read_file", {"absolute_path": "/app/.env"}),
    ("read_file", {"file_path": "/app/.env.local"}),
    ("read_many_files", {"paths": ["src/a.py", ".env"]}),
    ("run_shell_command", {"command": "cat .env"}),
    ("search_file_content", {"pattern": "KEY", "include": "*.pem"}),
    ("Bash", {"command": ["bash", "-lc", "printenv"]}),
    ("mcp__filesystem__read_file", {"path": "/home/me/.aws/credentials"}),
])
def test_other_agents_tool_names(tool, tool_input):
    assert guard.handle("tool", {"tool_name": tool, "tool_input": tool_input})[0] == 2


def test_session_end_scrubs_gemini_json(home):
    key = fakes.google()
    path = home.gemini_chat([{"type": "user", "content": f"use {key}"}])
    guard.handle("session-end", {"transcript_path": str(path)})
    assert key not in path.read_text()
    json.loads(path.read_text())


def test_cli_hook(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"prompt": fakes.npm()})))
    assert main(["hook", "prompt"]) == 2
    assert "npm access token" in capsys.readouterr().err


# ---- session end ------------------------------------------------------------------------

def test_session_end_scrubs_the_transcript(home, tmp_path):
    gh = fakes.github()
    t = home.claude_session(records=[
        {"type": "queue-operation", "operation": "enqueue", "content": f"deploy with {gh}"},
        {"type": "user", "message": {"content": "hello"}},
    ])
    assert guard.handle("session-end", {"transcript_path": str(t)}) == (0, "")
    text = t.read_text()
    assert gh not in text and "[REDACTED:github-token:" in text
    for line in text.splitlines():
        json.loads(line)


def test_session_end_respects_the_ignore_list(home):
    from spillage.models import fingerprint
    from spillage.scanner import add_ignore

    gh = fakes.github()
    add_ignore([fingerprint(gh)])
    t = home.claude_session(records=[{"type": "user", "message": {"content": gh}}])
    guard.handle("session-end", {"transcript_path": str(t)})
    assert gh in t.read_text()


@pytest.mark.parametrize("payload", [{}, {"transcript_path": 5}, {"transcript_path": "/nope/x.jsonl"},
                                     {"transcript_path": "/etc/hosts"}])
def test_session_end_ignores_odd_payloads(payload):
    assert guard.handle("session-end", payload) == (0, "")


def test_blocked_prompts_count_as_prompts(home):
    from spillage.models import Origin
    from spillage.scanner import Scanner
    from spillage.sources import build_sources

    home.claude_session(records=[{"type": "queue-operation", "operation": "enqueue", "content": fakes.npm()}])
    (f,) = Scanner(workers=1).scan(build_sources(["claude"])).findings
    assert f.origins == [Origin.PROMPT]


def test_hook_command_prefers_the_launcher(monkeypatch, tmp_path):
    launcher = tmp_path / "bin with space" / "spillage"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\n")
    monkeypatch.setattr(guard.shutil, "which", lambda name: str(launcher))
    assert guard.hook_command("prompt") == f'"{launcher.resolve()}" hook prompt'
    monkeypatch.setattr(guard.shutil, "which", lambda name: None)
    assert guard.hook_command("tool").endswith("-m spillage hook tool")
    assert guard.MARK in guard.hook_command("tool")


@pytest.mark.parametrize("command", [
    "spillage hook prompt",
    "/opt/homebrew/bin/spillage hook tool",
    '"/Users/me/bin with space/spillage" hook session-end',
    "/usr/bin/python3 -m spillage hook prompt",
    r"C:\Python314\Scripts\spillage.exe hook prompt",
    r'"C:\Program Files\Python314\Scripts\spillage.exe" hook tool',
    r'"C:\Program Files\Python314\python.exe" -m spillage hook session-end',
])
def test_hook_commands_are_recognised(command):
    assert guard.is_hook_command(command)


@pytest.mark.parametrize("command", ["echo spillage", "my-spillage hook prompt", "spillage scan", "npx prettier"])
def test_other_commands_are_not_ours(command):
    assert not guard.is_hook_command(command)


def test_windows_launcher_install_is_idempotent(tmp_path, monkeypatch):
    launcher = r"C:\Python314\Scripts\spillage.exe"
    monkeypatch.setattr(guard, "hook_command", lambda event: f"{launcher} hook {event}")
    path = tmp_path / "settings.json"
    assert guard.install(path)
    assert not guard.install(path)
    assert all(guard.status(path).values())
    assert guard.uninstall(path)
    assert json.loads(path.read_text()) == {}


def test_install_warns_when_the_hook_cannot_run(home, capsys, monkeypatch):
    monkeypatch.setattr(guard, "hook_command", lambda event: "definitely-not-a-command-xyz hook prompt")
    assert main(["guard", "install", "--agent", "claude"]) == 2
    assert "doesn't run" in capsys.readouterr().out


def test_verify_works_for_the_real_command():
    assert guard.verify() is None


# ---- review fixes -------------------------------------------------------------------------

def test_status_only_checks_installed_agents(home, capsys):
    (home.root / ".claude").mkdir()
    assert main(["guard", "install"]) == 0
    assert main(["guard", "status"]) == 0
    out = capsys.readouterr().out
    assert "Codex" not in out.split("guard installed")[-1]


def test_gemini_settings_with_comments(home, capsys):
    path = home.root / ".gemini/settings.json"
    path.parent.mkdir()
    path.write_text('{\n  // my theme\n  "theme": "GitHub", /* note */\n  "url": "http://x//y",\n}\n')
    assert main(["guard", "install", "--agent", "gemini"]) == 0
    out = capsys.readouterr().out
    assert "comments in that file were dropped" in out
    data = json.loads(path.read_text())
    assert data["theme"] == "GitHub" and data["url"] == "http://x//y" and "BeforeAgent" in data["hooks"]
    assert "// my theme" in (home.root / ".gemini/settings.json.spillage-backup").read_text()


def test_one_broken_agent_doesnt_stop_the_others(home, capsys):
    (home.root / ".claude").mkdir()
    (home.root / ".codex").mkdir()
    (home.root / ".codex/hooks.json").write_text("{ broken")
    assert main(["guard", "install"]) == 2
    out = capsys.readouterr().out
    assert "Claude Code  guard installed" in out and "✗ Codex CLI" in out


def test_local_scope_only_where_it_exists(home, capsys):
    assert main(["guard", "install", "--agent", "codex", "--scope", "local"]) == 2
    assert "no uncommitted per-project config" in capsys.readouterr().out


@pytest.mark.parametrize("tool,tool_input", [
    ("read_many_files", {"paths": ["."], "include": ["**/.env"]}),
    ("read_many_files", {"include": [".env"]}),
    ("mcp__filesystem__read_text_file", {"path": "/app/.env"}),
    ("mcp__filesystem__read_multiple_files", {"paths": ["a.py", "/home/me/.ssh/id_ed25519"]}),
    ("Bash", {"command": ["bash", "-lc", "cat .env", "bash"]}),
    ("Bash", {"command": ["bash", "-l", "-c", "cat .env"]}),
    ("Bash", {"command": ["/usr/bin/env", "bash", "-c", "printenv"]}),
    ("Bash", {"command": ["zsh", "-lc", "gh auth token"]}),
])
def test_more_blocked_tool_calls(tool, tool_input):
    assert guard.handle("tool", {"tool_name": tool, "tool_input": tool_input})[0] == 2


def test_claude_matcher_sends_mcp_reads_to_the_hook():
    import re as _re

    assert _re.fullmatch(guard.TOOL_MATCHER, "mcp__filesystem__read_file")


def test_uninstall_says_when_nothing_was_there(home, capsys):
    assert main(["guard", "uninstall"]) == 0
    assert "wasn't installed" in capsys.readouterr().out


def test_strip_json_comments_keeps_strings():
    text = '{"a": "// not a comment", "b": "/* nor this */", /* c */ "c": [1, 2,], }'
    assert json.loads(guard.strip_json_comments(text)) == {"a": "// not a comment", "b": "/* nor this */", "c": [1, 2]}


def test_powershell_tool_is_checked():
    assert guard.check_tool("PowerShell", {"command": "Get-Content .env"})
    assert guard.check_tool("PowerShell", {"command": "Get-ChildItem"}) is None
    import re as _re

    assert _re.fullmatch(guard.TOOL_MATCHER, "PowerShell")
