"""The hooks that run after a tool: a key in the output is replaced before the model sees it."""

from __future__ import annotations

import io
import json
import subprocess
import sys

import fakes
import pytest

from spillage import guard
from spillage.cli import main
from spillage.models import fingerprint
from spillage.rules import get_rules


def bash(stdout: str, stderr: str = "") -> dict:
    """What Claude Code hands a PostToolUse hook after a Bash call."""
    return {"stdout": stdout, "stderr": stderr, "interrupted": False, "isImage": False, "noOutputExpected": False}


def answer(event: str, payload: dict) -> dict:
    code, message = guard.handle(event, payload)
    assert code == 0  # these hooks never block, the tool already ran
    return json.loads(message) if message else {}


def test_a_key_in_bash_output_is_replaced_and_the_shape_stays():
    key = fakes.github()
    payload = {"tool_name": "Bash", "tool_response": bash(f"token: {key}\nnext line", stderr="warning")}
    out = answer("tool-output", payload)["hookSpecificOutput"]
    assert out["hookEventName"] == "PostToolUse"
    marker = f"[REDACTED:github-token:{fingerprint(key)}]"
    assert out["updatedToolOutput"] == bash(f"token: {marker}\nnext line", stderr="warning")
    assert "1 secret (GitHub" in out["additionalContext"] and key not in json.dumps(out)


def test_a_key_in_a_file_that_was_read_is_replaced():
    key = fakes.anthropic()
    response = {"type": "text", "file": {"filePath": "/app/notes.md", "content": f"key is {key}\n", "numLines": 2,
                                         "startLine": 1, "totalLines": 2}}
    out = answer("tool-output", {"tool_name": "Read", "tool_response": response})["hookSpecificOutput"]
    updated = out["updatedToolOutput"]
    assert key not in updated["file"]["content"] and "[REDACTED:" in updated["file"]["content"]
    assert updated["file"]["filePath"] == "/app/notes.md" and updated["file"]["numLines"] == 2


def test_every_key_is_counted_and_nested_lists_are_walked():
    first, second = fakes.github(), fakes.stripe()
    response = {"content": [{"type": "text", "text": f"{first} and {second}"}, {"type": "text", "text": first}]}
    out = answer("tool-output", {"tool_name": "mcp__files__read", "tool_response": response})["hookSpecificOutput"]
    assert out["additionalContext"].startswith("spillage replaced 3 secrets (")
    assert first not in json.dumps(out) and second not in json.dumps(out)


def test_a_plain_string_result_is_replaced_too():
    key = fakes.github()
    out = answer("tool-output", {"tool_name": "mcp__x__get", "tool_response": f"here: {key}"})
    assert out["hookSpecificOutput"]["updatedToolOutput"] == f"here: [REDACTED:github-token:{fingerprint(key)}]"


@pytest.mark.parametrize("response", [
    bash("nothing to see here"), {"type": "text", "file": {"content": "plain text", "numLines": 1}}, None, 7, [],
    "just words",
])
def test_output_without_a_secret_is_left_alone(response):
    assert guard.handle("tool-output", {"tool_name": "Bash", "tool_response": response}) == (0, "")
    assert guard.handle("tool-output", {}) == (0, "")


def test_low_severity_keys_stay_so_the_agent_can_work_with_them():
    key = fakes.stripe(live=False)
    assert guard.handle("tool-output", {"tool_name": "Bash", "tool_response": bash(f"STRIPE={key}")}) == (0, "")


def test_images_are_not_touched():
    key = fakes.github()
    image = dict(bash(key), isImage=True)
    assert guard.handle("tool-output", {"tool_name": "Bash", "tool_response": image}) == (0, "")
    read = {"type": "image", "file": {"base64": key, "type": "image/png"}}
    assert guard.handle("tool-output", {"tool_name": "Read", "tool_response": read}) == (0, "")


def test_an_ignored_key_is_not_replaced():
    key = fakes.github()
    cleaned, names = guard.redact_output(bash(key), get_rules(), ignore={fingerprint(key)})
    assert cleaned == bash(key) and names == []


def test_a_value_from_the_projects_env_file_is_replaced(tmp_path):
    password = fakes.db_password()
    (tmp_path / ".env").write_text(f"POSTGRES_PASSWORD={password}\n", encoding="utf-8")
    payload = {"tool_name": "Bash", "cwd": str(tmp_path), "tool_response": bash(f"connecting with {password}")}
    out = answer("tool-output", payload)["hookSpecificOutput"]
    assert password not in json.dumps(out) and "POSTGRES_PASSWORD" in out["additionalContext"]


def test_a_failed_command_cannot_be_changed_so_it_is_reported():
    key = fakes.github()
    payload = {"tool_name": "Bash", "error": f"Exit code 22\n> Authorization: Bearer {key}", "is_interrupt": False}
    out = answer("tool-failure", payload)
    assert "rotate it" in out["systemMessage"] and "1 secret (GitHub" in out["systemMessage"]
    assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUseFailure"
    assert "updatedToolOutput" not in out["hookSpecificOutput"] and key not in json.dumps(out)


@pytest.mark.parametrize("payload", [{}, {"error": None}, {"error": ["x"]}, {"error": "Exit code 1\nno such file"}])
def test_a_failure_without_a_secret_says_nothing(payload):
    assert guard.handle("tool-failure", payload) == (0, "")


def test_the_answer_goes_to_stdout_as_one_line_of_ascii_json():
    key = fakes.github()
    payload = {"tool_name": "Bash", "tool_response": bash(f"{key} naïve …")}
    out, err = io.StringIO(), io.StringIO()
    assert guard.run_hook("tool-output", io.StringIO(json.dumps(payload)), err, out) == 0
    assert err.getvalue() == "" and out.getvalue().count("\n") == 1 and out.getvalue().isascii()
    assert json.loads(out.getvalue())["hookSpecificOutput"]["updatedToolOutput"]["stdout"].endswith(" naïve …")


def test_garbage_on_stdin_is_tolerated():
    for event in guard.STDOUT_EVENTS:
        assert guard.run_hook(event, io.StringIO("not json"), io.StringIO(), io.StringIO()) == 0
        assert guard.run_hook(event, io.StringIO('{"tool_response": {"a": [1, null, {"b": 2.5}]}}'),
                              io.StringIO(), io.StringIO()) == 0


def test_as_a_real_process():
    key = fakes.github()
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_response": bash(f"TOKEN={key}")}
    proc = subprocess.run([sys.executable, "-m", "spillage", "hook", "tool-output"], input=json.dumps(payload),
                          capture_output=True, text=True, encoding="utf-8", timeout=60)  # fmt: skip
    assert proc.returncode == 0 and proc.stderr == "" and key not in proc.stdout
    assert "[REDACTED:github-token:" in json.loads(proc.stdout)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


def test_install_adds_the_output_hooks_for_claude_code_only(tmp_path):
    path = tmp_path / "settings.json"
    assert guard.install(path)
    hooks = json.loads(path.read_text())["hooks"]
    assert list(hooks) == ["UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionEnd"]
    for event, name in (("PostToolUse", "tool-output"), ("PostToolUseFailure", "tool-failure")):
        assert hooks[event][0]["matcher"] == guard.OUTPUT_MATCHER
        assert hooks[event][0]["hooks"][0]["command"].endswith(f"hook {name}")
    assert not guard.install(path)  # nothing to change the second time
    assert all(guard.status(path).values()) and len(guard.status(path)) == 5
    for agent in ("codex", "gemini"):
        other = tmp_path / f"{agent}.json"
        guard.install(other, agent)
        assert len(json.loads(other.read_text())["hooks"]) == 3


def test_an_install_from_before_the_output_hooks_counts_as_part_and_is_completed(tmp_path):
    path = tmp_path / "settings.json"
    guard.install(path)
    data = json.loads(path.read_text())
    del data["hooks"]["PostToolUse"], data["hooks"]["PostToolUseFailure"]
    path.write_text(json.dumps(data))
    state = guard.status(path)
    assert not state["PostToolUse"] and state["PreToolUse"]
    assert guard.install(path) and all(guard.status(path).values())
    assert guard.uninstall(path) and "hooks" not in json.loads(path.read_text())


def test_cli_hook_prints_the_answer(monkeypatch, capsys):
    key = fakes.github()
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"tool_response": bash(key)})))
    assert main(["hook", "tool-output"]) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and key not in captured.out and "updatedToolOutput" in captured.out
