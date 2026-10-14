"""The hooks must not fail open: what a third review found in the guard of PR #92.

Claude Code takes any exit code other than 2 from a PreToolUse hook as "go ahead", and a
PostToolUse hook that crashes leaves the tool's output as it was. So a crash, a stack of
wrappers we stop counting, or a payload too deep to walk is a way around the guard.
"""

from __future__ import annotations

import io
import json

import fakes
import pytest

from spillage import guard


@pytest.mark.parametrize("command", [
    # wrappers stacked deeper than we used to look
    "sudo " * 9 + "cat .env", "nice " * 12 + "cat .env", "time " * 20 + "cat .env",
    "busybox cat .env", "toybox cat .env", "sudo busybox head .env",
    # interpreters by another name
    """python3.12 -c "print(open('.env').read())\"""", """py -c "print(open('.env').read())\"""",
    """py -3 -c "print(open('.env').read())\"""", """python3.12 -c "import os; print(os.environ['OPENAI_API_KEY'])\"""",
    "cat.exe .env", "C:/Windows/System32/more.com < .env",
    """php -r 'echo file_get_contents(".env");'""",
    """bun -e "console.log(require('fs').readFileSync('.env','utf8'))\"""",
    """deno eval "console.log(Deno.readTextFileSync('.env'))\"""",
    # git that prints a file's content, not just its name
    "git log -p -- .env", "git log --patch .env.production", "git log -u -1 -- config/.env",
    # every variable with its value
    "declare -p", "typeset -p", "declare -px",
    "strings /proc/self/environ", "xxd /proc/1/environ", "tr '\\0' '\\n' < /proc/self/environ",
    # the file is an argument of the wrapper
    "xargs -a .env echo", "xargs --arg-file=.env echo",
])
def test_more_ways_around_are_closed(command):
    assert guard.risky_command(command), command


@pytest.mark.parametrize("command", [
    "git log --oneline -- .env", "git log -1 --stat", "declare -p PATH", "declare -i n=3", "typeset -i n",
    "python3.12 -m pytest", "py -3 -m pip install -e .", "php artisan migrate", "bun test", "deno test",
    "busybox ls", "xargs -a files.txt rm", "sudo " * 9 + "ls",
    "strings build/app.bin", "cat.exe README.md",
])
def test_harmless_commands_still_pass(command):
    assert guard.risky_command(command) is None, command


def _run(event: str, payload) -> tuple:
    out, err = io.StringIO(), io.StringIO()
    code = guard.run_hook(event, io.StringIO(payload if isinstance(payload, str) else json.dumps(payload)), err, out)
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize("depth", [50, 300, 450, 2000])
def test_a_deep_tool_output_is_still_redacted(depth):
    key = fakes.github()
    # built as text: json.dumps itself can't go this deep
    response = '{"content": [' * depth + json.dumps(key) + "]}" * depth
    code, out, _ = _run("tool-output", '{"tool_response": ' + response + "}")
    assert code == 0
    assert key not in out
    # it came back redacted, or (too deep to parse) the model is told it was exposed
    assert "REDACTED" in out or "systemMessage" in out


def test_a_deep_tool_output_keeps_its_shape():
    key = fakes.github()
    response = key
    for _ in range(300):
        response = {"content": [response]}
    _, out, _ = _run("tool-output", {"tool_response": response})
    node = json.loads(out)["hookSpecificOutput"]["updatedToolOutput"]
    for _ in range(300):
        node = node["content"][0]
    assert node.startswith("[REDACTED:github-token:")


def test_a_path_nested_in_lists_is_still_checked():
    deep = [[[".env"]]]
    assert guard.check_tool("mcp__fs__read_file", {"path": deep})
    assert guard.check_tool("Read", {"paths": ["a.txt", [".env"]]})


def test_a_tool_input_too_deep_to_read_is_blocked():
    deep = "[" * 100_000 + '".env"' + "]" * 100_000  # too deep for json on every Python version
    payload = '{"tool_name": "mcp__fs__read_file", "tool_input": {"path": ' + deep + "}}"
    code, _, err = _run("tool", payload)
    assert code == 2
    assert "spillage" in err


def test_a_crash_in_the_tool_check_blocks_instead_of_letting_it_through(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("bug with " + fakes.github())

    monkeypatch.setattr(guard, "check_tool", boom)
    code, out, err = _run("tool", {"tool_name": "Bash", "tool_input": {"command": "ls"}})
    assert code == 2
    assert "ghp_" not in err + out  # the exception's text is not repeated: it can hold anything
    assert "Traceback" not in err


def test_a_crash_while_redacting_withholds_the_output(monkeypatch):
    key = fakes.github()

    def boom(*args, **kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr(guard, "find_in_text", boom)
    code, out, _ = _run("tool-output", {"tool_response": {"stdout": key, "stderr": "", "interrupted": False}})
    assert code == 0
    assert key not in out
    answer = json.loads(out)["hookSpecificOutput"]
    replaced = answer["updatedToolOutput"]
    assert set(replaced) == {"stdout", "stderr", "interrupted"} and replaced["interrupted"] is False
    assert "spillage" in replaced["stdout"]


def test_a_crash_in_the_prompt_or_session_end_hook_does_not_block(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr(guard, "scan_text", boom)
    code, _, err = _run("prompt", {"prompt": "hello"})
    assert code == 0 and "Traceback" not in err and "spillage" in err
