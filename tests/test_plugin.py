"""The Claude Code plugin in this repository: `.claude-plugin/` and `hooks/`."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import fakes

import spillage
from spillage import guard

ROOT = Path(__file__).resolve().parent.parent


def load(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_plugin_version_is_the_package_version():
    assert load(".claude-plugin/plugin.json")["version"] == spillage.__version__


def test_marketplace_lists_the_plugin_at_the_repository_root():
    (entry,) = load(".claude-plugin/marketplace.json")["plugins"]
    assert entry["name"] == load(".claude-plugin/plugin.json")["name"] == "spillage"
    assert entry["source"] == "./"


def test_plugin_hooks_are_the_ones_guard_installs():
    hooks = load("hooks/hooks.json")["hooks"]
    claude = guard.get_agent("claude")
    assert set(hooks) == set(claude.events())
    assert hooks[claude.tool_event][0]["matcher"] == guard.TOOL_MATCHER
    for event, name in zip(claude.events(), ("prompt", "tool", "session-end")):
        (hook,) = hooks[event][0]["hooks"]
        assert hook["command"].endswith(f'"${{CLAUDE_PLUGIN_ROOT}}/hooks/run.py" {name}; done')


def run(event: str, payload: dict, cwd) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "hooks" / "run.py"), event], input=json.dumps(payload), cwd=str(cwd),
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )  # fmt: skip


def test_launcher_runs_from_any_folder(tmp_path):
    """The plugin is run from the project the agent works in, not from where spillage lives."""
    blocked = run("tool", {"tool_name": "Bash", "tool_input": {"command": "cat .env"}}, tmp_path)
    assert blocked.returncode == 2 and "holds secrets" in blocked.stderr
    assert run("tool", {"tool_name": "Bash", "tool_input": {"command": "ls"}}, tmp_path).returncode == 0
    key = fakes.github()
    prompt = run("prompt", {"prompt": f"use {key}"}, tmp_path)
    assert prompt.returncode == 2 and key not in prompt.stderr
