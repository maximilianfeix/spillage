"""Agent settings: MCP server configs, Claude Code's allowed commands, old prompt history (#47)."""

from __future__ import annotations

import json
import os
import time

import fakes
import pytest
from conftest import write_json

from spillage.models import Origin
from spillage.scanner import Scanner
from spillage.scrub import scrub
from spillage.sources import AgentConfig, build_sources


def scan(agents=("config",)):
    return {f.secret: f for f in Scanner(workers=1).scan(build_sources(list(agents))).findings}


def old(path):
    """Scrub skips files written in the last minute."""
    t = time.time() - 3600
    os.utime(path, (t, t))
    return path


def test_mcp_servers_in_claude_json_but_not_the_own_login(home):
    gh, ak = fakes.github(), fakes.anthropic()
    write_json(home.root / ".claude.json", {
        "primaryApiKey": ak,  # Claude Code's own login: where the key belongs
        "mcpServers": {"github": {"command": "npx", "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": gh}}},
    })
    found = scan()
    assert list(found) == [gh]
    loc = found[gh].locations[0]
    assert loc.origin == Origin.CONFIG and loc.agent == "config"
    assert loc.json_path == "mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN"


def test_old_prompt_history_in_claude_json(home):
    sk = fakes.stripe()
    write_json(home.root / ".claude.json", {"projects": {"/work/app": {
        "history": [{"display": f"use {sk} for the test"}],
        "mcpServers": {},
    }}})
    assert scan()[sk].origins == [Origin.HISTORY]


def test_allowed_command_in_project_settings(home, tmp_path):
    project = tmp_path / "work" / "shop"
    project.mkdir(parents=True)
    home.claude_session(project=str(project), records=[{"type": "user", "message": {"content": "hi"}}])
    ak = fakes.anthropic()
    write_json(project / ".claude" / "settings.local.json", {"permissions": {"allow": [
        f'Bash(curl -H "x-api-key: {ak}" https://api.anthropic.com/v1/models)']}})
    loc = scan()[ak].locations[0]
    assert loc.origin == Origin.CONFIG and loc.project == str(project)
    assert loc.json_path == "permissions.allow[0]"


@pytest.mark.parametrize("where", [
    ".cursor/mcp.json", ".codeium/windsurf/mcp_config.json", ".gemini/settings.json", ".mcp.json",
])
def test_mcp_json_of_other_agents(home, where):
    gh = fakes.github()
    write_json(home.root / where, {"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": gh}}}})
    assert scan()[gh].origins == [Origin.CONFIG]


def test_toml_yaml_and_app_support_files(home):
    gh, npm, sg = fakes.github(), fakes.npm(), fakes.sendgrid()
    (home.root / ".codex").mkdir()
    (home.root / ".codex" / "config.toml").write_text(
        f'[mcp_servers.github]\ncommand = "npx"\nenv = {{ "GITHUB_TOKEN" = "{gh}" }}\n', encoding="utf-8")
    goose = home.root / ".config" / "goose"
    goose.mkdir(parents=True)
    (goose / "config.yaml").write_text(f"extensions:\n  npm:\n    envs:\n      NPM_TOKEN: {npm}\n", encoding="utf-8")
    app = AgentConfig(home.root)
    from spillage.sources import _app_support
    cline = _app_support()[0] / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
    write_json(cline / "cline_mcp_settings.json", {"mcpServers": {"mail": {"env": {"SENDGRID_API_KEY": sg}}}})
    assert {p.name for p in app.discover()} >= {"config.toml", "config.yaml", "cline_mcp_settings.json"}
    found = scan()
    assert {gh, npm, sg} <= set(found)


def test_codex_home_and_claude_config_dir(home, tmp_path, monkeypatch):
    gh, sk = fakes.github(), fakes.stripe()
    codex, claude = tmp_path / "codex", tmp_path / "claude"
    codex.mkdir()
    (codex / "config.toml").write_text(f'env = {{ "T" = "{gh}" }}\n', encoding="utf-8")
    write_json(claude / "settings.json", {"env": {"STRIPE_KEY": sk}})
    monkeypatch.setenv("CODEX_HOME", str(codex))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude))
    assert {gh, sk} <= set(scan())


def test_selected_with_agent_config_only(home):
    gh = fakes.github()
    write_json(home.root / ".cursor" / "mcp.json", {"mcpServers": {"gh": {"env": {"T": gh}}}})
    assert gh not in scan(["claude"])
    assert gh in scan(["config"])


def test_scrub_leaves_settings_alone(home):
    gh = fakes.github()
    path = old(write_json(home.root / ".cursor" / "mcp.json", {"mcpServers": {"gh": {"env": {"T": gh}}}}))
    before = path.read_bytes()
    findings = Scanner(workers=1).scan(build_sources(["config"])).findings
    report = scrub(findings)
    assert report.settings == [str(path)] and report.replacements == 0 and not report.failed
    assert path.read_bytes() == before


def test_default_scan_includes_settings(home):
    gh = fakes.github()
    write_json(home.root / ".mcp.json", {"mcpServers": {"gh": {"env": {"T": gh}}}})
    found = {f.secret: f for f in Scanner(workers=1).scan(build_sources()).findings}
    assert gh in found and found[gh].agents == ["config"]


def test_nothing_there(home):
    assert not AgentConfig(home.root).installed()
    (home.root / ".claude.json").write_text(json.dumps({"numStartups": 3}), encoding="utf-8")
    assert AgentConfig(home.root).installed() and scan() == {}


def test_own_login_key_pasted_elsewhere_still_counts(home):
    ak = fakes.anthropic()
    write_json(home.root / ".claude.json", {
        "primaryApiKey": ak,
        "projects": {"/work/app": {"history": [{"display": f"why does {ak} fail"}]}},
    })
    found = scan()
    assert [loc.origin for loc in found[ak].locations] == [Origin.HISTORY]


def test_scrub_redacts_old_history_but_not_mcp_env(home):
    gh, sk = fakes.github(), fakes.stripe()
    path = old(write_json(home.root / ".claude.json", {
        "mcpServers": {"gh": {"env": {"GITHUB_TOKEN": gh}}},
        "projects": {"/work/app": {"history": [{"display": f"pay with {sk} and {gh}"}]}},
    }))
    report = scrub(Scanner(workers=1).scan(build_sources(["config"])).findings)
    data = json.loads(path.read_text())
    assert data["mcpServers"]["gh"]["env"]["GITHUB_TOKEN"] == gh  # the server keeps working
    display = data["projects"]["/work/app"]["history"][0]["display"]
    assert sk not in display and gh not in display and "[REDACTED:" in display
    assert report.settings == [str(path)] and report.replacements == 2


def test_claude_config_dir_holds_claude_json(home, tmp_path, monkeypatch):
    gh = fakes.github()
    write_json(tmp_path / "cfg" / ".claude.json", {"mcpServers": {"gh": {"env": {"T": gh}}}})
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cfg"))
    assert gh in scan()


def test_a_file_reached_two_ways_is_read_once(home, tmp_path):
    gh = fakes.github()
    write_json(home.root / ".mcp.json", {"mcpServers": {"gh": {"env": {"T": gh}}}})
    link = tmp_path / "home-link"
    try:
        link.symlink_to(home.root, target_is_directory=True)
    except OSError:
        pytest.skip("no symlinks here")
    # home through a symlink, the current folder (a project folder too) as the real path
    names = [p.name for p in AgentConfig(link).discover()]
    assert names.count(".mcp.json") == 1
