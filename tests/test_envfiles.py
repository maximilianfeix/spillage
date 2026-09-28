from __future__ import annotations

import json

import fakes
import pytest

from spillage.cli import main
from spillage.envfiles import collect, env_files, parse
from spillage.rules import KnownValueRule, get_rules, rule_spec, rules_from_spec, with_known_values
from spillage.scanner import find_in_text


def test_parse_keeps_only_secret_looking_values():
    pw = fakes.rand(24)
    text = f"""
# comment
export DB_PASSWORD="{pw}"
AZURE_OPENAI_KEY={fakes.rand(32, "0123456789abcdef")}
PORT=3000
DEBUG=true
API_KEY=your-api-key-here
SHORT_TOKEN=abc
PUBLIC_URL=https://example.org
SESSION_SECRET='{fakes.rand(40)}'  # rotate monthly
REDIS_PASS={fakes.rand(18)} # inline comment
"""
    got = parse(text)
    assert set(got) == {"DB_PASSWORD", "AZURE_OPENAI_KEY", "SESSION_SECRET", "REDIS_PASS"}
    assert got["DB_PASSWORD"] == pw
    assert " " not in got["REDIS_PASS"]


def test_env_files_skip_templates(tmp_path):
    (tmp_path / ".env").write_text("A=1")
    (tmp_path / ".env.local").write_text("A=1")
    (tmp_path / ".env.example").write_text("A=1")
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / ".env").write_text("A=1")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / ".env").write_text("A=1")
    names = sorted(str(p.relative_to(tmp_path)) for p in env_files([tmp_path]))
    assert names == [".env", ".env.local", "api/.env"]


def test_known_values_are_found_raw_and_json_escaped():
    pw = 'p"a\\ss' + fakes.rand(16)
    rule = KnownValueRule({pw: "DB_PASSWORD from ~/app/.env"})
    raw = json.dumps({"content": f"connect with {pw} now"})
    ((_, m),) = find_in_text(raw, [rule])
    assert json.loads('"' + m.secret + '"') == pw
    assert rule.name_for(pw) == "Value of DB_PASSWORD from ~/app/.env"


def test_known_value_inside_a_longer_token_is_ignored():
    value = fakes.rand(20)
    rule = KnownValueRule({value: "X"})
    assert find_in_text("x" + value + "y", [rule]) == []
    assert len(find_in_text(f"={value};", [rule])) == 1


def test_specific_rules_still_win():
    gh = fakes.github()
    rules = with_known_values(get_rules(), {gh: "GITHUB_TOKEN from .env"})
    ((rule, _),) = find_in_text(f"token {gh}", rules)
    assert rule.id == "github-token"
    assert [r.id for r in rules][-2:] == ["env-value", "generic-secret"]


def test_rule_spec_roundtrip():
    rules = with_known_values(get_rules(), {"abcdefghijkl12345": "A"})
    again = rules_from_spec(rule_spec(rules))
    assert [r.id for r in again] == [r.id for r in rules]
    assert again[-2].values == {"abcdefghijkl12345": "A"}


@pytest.fixture
def project_with_env(home, tmp_path, monkeypatch):
    proj = tmp_path / "shop"
    proj.mkdir()
    pw = fakes.rand(22)
    (proj / ".env").write_text(f"POSTGRES_PASSWORD={pw}\nPORT=5432\n")
    home.claude_session(project=str(proj), records=[
        {"type": "user", "message": {"content": [{"type": "tool_result", "content": f"psql -W {pw}"}]}},
    ])
    monkeypatch.chdir(home.root)
    return proj, pw


def test_cli_finds_env_values(project_with_env, capsys):
    _, pw = project_with_env
    assert main(["scan", "-f", "json"]) == 1
    out = capsys.readouterr().out
    (finding,) = json.loads(out)["findings"]
    assert finding["name"].startswith("Value of POSTGRES_PASSWORD from")
    assert pw not in out


def test_cli_no_env(project_with_env, capsys):
    assert main(["scan", "--no-env"]) == 0


def test_scrub_removes_env_values(project_with_env, home, capsys):
    import os
    import time

    proj, pw = project_with_env
    session = next(home.root.rglob("s1.jsonl"))
    os.utime(session, (time.time() - 3600,) * 2)
    assert main(["scrub", "--yes"]) == 0
    assert main(["scan"]) == 0
    assert "[REDACTED:env-value:" in session.read_text()
    assert pw in (proj / ".env").read_text()  # the .env file itself is never touched


def test_collect_labels(tmp_path):
    (tmp_path / ".env").write_text(f"API_SECRET={fakes.rand(30)}\n")
    ((_, label),) = collect([tmp_path]).items()
    assert label.startswith("API_SECRET from ")
