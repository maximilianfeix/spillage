from __future__ import annotations

import io
import json
import time

import fakes
import pytest

from spillage import __version__
from spillage.cli import main, parse_since
from spillage.models import fingerprint


def run(capsys, *args):
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


def test_default_command_is_scan(leaky_home, capsys):
    code, out, _ = run(capsys, "--workers", "1")
    assert code == 1
    assert "4 secrets spilled" in out
    assert "Next steps" in out


def test_clean_exit(home, capsys):
    home.claude_session(records=[{"type": "user", "message": {"content": "hello"}}])
    code, out, _ = run(capsys, "scan")
    assert code == 0
    assert "Nothing spilled" in out


def test_no_logs(home, capsys):
    code, out, _ = run(capsys)
    assert code == 0 and "No agent logs found" in out


def test_exit_zero(leaky_home, capsys):
    assert run(capsys, "scan", "--exit-zero")[0] == 0


def test_json_output_is_masked(leaky_home, capsys):
    _, out, _ = run(capsys, "scan", "--format", "json")
    data = json.loads(out)
    assert data["version"] == __version__
    assert data["summary"]["critical"] >= 2
    for secret in leaky_home.secrets.values():
        assert secret not in out


def test_markdown_output_to_file(leaky_home, capsys, tmp_path):
    target = tmp_path / "report.md"
    code, out, err = run(capsys, "scan", "-f", "markdown", "-o", str(target))
    assert code == 1 and out == ""
    assert "wrote markdown report" in err
    text = target.read_text()
    assert text.startswith("# spillage report") and "| critical |" in text


def test_verbose_lists_every_location(leaky_home, capsys):
    _, out, _ = run(capsys, "scan", "-v", "--agent", "claude,codex")
    assert "more (--verbose)" not in out


def test_agent_filter_and_unknown_agent(leaky_home, capsys):
    _, out, _ = run(capsys, "scan", "--agent", "codex")
    assert "2 secrets spilled" in out
    code, _, err = run(capsys, "scan", "--agent", "nope")
    assert code == 2 and "unknown agent" in err


def test_path_option(home, capsys, tmp_path):
    f = tmp_path / "chat.md"
    f.write_text(f"here {fakes.npm()}", encoding="utf-8")
    code, out, _ = run(capsys, "scan", "--path", str(f), "--no-color")
    assert code == 1 and "npm access token" in out


def test_min_severity_flag(leaky_home, capsys):
    _, out, _ = run(capsys, "scan", "--min-severity", "critical", "-f", "json")
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"critical"}
    with pytest.raises(SystemExit):
        main(["scan", "--min-severity", "extreme"])


def test_rules_filter(leaky_home, capsys):
    _, out, _ = run(capsys, "scan", "--rules", "github-token", "-f", "json")
    assert [f["rule"] for f in json.loads(out)["findings"]] == ["github-token"]
    code, _, err = run(capsys, "scan", "--skip-rules", "bogus")
    assert code == 2 and "unknown rule" in err


def test_check_argument_and_stdin(capsys, monkeypatch):
    code, out, _ = run(capsys, "check", f"token {fakes.github()}")
    assert code == 1 and "GitHub token" in out
    monkeypatch.setattr("sys.stdin", io.StringIO("all good"))
    code, out, _ = run(capsys, "check")
    assert code == 0 and "no secrets" in out
    assert run(capsys, "check", "-q", fakes.npm()) == (1, "", "")


def test_ignore_command(leaky_home, capsys):
    gh = leaky_home.secrets["github"]
    code, out, _ = run(capsys, "ignore", fingerprint(gh), "--note", "old key")
    assert code == 0 and "ignoring 1" in out
    _, out, _ = run(capsys, "scan", "-f", "json")
    assert json.loads(out)["summary"]["ignored"] == 1
    code, _, err = run(capsys, "ignore", "not-a-fingerprint")
    assert code == 2 and "not a fingerprint" in err


def test_agents_and_rules_commands(leaky_home, capsys):
    code, out, _ = run(capsys, "agents")
    assert code == 0 and "Claude Code" in out and "not found" in out
    code, out, _ = run(capsys, "rules")
    assert code == 0 and "github-token" in out and "rules." in out


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


@pytest.mark.parametrize("value,days", [("7d", 7), ("12h", 0.5), ("2w", 14), ("30m", 30 / 1440)])
def test_parse_since_relative(value, days):
    assert abs((time.time() - parse_since(value)) / 86400 - days) < 0.01


def test_parse_since_date_and_garbage():
    assert parse_since("2026-09-01") < time.time()
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        parse_since("last tuesday")


def test_ellipsize():
    from spillage.term import ellipsize

    path = "~/.claude/projects/-Users-you-code-shop/8f2c41d0-6a1e-4c55-9d0e-5b7e2a91c3f4.jsonl:12"
    short = ellipsize(path, 60)
    assert len(short) == 60 and "…" in short and short.endswith(".jsonl:12") and short.startswith("~/.claude")
    assert ellipsize("short", 60) == "short"
