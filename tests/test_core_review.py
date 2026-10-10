from __future__ import annotations

import json
import sqlite3

import fakes

from spillage import scanner as scanner_mod
from spillage.models import Severity
from spillage.rules import BUILTIN_RULES, Rule, get_rules, with_known_values
from spillage.scanner import Scanner, find_in_text, scan_text
from spillage.sources import Goose, PathSource, build_sources


def test_sentry_tokens_match():
    (f,) = scan_text(fakes.sentry_user())
    assert f.rule_id == "sentry-token"


def test_private_key_with_a_word_in_its_body():
    pk = fakes.private_key()
    lines = pk.split("\n")
    lines[3] = "TODOfake" + lines[3][8:]
    assert [r.id for r, _ in find_in_text("\n".join(lines), BUILTIN_RULES)] == ["private-key"]


def test_aws_secret_in_other_spellings():
    value = fakes.aws_secret()
    for name in ("AWSSecretAccessKey", "Aws_Secret_Access_Key", "AWS_Secret_Key"):
        assert [r.id for r, _ in find_in_text(f'{name} = "{value}"', BUILTIN_RULES)] == ["aws-secret-access-key"]


def test_goose_rows_still_in_the_wal_are_seen(home):
    db = home.root / ".local/share/goose/sessions/sessions.db"
    db.parent.mkdir(parents=True)
    key = fakes.github()
    writer = sqlite3.connect(str(db))
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("CREATE TABLE messages (session_id TEXT, content_json TEXT)")
    writer.commit()
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("INSERT INTO messages VALUES ('s', ?)", (json.dumps([{"text": key}]),))
    writer.commit()  # committed, but not checkpointed into the main file
    try:
        assert key in (Goose(home.root).load(db) or "")
    finally:
        writer.close()


def test_a_single_huge_jsonl_is_read_in_parts(home, tmp_path, monkeypatch):
    path = tmp_path / "big.jsonl"
    key = fakes.npm()
    lines = [json.dumps({"content": "x" * 1000}) for _ in range(300)]
    lines[250] = json.dumps({"content": f"k {key}"})
    path.write_text("\n".join(lines) + "\n")
    monkeypatch.setattr(scanner_mod, "MAX_FILE_BYTES", 100_000)
    result = Scanner(workers=1).scan([PathSource([path])])
    (f,) = result.findings
    assert f.secret == key and f.locations[0].line == 251 and not result.stats.errors


def test_most_specific_rule_names_the_finding(home, tmp_path):
    value = fakes.aws_secret()
    big = tmp_path / "a.jsonl"
    big.write_text(json.dumps({"content": "y" * 5000 + f" {value} "}) + "\n")
    small = tmp_path / "b.jsonl"
    small.write_text(json.dumps({"content": f"aws_secret_access_key={value}"}) + "\n")
    rules = with_known_values(get_rules(), {value: "AWS_SECRET from .env"})
    (f,) = Scanner(rules=rules, workers=1).scan([PathSource([big, small])]).findings
    assert f.rule_id == "aws-secret-access-key" and f.severity is Severity.CRITICAL


def test_custom_rules_work_in_parallel(home, monkeypatch):
    custom = Rule("acme-token", "ACME token", "ACME", r"(acme_[a-z0-9]{20})", Severity.HIGH, ("acme_",), group=1,
                  validator=lambda s: True)
    for i in range(3):
        home.claude_session(name=f"s{i}", records=[{"type": "user", "message": {"content": "acme_" + "a1" * 10}}])
    monkeypatch.setattr(scanner_mod, "PARALLEL_THRESHOLD", 0)
    (f,) = Scanner(rules=get_rules() + [custom], workers=2).scan(build_sources(["claude"])).findings
    assert f.rule_id == "acme-token"


def test_a_key_in_the_metadata_never_reaches_a_report(home):
    """A key in a folder name, a session id or a timestamp field is printed by no format."""
    from spillage.reporters import formats, render

    key, other = fakes.github(), fakes.npm()
    home.claude_session(records=[{
        "type": "user", "sessionId": f"s-{key}", "cwd": f"/work/{key}", "timestamp": f"2026-01-01 {key}",
        "message": {"role": "user", "content": f"use {key}"},
    }])
    named = home.root / ".claude" / "projects" / "p" / f"{key}.jsonl"
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text(json.dumps({"type": "user", "message": {"role": "user", "content": other}}) + "\n",
                     encoding="utf-8")
    result = Scanner(workers=1).scan(build_sources(["claude"]))
    assert {f.secret for f in result.findings} == {key, other}
    for fmt in formats():
        report = render(result, fmt, verbose=True)
        assert key not in report and other not in report, fmt
    assert key not in json.dumps(result.to_dict())
    # the path itself stays usable for scrub
    assert any(key in loc.file for f in result.findings for loc in f.locations)


def test_a_key_below_min_severity_in_the_metadata_is_hidden_too(home):
    from spillage.reporters import render

    low, shown = fakes.stripe(live=False), fakes.github()
    home.claude_session(records=[
        {"type": "user", "cwd": f"/work/{low}", "message": {"role": "user", "content": f"{low} {shown}"}},
    ])
    result = Scanner(workers=1, min_severity=Severity.HIGH).scan(build_sources(["claude"]))
    assert [f.secret for f in result.findings] == [shown]
    assert low not in render(result, "json")


def test_an_ignored_value_is_not_hidden(home):
    """You said it isn't a secret, so a path that happens to hold it stays readable."""
    from spillage.models import fingerprint
    from spillage.reporters import render

    ignored, shown = fakes.github(), fakes.npm()
    home.claude_session(records=[
        {"type": "user", "cwd": f"/work/{ignored}", "message": {"role": "user", "content": f"{ignored} {shown}"}},
    ])
    result = Scanner(workers=1, ignore=[fingerprint(ignored)]).scan(build_sources(["claude"]))
    assert [f.secret for f in result.findings] == [shown]
    assert f"/work/{ignored}" in render(result, "json")


def test_hiding_is_one_pass_however_many_secrets():
    import time

    from spillage.models import Finding, Location
    from spillage.scanner import ScanResult, ScanStats

    findings = []
    for _ in range(300):
        finding = Finding("npm-token", "npm access token", "npm", Severity.HIGH, fakes.npm())
        finding.locations = [Location("claude", f"/logs/{i}.jsonl", i, session=f"s{i}") for i in range(20)]
        findings.append(finding)
    started = time.perf_counter()
    ScanResult(findings, ScanStats(files=1)).to_dict()
    assert time.perf_counter() - started < 2


def test_unreadable_files_show_up_in_every_format(home, monkeypatch):
    from spillage.html import render_html
    from spillage.reporters import render

    home.claude_session(records=[{"type": "user", "message": {"role": "user", "content": "hello"}}])

    def broken(*args, **kwargs):
        raise PermissionError("no access")

    monkeypatch.setattr(scanner_mod, "scan_file", broken)
    result = Scanner(workers=1).scan(build_sources(["claude"]))
    (note,) = json.loads(render(result, "sarif"))["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert "no access" in note["message"]["text"]
    assert "no access" in render_html(result)  # the page reads it from summary.errors
    result.stats.files = 0
    assert "could not be scanned" in render(result, "text")


def test_short_values_are_not_hidden_as_words():
    from spillage.models import hide_secrets

    assert hide_secrets("~/code/postgres/app", ["postgres"]) == "~/code/postgres/app"


def test_files_that_could_not_be_scanned_are_reported(home, monkeypatch):
    from spillage.reporters import render

    home.claude_session(records=[{"type": "user", "message": {"role": "user", "content": "hello"}}])

    def broken(*args, **kwargs):
        raise PermissionError("no access")

    monkeypatch.setattr(scanner_mod, "scan_file", broken)
    result = Scanner(workers=1).scan(build_sources(["claude"]))
    assert len(result.stats.errors) == 1
    text = render(result, "text")
    assert "1 file could not be scanned" in text and "no access" in text
    assert "Nothing spilled" not in text
    assert json.loads(render(result, "json"))["summary"]["errors"] == result.stats.errors
    assert "could not be scanned" in render(result, "markdown")
