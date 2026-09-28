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
