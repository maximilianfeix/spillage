"""Keys spelled with JSON `\\u` escapes.

What is covered: the ways real serializers write a value. Go's encoding/json (Crush and other
Go tools) writes `&`, `<` and `>` as `\\u0026`, `\\u003c` and `\\u003e`, so a .env value such as a
DATABASE_URL with `&` in it was missed in their logs. Python with ensure_ascii writes `é` as
`\\u00e9`, which was fixed before.

What is not: a key whose ordinary ASCII letters are written as `\\u0041`. No serializer does
that; only someone hiding a key on purpose would, and spillage doesn't claim to see through
deliberate obfuscation. The README says so under Limitations.
"""

from __future__ import annotations

import json

from spillage.models import fingerprint
from spillage.rules import KnownValueRule, get_rules, with_known_values
from spillage.scanner import Scanner, find_in_text
from spillage.scrub import scrub
from spillage.sources import PathSource

VALUE = "postgres://app:S3cr3t&Pw<x>9Q@db.internal:5432/app?sslmode=require&pool=5"


def go_json(value: str) -> str:
    """How Go's encoding/json writes a string."""
    return json.dumps(value).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


def test_a_value_written_the_way_go_escapes_it_is_found():
    rule = KnownValueRule({VALUE: "DATABASE_URL from ~/app/.env"})
    text = '{"role":"tool","content":' + go_json(VALUE) + "}"
    matches = list(rule.find(text))
    assert len(matches) == 1
    assert json.loads('"' + matches[0].secret + '"') == VALUE


def test_scan_and_scrub_of_a_go_written_log(tmp_path):
    log = tmp_path / "session.jsonl"
    log.write_text('{"role":"tool","content":' + go_json(VALUE) + "}\n", encoding="utf-8")
    rules = with_known_values(get_rules(), {VALUE: "DATABASE_URL from ~/app/.env"})
    result = Scanner(rules=rules, workers=1).scan([PathSource([log])])
    assert [f.fingerprint for f in result.findings] == [fingerprint(VALUE)]
    report = scrub(result.findings, rules=rules, include_active=True)
    assert report.replacements == 1 and not report.failed
    text = log.read_text(encoding="utf-8")
    assert "S3cr3t" not in text and json.loads(text)["content"].startswith("[REDACTED:env-value:")


def test_ascii_letters_spelled_as_escapes_are_a_known_limit():
    key = "ghp_" + "A" * 36
    hidden = "".join(f"\\u{ord(c):04x}" for c in key)
    assert not find_in_text(hidden, get_rules())
