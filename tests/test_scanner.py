from __future__ import annotations

import os
import time

import fakes
from hypothesis import given, settings
from hypothesis import strategies as st

from spillage import scanner as scanner_mod
from spillage.models import Severity, fingerprint, mask
from spillage.scanner import Scanner, add_ignore, load_ignore, scan_text
from spillage.sources import build_sources


def test_ignore_by_fingerprint(leaky_home):
    gh = leaky_home.secrets["github"]
    result = Scanner(workers=1, ignore={fingerprint(gh)}).scan(build_sources())
    assert gh not in {f.secret for f in result.findings}
    assert result.stats.ignored == 1


def test_min_severity(leaky_home):
    result = Scanner(workers=1, min_severity=Severity.CRITICAL).scan(build_sources())
    assert result.findings and all(f.severity is Severity.CRITICAL for f in result.findings)


def test_since_skips_old_files(leaky_home):
    for path in leaky_home.root.rglob("*.jsonl"):
        os.utime(path, (time.time() - 30 * 86400,) * 2)
    result = Scanner(workers=1, since=time.time() - 86400).scan(build_sources())
    assert result.stats.files == 0


def test_sorted_worst_first(leaky_home):
    result = Scanner(workers=1).scan(build_sources())
    sev = [f.severity for f in result.findings]
    assert sev == sorted(sev, reverse=True)
    assert result.worst is Severity.CRITICAL


def test_parallel_matches_serial(leaky_home, monkeypatch):
    for i in range(6):
        leaky_home.claude_session(name=f"extra{i}", records=[
            {"type": "user", "message": {"content": f"key {fakes.npm()}"}}])
    serial = Scanner(workers=1).scan(build_sources())
    monkeypatch.setattr(scanner_mod, "PARALLEL_THRESHOLD", 0)
    seen = []
    parallel = Scanner(workers=2, progress=lambda d, t, a: seen.append((d, t))).scan(build_sources())
    key = lambda r: sorted((f.fingerprint, len(f.locations)) for f in r.findings)  # noqa: E731
    assert key(serial) == key(parallel)
    assert seen and seen[-1][0] == seen[-1][1]


def test_progress_callback_serial(leaky_home):
    calls = []
    Scanner(workers=1, progress=lambda d, t, a: calls.append((d, t, a))).scan(build_sources())
    assert calls[-1][0] == calls[-1][1] == 2


def test_to_dict_never_contains_the_secret(leaky_home):
    import json

    result = Scanner(workers=1).scan(build_sources())
    dumped = json.dumps(result.to_dict())
    for secret in leaky_home.secrets.values():
        assert secret not in dumped
        assert secret[: len(secret) // 2] not in dumped
    assert result.to_dict()["summary"]["findings"] == 4


def test_unreadable_file_is_reported_not_fatal(leaky_home, monkeypatch):
    def boom(self, path):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr("spillage.sources.Source.load", boom)
    result = Scanner(workers=1).scan(build_sources())
    assert result.findings == [] and len(result.stats.errors) == 2


def test_scan_text():
    gh, sk = fakes.github(), fakes.stripe()
    found = scan_text(f"{gh} {sk} {gh}")
    assert [f.secret for f in found] == [gh, sk] or [f.secret for f in found] == [sk, gh]
    assert scan_text("nothing to see") == []


def test_ignore_file_roundtrip(tmp_path):
    path = tmp_path / "ignore"
    add_ignore(["aaaaaaaaaaaa", "bbbbbbbbbbbb"], note="test key", path=path)
    add_ignore(["aaaaaaaaaaaa"], path=path)
    assert load_ignore(path) == {"aaaaaaaaaaaa", "bbbbbbbbbbbb"}
    assert path.read_text().count("aaaaaaaaaaaa") == 1
    assert load_ignore(tmp_path / "missing") == set()


@settings(max_examples=200)
@given(st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=1, max_size=200))
def test_mask_never_reveals_more_than_a_quarter(secret):
    shown = mask(secret).split("…")[0]
    assert len(shown) <= max(1, len(secret) // 4)
    assert not mask(secret).startswith(secret) or len(secret) <= 1


@settings(max_examples=100)
@given(st.text(max_size=300))
def test_scan_text_never_crashes(text):
    scan_text(text)


def test_big_files_are_split_without_changing_results(home, monkeypatch):
    """Parts are cut at line breaks; line numbers and the session from line 1 must survive."""
    keys = [fakes.npm() for _ in range(40)]
    records = []
    for key in keys:
        records.append({"timestamp": "2026-09-20T11:01:00Z", "type": "response_item",
                        "payload": {"type": "function_call_output", "output": "x" * 3000 + f" {key}"}})
        records.append({"timestamp": "2026-09-20T11:01:00Z", "type": "response_item",
                        "payload": {"type": "message", "role": "assistant", "content": "y" * 2000}})
    home.codex_session(records=records)
    for i in range(3):
        home.claude_session(name=f"s{i}", records=[{"type": "user", "message": {"content": "hi"}}])
    whole = Scanner(workers=1).scan(build_sources())
    monkeypatch.setattr(scanner_mod, "PARALLEL_THRESHOLD", 0)
    monkeypatch.setattr(scanner_mod, "SPLIT_BYTES", 20_000)
    split = Scanner(workers=2).scan(build_sources())

    def view(result):
        return sorted((f.fingerprint, [(loc.line, loc.session, loc.project, loc.origin) for loc in f.locations])
                      for f in result.findings)

    assert len(whole.findings) == 40
    assert view(whole) == view(split)
    assert {loc.session for f in split.findings for loc in f.locations} == {"rollout-1"}


def test_read_part_covers_the_file_exactly(tmp_path):
    from spillage.scanner import read_part

    path = tmp_path / "x.jsonl"
    lines = [f'{{"n": {i}, "pad": "{"z" * (i % 17)}"}}\n' for i in range(500)]
    path.write_text("".join(lines), encoding="utf-8")
    for parts in (1, 2, 3, 7, 50):
        pieces = [read_part(path, i, parts) for i in range(parts)]
        assert "".join(p[0] for p in pieces) == "".join(lines)
        assert all(p[2] == lines[0] for p in pieces)
        assert all(not p[0] or p[0].endswith("\n") for p in pieces)
