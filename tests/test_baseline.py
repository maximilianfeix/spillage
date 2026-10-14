"""A baseline for CI (#77): accept the secrets a repository already has, fail on new ones."""

from __future__ import annotations

import json
import subprocess

import fakes
import pytest

from spillage import baseline
from spillage.cli import main
from spillage.models import fingerprint


@pytest.fixture
def repo(tmp_path, home):
    root = tmp_path / "shop"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    key = fakes.anthropic()
    hist = root / ".specstory" / "history"
    hist.mkdir(parents=True)
    (hist / "old.md").write_text(f"_**User**_\n\nkey: {key}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    return root, key


def add_transcript(root, name, text):
    path = root / ".specstory" / "history" / name
    path.write_text(text, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)


def run(capsys, *args):
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


def test_write_then_check_passes(repo, capsys):
    root, _key = repo
    file = root / ".spillage-baseline.json"
    code, _, err = run(capsys, "repo", str(root), "--write-baseline", str(file))
    assert code == 0 and "1 secret" in err
    code, out, _ = run(capsys, "repo", str(root), "--baseline", str(file), "--no-color")
    assert code == 0
    assert "1 accepted by the baseline" in out


def test_a_new_secret_fails_and_only_it_is_reported(repo, capsys):
    root, _old = repo
    file = root / ".spillage-baseline.json"
    run(capsys, "repo", str(root), "--write-baseline", str(file))
    new = fakes.github()
    add_transcript(root, "new.md", f"_**User**_\n\n{new}\n")
    code, out, _ = run(capsys, "repo", str(root), "--baseline", str(file), "-f", "json")
    data = json.loads(out)
    assert code == 1
    assert [f["fingerprint"] for f in data["findings"]] == [fingerprint(new)]
    assert data["baseline"] == {"file": str(file), "accepted": 1, "stale": 0}


def test_the_file_never_holds_a_secret_and_is_deterministic(repo, capsys):
    root, key = repo
    file = root / "b.json"
    run(capsys, "repo", str(root), "--write-baseline", str(file))
    first = file.read_bytes()
    text = first.decode("utf-8")
    assert key not in text and key[:12] not in text
    entry = json.loads(text)["findings"][0]
    assert entry == {"fingerprint": fingerprint(key), "rule": "anthropic-api-key",
                     "locations": [{"file": ".specstory/history/old.md", "line": 3}]}
    run(capsys, "repo", str(root), "--write-baseline", str(file))
    assert file.read_bytes() == first


def test_a_secret_that_is_gone_is_stale_not_a_failure(repo, capsys):
    root, _ = repo
    file = root / "b.json"
    run(capsys, "repo", str(root), "--write-baseline", str(file))
    (root / ".specstory" / "history" / "old.md").write_text("_**User**_\n\nhello\n", encoding="utf-8")
    code, out, _ = run(capsys, "repo", str(root), "--baseline", str(file), "--no-color")
    assert code == 0
    assert "1 entry in the baseline is no longer found" in out


def test_the_same_secret_in_another_file_stays_accepted(repo, capsys):
    root, key = repo
    file = root / "b.json"
    run(capsys, "repo", str(root), "--write-baseline", str(file))
    add_transcript(root, "copy.md", f"_**User**_\n\nagain {key}\n")
    code, _, _ = run(capsys, "repo", str(root), "--baseline", str(file))
    assert code == 0


@pytest.mark.parametrize("content", ["not json", "[]", '{"findings": 3}', '{"findings": [{"fingerprint": "xyz"}]}',
                                     '{"version": 99, "findings": []}'])
def test_a_broken_baseline_is_a_usage_error(repo, capsys, content):
    root, _ = repo
    file = root / "b.json"
    file.write_text(content, encoding="utf-8")
    code, _, err = run(capsys, "repo", str(root), "--baseline", str(file))
    assert code == 2 and "baseline" in err


def test_a_missing_baseline_is_a_usage_error(repo, capsys):
    root, _ = repo
    code, _, err = run(capsys, "repo", str(root), "--baseline", str(root / "nope.json"))
    assert code == 2 and "nope.json" in err


def test_strict_still_fails_on_transcripts(repo, capsys):
    root, _ = repo
    file = root / "b.json"
    run(capsys, "repo", str(root), "--write-baseline", str(file))
    code, _, _ = run(capsys, "repo", str(root), "--baseline", str(file), "--strict")
    assert code == 1


def test_sarif_and_github_only_report_new_secrets(repo, capsys, monkeypatch):
    root, old = repo
    file = root / "b.json"
    run(capsys, "repo", str(root), "--write-baseline", str(file))
    new = fakes.github()
    add_transcript(root, "new.md", f"_**User**_\n\n{new}\n")
    code, out, _ = run(capsys, "repo", str(root), "--baseline", str(file), "-f", "sarif")
    results = json.loads(out)["runs"][0]["results"]
    assert code == 1 and len(results) == 1
    assert fingerprint(new) in out and fingerprint(old) not in out
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    code, out, _ = run(capsys, "repo", str(root), "--baseline", str(file), "-f", "github")
    assert out.count("::error") == 1 and fingerprint(new) in out


def test_load_and_split():
    data = {"version": 1, "findings": [{"fingerprint": "0123456789ab", "rule": "x", "locations": []}]}
    assert baseline.parse(json.dumps(data), "b.json") == {"0123456789ab"}
