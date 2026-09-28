from __future__ import annotations

import json
import re

import fakes

from spillage.cli import main
from spillage.html import render_html
from spillage.models import Finding, Location, Severity
from spillage.scanner import Scanner, ScanResult, ScanStats
from spillage.sources import build_sources


def embedded(page: str) -> dict:
    raw = re.search(r'<script id="data" type="application/json">(.*?)</script>', page, re.S).group(1)
    return json.loads(raw)


def test_report_is_self_contained_and_masked(leaky_home):
    result = Scanner(workers=1).scan(build_sources())
    page = render_html(result)
    assert page.startswith("<!doctype html>")
    for secret in leaky_home.secrets.values():
        assert secret not in page
    assert not re.search(r'<(script|link)[^>]+(src|href)="https?://', page)
    data = embedded(page)
    assert data["summary"]["findings"] == 4
    assert data["labels"]["claude"] == "Claude Code"


def test_file_paths_cannot_break_out_of_the_script_tag():
    evil = Location(agent="claude", file="/tmp/</script><script>alert(1)</script>.jsonl", line=1)
    finding = Finding("npm-token", "npm access token", "npm", Severity.CRITICAL, fakes.npm(), "", [evil])
    page = render_html(ScanResult([finding], ScanStats(files=1)))
    assert "</script><script>alert(1)" not in page
    assert embedded(page)["findings"][0]["locations"][0]["file"] == evil.file


def test_empty_report():
    data = embedded(render_html(ScanResult([], ScanStats())))
    assert data["findings"] == [] and data["summary"]["files"] == 0


def test_cli_html_output(leaky_home, tmp_path, capsys):
    target = tmp_path / "report.html"
    assert main(["scan", "-f", "html", "-o", str(target)]) == 1
    assert "wrote html report" in capsys.readouterr().err
    assert "spillage report" in target.read_text(encoding="utf-8")


def test_comment_script_sequence_in_a_path():
    evil = Location(agent="claude", file="/tmp/<!--<script>x.jsonl", line=1, timestamp="yesterday")
    finding = Finding("npm-token", "npm access token", "npm", Severity.CRITICAL, fakes.npm(), "", [evil])
    page = render_html(ScanResult([finding], ScanStats(files=1)))
    data_block = page.split('<script id="data" type="application/json">')[1].split("</script>")[0]
    assert "<" not in data_block and ">" not in data_block
    assert embedded(page)["findings"][0]["locations"][0]["file"] == evil.file


def test_surrogates_from_odd_file_names(tmp_path):
    odd = Location(agent="path", file="/tmp/caf\udcff.jsonl", line=1)
    finding = Finding("npm-token", "npm access token", "npm", Severity.CRITICAL, fakes.npm(), "", [odd])
    page = render_html(ScanResult([finding], ScanStats(files=1)))
    (tmp_path / "r.html").write_text(page, encoding="utf-8")


def test_html_format_without_the_cli():
    import subprocess
    import sys

    code = "from spillage.reporters import formats; print(formats())"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60).stdout
    assert "html" in out
