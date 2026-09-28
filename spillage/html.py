"""A single self-contained HTML report: no CDN, no external fonts, works offline.

The data goes in as JSON (masked values only, same as `-f json`) and a small script renders
it. Everything from disk is inserted with textContent, never as HTML.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from .reporters import agent_label, reporter
from .scanner import ScanResult
from .term import human_bytes


def _template() -> str:
    """Through importlib.resources, so it also works from a zipped install."""
    try:
        from importlib.resources import files

        return (files("spillage") / "assets" / "report.html").read_text(encoding="utf-8")
    except (ImportError, AttributeError):  # pragma: no cover
        return (Path(__file__).with_name("assets") / "report.html").read_text(encoding="utf-8")


@reporter("html")
def render_html(result: ScanResult, **_) -> str:
    from . import __version__

    data = result.to_dict()
    data["generated"] = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    data["size"] = human_bytes(result.stats.bytes)
    data["agents"] = [agent_label(a) for a in result.stats.per_agent]
    data["labels"] = {a: agent_label(a) for f in result.findings for a in f.agents}
    # No raw "<", ">" or "&" inside the <script> block at all: "</script>" would end it and
    # "<!--<script" would keep it from ending. ASCII-only also turns stray surrogates from
    # odd file names into \\udcxx escapes instead of an encoding error.
    payload = (json.dumps(data, ensure_ascii=True)
               .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))
    template = _template()
    return template.replace("__VERSION__", __version__).replace("__DATA__", payload)
