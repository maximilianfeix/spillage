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

_TEMPLATE = Path(__file__).with_name("assets") / "report.html"


@reporter("html")
def render_html(result: ScanResult, **_) -> str:
    from . import __version__

    data = result.to_dict()
    data["generated"] = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    data["size"] = human_bytes(result.stats.bytes)
    data["agents"] = [agent_label(a) for a in result.stats.per_agent]
    data["labels"] = {a: agent_label(a) for f in result.findings for a in f.agents}
    # "</" inside a <script> block would end it early; JSON allows escaping the slash.
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    template = _TEMPLATE.read_text(encoding="utf-8")
    return template.replace("__VERSION__", __version__).replace("__DATA__", payload)
