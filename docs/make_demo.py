"""Renders docs/demo.svg: an animated terminal running the real spillage commands.

    python3 docs/make_demo.py

A throwaway home directory gets a few made-up agent sessions with fake keys, then
`spillage`, `spillage scrub` and `spillage guard install` run against it for real. Their
colored output is turned into SVG text and replayed line by line, so the demo can't drift
from what the program actually prints.
"""

from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

import fakes  # noqa: E402

COLS = 100
FONT = 13.5
CHAR_W = FONT * 0.6
LINE_H = 20
PAD_X, PAD_TOP = 22, 58
BG, FG = "#0E0F13", "#E9E7E2"
PALETTE = {
    "30": "#0E0F13", "31": "#FF5F6D", "32": "#3DDC97", "33": "#FFC24A", "34": "#5AA9FF", "35": "#D86BFF",
    "36": "#5CD6E0", "90": "#6E7382", "91": "#FF4D5E",
}
BG_PALETTE = {"41": "#FF4D5E", "43": "#FFC24A", "44": "#5AA9FF", "45": "#B04CE0"}
SANS_MONO = "'Geist Mono', 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace"


# ---- a fake home full of leaks ---------------------------------------------------------------

def jsonl(path: Path, records: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def build_home(root: Path) -> None:
    gh, ak, sk = fakes.github(), fakes.anthropic(), fakes.stripe()
    shop = root / ".claude/projects/-Users-you-code-shop"
    jsonl(shop / "8f2c41d0-6a1e-4c55-9d0e-5b7e2a91c3f4.jsonl", [
        {"type": "user", "sessionId": "8f2c41d0", "cwd": "/Users/you/code/shop", "timestamp": "2026-09-02T09:14:00Z",
         "message": {"role": "user", "content": f"push it, token is {gh}"}},
        {"type": "user", "sessionId": "8f2c41d0", "cwd": "/Users/you/code/shop", "timestamp": "2026-09-02T09:20:00Z",
         "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                                   "content": f"STRIPE_SECRET_KEY={sk}\nPORT=3000"}]}},
        {"type": "assistant", "sessionId": "8f2c41d0", "cwd": "/Users/you/code/shop", "timestamp": "2026-09-02T09:21:00Z",
         "message": {"role": "assistant", "content": [{"type": "text", "text": f"Your Stripe key {sk} is a live key."}]}},
    ])
    jsonl(root / ".codex/sessions/2026/09/19/rollout-2026-09-19T16-02-11-4c1e.jsonl", [
        {"timestamp": "2026-09-19T16:02:11Z", "type": "session_meta", "payload": {"id": "4c1e", "cwd": "/Users/you/code/bot"}},
        {"timestamp": "2026-09-19T16:03:40Z", "type": "response_item",
         "payload": {"type": "function_call_output", "call_id": "c1", "output": f"ANTHROPIC_API_KEY={ak}\n"}},
    ])
    jsonl(root / ".claude/projects/-Users-you-code-bot/1d9e7b22-0c3a-4f1b-8e6d-2a4c9f0b7e15.jsonl", [
        {"type": "user", "sessionId": "1d9e7b22", "cwd": "/Users/you/code/bot", "timestamp": "2026-09-24T11:05:00Z",
         "message": {"role": "user", "content": f"why does {gh} get a 401"}},
    ])
    old = time.time() - 86400
    for p in root.rglob("*.jsonl"):
        os.utime(p, (old, old))


def run(home: Path, *args: str) -> str:
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), FORCE_COLOR="1", COLUMNS=str(COLS),
               XDG_CONFIG_HOME=str(home / ".config"), XDG_DATA_HOME=str(home / ".local/share"), PYTHONPATH=str(ROOT))
    env.pop("NO_COLOR", None)
    env.pop("CLAUDE_CONFIG_DIR", None)
    env.pop("CODEX_HOME", None)
    proc = subprocess.run([sys.executable, "-m", "spillage", *args, "--workers", "1"] if args[0] in ("scan", "scrub")
                          else [sys.executable, "-m", "spillage", *args],
                          env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    return proc.stdout


# ---- ANSI -> SVG -------------------------------------------------------------------------------

SGR = re.compile(r"\x1b\[([0-9;]*)m")


def spans(line: str) -> list:
    out, style, pos = [], set(), 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            out.append((line[pos:m.start()], frozenset(style)))
        codes = m.group(1).split(";") if m.group(1) else ["0"]
        for c in codes:
            if c == "0":
                style = set()
            else:
                style.add(c)
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], frozenset(style)))
    return out


def line_svg(line: str, x: float, y: float) -> str:
    parts, backs = [], []
    col = 0
    for text, style in spans(line):
        if not text:
            continue
        fill = next((PALETTE[c] for c in style if c in PALETTE), FG)
        attrs = [f'fill="{fill}"']
        if "1" in style:
            attrs.append('font-weight="700"')
        if "2" in style:
            attrs.append('fill-opacity=".55"')
        if "4" in style:
            attrs.append('text-decoration="underline"')
        back = next((BG_PALETTE[c] for c in style if c in BG_PALETTE), None)
        if back:
            backs.append(f'<rect x="{x + col * CHAR_W - 2:.1f}" y="{y - FONT + 1:.1f}" width="{len(text) * CHAR_W + 2:.1f}" '
                         f'height="{FONT + 5:.1f}" rx="3" fill="{back}"/>')
            if "30" not in style:
                attrs[0] = 'fill="#fff"'
        parts.append(f'<tspan x="{x + col * CHAR_W:.1f}" {" ".join(attrs)}>{html.escape(text)}</tspan>')
        col += len(text)
    return "".join(backs) + f'<text y="{y:.1f}" xml:space="preserve">{"".join(parts)}</text>'


# ---- timeline ----------------------------------------------------------------------------------

class Timeline:
    """Collects elements with the second they appear, and the frame they belong to."""

    def __init__(self) -> None:
        self.items: list = []  # (svg, start, end) end = frame end
        self.frames: list = []
        self.settled: list = []  # the second each frame has finished printing
        self.t = 0.0

    def frame(self, lines: list, gap: float = 0.035) -> None:
        """lines: list of (kind, payload). kind 'type' types a command, 'out' prints a line, 'wait' pauses."""
        start = self.t
        members = []
        row = 0
        for kind, payload in lines:
            y = PAD_TOP + row * LINE_H
            if kind == "wait":
                self.t += payload
                continue
            if kind == "type":
                prompt = f'<text y="{y}" xml:space="preserve"><tspan x="{PAD_X}" fill="#FF6B4A" font-weight="700">❯</tspan>' \
                         f'<tspan x="{PAD_X + 2 * CHAR_W:.1f}" fill="{FG}">{html.escape(payload)}</tspan></text>'
                n = len(payload)
                dur = 0.05 * n + 0.2
                members.append((prompt, self.t, None, ("type", n, dur, y)))
                self.t += dur + 0.35
            else:
                members.append((line_svg(payload, PAD_X, y), self.t, None, None))
                self.t += gap
            row += 1
        self.settled.append(self.t)
        self.t += 3.2  # let it sit
        self.frames.append((start, self.t))
        for svg, t0, _, extra in members:
            self.items.append((svg, t0, self.t, extra, len(self.frames) - 1))
        self.t += 0.4


def render(tl: Timeline, rows: int, still: int = -1) -> str:
    """still >= 0 draws that frame without animation, for checking the layout."""
    total = tl.t
    # the loop starts where the first run has just finished printing, so the first thing anyone
    # sees is a result and not an empty terminal
    skip = tl.settled[0]
    height = PAD_TOP + rows * LINE_H + 10
    width = PAD_X * 2 + COLS * CHAR_W
    css, body = [], []

    def pct(t: float) -> str:
        return f"{max(0.0, min(100.0, t / total * 100)):.3f}%"

    for i, (svg, t0, t1, extra, frame) in enumerate(tl.items):
        if still >= 0:
            f0, f1 = tl.frames[still]
            if f0 <= t0 < f1:
                body.append(svg)
            continue
        name = f"a{i}"
        fade = 0.25
        css.append(f"@keyframes {name}{{0%,{pct(t0)}{{opacity:0}}{pct(t0 + 0.01)},{pct(t1)}{{opacity:1}}"
                   f"{pct(t1 + fade)},100%{{opacity:0}}}}")
        css.append(f".{name}{{animation:{name} {total:.2f}s linear -{skip:.2f}s infinite}}")
        body.append(f'<g class="{name} f{frame}">{svg}')
        if extra and extra[0] == "type":
            _, n, dur, y = extra
            cover = f"c{i}"
            x0 = PAD_X + 2 * CHAR_W
            css.append(f"@keyframes {cover}{{0%,{pct(t0)}{{transform:translateX(0)}}{pct(t0 + dur)},100%"
                       f"{{transform:translateX({n * CHAR_W + 4:.1f}px)}}}}")
            css.append(f".{cover}{{animation:{cover} {total:.2f}s steps({n * 4}, end) -{skip:.2f}s infinite}}")
            body.append(f'<rect class="{cover} cover" x="{x0 - 1:.1f}" y="{y - FONT:.1f}" width="{width:.0f}" '
                        f'height="{LINE_H}" fill="{BG}"/>')
        body.append("</g>")
    styles = "\n".join(css)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {height}" width="{width:.0f}" height="{height}" role="img" aria-label="Animated demo: spillage finds three leaked keys in Claude Code and Codex logs, scrubs them and installs the guard hooks">
<style>
text {{ font-family: {SANS_MONO}; font-size: {FONT}px; }}
{styles}
/* without motion: the finished first run, nothing else */
@media (prefers-reduced-motion: reduce) {{
  g, rect {{ animation: none !important; }}
  .cover, g:not(.f0) {{ display: none; }}
}}
</style>
<rect width="100%" height="100%" rx="14" fill="{BG}"/>
<rect x=".5" y=".5" width="{width - 1:.0f}" height="{height - 1}" rx="14" fill="none" stroke="#262A35"/>
<circle cx="24" cy="22" r="6" fill="#FF5F57"/><circle cx="44" cy="22" r="6" fill="#FEBC2E"/><circle cx="64" cy="22" r="6" fill="#28C840"/>
<text x="{width / 2:.0f}" y="27" text-anchor="middle" fill="#6E7382" font-size="12">~ spillage</text>
{"".join(body)}
</svg>
'''


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / "you"
        home.mkdir()
        build_home(home)
        scan = run(home, "scan").rstrip("\n").split("\n")
        scrub = run(home, "scrub", "--yes").strip("\n").split("\n")
        guard = run(home, "guard", "install").strip("\n").split("\n")
        after = run(home, "scan").strip("\n").split("\n")
    tl = Timeline()
    scan_lines = [("type", "spillage"), ("wait", 0.5)] + [("out", ln) for ln in scan]
    tl.frame(scan_lines, gap=0.045)
    second = [("type", "spillage scrub --yes")] + [("out", ln) for ln in scrub]
    second += [("out", ""), ("type", "spillage guard install")] + [("out", ln) for ln in guard]
    second += [("out", ""), ("type", "spillage")] + [("out", ln) for ln in after if ln.strip()]
    tl.frame(second, gap=0.06)
    rows = max(sum(1 for k, _ in f if k != "wait") for f in (scan_lines, second))
    out = ROOT / "docs" / "demo.svg"
    out.write_text(render(tl, rows), encoding="utf-8")
    if "--stills" in sys.argv:
        for i in range(len(tl.frames)):
            (ROOT / "docs" / f"demo-still-{i}.svg").write_text(render(tl, rows, still=i), encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)} ({out.stat().st_size // 1024} KB, {tl.t:.1f}s loop, {rows} rows)")


if __name__ == "__main__":
    main()
