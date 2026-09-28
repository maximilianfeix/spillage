"""Draws docs/banner-dark.svg and docs/banner-light.svg.

    python3 docs/make_banner.py

The right half is a tiny session log. One line holds a key; it gets found and redacted.
"""

from __future__ import annotations

from pathlib import Path

DOCS = Path(__file__).resolve().parent
SANS = "'Geist', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "'Geist Mono', 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace"

THEMES = {
    "dark": {"bg": "#0E0F13", "panel": "#16181F", "line": "#262A35", "text": "#EDEBE6", "muted": "#9A97A0",
             "bar": "#2A2E3A", "accent": "#FF6B4A", "ok": "#3DDC97"},
    "light": {"bg": "#F7F5F1", "panel": "#FFFFFF", "line": "#E4E0D8", "text": "#16171C", "muted": "#6B6F7A",
              "bar": "#E9E5DD", "accent": "#E8502E", "ok": "#139E62"},
}

# (indent, width) of the grey "log lines"; None marks the line with the key in it
LINES = [(0, 230), (24, 180), (24, 270), None, (24, 150), (0, 250), (24, 200)]


def drop(x: float, y: float, s: float, color: str) -> str:
    return (f'<path transform="translate({x} {y}) scale({s})" d="M32 6c9 13 18 23 18 34a18 18 0 0 1-36 0C14 29 23 19 32 6z" '
            f'fill="{color}"/>')


def banner(t: dict) -> str:
    rows = []
    y0 = 92
    for i, spec in enumerate(LINES):
        y = y0 + i * 30
        delay = 0.15 + i * 0.06
        if spec is None:
            rows.append(f'''
    <g class="fade" style="animation-delay:{delay:.2f}s">
      <rect x="830" y="{y}" width="80" height="12" rx="6" fill="{t["bar"]}"/>
      <text x="922" y="{y + 11}" font-family="{MONO}" font-size="15" fill="{t["accent"]}" class="key">sk-ant-api03-Xq7…</text>
      <g class="redact">
        <rect x="918" y="{y - 5}" width="200" height="22" rx="6" fill="{t["accent"]}" fill-opacity=".14"/>
        <text x="928" y="{y + 11}" font-family="{MONO}" font-size="14" font-weight="600" fill="{t["accent"]}">[REDACTED:anthropic]</text>
      </g>
      <circle class="ping" cx="1140" cy="{y + 6}" r="6" fill="{t["ok"]}"/>
    </g>''')
        else:
            indent, width = spec
            rows.append(f'    <rect class="fade" style="animation-delay:{delay:.2f}s" x="{830 + indent}" y="{y}" '
                        f'width="{width}" height="12" rx="6" fill="{t["bar"]}"/>')
    rows_svg = "\n".join(rows)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 360" width="1280" height="360" role="img" aria-label="spillage – your coding agents spill secrets. Find them, scrub them, stop the next one.">
  <style>
    .fade {{ animation: fade .8s cubic-bezier(.16,1,.3,1) both; }}
    .key {{ animation: key 6s ease-in-out infinite; }}
    .redact {{ opacity: 0; animation: redact 6s ease-in-out infinite; }}
    .ping {{ opacity: 0; transform-box: fill-box; transform-origin: center; animation: ping 6s ease-in-out infinite; }}
    .drip {{ animation: drip 6s cubic-bezier(.5,0,.75,0) infinite; }}
    @keyframes fade {{ from {{ opacity: 0; transform: translateY(8px); }} to {{ opacity: 1; transform: none; }} }}
    @keyframes key {{ 0%, 38% {{ opacity: 1; }} 46%, 92% {{ opacity: 0; }} 100% {{ opacity: 1; }} }}
    @keyframes redact {{ 0%, 40% {{ opacity: 0; }} 48%, 90% {{ opacity: 1; }} 98%, 100% {{ opacity: 0; }} }}
    @keyframes ping {{ 0%, 46% {{ opacity: 0; transform: scale(.4); }} 52% {{ opacity: 1; transform: scale(1); }} 88% {{ opacity: 1; }} 94%, 100% {{ opacity: 0; }} }}
    @keyframes drip {{ 0%, 8% {{ transform: translateY(0); opacity: 0; }} 12% {{ opacity: 1; }} 30% {{ transform: translateY(58px); opacity: 1; }} 34%, 100% {{ transform: translateY(58px); opacity: 0; }} }}
    @media (prefers-reduced-motion: reduce) {{ .fade, .key, .drip {{ animation: none; }} .redact, .ping {{ animation: none; opacity: 1; }} .key {{ opacity: 0; }} }}
  </style>
  <defs><clipPath id="frame"><rect width="1280" height="360" rx="24"/></clipPath></defs>
  <g clip-path="url(#frame)">
    <rect width="1280" height="360" fill="{t["bg"]}"/>
    <rect x="800" y="52" width="410" height="256" rx="18" fill="{t["panel"]}" stroke="{t["line"]}"/>
    <circle cx="824" cy="72" r="5" fill="{t["line"]}"/><circle cx="842" cy="72" r="5" fill="{t["line"]}"/><circle cx="860" cy="72" r="5" fill="{t["line"]}"/>
    <text x="1190" y="77" text-anchor="end" font-family="{MONO}" font-size="12" fill="{t["muted"]}">~/.claude/projects/…/session.jsonl</text>
{rows_svg}
    <g class="drip">{drop(1224, 96, 0.3, t["accent"])}</g>
  </g>

  <g class="fade">
    {drop(70, 64, 0.9, t["accent"])}
    <text x="134" y="104" fill="{t["text"]}" font-family="{SANS}" font-size="30" font-weight="600" letter-spacing="-1">spillage</text>
    <text x="70" y="190" fill="{t["text"]}" font-family="{SANS}" font-size="60" font-weight="600" letter-spacing="-3">Your agents spill</text>
    <text x="70" y="252" fill="{t["text"]}" font-family="{SANS}" font-size="60" font-weight="600" letter-spacing="-3">secrets. <tspan fill="{t["accent"]}">Mop up.</tspan></text>
    <text x="72" y="302" fill="{t["muted"]}" font-family="{SANS}" font-size="17">Finds leaked keys in Claude Code, Codex and Gemini logs,</text>
    <text x="72" y="330" fill="{t["muted"]}" font-family="{SANS}" font-size="17">scrubs them and blocks the next one.</text>
  </g>
</svg>
'''


def main() -> None:
    for name, theme in THEMES.items():
        (DOCS / f"banner-{name}.svg").write_text(banner(theme), encoding="utf-8")
        print(f"wrote docs/banner-{name}.svg")


if __name__ == "__main__":
    main()
