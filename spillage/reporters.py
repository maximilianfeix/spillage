"""Output formats. Each reporter turns a ScanResult into a string; none of them ever sees
more of a secret than its masked form."""

from __future__ import annotations

import json
from collections import Counter
from typing import Callable, Dict

from .models import Finding, Origin, Severity
from .scanner import ScanResult
from .sources import get_source
from .term import SEVERITY_FG, Painter, ellipsize, human_bytes, short_path, width

Reporter = Callable[..., str]
_REPORTERS: Dict[str, Reporter] = {}


def reporter(name: str) -> Callable[[Reporter], Reporter]:
    def wrap(fn: Reporter) -> Reporter:
        _REPORTERS[name] = fn
        return fn

    return wrap


def formats() -> list:
    return sorted(_REPORTERS)


def render(result: ScanResult, fmt: str = "text", **options) -> str:
    try:
        fn = _REPORTERS[fmt]
    except KeyError:
        raise ValueError(f"unknown format {fmt!r} (use one of {', '.join(formats())})") from None
    return fn(result, **options)


def agent_label(name: str) -> str:
    try:
        return get_source(name).label
    except ValueError:
        return name


def _date(stamp: str) -> str:
    return stamp[:10] if stamp else "?"


def _how(finding: Finding) -> str:
    order = [Origin.PROMPT, Origin.TOOL, Origin.ASSISTANT, Origin.FILE, Origin.HISTORY, Origin.OTHER]
    origins = [o for o in order if o in finding.origins]
    return ", ".join(Origin.DESCRIPTIONS[o] for o in origins)


@reporter("json")
def render_json(result: ScanResult, **_) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


@reporter("text")
def render_text(result: ScanResult, color: bool = False, verbose: bool = False, repo: bool = False, **_) -> str:
    p = Painter(color)
    w = width()
    out = []
    stats = result.stats
    agents = ", ".join(agent_label(a) for a in stats.per_agent) or "nothing"
    out.append("")
    out.append(
        f"  {p('spillage', 'bold')} {p('scanned', 'dim')} {stats.files} files "
        f"{p('(' + human_bytes(stats.bytes) + ')', 'dim')} {p('from', 'dim')} {agents} "
        f"{p('in', 'dim')} {stats.seconds:.1f}s"
    )
    out.append("")

    if not stats.files:
        out.append(f"  {p('No agent logs found.', 'yellow')} Try --path to point at them.")
        out.append("")
        return "\n".join(out)

    if not result.findings:
        out.append(f"  {p('✓', 'green', 'bold')} {p('Nothing spilled.', 'green', 'bold')} "
                   f"No secrets in your agent logs.")
        if stats.ignored:
            out.append(p(f"    ({stats.ignored} ignored by fingerprint)", "dim"))
        out.append("")
        return "\n".join(out)

    counts = Counter(f.severity for f in result.findings)
    parts = [
        p(f"{counts[s]} {s.label}", _fg(s), "bold") if counts[s] else p(f"0 {s.label}", "dim")
        for s in sorted(Severity, reverse=True)
    ]
    total = len(result.findings)
    noun = "secret" if total == 1 else "secrets"
    out.append(f"  {p('●', 'bright_red')} {p(f'{total} {noun} spilled', 'bold')}   " + p(" · ", "dim").join(parts))
    out.append("  " + p("─" * (w - 4), "dim"))

    for f in result.findings:
        out.extend(_finding_block(f, p, verbose))

    out.append("")
    if repo:
        out.append(p("  Next steps", "bold"))
        out.append(f"    1. {p('Rotate these keys.', 'bold')} If the repo was ever pushed, assume they're public. "
                   "Deleting the file")
        out.append("       doesn't remove them from git history.")
        out.append(f"    2. Add the transcripts to {p('.gitignore', 'cyan')}, e.g. {p('.specstory/', 'cyan')} and "
                   f"{p('.aider*', 'cyan')}")
        out.append(f"    3. {p('pre-commit', 'cyan')}: the spillage hook stops the next one, see the README")
        out.append("")
        return "\n".join(out)
    out.append(p("  Next steps", "bold"))
    out.append(f"    1. {p('Rotate these keys.', 'bold')} They were sent to the model provider when the "
               f"conversation happened;")
    out.append("       deleting them locally does not undo that. The rotate links are above.")
    out.append(f"    2. {p('spillage scrub', 'cyan')}           removes them from the logs on disk")
    out.append(f"    3. {p('spillage guard install', 'cyan')}   blocks prompts and file reads that would leak "
               "the next one")
    out.append(f"    {p('False alarm?', 'dim')} {p('spillage ignore <fingerprint>', 'cyan')}")
    if stats.ignored:
        out.append(p(f"    ({stats.ignored} ignored by fingerprint)", "dim"))
    out.append("")
    return "\n".join(out)


def _fg(severity: Severity) -> str:
    return SEVERITY_FG[severity]


def _finding_block(f: Finding, p: Painter, verbose: bool) -> list:
    lines = [""]
    lines.append(
        f"  {p.badge(f.severity)} {p(f.rule_name, 'bold')}  {p(f.masked, 'cyan')}  {p(f.fingerprint, 'gray')}"
    )
    sessions = len(f.sessions)
    seen = f"seen {len(f.locations)}× in {sessions} session{'s' if sessions != 1 else ''}"
    span = _date(f.first_seen or "")
    if f.last_seen and _date(f.last_seen) != span:
        span += f" → {_date(f.last_seen)}"
    agents = ", ".join(agent_label(a) for a in f.agents)
    lines.append(f"{' ' * 13}{p(seen, 'dim')} {p('·', 'dim')} {agents} {p('·', 'dim')} {p(span, 'dim')}")
    lines.append(f"{' ' * 13}{p('how:', 'dim')}    {_how(f)}")
    shown = f.locations if verbose else f.locations[:1]
    for i, loc in enumerate(shown):
        label = "where:" if i == 0 else "      "
        where = ellipsize(short_path(loc.file) + (f":{loc.line}" if loc.line else ""), width() - 22)
        lines.append(f"{' ' * 13}{p(label, 'dim')}  {where}")
    if not verbose and len(f.locations) > 1:
        lines.append(f"{' ' * 13}{p(f'        +{len(f.locations) - 1} more (--verbose)', 'dim')}")
    if f.rotate_url:
        lines.append(f"{' ' * 13}{p('rotate:', 'dim')} {p(f.rotate_url, 'underline')}")
    return lines


@reporter("markdown")
def render_markdown(result: ScanResult, **_) -> str:
    stats = result.stats
    out = [
        "# spillage report",
        "",
        f"Scanned **{stats.files}** files ({human_bytes(stats.bytes)}) in {stats.seconds:.1f}s.",
        "",
    ]
    if not result.findings:
        out.append("Nothing spilled. ✅")
        return "\n".join(out) + "\n"
    out += [
        "| Severity | What | Masked | Seen | Sessions | How | Rotate |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for f in result.findings:
        rotate = f"[rotate]({f.rotate_url})" if f.rotate_url else ""
        out.append(
            f"| {f.severity.label} | {f.rule_name} | `{f.masked}` | {len(f.locations)}× | "
            f"{len(f.sessions)} | {_how(f)} | {rotate} |"
        )
    out += ["", "Rotate first, then `spillage scrub` to remove them from disk.", ""]
    return "\n".join(out)
