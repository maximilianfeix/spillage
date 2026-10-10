"""Output formats. Each reporter turns a ScanResult into a string; none of them ever sees
more of a secret than its masked form."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, Optional

from .models import Finding, Origin, Severity
from .scanner import ScanResult
from .sources import get_source
from .term import SEVERITY_FG, Painter, ellipsize, human_bytes, short_path, width

HOMEPAGE = "https://github.com/maximilianfeix/spillage"
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
    return result.hide(fn(result, **options))


def agent_label(name: str) -> str:
    try:
        return get_source(name).label
    except ValueError:
        return name


def _date(stamp: str) -> str:
    return stamp[:10] if stamp else "?"


def _how(finding: Finding) -> str:
    order = [Origin.PROMPT, Origin.TOOL, Origin.ASSISTANT, Origin.FILE, Origin.HISTORY, Origin.CONFIG, Origin.OTHER]
    origins = [o for o in order if o in finding.origins]
    return ", ".join(Origin.DESCRIPTIONS[o] for o in origins)


@reporter("json")
def render_json(result: ScanResult, **_) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


@reporter("text")
def render_text(
    result: ScanResult, color: bool = False, verbose: bool = False, repo: bool = False, repo_ignore: str = "",
    star: bool = False, **_
) -> str:
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
        out.extend(_errors(stats.errors, p, verbose))
        out.append("")
        return "\n".join(out)

    if not result.findings:
        if stats.errors:
            out.append(f"  {p('?', 'yellow', 'bold')} {p('No secrets in the files that could be read.', 'bold')}")
        else:
            out.append(f"  {p('✓', 'green', 'bold')} {p('Nothing spilled.', 'green', 'bold')} "
                       f"No secrets in your agent logs.")
        if stats.ignored:
            out.append(p(f"    ({stats.ignored} ignored by fingerprint)", "dim"))
        out.extend(_errors(stats.errors, p, verbose))
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

    out.extend(_errors(stats.errors, p, verbose))
    out.append("")
    if repo:
        out.append(p("  Next steps", "bold"))
        out.append(f"    1. {p('Rotate these keys.', 'bold')} If the repo was ever pushed, assume they're public. "
                   "Deleting the file")
        out.append("       doesn't remove them from git history.")
        out.append(f"    2. Take agent transcripts out of git and add them to {p('.gitignore', 'cyan')}, "
                   f"e.g. {p('.specstory/', 'cyan')} and {p('.aider*', 'cyan')}")
        out.append(f"    3. {p('pre-commit', 'cyan')}: the spillage hook stops the next one, see the README")
        ignore_file = p(repo_ignore or ".spillageignore", "cyan")
        out.append(f"    {p('False alarm?', 'dim')} add its fingerprint to {ignore_file} in the repo")
        if stats.ignored:
            out.append(p(f"    ({stats.ignored} ignored by fingerprint)", "dim"))
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
    if star:
        # only for a person at a terminal who just saw it find something, never in a file or in CI
        out.append("")
        out.append(p(f"    Glad it caught these? A star helps the next person find it: {HOMEPAGE}", "dim"))
    out.append("")
    return "\n".join(out)


def _errors(errors: list, p: Painter, verbose: bool) -> list:
    """Files the scan could not read. A scan that skipped something must not look complete."""
    if not errors:
        return []
    n = len(errors)
    more = "" if verbose or n <= 3 else " (--verbose lists them all)"
    lines = ["", p(f"  ! {n} file{'s' if n != 1 else ''} could not be scanned{more}", "yellow")]
    lines.extend(p(f"    {ellipsize(short_path(e), width() - 6)}", "dim") for e in (errors if verbose else errors[:3]))
    return lines


def _fg(severity: Severity) -> str:
    return SEVERITY_FG[severity]


def _finding_block(f: Finding, p: Painter, verbose: bool) -> list:
    lines = [""]
    lines.append(
        f"  {p.badge(f.severity)} {p(f.rule_name, 'bold')}  {p(f.masked, 'cyan')}  {p(f.fingerprint, 'gray')}"
    )
    sessions = len(f.sessions)
    seen = f"seen {len(f.locations)}×"
    if sessions:  # settings files have no sessions and no timestamps
        seen += f" in {sessions} session{'s' if sessions != 1 else ''}"
    parts = [p(seen, "dim"), ", ".join(agent_label(a) for a in f.agents)]
    if f.first_seen:
        span = _date(f.first_seen)
        if f.last_seen and _date(f.last_seen) != span:
            span += f" → {_date(f.last_seen)}"
        parts.append(p(span, "dim"))
    lines.append(" " * 13 + f" {p('·', 'dim')} ".join(parts))
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
    if stats.errors:
        noun = "file" if len(stats.errors) == 1 else "files"
        out += [f"**{len(stats.errors)} {noun} could not be scanned.**", ""]
    if not result.findings:
        out.append("No secrets in the files that could be read." if stats.errors else "Nothing spilled. ✅")
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


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
# GitHub code scanning sorts and labels alerts by this 0-10 score (9+ critical, 7+ high, 4+ medium)
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0"}


@reporter("sarif")
def render_sarif(result: ScanResult, uri: Optional[Callable[[str], str]] = None, **_) -> str:
    """SARIF 2.1.0, for GitHub code scanning and other viewers. `uri` turns a file path into
    the artifact URI: relative to the checkout for code scanning, a file:// URI by default."""
    from . import __version__
    from .rules import get_rules

    to_uri = uri or (lambda f: Path(f).resolve().as_uri())
    default = {r.id: r.severity for r in get_rules()}
    rules: Dict[str, dict] = {}
    results = []
    for f in result.findings:
        level = _SARIF_LEVEL[f.severity]
        rotate = f" Rotate it: {f.rotate_url}" if f.rotate_url else ""
        # code scanning takes the severity from the rule, and one rule can rate secrets differently
        # (a Stripe test key is low, a live one critical): other severities get a rule of their own
        rule_id = f.rule_id if default.get(f.rule_id) == f.severity else f"{f.rule_id}/{f.severity.label}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": f.rule_name},
            "fullDescription": {"text": f"A {f.provider} credential that an AI coding agent wrote to disk."},
            "helpUri": f.rotate_url or HOMEPAGE,
            "help": {
                "text": f"Rotate the key first{': ' + f.rotate_url if f.rotate_url else ''}, then remove it from "
                        "the file. Deleting it doesn't un-send it: it went to the model provider too.",
                "markdown": f"**Rotate the key first**{f' ([here]({f.rotate_url}))' if f.rotate_url else ''}, then "
                            "remove it from the file. Deleting it doesn't un-send it: it went to the model "
                            "provider too.",
            },
            "defaultConfiguration": {"level": level},
            "properties": {"tags": ["security", "secret", f.provider], "precision": "high",
                           "security-severity": _SECURITY_SEVERITY[f.severity]},
        })
        for loc in f.locations:
            artifact = to_uri(loc.file)
            physical: dict = {"artifactLocation": {"uri": artifact}}
            if loc.line:
                physical["region"] = {"startLine": loc.line}
            how = Origin.DESCRIPTIONS.get(loc.origin, "")
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"{f.rule_name} ({f.masked}, fingerprint {f.fingerprint})"
                                    f"{': ' + how if how else ''}.{rotate}"},
                "locations": [{"physicalLocation": physical}],
                # one alert per secret and file, stable across runs and line shifts
                "partialFingerprints": {"spillageSecret/v1": f"{f.fingerprint}:{artifact}"},
                "properties": {"agent": loc.agent, "origin": loc.origin},
            })
    run = {
        "tool": {"driver": {"name": "spillage", "version": __version__, "informationUri": HOMEPAGE,
                            "rules": list(rules.values())}},
        "results": results,
    }
    if result.stats.errors:
        # SARIF's place for "the tool ran, but not over everything"
        run["invocations"] = [{
            "executionSuccessful": True,
            "toolExecutionNotifications": [
                {"level": "warning", "message": {"text": f"could not scan {error}"}} for error in result.stats.errors
            ],
        }]
    return json.dumps({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}, indent=2, ensure_ascii=False)


# registered here so `render(result, "html")` works without importing the CLI first
from . import html as _html  # noqa: E402,F401
