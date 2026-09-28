"""Command line interface."""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, guard
from . import html as _html  # noqa: F401  (registers the html format)
from .models import Severity
from .reporters import agent_label, formats, render
from .rules import get_rules
from .scanner import Scanner, ScanResult, add_ignore, default_ignore_file, load_ignore, scan_text
from .scrub import plan, scrub
from .sources import all_sources, build_sources
from .term import Painter, Progress, short_path, supports_color

EXIT_CLEAN, EXIT_FOUND, EXIT_USAGE = 0, 1, 2


def parse_since(value: str) -> float:
    """`7d`, `12h`, `30m`, `2w` or an ISO date -> unix timestamp."""
    m = re.fullmatch(r"(\d+)\s*([mhdw])", value.strip())
    if m:
        seconds = {"m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
        return time.time() - int(m.group(1)) * seconds
    try:
        return time.mktime(time.strptime(value.strip()[:10], "%Y-%m-%d"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"can't read {value!r}: use 7d, 12h, 2w or 2026-09-01") from None


def _csv(value: str) -> List[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-a", "--agent", type=_csv, default=[], metavar="NAMES",
                        help="only these agents, comma separated (see `spillage agents`)")
    parser.add_argument("-p", "--path", action="append", type=Path, default=[], metavar="PATH",
                        help="also scan this file or folder (repeatable)")
    parser.add_argument("--since", type=parse_since, metavar="WHEN",
                        help="only files changed since: 7d, 12h, 2w or 2026-09-01")
    parser.add_argument("--min-severity", type=Severity.parse, default=Severity.LOW, metavar="LEVEL",
                        help="low, medium, high or critical (default: low)")
    parser.add_argument("--rules", type=_csv, metavar="IDS", help="only these rules")
    parser.add_argument("--skip-rules", type=_csv, metavar="IDS", help="leave out these rules")
    parser.add_argument("--workers", type=int, metavar="N", help="parallel processes (default: up to 8)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spillage",
        description="Find the secrets your coding agents spilled into their logs.",
        epilog="Run without a command to scan every agent it knows about.",
    )
    parser.add_argument("-V", "--version", action="version", version=f"spillage {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser("scan", help="look for secrets (the default)")
    _add_scan_options(scan)
    scan.add_argument("-f", "--format", choices=formats(), default="text", help="output format")
    scan.add_argument("-o", "--output", type=Path, metavar="FILE", help="write the report to a file")
    scan.add_argument("-v", "--verbose", action="store_true", help="list every place a secret was seen")
    scan.add_argument("--exit-zero", action="store_true", help="exit 0 even when something was found")
    scan.add_argument("--no-color", action="store_true", help="plain output")

    check = sub.add_parser("check", help="scan text from an argument or stdin (`pbpaste | spillage check`)")
    check.add_argument("text", nargs="?", default="-", help="the text, or - for stdin")
    check.add_argument("-q", "--quiet", action="store_true", help="no output, just the exit code")

    scrub = sub.add_parser("scrub", help="remove found secrets from the logs on disk")
    _add_scan_options(scrub)
    scrub.add_argument("--only", type=_csv, metavar="FPS", help="only these fingerprints, comma separated")
    scrub.add_argument("-n", "--dry-run", action="store_true", help="show what would change, change nothing")
    scrub.add_argument("-y", "--yes", action="store_true", help="don't ask")
    scrub.add_argument("--include-active", action="store_true",
                       help="also touch files written in the last minute (probably a running session)")

    guard = sub.add_parser("guard", help="install Claude Code hooks that block leaks before they happen")
    guard.add_argument("action", choices=["install", "uninstall", "status"])
    guard.add_argument("--scope", choices=["user", "project", "local"], default="user",
                       help="user: ~/.claude/settings.json (default), project: .claude/settings.json, "
                            "local: .claude/settings.local.json")

    hook = sub.add_parser("hook")  # called by the agent, not by you
    hook.add_argument("event", choices=["prompt", "tool", "session-end"])

    sub.add_parser("agents", help="show which agents' logs were found and where")
    sub.add_parser("rules", help="list the detection rules")

    ignore = sub.add_parser("ignore", help="stop reporting a secret by its fingerprint")
    ignore.add_argument("fingerprints", nargs="+", metavar="FINGERPRINT")
    ignore.add_argument("--note", default="", help="why, for future you")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    commands = {"scan", "scrub", "check", "guard", "hook", "agents", "rules", "ignore"}
    if not argv or (argv[0] not in commands and argv[0] not in ("-h", "--help", "-V", "--version")):
        argv = ["scan"] + argv
    args = parser.parse_args(argv)
    try:
        return {
            "scan": cmd_scan,
            "scrub": cmd_scrub,
            "guard": cmd_guard,
            "hook": lambda a: guard.run_hook(a.event),
            "check": cmd_check,
            "agents": cmd_agents,
            "rules": cmd_rules,
            "ignore": cmd_ignore,
        }[args.command](args)
    except ValueError as exc:
        print(f"spillage: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return 130


def run_scan(args: argparse.Namespace, progress: Optional[Progress] = None) -> ScanResult:
    rules = get_rules(only=args.rules, exclude=args.skip_rules)
    sources = build_sources(args.agent, args.path)
    scanner = Scanner(
        rules=rules,
        ignore=load_ignore(),
        since=args.since,
        min_severity=args.min_severity,
        progress=progress,
        workers=args.workers,
    )
    try:
        return scanner.scan(sources)
    finally:
        if progress:
            progress.clear()


def cmd_scan(args: argparse.Namespace) -> int:
    to_terminal = args.output is None and args.format == "text"
    color = to_terminal and not args.no_color and supports_color(sys.stdout)
    progress = Progress() if to_terminal else None
    result = run_scan(args, progress)
    report = render(result, args.format, color=color, verbose=args.verbose)
    if args.output:
        args.output.write_text(report + ("" if report.endswith("\n") else "\n"), encoding="utf-8")
        print(f"spillage: wrote {args.format} report to {args.output} "
              f"({len(result.findings)} finding{'s' if len(result.findings) != 1 else ''})", file=sys.stderr)
    else:
        print(report)
    return EXIT_FOUND if result.findings and not args.exit_zero else EXIT_CLEAN


def cmd_scrub(args: argparse.Namespace) -> int:
    p = Painter(supports_color(sys.stdout))
    result = run_scan(args, Progress())
    findings = [f for f in result.findings if not args.only or f.fingerprint in args.only]
    if not findings:
        print(p("✓ nothing to scrub", "green"))
        return EXIT_CLEAN
    files = plan(findings)
    occurrences = sum(len(f.locations) for f in findings)
    print(f"\n  {len(findings)} secret{'s' if len(findings) != 1 else ''}, {occurrences} places, "
          f"{len(files)} file{'s' if len(files) != 1 else ''}:")
    for f in findings:
        print(f"    {p.badge(f.severity)} {f.rule_name:<28} {p(f.masked, 'cyan')}  {p(f.fingerprint, 'gray')}")
    print()
    if not args.dry_run and not args.yes:
        if not sys.stdin.isatty():
            print("spillage: not a terminal, pass --yes to scrub without asking", file=sys.stderr)
            return EXIT_USAGE
        answer = input(f"  Replace them with [REDACTED:…] markers in {len(files)} files? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("  Nothing changed.")
            return EXIT_CLEAN
    report = scrub(findings, rules=get_rules(only=args.rules, exclude=args.skip_rules),
                   dry_run=args.dry_run, include_active=args.include_active)
    verb = "Would redact" if args.dry_run else "Redacted"
    print(f"  {p('✓', 'green')} {verb} {report.replacements} occurrences in {len(report.files_changed)} files.")
    for file in report.skipped_active:
        print(p(f"  skipped {short_path(file)}: written in the last minute, probably this session. "
                "Run again later or pass --include-active.", "yellow"))
    for file, why in report.failed:
        print(p(f"  could not scrub {short_path(file)}: {why}", "red"))
    if not args.dry_run and report.replacements:
        print(p("  Removing them locally doesn't un-send them. Rotate them if you haven't yet.", "dim"))
    print()
    return EXIT_USAGE if report.failed else EXIT_CLEAN


def cmd_guard(args: argparse.Namespace) -> int:
    p = Painter(supports_color(sys.stdout))
    path = guard.settings_path(args.scope)
    where = short_path(str(path))
    if args.action == "install":
        changed = guard.install(path)
        if changed:
            print(f"  {p('✓', 'green')} guard installed in {where}")
        else:
            print(f"  {p('✓', 'green')} guard was already installed in {where}")
        print(p("    prompts with a secret in them are blocked before they're sent", "dim"))
        print(p("    reading .env files, keys and credential files is blocked, also via Bash", "dim"))
        print(p("    when a session ends, its transcript is scrubbed", "dim"))
        print(p("    takes effect in new Claude Code sessions. Undo: spillage guard uninstall", "dim"))
    elif args.action == "uninstall":
        changed = guard.uninstall(path)
        print(f"  {p('✓', 'green')} guard removed from {where}" if changed else f"  guard wasn't installed in {where}")
    else:
        state = guard.status(path)
        for event, on in state.items():
            mark = p("● on ", "green") if on else p("○ off", "gray")
            print(f"  {mark}  {event:<17} {where}")
        return EXIT_CLEAN if all(state.values()) else EXIT_FOUND
    return EXIT_CLEAN


def cmd_check(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.text == "-" else args.text
    findings = scan_text(text)
    if not args.quiet:
        p = Painter(supports_color(sys.stdout))
        if not findings:
            print(p("✓ no secrets", "green"))
        for f in findings:
            print(f"{p.badge(f.severity)} {f.rule_name}  {p(f.masked, 'cyan')}  {p(f.fingerprint, 'gray')}")
    return EXIT_FOUND if findings else EXIT_CLEAN


def cmd_agents(args: argparse.Namespace) -> int:
    p = Painter(supports_color(sys.stdout))
    print()
    for cls in all_sources():
        source = cls()
        files = list(source.discover())
        size = sum(f.stat().st_size for f in files if f.exists())
        mark = p("●", "green") if files else p("○", "gray")
        roots = ", ".join(short_path(str(r)) for r in source.roots())
        detail = f"{len(files)} files, {size / 1e6:.1f} MB" if files else p("not found", "dim")
        print(f"  {mark} {p(f'{cls.name:<9}', 'bold')} {cls.label:<20} {detail}")
        print(f"    {p(roots, 'dim')}")
    print()
    return EXIT_CLEAN


def cmd_rules(args: argparse.Namespace) -> int:
    p = Painter(supports_color(sys.stdout))
    rules = get_rules()
    print()
    for rule in rules:
        print(f"  {p.badge(rule.severity)} {p(f'{rule.id:<26}', 'bold')} {rule.name}")
    print(p(f"\n  {len(rules)} rules. Leave some out with --skip-rules id,id\n", "dim"))
    return EXIT_CLEAN


def cmd_ignore(args: argparse.Namespace) -> int:
    for fp in args.fingerprints:
        if not re.fullmatch(r"[0-9a-f]{12}", fp):
            raise ValueError(f"{fp!r} is not a fingerprint (12 hex characters, shown next to each finding)")
    path = add_ignore(args.fingerprints, args.note)
    print(f"spillage: ignoring {len(args.fingerprints)} fingerprint(s) via {short_path(str(path))}")
    return EXIT_CLEAN


__all__ = ["agent_label", "build_parser", "default_ignore_file", "main", "parse_since"]


def entry() -> None:
    sys.exit(main())
