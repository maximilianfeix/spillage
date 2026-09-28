"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, guard
from . import html as _html  # noqa: F401  (registers the html format)
from .models import Origin, Severity
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
    parser.add_argument("--no-env", action="store_true",
                        help="don't look for the values from your projects' .env files")


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

    guard = sub.add_parser("guard", help="install agent hooks that block leaks before they happen")
    guard.add_argument("action", choices=["install", "uninstall", "status"])
    guard.add_argument("-a", "--agent", type=_csv, default=[], metavar="NAMES",
                       help="claude, codex, gemini (default: every one installed on this machine)")
    guard.add_argument("--scope", choices=["user", "project", "local"], default="user",
                       help="user: in your home folder (default), project: this repo's .claude/.codex/.gemini "
                            "folder, local: .claude/settings.local.json")

    hook = sub.add_parser("hook")  # called by the agent, not by you
    hook.add_argument("event", choices=["prompt", "tool", "session-end"])

    watch = sub.add_parser("watch", help="keep watching the logs and report new secrets as they land")
    watch.add_argument("-a", "--agent", type=_csv, default=[], metavar="NAMES", help="only these agents")
    watch.add_argument("--scrub", action="store_true",
                       help="scrub a file once it has been quiet for --quiet seconds after a new secret")
    watch.add_argument("--quiet", type=float, default=90, metavar="SECONDS",
                       help="how long a file must be untouched before --scrub touches it (default: 90)")
    watch.add_argument("--interval", type=float, default=2.0, metavar="SECONDS", help="poll interval (default: 2)")
    watch.add_argument("--no-notify", action="store_true", help="no desktop notifications, terminal only")
    watch.add_argument("--no-env", action="store_true", help="don't look for the values from your .env files")

    repo = sub.add_parser("repo", help="find agent transcripts committed to a git repo, and secrets in them")
    repo.add_argument("path", nargs="?", default=".", type=Path, help="the repository (default: here)")
    repo.add_argument("--files", nargs="*", metavar="FILE", help="only these files (what pre-commit passes)")
    repo.add_argument("--all-files", action="store_true", help="scan every tracked file, not just transcripts")
    repo.add_argument("--strict", action="store_true", help="fail on any committed transcript, even a clean one")
    repo.add_argument("-f", "--format", choices=["text", "json", "markdown", "github"], default="text",
                      help="github: annotations plus a job summary, for Actions")
    repo.add_argument("--no-color", action="store_true", help="plain output")

    sub.add_parser("agents", help="show which agents' logs were found and where")
    sub.add_parser("rules", help="list the detection rules")

    ignore = sub.add_parser("ignore", help="stop reporting a secret by its fingerprint")
    ignore.add_argument("fingerprints", nargs="+", metavar="FINGERPRINT")
    ignore.add_argument("--note", default="", help="why, for future you")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    commands = {"scan", "scrub", "check", "guard", "hook", "repo", "watch", "agents", "rules", "ignore"}
    if not argv or (argv[0] not in commands and argv[0] not in ("-h", "--help", "-V", "--version")):
        argv = ["scan"] + argv
    args = parser.parse_args(argv)
    try:
        return {
            "scan": cmd_scan,
            "scrub": cmd_scrub,
            "guard": cmd_guard,
            "repo": cmd_repo,
            "watch": cmd_watch,
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


ENV_RULE = "env-value"


def build_rules(args: argparse.Namespace) -> list:
    """Built-in rules, plus the exact values from the .env files of your projects.

    `env-value` works with --rules and --skip-rules like any other id."""
    only = list(getattr(args, "rules", None) or [])
    skip = list(getattr(args, "skip_rules", None) or [])
    want_env = not getattr(args, "no_env", False) and ENV_RULE not in skip and (not only or ENV_RULE in only)
    only = [r for r in only if r != ENV_RULE]
    skip = [r for r in skip if r != ENV_RULE]
    only_env = bool(getattr(args, "rules", None)) and not only  # --rules env-value
    rules = [] if only_env else get_rules(only=only or None, exclude=skip or None)
    if not want_env:
        return rules
    from .envfiles import rules_with_env
    from .sources import known_projects

    return rules_with_env(rules, known_projects(Path.home()))


def run_scan(args: argparse.Namespace, progress: Optional[Progress] = None) -> ScanResult:
    rules = build_rules(args)
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
    report = scrub(findings, rules=build_rules(args),
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


def _guard_agents(args: argparse.Namespace) -> List[str]:
    if args.agent:
        for name in args.agent:
            guard.get_agent(name)
        return args.agent
    if args.action != "install":
        return list(guard.AGENTS)
    found = [name for name, target in guard.AGENTS.items() if target.present()]
    return found or ["claude"]


def cmd_guard(args: argparse.Namespace) -> int:
    p = Painter(supports_color(sys.stdout))
    agents = _guard_agents(args)
    all_on = True
    print()
    for name in agents:
        target = guard.get_agent(name)
        path = guard.settings_path(args.scope, agent=name)
        where = short_path(str(path))
        if args.action == "install":
            changed = guard.install(path, name)
            state = "installed" if changed else "already installed"
            print(f"  {p('✓', 'green')} {target.label:<12} guard {state} in {where}")
        elif args.action == "uninstall":
            if guard.uninstall(path):
                print(f"  {p('✓', 'green')} {target.label:<12} guard removed from {where}")
            elif args.agent:
                print(f"    {target.label:<12} guard wasn't installed in {where}")
        else:
            state = guard.status(path, name)
            on = all(state.values())
            all_on = all_on and on
            mark = p("● on ", "green") if on else (p("◐ part", "yellow") if any(state.values()) else p("○ off", "gray"))
            print(f"  {mark}  {target.label:<12} {p(where, 'dim')}")
    if args.action == "install":
        problem = guard.verify()
        if problem:
            print(p(f"\n  ✗ the hook command doesn't run: {problem}", "red"))
            print(p(f"    {guard.hook_command('prompt')}", "dim"))
            print(p("    Make sure `spillage` is on your PATH (pipx or brew), then run this again.", "dim"))
            return EXIT_USAGE
        print()
        print(p("    prompts with a secret in them are blocked before they're sent", "dim"))
        print(p("    reading .env files, keys and credential files is blocked, also via the shell", "dim"))
        print(p("    when a session ends, its transcript is scrubbed", "dim"))
        print(p("    takes effect in new sessions. Undo: spillage guard uninstall", "dim"))
        if "codex" in agents:
            print(p("    Codex asks you to trust new hooks once: run /hooks inside Codex", "yellow"))
    print()
    if args.action == "status":
        return EXIT_CLEAN if all_on else EXIT_FOUND
    return EXIT_CLEAN


def cmd_watch(args: argparse.Namespace, max_ticks: Optional[int] = None) -> int:
    from .watch import Watcher, notify

    p = Painter(supports_color(sys.stdout))
    watcher = Watcher(build_sources(args.agent), rules=build_rules(args), ignore=load_ignore(),
                      scrub_after=args.quiet if args.scrub else None)
    count = watcher.prime()
    mode = f", scrubbing files {args.quiet:.0f}s after they go quiet" if args.scrub else ""
    print(f"\n  {p('spillage watch', 'bold')} {p(f'· {count} log files, every {args.interval:g}s{mode}', 'dim')}")
    print(p("  Ctrl+C to stop.\n", "dim"), flush=True)
    ticks = 0
    while max_ticks is None or ticks < max_ticks:
        ticks += 1
        for event in watcher.tick():
            f, loc = event.finding, event.location
            where = short_path(loc.project) if loc.project else short_path(loc.file)
            how = Origin.DESCRIPTIONS.get(loc.origin, loc.origin)
            print(f"  {p(time.strftime('%H:%M:%S'), 'dim')}  {p.badge(f.severity)} {p(f.rule_name, 'bold')}  "
                  f"{p(f.masked, 'cyan')}  {agent_label(loc.agent)} {p('·', 'dim')} {where}")
            print(p(f"            {how}" + (f" · rotate: {f.rotate_url}" if f.rotate_url else ""), "dim"), flush=True)
            if not args.no_notify:
                notify(f"spillage: {f.rule_name} leaked",
                       f"{f.masked} in {agent_label(loc.agent)}. Rotate it.")
        for path, n in watcher.scrub_quiet():
            stamp = p(time.strftime("%H:%M:%S"), "dim")
            print(f"  {stamp}  {p('✓ scrubbed', 'green')} {n} in {short_path(str(path))}", flush=True)
        if max_ticks is None or ticks < max_ticks:
            time.sleep(args.interval)
    return EXIT_CLEAN


def cmd_repo(args: argparse.Namespace) -> int:
    from .repo import REPO_IGNORE, scan_repo

    root = args.path.resolve()
    result = scan_repo(root, files=args.files, all_files=args.all_files, ignore=load_ignore())
    findings = result.findings
    strict_fail = args.strict and bool(result.transcripts)
    failed = bool(findings) or strict_fail
    rel = lambda f: os.path.relpath(f, root).replace(os.sep, "/")  # noqa: E731

    if args.format == "json":
        data = result.scan.to_dict()
        data["transcripts"] = result.transcripts
        for f in data["findings"]:
            for loc in f["locations"]:
                loc["file"] = rel(loc["file"])
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return EXIT_FOUND if failed else EXIT_CLEAN

    if args.format in ("markdown", "github"):
        md = _repo_markdown(result, rel)
        if args.format == "markdown":
            print(md)
        else:
            _github_output(result, root, args.strict, md)
        return EXIT_FOUND if failed else EXIT_CLEAN

    p = Painter(not args.no_color and supports_color(sys.stdout))
    print()
    print(f"  {p('spillage repo', 'bold')} {p(short_path(str(root)), 'dim')}")
    print()
    if not result.transcripts:
        print(f"  {p('✓', 'green', 'bold')} No agent transcripts committed here.")
    else:
        n = len(result.transcripts)
        headline = f"{n} agent transcript" + ("s are" if n != 1 else " is") + " committed"
        print(f"  {p('●', 'yellow')} {p(headline, 'bold')}"
              f" {p('(anyone who can read the repo can read the conversation)', 'dim')}")
        for path, agent in sorted(result.transcripts.items())[:20]:
            print(f"      {path}  {p(agent_label(agent), 'dim')}")
        if n > 20:
            print(p(f"      … and {n - 20} more", "dim"))
    if findings or args.all_files:
        print(render(result.scan, "text", color=p.color, repo=True, repo_ignore=REPO_IGNORE))
    elif result.transcripts:
        print(f"\n  {p('✓', 'green')} No secrets in them.")
    if strict_fail:
        print(p("\n  ✗ --strict: committed agent transcripts fail even without secrets. "
                "Remove them from git and add them to .gitignore.", "red"))
    print()
    return EXIT_FOUND if failed else EXIT_CLEAN


def _github_output(result, root: Path, strict: bool, md: str) -> None:
    """Annotations (paths relative to the workspace, which is what GitHub resolves them
    against), the job summary, and step outputs."""
    base = Path(os.environ.get("GITHUB_WORKSPACE") or Path.cwd()).resolve()

    def ws(path) -> str:
        try:
            return os.path.relpath(Path(path).resolve(), base).replace(os.sep, "/")
        except ValueError:
            return str(path)

    transcripts = {str((root / r).resolve()) for r in result.transcripts}
    for f in result.findings:
        for loc in f.locations:
            line = f",line={loc.line}" if loc.line else ""
            rotate = f" Rotate it: {f.rotate_url}" if f.rotate_url else ""
            in_transcript = str(Path(loc.file).resolve()) in transcripts
            where = "a committed agent transcript" if in_transcript else "a committed file"
            print(f"::error file={ws(loc.file)}{line},title=spillage: {f.rule_name}::"
                  f"{f.rule_name} ({f.masked}, {f.fingerprint}) is in {where}.{rotate}")
    if strict:
        for path, agent in result.transcripts.items():
            print(f"::warning file={ws(root / path)},title=spillage: agent transcript::"
                  f"{agent_label(agent)} transcript is committed. Add it to .gitignore.")
    for name, value in (("GITHUB_STEP_SUMMARY", md + "\n"),
                        ("GITHUB_OUTPUT", f"transcripts={len(result.transcripts)}\nsecrets={len(result.findings)}\n")):
        target = os.environ.get(name)
        if target:
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(value)
    print(f"spillage: {len(result.transcripts)} transcript(s), {len(result.findings)} secret(s)")


def _repo_markdown(result, rel) -> str:
    out = ["## spillage", ""]
    if not result.transcripts and not result.findings:
        return "\n".join(out + ["No agent transcripts committed. ✅"])
    if result.transcripts:
        out += [f"**{len(result.transcripts)} agent transcript(s) committed:**", ""]
        out += [f"- `{path}` ({agent_label(agent)})" for path, agent in sorted(result.transcripts.items())[:50]]
        out.append("")
    if result.findings:
        out += ["| Severity | What | Masked | Where | Rotate |", "| --- | --- | --- | --- | --- |"]
        for f in result.findings:
            loc = f.locations[0]
            where = f"`{rel(loc.file)}:{loc.line}`" + (f" +{len(f.locations) - 1}" if len(f.locations) > 1 else "")
            rotate = f"[rotate]({f.rotate_url})" if f.rotate_url else ""
            out.append(f"| {f.severity.label} | {f.rule_name} | `{f.masked}` | {where} | {rotate} |")
        out += ["", "Rotate these keys: the repo history keeps them even after the file is deleted."]
    else:
        out.append("No secrets in them.")
    return "\n".join(out)


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
        dirs = source.roots()
        roots = ", ".join(short_path(str(r)) for r in dirs[:3])
        if len(dirs) > 3:
            roots = f"{len(dirs)} project folders (this one and the ones your agent sessions ran in)"
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
    print(f"  {p.badge(Severity.HIGH)} {p(f'{ENV_RULE:<26}', 'bold')} Values from your projects' .env files")
    print(p(f"\n  {len(rules) + 1} rules. Leave some out with --skip-rules id,id\n", "dim"))
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
