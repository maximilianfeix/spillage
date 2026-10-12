"""`spillage doctor`: where this machine stands, in one screen.

Each check is a small function that returns what it found and the command that fixes it.
"""

from __future__ import annotations

import os
import stat as modes
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, List, NamedTuple, Optional

from . import guard
from .models import Origin, Severity
from .reporters import agent_label
from .scanner import ScanResult

OK, TODO, INFO = "ok", "todo", "info"


class Check(NamedTuple):
    name: str
    state: str  # OK, TODO or INFO (nothing to judge, like "no agents installed")
    text: str
    fix: str = ""

    def to_dict(self) -> dict:
        return {"check": self.name, "state": self.state, "text": self.text, "fix": self.fix}


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


def check_logs(result: ScanResult) -> Check:
    stats = result.stats
    agents = [a for a in stats.per_agent if a != "config"]
    if not agents:
        return Check("logs", INFO, "no agent logs on this machine", "spillage scan --path <folder>")
    names = ", ".join(agent_label(a) for a in agents)
    return Check("logs", OK, f"{_n(stats.files, 'file')} from {names}")


def _in_settings(finding) -> bool:
    return finding.origins == [Origin.CONFIG]


def check_leaks(result: ScanResult) -> Check:
    found = [f for f in result.findings if not _in_settings(f)]
    if not found:
        return Check("leaks", OK, "no secrets in the logs")
    worst = Counter(f.severity for f in found)
    top = max(worst)
    detail = f", {worst[top]} {top.label}" if top >= Severity.HIGH else ""
    return Check("leaks", TODO, f"{_n(len(found), 'secret')} in the logs{detail}",
                 "spillage   (rotate them, then: spillage scrub)")


def check_settings(result: ScanResult) -> Check:
    found = [f for f in result.findings if Origin.CONFIG in f.origins]
    if not found:
        return Check("settings", OK, "no keys in plain text in agent settings")
    return Check("settings", TODO, f"{_n(len(found), 'key')} in plain text in agent settings",
                 "spillage scan --agent config   (move them into environment variables)")


def check_guard() -> Check:
    present = [name for name, target in guard.AGENTS.items() if target.present()]
    if not present:
        return Check("guard", INFO, "no agent with hooks installed (Claude Code, Codex, Gemini CLI)")
    off, broken = [], []
    for name in present:
        label = guard.get_agent(name).label
        try:
            state = guard.status(guard.settings_path("user", agent=name), name)
        except ValueError:
            broken.append(label)
            continue
        if not all(state.values()):
            off.append(label)
    if broken:
        return Check("guard", TODO, f"can't read the settings of {', '.join(broken)}", "spillage guard status")
    if off:
        return Check("guard", TODO, f"hooks are off for {', '.join(off)}", "spillage guard install")
    return Check("guard", OK, f"hooks are on for {', '.join(guard.get_agent(n).label for n in present)}")


def check_env(home: Path) -> Check:
    from .envfiles import collect
    from .sources import known_projects

    values = collect(known_projects(home))
    if not values:
        return Check("env", INFO, "no secret values in your projects' .env files to look for")
    return Check("env", OK, f"looking for {_n(len(values), 'value')} from your projects' .env files")


def readable_by_others(path: Path, home: Path, stat: Callable[[Path], os.stat_result] = os.stat) -> bool:
    """Whether every user on the machine can read `path`. That takes the read bit for others on
    the file and their search bit on every folder between it and `home`, `home` included: a
    closed folder on the way keeps what is below it private. The group is left out, since on
    most systems it is a group of one, yours."""
    try:
        if not stat(path).st_mode & modes.S_IROTH:
            return False
        folder = path.parent
        while stat(folder).st_mode & modes.S_IXOTH:
            if folder == home or folder == folder.parent:
                return True
            folder = folder.parent
    except (OSError, ValueError):
        pass
    return False


def _chmod_target(root: Path, path: Path, home: Path) -> Path:
    """The folder to close for `path`: the agent's own one (`~/.claude`), or below a folder it
    shares with other programs the first part that is the agent's (`~/.config/goose`)."""
    if root.parent == home:
        return root
    return root / path.relative_to(root).parts[0]


def _for_shell(path: str) -> str:
    """`~/.claude`, or the whole path in quotes when it has a space: a `~` in quotes stays a `~`."""
    from .term import short_path

    return f'"{path}"' if " " in path else short_path(path)


def check_perms(home: Path) -> Optional[Check]:
    """Only where file modes say who may read; None on Windows."""
    from .sources import all_sources

    if os.name != "posix":
        return None
    cache: Dict[Path, os.stat_result] = {}

    def stat(path: Path) -> os.stat_result:
        if path not in cache:
            cache[path] = os.stat(path)
        return cache[path]

    count, targets = 0, []
    for cls in all_sources():
        if cls.name == "config":
            continue
        source = cls(home)
        roots = [r for r in source.roots() if r.is_dir()]
        for path in source.discover():
            if not readable_by_others(path, home, stat):
                continue
            count += 1
            root = next((r for r in roots if r in path.parents), path.parent)
            target = _chmod_target(root, path, home)
            if target not in targets:
                targets.append(target)
    if not count:
        return Check("perms", OK, "the logs can only be read by you")
    return Check("perms", TODO, f"{_n(count, 'log file')} can be read by other users on this machine",
                 "chmod -R go-rwx " + " ".join(_for_shell(str(t)) for t in targets))


CLAUDE_KEEPS_DAYS = 30  # cleanupPeriodDays when the settings don't say


def check_retention() -> Optional[Check]:
    """How long Claude Code keeps its transcripts; None without Claude Code. Never a TODO:
    how long is right is yours to decide."""
    if not guard.AGENTS["claude"].present():
        return None
    from .term import short_path

    settings = guard.settings_path("user", agent="claude")
    try:
        days = guard._load(settings).get("cleanupPeriodDays")
    except (OSError, ValueError):
        days = None
    hint = f"set cleanupPeriodDays in {short_path(str(settings))} to keep them for less"
    if isinstance(days, bool) or not isinstance(days, int) or days < 0:
        return Check("retention", INFO, f"Claude Code keeps transcripts for {CLAUDE_KEEPS_DAYS} days (its default)",
                     hint)
    text = f"Claude Code keeps transcripts for {_n(days, 'day')}"
    return Check("retention", INFO, text, hint) if days > CLAUDE_KEEPS_DAYS else Check("retention", OK, text)


def check_repo(cwd: Path, ignore: set) -> Optional[Check]:
    """Only inside a git repository; None anywhere else."""
    from .repo import scan_repo

    if not (cwd / ".git").exists():
        return None
    try:
        result = scan_repo(cwd, ignore=ignore)
    except ValueError:
        return None
    if result.findings:
        return Check("repo", TODO, f"{_n(len(result.findings), 'secret')} committed in this repository",
                     "spillage repo")
    if result.transcripts:
        return Check("repo", TODO, f"{_n(len(result.transcripts), 'agent transcript')} committed in this repository",
                     "spillage repo   (take them out of git, add them to .gitignore)")
    return Check("repo", OK, "no agent transcripts committed in this repository")


def run(result: ScanResult, home: Path, cwd: Optional[Path], ignore: set) -> List[Check]:
    checks = [check_logs(result), check_leaks(result), check_settings(result), check_guard(), check_env(home)]
    extra = [check_perms(home), check_retention(), check_repo(cwd, ignore) if cwd else None]
    return checks + [c for c in extra if c]
