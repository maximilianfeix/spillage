"""Agent transcripts that got committed to a git repository.

On your disk a leaked key is a problem; in a pushed repo it's public. `spillage repo` lists
the transcripts git tracks (SpecStory, Aider, Claude Code, Codex, ...) and scans them.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .models import Finding
from .rules import Rule
from .scanner import Scanner, ScanResult, load_ignore
from .sources import Aider, PathSource, Source, SpecStory

# (regex on the repo-relative path, agent). Anchored on path segments so an unrelated
# `data/rollout-metrics.jsonl` doesn't count. .pre-commit-hooks.yaml uses TRANSCRIPT_REGEX
# below verbatim, and a test keeps the two in sync.
TRANSCRIPTS = (
    (r"(^|/)\.specstory/history/[^/]+\.md$", "specstory"),
    (r"(^|/)\.aider\.chat\.history\.md$", "aider"),
    (r"(^|/)\.aider\.input\.history$", "aider"),
    (r"(^|/)\.claude/.+\.jsonl$", "claude"),
    (r"(^|/)\.codex/.+\.jsonl$", "codex"),
    (r"(^|/)rollout-\d{4}-\d\d-\d\dT[\d-]+-[0-9a-f-]+\.jsonl$", "codex"),
    (r"(^|/)\.gemini/(.+/)?chats/[^/]+\.json$", "gemini"),
    (r"(^|/)\.continue/sessions/[^/]+\.json$", "continue"),
    (r"(^|/)api_conversation_history\.json$", "cline"),
    (r"(^|/)cline_task_[a-z]{3}-\d{1,2}-\d{4}[^/]*\.md$", "cline"),
)
_COMPILED = [(re.compile(p), agent) for p, agent in TRANSCRIPTS]
TRANSCRIPT_REGEX = "|".join(f"({p})" for p, _ in TRANSCRIPTS)

# Agent settings that are often committed on purpose (.mcp.json is meant to be shared). They're
# scanned for secrets but aren't transcripts, so --strict doesn't fail on them.
SETTINGS = (
    r"(^|/)\.mcp\.json$",
    r"(^|/)\.claude/settings(\.local)?\.json$",
    r"(^|/)\.(cursor|vscode)/mcp\.json$",
    r"(^|/)\.(gemini|qwen)/settings\.json$",
    r"(^|/)(opencode\.jsonc?|\.crush\.json|claude_desktop_config\.json)$",
)
_SETTINGS = [re.compile(p) for p in SETTINGS]
# what the `spillage` pre-commit hook passes on: transcripts and settings
HOOK_REGEX = TRANSCRIPT_REGEX + "|" + "|".join(f"({p})" for p in SETTINGS)

# fingerprints to ignore for this repo, one per line, committed with it
REPO_IGNORE = ".spillageignore"


def transcript_agent(relpath: str) -> Optional[str]:
    rel = relpath.replace("\\", "/")
    for pattern, agent in _COMPILED:
        if pattern.search(rel):
            return agent
    return None


def is_settings(relpath: str) -> bool:
    rel = relpath.replace("\\", "/")
    return any(p.search(rel) for p in _SETTINGS)


def tracked_files(repo: Path) -> List[str]:
    try:
        proc = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"], capture_output=True, timeout=120)
    except FileNotFoundError:
        raise ValueError("git isn't installed") from None
    except subprocess.TimeoutExpired:
        raise ValueError(f"git ls-files in {repo} took longer than 2 minutes") from None
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()
        raise ValueError(f"git ls-files failed in {repo}: {err[-1] if err else 'exit ' + str(proc.returncode)}")
    return [p for p in proc.stdout.decode("utf-8", errors="replace").split("\0") if p]


class _Files(PathSource):
    """A fixed list of files, read the way a given agent's logs are read. `document()` hands
    the flavor adapter to Document, so origin and session come from it."""

    def __init__(self, paths: Iterable[Path], flavor: Source, name: str) -> None:
        super().__init__(paths)
        self.flavor = flavor
        self.name = name

    def document(self, path, text):
        return self.flavor.document(path, text)


def _flavor(agent: str) -> Source:
    from .sources import get_source

    if agent == "aider":
        return Aider()
    if agent == "specstory":
        return SpecStory()
    if agent == "file":
        return PathSource([])
    try:
        return get_source(agent)()
    except ValueError:
        return Source()


@dataclass
class RepoResult:
    root: Path
    scan: ScanResult
    transcripts: Dict[str, str] = field(default_factory=dict)  # relpath -> agent

    @property
    def findings(self) -> List[Finding]:
        return self.scan.findings


def repo_ignore(root: Path) -> set:
    return load_ignore(root / REPO_IGNORE)


def scan_repo(
    root: Path,
    files: Optional[Sequence[str]] = None,
    all_files: bool = False,
    rules: Optional[Sequence[Rule]] = None,
    ignore: Iterable[str] = (),
) -> RepoResult:
    """`files` limits the scan, the way pre-commit passes them: absolute, or relative to the
    current folder. Files outside the repository are skipped."""
    root = root.resolve()
    if files:
        rels = []
        for f in files:
            p = Path(f)
            p = p if p.is_absolute() else (Path.cwd() / p)
            try:
                rel = os.path.relpath(p.resolve(), root).replace(os.sep, "/")
            except ValueError:  # another drive on Windows
                continue
            if not rel.startswith("../") and rel != "..":
                rels.append(rel)
    else:
        rels = tracked_files(root)
    transcripts: Dict[str, str] = {}
    groups: Dict[str, List[Path]] = {}
    for rel in rels:
        agent = transcript_agent(rel)
        if agent:
            transcripts[rel] = agent
        elif is_settings(rel):
            agent = "config"
        elif not all_files:
            continue
        path = root / rel
        if path.is_file():
            groups.setdefault(agent or "file", []).append(path)
    sources: List[Source] = [
        _Files(paths, _flavor(agent), agent if agent != "file" else "path") for agent, paths in sorted(groups.items())
    ]
    skip = set(ignore) | repo_ignore(root)
    scan = Scanner(rules=rules, ignore=skip, workers=1).scan(sources)
    return RepoResult(root, scan, transcripts)
