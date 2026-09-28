"""Agent transcripts that got committed to a git repository.

On your disk a leaked key is a problem; in a pushed repo it's public. `spillage repo` lists
the transcripts git tracks (SpecStory, Aider, Claude Code, Codex, ...) and scans them.
"""

from __future__ import annotations

import fnmatch
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .models import Finding
from .rules import Rule
from .scanner import Scanner, ScanResult
from .sources import Aider, PathSource, Source, SpecStory

# (glob on the repo-relative path, agent name)
TRANSCRIPTS = (
    (".specstory/history/*.md", "specstory"),
    ("*/.specstory/history/*.md", "specstory"),
    (".aider.chat.history.md", "aider"),
    ("*/.aider.chat.history.md", "aider"),
    (".aider.input.history", "aider"),
    ("*/.aider.input.history", "aider"),
    (".claude/*.jsonl", "claude"),
    (".claude/**/*.jsonl", "claude"),
    ("*/.claude/projects/*/*.jsonl", "claude"),
    ("*rollout-*.jsonl", "codex"),
    (".codex/*.jsonl", "codex"),
    (".gemini/*/chats/*.json", "gemini"),
    (".continue/sessions/*.json", "continue"),
    ("*api_conversation_history.json", "cline"),
    ("*cline_task_*.md", "cline"),
)


def transcript_agent(relpath: str) -> Optional[str]:
    rel = relpath.replace("\\", "/")
    for pattern, agent in TRANSCRIPTS:
        if fnmatch.fnmatch(rel, pattern):
            return agent
    return None


def tracked_files(repo: Path) -> List[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z"], capture_output=True, check=True, timeout=120
        ).stdout
    except FileNotFoundError:
        raise ValueError("git isn't installed") from None
    except subprocess.CalledProcessError:
        raise ValueError(f"{repo} isn't a git repository") from None
    return [p for p in out.decode("utf-8", errors="replace").split("\0") if p]


class _Files(PathSource):
    """A fixed list of files, read the way a given agent's logs are read."""

    def __init__(self, paths: Iterable[Path], flavor: Source, name: str) -> None:
        super().__init__(paths)
        self.flavor = flavor
        self.name = name

    def document(self, path, text):
        return self.flavor.document(path, text)

    def origin(self, record, path):
        return self.flavor.origin(record, path)

    def text_origin_at(self, path, text, offset):
        return self.flavor.text_origin_at(path, text, offset)

    def update_state(self, record, state):
        self.flavor.update_state(record, state)

    def session_for(self, path, state):
        return self.flavor.session_for(path, state)


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
    transcripts: Dict[str, str] = field(default_factory=dict)  # relpath -> agent
    scan: Optional[ScanResult] = None

    @property
    def findings(self) -> List[Finding]:
        return self.scan.findings if self.scan else []


def scan_repo(
    root: Path,
    files: Optional[Sequence[str]] = None,
    all_files: bool = False,
    rules: Optional[Sequence[Rule]] = None,
    ignore: Iterable[str] = (),
) -> RepoResult:
    """`files` (repo-relative or absolute) limits the scan, as pre-commit passes them."""
    root = root.resolve()
    if files:
        rels = []
        for f in files:
            p = Path(f)
            p = p if p.is_absolute() else (Path.cwd() / p)
            try:
                rels.append(os.path.relpath(p.resolve(), root).replace(os.sep, "/"))
            except ValueError:
                continue
    else:
        rels = tracked_files(root)
    result = RepoResult(root)
    groups: Dict[str, List[Path]] = {}
    for rel in rels:
        agent = transcript_agent(rel)
        if agent:
            result.transcripts[rel] = agent
        elif not all_files:
            continue
        path = root / rel
        if path.is_file():
            groups.setdefault(agent or "file", []).append(path)
    sources: List[Source] = [
        _Files(paths, _flavor(agent), agent if agent != "file" else "path") for agent, paths in sorted(groups.items())
    ]
    result.scan = Scanner(rules=rules, ignore=ignore, workers=1).scan(sources)
    return result
