"""Secret values from your projects' .env files, to look for verbatim in the logs.

Patterns can't recognise a random database password or an Azure key. But if it's in a .env
file, we know the exact string and can simply search for it.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Dict, Iterable, List

from .rules import looks_like_placeholder, shannon_entropy
from .term import short_path

SECRET_NAME = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|CREDENTIAL|AUTH|PRIVATE|DSN|DATABASE_URL|CONN|WEBHOOK)", re.I
)
ENV_GLOBS = (".env", ".env.*", "*.env")
TEMPLATES = ("*.example", "*.sample", "*.template", "*.dist", "*.defaults", ".env.*.example")
MIN_LENGTH = 10
LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.*?)\s*$")


def env_files(projects: Iterable[Path]) -> List[Path]:
    """.env files in each project and one level below (monorepos), templates left out."""
    found = []
    for project in projects:
        for folder in [project] + [p for p in _subdirs(project)]:
            for pattern in ENV_GLOBS:
                for path in folder.glob(pattern):
                    if path.is_file() and not any(fnmatch.fnmatch(path.name, t) for t in TEMPLATES):
                        found.append(path)
    return sorted(set(found))


def _subdirs(project: Path) -> List[Path]:
    try:
        return [p for p in project.iterdir() if p.is_dir() and not p.name.startswith(".")
                and p.name not in ("node_modules", "venv", "dist", "build")]
    except OSError:
        return []


def parse(text: str) -> Dict[str, str]:
    """NAME -> value for the lines that look like secrets."""
    out: Dict[str, str] = {}
    for raw in text.splitlines():
        m = LINE.match(raw)
        if not m or raw.lstrip().startswith("#"):
            continue
        name, value = m.group(1), m.group(2)
        if value[:1] in "\"'" and value.endswith(value[:1]) and len(value) >= 2:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if not SECRET_NAME.search(name) or len(value) < MIN_LENGTH:
            continue
        if looks_like_placeholder(value) or shannon_entropy(value) < 3.0 or "\n" in value:
            continue
        if value.lower().startswith(("http://localhost", "http://127.0.0.1")):
            continue
        out[name] = value
    return out


def collect(projects: Iterable[Path], limit: int = 2000) -> Dict[str, str]:
    """value -> "NAME from ~/path/.env" across all projects."""
    values: Dict[str, str] = {}
    for path in env_files(projects):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, value in parse(text).items():
            values.setdefault(value, f"{name} from {short_path(str(path))}")
            if len(values) >= limit:
                return values
    return values
