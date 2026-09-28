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

# Whole words of the variable name (split on _ - . and camelCase): AUTHOR or BYPASS don't count.
SECRET_WORDS = {
    "KEY", "APIKEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "PASS", "PWD", "CREDENTIAL", "CREDENTIALS",
    "AUTH", "DSN", "WEBHOOK", "PRIVATE", "CONNECTION", "CONN",
}
PUBLIC_WORDS = {"PUBLIC", "PUBLISHABLE", "ANON"}  # meant to ship to browsers
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


def name_words(name: str) -> set:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return {w.upper() for w in re.split(r"[_.\-]+", spaced) if w}


def is_secret_name(name: str) -> bool:
    words = name_words(name)
    if words & PUBLIC_WORDS:
        return False
    return bool(words & SECRET_WORDS) or name.upper() in ("DATABASE_URL", "REDIS_URL", "MONGODB_URI", "MONGO_URL")


def _value(raw: str) -> str:
    """The value part of a line: quotes removed, a trailing comment cut off. An opening quote
    that doesn't close on the same line (a multi-line PEM, say) gives an empty value."""
    if raw and raw[0] in "\"'":
        end = raw.find(raw[0], 1)
        return raw[1:end] if end != -1 else ""
    if " #" in raw:
        raw = raw.split(" #", 1)[0]
    return raw.strip()


def parse(text: str) -> Dict[str, str]:
    """NAME -> value for the lines that look like secrets."""
    out: Dict[str, str] = {}
    for raw in text.splitlines():
        m = LINE.match(raw)
        if not m or raw.lstrip().startswith("#"):
            continue
        name, value = m.group(1), _value(m.group(2))
        if not is_secret_name(name) or len(value) < MIN_LENGTH:
            continue
        if looks_like_placeholder(value) or shannon_entropy(value) < 3.0 or value.startswith("-----"):
            continue
        if re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I) and "@" not in value:
            continue  # a plain URL, no credentials in it
        out[name] = value
    return out


def rules_with_env(rules, projects: Iterable[Path]) -> list:
    """`rules` plus the values from the .env files in `projects`."""
    from .rules import with_known_values

    return with_known_values(rules, collect(projects))


def collect(projects: Iterable[Path], limit: int = 2000) -> Dict[str, str]:
    """value -> "NAME from ~/path/.env" across all projects."""
    values: Dict[str, str] = {}
    for path in env_files(projects):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            found = parse(text)
        except Exception:  # an odd .env file must never stop a scan
            continue
        for name, value in found.items():
            values.setdefault(value, f"{name} from {short_path(str(path))}")
            if len(values) >= limit:
                return values
    return values
