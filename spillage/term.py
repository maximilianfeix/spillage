"""Tiny ANSI helpers. No dependencies, respects NO_COLOR and FORCE_COLOR."""

from __future__ import annotations

import os
import shutil
import sys
from typing import IO, Optional

from .models import Severity

RESET = "\033[0m"
_CODES = {
    "bold": "1",
    "dim": "2",
    "italic": "3",
    "underline": "4",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "gray": "90",
    "bright_red": "91",
    "on_red": "41",
    "on_yellow": "43",
    "on_magenta": "45",
    "on_blue": "44",
    "black": "30",
}

SEVERITY_STYLE = {
    Severity.CRITICAL: ("on_red", "bold"),
    Severity.HIGH: ("on_magenta", "bold"),
    Severity.MEDIUM: ("on_yellow", "black"),
    Severity.LOW: ("on_blue", "bold"),
}
SEVERITY_FG = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "magenta",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}


def supports_color(stream: Optional[IO] = None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


class Painter:
    def __init__(self, color: bool) -> None:
        self.color = color

    def __call__(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        codes = ";".join(_CODES[s] for s in styles)
        return f"\033[{codes}m{text}{RESET}"

    def badge(self, severity: Severity) -> str:
        label = f" {severity.name:<8}"[:10]
        return self(label, *SEVERITY_STYLE[severity]) if self.color else f"[{severity.name}]".ljust(10)


def width(default: int = 88) -> int:
    return max(60, min(shutil.get_terminal_size((default, 24)).columns, 110))


def short_path(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home) :] if path.startswith(home) else path


def ellipsize(text: str, limit: int) -> str:
    """Shorten from the middle, where paths are least interesting: ~/.claude/…/abc.jsonl:12"""
    if len(text) <= limit or limit < 12:
        return text
    keep = limit - 1
    head = keep * 2 // 5
    return text[:head] + "…" + text[len(text) - (keep - head):]


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


class Progress:
    """A one-line progress bar on stderr. Silent when stderr isn't a terminal."""

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, stream: Optional[IO] = None, enabled: Optional[bool] = None) -> None:
        self.stream = stream or sys.stderr
        self.enabled = supports_color(self.stream) if enabled is None else enabled
        self.tick = 0

    def __call__(self, done: int, total: int, agent: str) -> None:
        if not self.enabled or not total:
            return
        self.tick += 1
        bar_w = 24
        filled = int(bar_w * done / total)
        bar = "█" * filled + "░" * (bar_w - filled)
        frame = self.FRAMES[self.tick % len(self.FRAMES)]
        self.stream.write(f"\r\033[2K  {frame} scanning {agent:<9} {bar} {done}/{total} files")
        self.stream.flush()

    def clear(self) -> None:
        if self.enabled:
            self.stream.write("\r\033[2K")
            self.stream.flush()
