"""The small value types everything else passes around."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (use one of {names})") from None

    @property
    def label(self) -> str:
        return self.name.lower()


class Origin:
    """Where in a conversation a string came from. Plain strings so JSON stays readable."""

    PROMPT = "prompt"  # you typed or pasted it
    TOOL = "tool-output"  # a tool the agent ran printed it (cat .env, env, ...)
    ASSISTANT = "assistant"  # the model wrote it back
    FILE = "file-snapshot"  # a backup copy of a file the agent edited
    HISTORY = "history"  # the prompt history file
    OTHER = "other"

    DESCRIPTIONS = {
        PROMPT: "you pasted it into a prompt",
        TOOL: "a tool printed it (a file read or a command)",
        ASSISTANT: "the model repeated it in an answer",
        FILE: "a file backup the agent keeps",
        HISTORY: "your prompt history",
        OTHER: "session metadata",
    }


@dataclass(frozen=True)
class Location:
    """One place a secret was seen."""

    agent: str
    file: str
    line: int = 0
    json_path: str = ""
    session: str = ""
    project: str = ""
    timestamp: str = ""
    origin: str = Origin.OTHER


def fingerprint(secret: str) -> str:
    """A stable, non-reversible id for a secret. Used for dedup and the ignore file."""
    return hashlib.sha256(secret.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def mask(secret: str, keep: int = 6) -> str:
    """Show just enough of a secret to recognise it, never enough to use it."""
    if len(secret) <= 12:
        keep = min(keep, 2)
    keep = min(keep, len(secret) // 4 or 1)
    return f"{secret[:keep]}…({len(secret)} chars)"


@dataclass
class Finding:
    """One secret, with every place it turned up."""

    rule_id: str
    rule_name: str
    provider: str
    severity: Severity
    secret: str = field(repr=False)
    rotate_url: str = ""
    locations: list = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.secret)

    @property
    def masked(self) -> str:
        return mask(self.secret)

    @property
    def sessions(self) -> set:
        return {loc.session for loc in self.locations if loc.session}

    @property
    def agents(self) -> list:
        return sorted({loc.agent for loc in self.locations})

    @property
    def origins(self) -> list:
        return sorted({loc.origin for loc in self.locations})

    @property
    def first_seen(self) -> Optional[str]:
        stamps = sorted(loc.timestamp for loc in self.locations if loc.timestamp)
        return stamps[0] if stamps else None

    @property
    def last_seen(self) -> Optional[str]:
        stamps = sorted(loc.timestamp for loc in self.locations if loc.timestamp)
        return stamps[-1] if stamps else None

    def to_dict(self) -> dict:
        """JSON-safe view. Never includes the secret itself."""
        return {
            "rule": self.rule_id,
            "name": self.rule_name,
            "provider": self.provider,
            "severity": self.severity.label,
            "fingerprint": self.fingerprint,
            "masked": self.masked,
            "rotate_url": self.rotate_url,
            "agents": self.agents,
            "origins": self.origins,
            "sessions": len(self.sessions),
            "occurrences": len(self.locations),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "locations": [
                {
                    "agent": loc.agent,
                    "file": loc.file,
                    "line": loc.line,
                    "path": loc.json_path,
                    "session": loc.session,
                    "project": loc.project,
                    "timestamp": loc.timestamp,
                    "origin": loc.origin,
                }
                for loc in self.locations
            ],
        }
