"""The small value types everything else passes around."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, Iterable, Optional


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
    CONFIG = "config"  # an agent's settings: an MCP server's env, an allowed command
    OTHER = "other"

    DESCRIPTIONS = {
        PROMPT: "you pasted it into a prompt",
        TOOL: "a tool printed it (a file read or a command)",
        ASSISTANT: "the model repeated it in an answer",
        FILE: "a file backup the agent keeps",
        HISTORY: "your prompt history",
        CONFIG: "saved in an agent's settings (an MCP server, an allowed command)",
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


HIDE_MIN_LENGTH = 12  # shorter values (a password like "postgres") are ordinary words too


class Hider:
    """Takes full secrets out of text: `Hider(secrets)(text)`.

    Reports show secrets masked, but a key can also sit where nobody expects one: in a folder
    name, a session id, a timestamp field. Everything that leaves the program goes through
    here, so those places can't carry it out either. One compiled pattern for all secrets, so a
    report with thousands of strings is one pass each."""

    def __init__(self, secrets: Iterable[str]) -> None:
        self._markers: Dict[str, str] = {}
        for secret in set(secrets):
            if len(secret) < HIDE_MIN_LENGTH:
                continue
            # as it is, and the two ways JSON may have written it
            for form in (secret, json.dumps(secret)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1]):
                self._markers[form] = f"[REDACTED:{fingerprint(secret)}]"
        longest_first = sorted(self._markers, key=len, reverse=True)
        self._pattern = re.compile("|".join(map(re.escape, longest_first))) if longest_first else None

    def __call__(self, text: str) -> str:
        if self._pattern is None:
            return text
        return self._pattern.sub(lambda match: self._markers[match.group(0)], text)


def hide_secrets(text: str, secrets: Iterable[str]) -> str:
    """`text` with every full secret replaced by a marker, see Hider."""
    return Hider(secrets)(text)


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
