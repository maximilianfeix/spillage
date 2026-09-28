"""Where coding agents keep their conversations, and how to read them.

Each agent gets a small adapter: where its files live, and how to tell a pasted prompt from
tool output in its format. Reading is shared. Every JSON string is scanned no matter how
deep it sits, so a format change on the agent's side costs us context labels, not findings.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Type

from .models import Location, Origin
from .walker import Path as JsonPath
from .walker import format_path, iter_strings

MAX_FILE_BYTES = 256 * 1024 * 1024

_REGISTRY: Dict[str, Type[Source]] = {}


def register(cls: Type[Source]) -> Type[Source]:
    _REGISTRY[cls.name] = cls
    return cls


def all_sources() -> List[Type[Source]]:
    return list(_REGISTRY.values())


def get_source(name: str) -> Type[Source]:
    try:
        return _REGISTRY[name]
    except KeyError:
        names = ", ".join(_REGISTRY)
        raise ValueError(f"unknown agent {name!r} (known: {names})") from None


def _app_support() -> List[Path]:
    """Per-OS roots where VS Code-style editors keep extension storage."""
    home = Path.home()
    if sys.platform == "darwin":
        return [home / "Library" / "Application Support"]
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        return [Path(appdata)] if appdata else []
    return [Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))]


def _keys(path: JsonPath) -> set:
    return {p for p in path if isinstance(p, str)}


class Source:
    """Base adapter. Subclasses set `name`, `label` and `patterns` and may refine `origin`."""

    name = "generic"
    label = "Files"
    patterns: Tuple[str, ...] = ()

    def __init__(self, home: Optional[Path] = None) -> None:
        self.home = Path(home) if home else Path.home()

    # -- discovery -----------------------------------------------------------------------
    def roots(self) -> List[Path]:
        return [self.home]

    def discover(self) -> Iterator[Path]:
        seen = set()
        for root in self.roots():
            if not root.is_dir():
                continue
            for pattern in self.patterns:
                for path in sorted(root.glob(pattern)):
                    if path.is_file() and not path.is_symlink() and path not in seen:
                        seen.add(path)
                        yield path

    def installed(self) -> bool:
        return any(True for _ in self.discover())

    # -- reading -------------------------------------------------------------------------
    def load(self, path: Path) -> Optional[str]:
        """The raw file text, or None for binary and oversized files."""
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                return None
            with open(path, encoding="utf-8", errors="strict") as fh:
                return fh.read()
        except UnicodeDecodeError:
            try:
                raw = path.read_bytes()
            except OSError:
                return None
            if b"\0" in raw[:8192]:
                return None
            return raw.decode("utf-8", errors="replace")
        except OSError:
            return None

    def document(self, path: Path, text: str) -> Document:
        return Document(self, path, text)

    # -- format knowledge -----------------------------------------------------------------
    def update_state(self, record: Any, state: dict) -> None:
        """Pick up session id and project directory as records stream past."""
        if not isinstance(record, dict):
            return
        for key in ("sessionId", "session_id"):
            if isinstance(record.get(key), str):
                state["session"] = record[key]
        if isinstance(record.get("cwd"), str):
            state["project"] = record["cwd"]

    def origin(self, record: Any, path: JsonPath) -> str:
        return generic_origin(record, path)

    def text_origin(self, path: Path) -> str:
        return Origin.OTHER

    def session_for(self, path: Path, state: dict) -> str:
        return state.get("session") or path.stem


def decode_json_fragment(raw: str) -> str:
    """Undo JSON string escaping on a match taken from a raw log line (`\\n` -> newline)."""
    if "\\" not in raw:
        return raw
    try:
        return json.loads('"' + raw + '"')
    except ValueError:
        return raw


class Document:
    """One file's raw text, plus lazy JSON parsing to put a match into context.

    The rules run over the raw text in one go, which is fast. Only lines that actually contain
    a match get parsed, to find out who said it (prompt, tool output, ...) and in which session.
    """

    def __init__(self, source: Source, path: Path, text: str, kind: Optional[str] = None) -> None:
        self.source = source
        self.path = path
        self.text = text
        self.kind = kind or {".jsonl": "jsonl", ".json": "json"}.get(path.suffix.lower(), "text")
        self._parsed: Any = _UNSET
        self._first_state: Optional[dict] = None
        # set when this document is only one part of a big file
        self.line_offset = 0
        self.first_line: Optional[str] = None

    @property
    def is_json(self) -> bool:
        return self.kind != "text"

    def decode(self, raw: str) -> str:
        return decode_json_fragment(raw) if self.is_json else raw

    def line_of(self, offset: int) -> int:
        return self.line_offset + self.text.count("\n", 0, offset) + 1

    def locate(self, start: int, secret: str) -> Optional[Location]:
        """Where a secret sits. None if it only occurs inside a blob we deliberately skip
        (a base64 image, a thinking signature): those matches are noise."""
        lineno = self.line_of(start)
        if self.kind == "jsonl":
            return self._locate_jsonl(start, lineno, secret)
        if self.kind == "json":
            return self._locate_json(lineno, secret)
        state = {"session": "", "project": ""}
        return self._location(lineno, (), self.source.text_origin(self.path), state, "")

    def _locate_jsonl(self, start: int, lineno: int, secret: str) -> Optional[Location]:
        begin = self.text.rfind("\n", 0, start) + 1
        end = self.text.find("\n", start)
        line = self.text[begin : end if end != -1 else len(self.text)]
        state = dict(self._initial_state())
        try:
            record = json.loads(line)
        except ValueError:
            return self._location(lineno, (), Origin.OTHER, state, "")
        self.source.update_state(record, state)
        return self._in_record(record, (), lineno, secret, state)

    def _locate_json(self, lineno: int, secret: str) -> Optional[Location]:
        if self._parsed is _UNSET:
            try:
                self._parsed = json.loads(self.text)
            except ValueError:
                self._parsed = None
        data = self._parsed
        state = {"session": "", "project": ""}
        if data is None:
            return self._location(lineno, (), Origin.OTHER, state, "")
        if isinstance(data, dict):
            self.source.update_state(data, state)
            return self._in_record(data, (), lineno, secret, state)
        if isinstance(data, list):
            for i, record in enumerate(data):
                if _contains(record, secret):
                    rstate = dict(state)
                    self.source.update_state(record, rstate)
                    return self._in_record(record, (i,), lineno, secret, rstate)
        return None

    def _in_record(self, record: Any, prefix: JsonPath, lineno: int, secret: str, state: dict) -> Optional[Location]:
        stamp = record.get("timestamp", "") if isinstance(record, dict) else ""
        for jpath, value in iter_strings(record):
            if secret in value:
                origin = self.source.origin(record, jpath)
                return self._location(lineno, prefix + jpath, origin, state, stamp if isinstance(stamp, str) else "")
        if _in_keys(record, secret):
            return self._location(lineno, prefix, self.source.origin(record, ()), state, "")
        return None

    def _initial_state(self) -> dict:
        if self._first_state is None:
            state = {"session": "", "project": ""}
            end = self.text.find("\n")
            first = self.first_line
            if first is None:
                first = self.text[: end if end != -1 else len(self.text)]
            try:
                self.source.update_state(json.loads(first), state)
            except ValueError:
                pass
            self._first_state = state
        return self._first_state

    def _location(self, lineno: int, jpath: JsonPath, origin: str, state: dict, stamp: str) -> Location:
        return Location(
            agent=self.source.name,
            file=str(self.path),
            line=lineno,
            json_path=format_path(jpath),
            session=self.source.session_for(self.path, state),
            project=state.get("project", ""),
            timestamp=stamp,
            origin=origin,
        )


_UNSET = object()


def _contains(node: Any, secret: str) -> bool:
    return any(secret in value for _, value in iter_strings(node)) or _in_keys(node, secret)


def _in_keys(node: Any, secret: str) -> bool:
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if any(isinstance(k, str) and secret in k for k in cur):
                return True
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return False


_TOOL_KEYS = {
    "tool_result", "toolUseResult", "function_call_output", "functionResponse", "toolCalls",
    "output", "stdout", "stderr", "result", "aggregated_output", "formatted_output",
}


def generic_origin(record: Any, path: JsonPath) -> str:
    """A best guess that works for most chat-shaped JSON."""
    keys = _keys(path)
    if keys & _TOOL_KEYS:
        return Origin.TOOL
    if not isinstance(record, dict):
        return Origin.OTHER
    node: Any = record
    role = ""
    for part in path:
        if isinstance(node, dict):
            for key in ("role", "type", "speaker", "say", "ask"):
                value = node.get(key)
                if isinstance(value, str) and value in _ROLE_MAP:
                    role = _ROLE_MAP[value]
        try:
            node = node[part]
        except (KeyError, IndexError, TypeError):
            break
    return role or Origin.OTHER


_ROLE_MAP = {
    "user": Origin.PROMPT,
    "human": Origin.PROMPT,
    "user_message": Origin.PROMPT,
    "user_feedback": Origin.PROMPT,
    "assistant": Origin.ASSISTANT,
    "model": Origin.ASSISTANT,
    "gemini": Origin.ASSISTANT,
    "agent_message": Origin.ASSISTANT,
    "text": "",
    "tool_result": Origin.TOOL,
    "tool": Origin.TOOL,
    "function_call_output": Origin.TOOL,
    "exec_command_end": Origin.TOOL,
    "command_output": Origin.TOOL,
    "tool_use": Origin.ASSISTANT,
    "function_call": Origin.ASSISTANT,
}
_ROLE_MAP = {k: v for k, v in _ROLE_MAP.items() if v}


@register
class ClaudeCode(Source):
    name = "claude"
    label = "Claude Code"
    patterns = (
        "projects/**/*.jsonl",
        "history.jsonl",
        "file-history/**/*",
        "shell-snapshots/*",
        "todos/*.json",
        "paste-cache/**/*",
    )

    def roots(self) -> List[Path]:
        env = os.environ.get("CLAUDE_CONFIG_DIR")
        roots = [Path(env)] if env else []
        return roots + [self.home / ".claude"]

    def origin(self, record: Any, path: JsonPath) -> str:
        if not isinstance(record, dict):
            return Origin.OTHER
        kind = record.get("type")
        if kind == "file-history-snapshot":
            return Origin.FILE
        if kind in ("queue-operation", "last-prompt"):
            return Origin.PROMPT  # prompts are logged here even when a hook blocked them
        if "display" in record or "pastedContents" in record:
            return Origin.HISTORY
        if kind in ("attachment", "system") or "toolUseResult" in path[:1]:
            return Origin.TOOL
        if kind in ("user", "assistant"):
            if record.get("isMeta"):
                return Origin.OTHER
            if "tool_result" in _block_types(record, path):
                return Origin.TOOL
            if kind == "assistant":
                return Origin.ASSISTANT
            return Origin.PROMPT if path[:1] == ("message",) else Origin.OTHER
        return Origin.OTHER

    def text_origin(self, path: Path) -> str:
        parts = path.parts
        if "file-history" in parts:
            return Origin.FILE
        if "paste-cache" in parts:
            return Origin.PROMPT
        return Origin.OTHER


def _block_types(record: dict, path: JsonPath) -> set:
    """The `type` of each content block on the way down `path`."""
    types = set()
    node: Any = record
    for part in path:
        try:
            node = node[part]
        except (KeyError, IndexError, TypeError):
            break
        if isinstance(node, dict) and isinstance(node.get("type"), str):
            types.add(node["type"])
    return types


@register
class Codex(Source):
    name = "codex"
    label = "Codex CLI"
    patterns = ("sessions/**/*.jsonl", "archived_sessions/**/*.jsonl", "history.jsonl", "log/*.log")

    def roots(self) -> List[Path]:
        env = os.environ.get("CODEX_HOME")
        roots = [Path(env)] if env else []
        return roots + [self.home / ".codex"]

    def update_state(self, record: Any, state: dict) -> None:
        if not isinstance(record, dict):
            return
        payload = record.get("payload")
        if record.get("type") == "session_meta" and isinstance(payload, dict):
            state["session"] = payload.get("id", state["session"])
            state["project"] = payload.get("cwd", state["project"])
        if isinstance(record.get("session_id"), str):
            state["session"] = record["session_id"]

    def origin(self, record: Any, path: JsonPath) -> str:
        if not isinstance(record, dict):
            return Origin.OTHER
        if "text" in record and "session_id" in record and "ts" in record:
            return Origin.HISTORY
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        kind = payload.get("type")
        if kind in ("function_call_output", "custom_tool_call_output", "exec_command_end", "local_shell_call_output"):
            return Origin.TOOL
        if kind in ("function_call", "custom_tool_call", "local_shell_call", "agent_message", "reasoning"):
            return Origin.ASSISTANT
        if kind == "user_message":
            return Origin.PROMPT
        if kind == "message":
            role = payload.get("role")
            if role == "user":
                return Origin.PROMPT
            if role == "assistant":
                return Origin.ASSISTANT
            return Origin.OTHER
        return generic_origin(record, path)


@register
class GeminiCLI(Source):
    name = "gemini"
    label = "Gemini CLI"
    patterns = ("tmp/*/chats/*.json", "tmp/*/logs.json", "tmp/*/checkpoint*.json", "history/**/*.json")

    def roots(self) -> List[Path]:
        return [self.home / ".gemini"]

    def update_state(self, record: Any, state: dict) -> None:
        if isinstance(record, dict):
            if isinstance(record.get("sessionId"), str):
                state["session"] = record["sessionId"]
            if isinstance(record.get("projectHash"), str):
                state["project"] = record["projectHash"][:12]


@register
class OpenCode(Source):
    name = "opencode"
    label = "OpenCode"
    patterns = ("storage/message/**/*.json", "storage/part/**/*.json", "storage/session/**/*.json")

    def roots(self) -> List[Path]:
        base = os.environ.get("XDG_DATA_HOME")
        root = Path(base) if base else self.home / ".local" / "share"
        return [root / "opencode"]

    def update_state(self, record: Any, state: dict) -> None:
        if isinstance(record, dict):
            if isinstance(record.get("sessionID"), str):
                state["session"] = record["sessionID"]
            path = record.get("path")
            if isinstance(path, dict) and isinstance(path.get("cwd"), str):
                state["project"] = path["cwd"]


_CLINE_IDS = ("saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline", "kilocode.kilo-code")
_EDITORS = ("Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium", "Kiro")


@register
class Cline(Source):
    name = "cline"
    label = "Cline / Roo / Kilo"
    patterns = tuple(
        f"{editor}/User/globalStorage/{ext}/tasks/*/{name}"
        for editor in _EDITORS
        for ext in _CLINE_IDS
        for name in ("api_conversation_history.json", "ui_messages.json")
    )

    def roots(self) -> List[Path]:
        return _app_support()

    def session_for(self, path: Path, state: dict) -> str:
        return path.parent.name


@register
class Continue(Source):
    name = "continue"
    label = "Continue"
    patterns = ("sessions/*.json",)

    def roots(self) -> List[Path]:
        return [self.home / ".continue"]


@register
class CopilotCLI(Source):
    name = "copilot"
    label = "GitHub Copilot CLI"
    patterns = ("session-state/**/*.jsonl", "history-session-state/*.json", "logs/*.log")

    def roots(self) -> List[Path]:
        return [self.home / ".copilot"]


# ---- Cursor ------------------------------------------------------------------------------------

# Rows in Cursor's SQLite databases that hold chats. Everything else in there is editor state
# (and Cursor's own login token, which is none of our business).
_CURSOR_KV_PREFIXES = ("bubbleId:", "composerData:", "agentKv:", "messageRequestContext:", "checkpointId:")
_CURSOR_ITEM_KEYS = (
    "aiService.prompts",
    "aiService.generations",
    "workbench.panel.aichat.view.aichat.chatdata",
    "composer.composerData",
)


@register
class Cursor(Source):
    """Cursor keeps chats in SQLite (`state.vscdb`). Each chat row becomes one JSON line of a
    virtual JSONL document, so matching, context and dedup work exactly as for the others."""

    name = "cursor"
    label = "Cursor"
    patterns = ("Cursor/User/globalStorage/state.vscdb", "Cursor/User/workspaceStorage/*/state.vscdb")

    def roots(self) -> List[Path]:
        return _app_support()

    def load(self, path: Path) -> Optional[str]:
        import sqlite3

        try:
            # immutable: never take a lock on a database Cursor may have open
            conn = sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)
        except sqlite3.Error:
            return None
        lines = []
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "cursorDiskKV" in tables:
                where = " OR ".join("key LIKE ?" for _ in _CURSOR_KV_PREFIXES)
                rows = conn.execute(
                    f"SELECT key, value FROM cursorDiskKV WHERE {where} ORDER BY rowid",
                    [p + "%" for p in _CURSOR_KV_PREFIXES],
                )
                lines += [_cursor_line(k, v) for k, v in rows]
            if "ItemTable" in tables:
                marks = ",".join("?" for _ in _CURSOR_ITEM_KEYS)
                rows = conn.execute(f"SELECT key, value FROM ItemTable WHERE key IN ({marks})", _CURSOR_ITEM_KEYS)
                lines += [_cursor_line(k, v) for k, v in rows]
        except sqlite3.Error:
            return None
        finally:
            conn.close()
        return "\n".join(line for line in lines if line) or None

    def document(self, path: Path, text: str) -> Document:
        return Document(self, path, text, kind="jsonl")

    def update_state(self, record: Any, state: dict) -> None:
        if isinstance(record, dict) and isinstance(record.get("key"), str):
            parts = record["key"].split(":")
            if len(parts) >= 2:
                state["session"] = parts[1]

    def origin(self, record: Any, path: JsonPath) -> str:
        value = record.get("value") if isinstance(record, dict) else None
        if isinstance(value, dict):
            keys = _keys(path)
            if keys & {"toolResults", "toolFormerData", "result", "output"}:
                return Origin.TOOL
            if value.get("type") == 1:
                return Origin.PROMPT
            if value.get("type") == 2:
                return Origin.ASSISTANT
        return generic_origin(record, path)

    def session_for(self, path: Path, state: dict) -> str:
        return state.get("session") or path.parent.name


def _cursor_line(key: Any, value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if not isinstance(value, str) or not value:
        return ""
    try:
        parsed: Any = json.loads(value)
    except ValueError:
        parsed = value
    if isinstance(parsed, dict):
        # Cursor's own per-chat encryption keys, not something anyone leaked
        parsed = {k: v for k, v in parsed.items() if not str(k).endswith("EncryptionKey")}
    return json.dumps({"key": str(key), "value": parsed}, ensure_ascii=False)


class PathSource(Source):
    """Anything you point at with --path: a file or a folder, any of the formats above."""

    name = "path"
    label = "Custom path"

    def __init__(self, paths: Iterable[Path], home: Optional[Path] = None) -> None:
        super().__init__(home)
        self.paths = [Path(p).expanduser() for p in paths]

    def discover(self) -> Iterator[Path]:
        for p in self.paths:
            if p.is_file():
                yield p
            elif p.is_dir():
                for child in sorted(p.rglob("*")):
                    if child.is_file() and not child.is_symlink():
                        yield child


def build_sources(
    agents: Optional[Iterable[str]] = None,
    paths: Optional[Iterable[Path]] = None,
    home: Optional[Path] = None,
) -> List[Source]:
    """Instantiate the adapters to scan. No agents and no paths means every known agent."""
    names = list(agents or [])
    paths = list(paths or [])
    sources: List[Source] = [get_source(n)(home) for n in names]
    if paths:
        sources.append(PathSource(paths, home))
    if not names and not paths:
        sources = [cls(home) for cls in all_sources()]
    return sources


