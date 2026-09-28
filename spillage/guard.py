"""Claude Code hooks that stop the next leak before it happens.

Three hooks, all plain commands that read the hook event as JSON on stdin:

- UserPromptSubmit: a prompt containing a secret is blocked before it is sent.
- PreToolUse: reading `.env` files, private keys and credential files is blocked, through the
  Read / Grep tools as well as through Bash (`cat .env`, `printenv`, `gh auth token`, ...).
- SessionEnd: the session's transcript is scrubbed. Claude Code logs a prompt even when the
  hook above blocked it, and tool output may still have caught something.

Exit code 2 is Claude Code's "block" signal; whatever goes to stderr is shown to you (for
prompts) or to the model (for tools), so it can explain and find another way.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any, List, Optional, Tuple

from .scanner import scan_text

MARK = "spillage hook"
ALLOW_WORD = "spillage:allow"
TOOL_MATCHER = "Read|Grep|Bash|NotebookRead"
HOOK_EVENTS = ("UserPromptSubmit", "PreToolUse", "SessionEnd")

# Files that are nothing but secrets. Templates like .env.example are fine to read.
SECRET_FILES = (
    ".env", ".env.*", "*.env", ".envrc", ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials",
    ".dockercfg", "credentials", "credentials.json", "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore",
    "*.jks", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "*.ppk", "secrets.yml", "secrets.yaml",
    "secrets.json", ".secrets", "service-account*.json", "*.tfvars", "terraform.tfstate",
    "kubeconfig", ".kube/config", ".aws/credentials", ".docker/config.json", ".vault-token",
)
SAFE_FILES = ("*.example", "*.sample", "*.template", "*.dist", "*.defaults", "*.pub", ".env.*.example")

_READERS = {
    "cat", "less", "more", "head", "tail", "bat", "batcat", "strings", "xxd", "od", "hexdump", "grep",
    "rg", "ag", "awk", "sed", "sort", "nl", "tac", "cut", "base64", "type", "get-content", "gc", "jq",
    "yq", "source", ".", "python", "python3", "node", "ruby", "perl", "openssl",
}
_ENV_DUMPS = [
    re.compile(r"(?:^|[;&|]\s*)(?:printenv|env|export\s+-p|set|declare\s+-x)\s*(?:$|[;&|>])"),
    re.compile(r"\bgh\s+auth\s+token\b"),
    re.compile(r"\bgh\s+auth\s+status\b[^;&|]*--show-token"),
    re.compile(r"\bsecurity\s+find-(?:generic|internet)-password\b[^;&|]*\s-w\b"),
    re.compile(r"\baws\s+configure\s+(?:get|export-credentials)\b"),
    re.compile(r"\bgcloud\s+auth\s+print-access-token\b"),
    re.compile(r"\bop\s+(?:read|item\s+get)\b[^;&|]*(?:--reveal|op://)"),
    re.compile(r"\bcat\s+/proc/(?:self|\d+)/environ\b"),
]


def is_secret_file(path: str) -> bool:
    p = path.replace("\\", "/").rstrip("/")
    name = p.rsplit("/", 1)[-1]
    if any(fnmatch.fnmatch(name, pat) for pat in SAFE_FILES):
        return False
    for pat in SECRET_FILES:
        if "/" in pat:
            if p == pat or p.endswith("/" + pat):
                return True
        elif fnmatch.fnmatch(name, pat):
            return True
    return False


def _words(command: str) -> List[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def risky_command(command: str) -> Optional[str]:
    """Why a shell command would leak secrets into the conversation, or None."""
    for pattern in _ENV_DUMPS:
        if pattern.search(command):
            return "it prints environment variables or stored credentials"
    for segment in re.split(r"[;&|]+|\$\(|`", command):
        words = _words(segment.strip())
        if not words:
            continue
        verb = os.path.basename(words[0]).lower()
        if verb in ("sudo", "command", "exec", "time", "nice"):
            words = words[1:]
            verb = os.path.basename(words[0]).lower() if words else ""
        if verb not in _READERS:
            continue
        for word in words[1:]:
            target = word.split("=", 1)[-1] if word.startswith("-") else word
            target = target.lstrip("<").rstrip(")`'\"")
            if target and not target.startswith("-") and is_secret_file(target):
                return f"it reads {target}, which holds secrets"
    return None


def check_tool(tool: str, tool_input: Any) -> Optional[str]:
    if not isinstance(tool_input, dict):
        return None
    if tool in ("Read", "NotebookRead"):
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if isinstance(path, str) and is_secret_file(path):
            return f"{path} holds secrets"
    if tool == "Grep":
        path = tool_input.get("path") or ""
        glob = tool_input.get("glob") or ""
        for candidate in (path, glob):
            if isinstance(candidate, str) and candidate and is_secret_file(candidate):
                return f"searching {candidate} would print secrets"
    if tool == "Bash":
        command = tool_input.get("command") or ""
        if isinstance(command, str):
            return risky_command(command)
    return None


def handle(event: str, payload: dict) -> Tuple[int, str]:
    """(exit code, message) for one hook call. Pure, so it's easy to test."""
    if event == "prompt":
        prompt = payload.get("prompt") or ""
        if not isinstance(prompt, str) or ALLOW_WORD in prompt:
            return 0, ""
        findings = scan_text(prompt)
        if not findings:
            return 0, ""
        what = ", ".join(f"{f.rule_name} ({f.masked})" for f in findings[:3])
        return 2, (
            f"spillage blocked this prompt: it contains {what}.\n"
            "Anything you send ends up at the model provider and in a log file on your disk. "
            "Put it in an environment variable and mention the variable's name instead.\n"
            f"Meant to send it anyway? Add {ALLOW_WORD} to the prompt."
        )
    if event == "tool":
        reason = check_tool(str(payload.get("tool_name", "")), payload.get("tool_input"))
        if reason:
            return 2, (
                f"spillage blocked this: {reason}. Its contents would end up in the conversation and in "
                "the session log on disk. Don't read the secret values; ask the user which variable "
                "names exist, or read an .env.example instead."
            )
        return 0, ""
    if event == "session-end":
        transcript = payload.get("transcript_path")
        if isinstance(transcript, str) and transcript.endswith(".jsonl") and Path(transcript).is_file():
            from .scanner import load_ignore
            from .scrub import scrub_file

            scrub_file(Path(transcript), ignore=load_ignore())
        return 0, ""
    raise ValueError(f"unknown hook event {event!r}")


def run_hook(event: str, stdin: Optional[Any] = None, stderr: Optional[Any] = None) -> int:
    stdin = stdin or sys.stdin
    stderr = stderr or sys.stderr
    try:
        payload = json.loads(stdin.read() or "{}")
    except ValueError:
        return 0  # never get in the way because of our own parsing problem
    if not isinstance(payload, dict):
        return 0
    code, message = handle(event, payload)
    if message:
        print(message, file=stderr)
    return code


# ---- installing into settings.json ----------------------------------------------------------

def settings_path(scope: str = "user", cwd: Optional[Path] = None) -> Path:
    if scope == "user":
        base = Path(os.environ["CLAUDE_CONFIG_DIR"]) if os.environ.get("CLAUDE_CONFIG_DIR") else Path.home() / ".claude"
        return base / "settings.json"
    folder = (cwd or Path.cwd()) / ".claude"
    if scope == "project":
        return folder / "settings.json"
    if scope == "local":
        return folder / "settings.local.json"
    raise ValueError(f"unknown scope {scope!r} (user, project or local)")


def hook_command(event: str) -> str:
    exe = sys.executable
    quoted = f'"{exe}"' if " " in exe else exe
    return f"{quoted} -m spillage hook {event}"


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError(f"{path} is not valid JSON, fix it first so nothing gets lost") from None
    if not isinstance(data, dict):
        raise ValueError(f"{path} doesn't hold a JSON object")
    return data


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".spillage-", dir=str(path.parent))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    if path.exists():
        import shutil

        shutil.copymode(str(path), tmp)
    os.replace(tmp, str(path))


def _is_ours(group: Any) -> bool:
    return isinstance(group, dict) and any(
        isinstance(h, dict) and MARK in str(h.get("command", "")) for h in group.get("hooks", [])
    )


def _desired() -> dict:
    return {
        "UserPromptSubmit": {"hooks": [{"type": "command", "command": hook_command("prompt")}]},
        "PreToolUse": {"matcher": TOOL_MATCHER, "hooks": [{"type": "command", "command": hook_command("tool")}]},
        "SessionEnd": {"hooks": [{"type": "command", "command": hook_command("session-end")}]},
    }


def install(path: Path) -> bool:
    """Add our hooks, keep everyone else's. Returns False if they were already there as-is."""
    data = _load(path)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"'hooks' in {path} isn't an object")
    changed = False
    for event, group in _desired().items():
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError(f"'hooks.{event}' in {path} isn't a list")
        ours = [g for g in groups if _is_ours(g)]
        if ours == [group]:
            continue
        hooks[event] = [g for g in groups if not _is_ours(g)] + [group]
        changed = True
    if changed:
        if path.exists():
            backup = path.with_name(path.name + ".spillage-backup")
            if not backup.exists():
                backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        _save(path, data)
    return changed


def uninstall(path: Path) -> bool:
    data = _load(path)
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return False
    changed = False
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        kept = [g for g in groups if not _is_ours(g)]
        if len(kept) != len(groups):
            changed = True
            if kept:
                hooks[event] = kept
            else:
                del hooks[event]
    if changed:
        if not hooks:
            del data["hooks"]
        _save(path, data)
    return changed


def status(path: Path) -> dict:
    try:
        data = _load(path)
    except ValueError:
        return dict.fromkeys(HOOK_EVENTS, False)
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    return {
        event: any(_is_ours(g) for g in hooks.get(event, []) if isinstance(hooks.get(event), list))
        for event in HOOK_EVENTS
    }
