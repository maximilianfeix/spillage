"""Agent hooks that stop the next leak before it happens (Claude Code, Codex, Gemini CLI).

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
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple

from .scanner import scan_text

MARK = "spillage hook"
ALLOW_WORD = "spillage:allow"
TOOL_MATCHER = "Read|Grep|Bash|NotebookRead"

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


# Tool names differ per agent; they all boil down to reading, searching or running a shell.
READ_TOOLS = {"Read", "NotebookRead", "read_file", "read_many_files"}
SEARCH_TOOLS = {"Grep", "grep", "search_file_content"}
SHELL_TOOLS = {"Bash", "run_shell_command", "shell", "local_shell"}


def _strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def check_tool(tool: str, tool_input: Any) -> Optional[str]:
    if not isinstance(tool_input, dict):
        return None
    if tool in READ_TOOLS or tool.endswith("__read_file"):
        for key in ("file_path", "notebook_path", "absolute_path", "path", "paths"):
            for path in _strings(tool_input.get(key)):
                if is_secret_file(path):
                    return f"{path} holds secrets"
    if tool in SEARCH_TOOLS:
        for key in ("path", "glob", "include"):
            for candidate in _strings(tool_input.get(key)):
                if candidate and is_secret_file(candidate):
                    return f"searching {candidate} would print secrets"
    if tool in SHELL_TOOLS:
        command = tool_input.get("command") or ""
        if isinstance(command, list):  # Codex can pass argv, often ["bash", "-lc", "<script>"]
            argv = [str(c) for c in command]
            shell_c = len(argv) >= 3 and os.path.basename(argv[0]) in ("bash", "sh", "zsh") and argv[1] in ("-c", "-lc")
            command = argv[-1] if shell_c else " ".join(argv)
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
        if isinstance(transcript, str) and transcript.endswith((".jsonl", ".json")) and Path(transcript).is_file():
            from .envfiles import rules_with_env
            from .rules import get_rules
            from .scanner import load_ignore
            from .scrub import scrub_file

            cwd = payload.get("cwd")
            projects = [Path(cwd)] if isinstance(cwd, str) and Path(cwd).is_dir() else []
            scrub_file(Path(transcript), ignore=load_ignore(), rules=rules_with_env(get_rules(), projects))
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


# ---- installing ------------------------------------------------------------------------------

@dataclass(frozen=True)
class AgentHooks:
    """Where an agent keeps its hook config, and what it calls the three events."""

    name: str
    label: str
    home: str  # config folder in $HOME, e.g. ".claude"
    env: str  # environment variable that moves it, if any
    user_file: str
    project_file: str
    local_file: str
    prompt_event: str
    tool_event: str
    end_event: str
    tool_matcher: str

    def events(self) -> Tuple[str, str, str]:
        return (self.prompt_event, self.tool_event, self.end_event)

    def config_dir(self) -> Path:
        env = os.environ.get(self.env) if self.env else None
        return Path(env) if env else Path.home() / self.home

    def present(self) -> bool:
        return self.config_dir().is_dir()


AGENTS = {
    "claude": AgentHooks(
        "claude", "Claude Code", ".claude", "CLAUDE_CONFIG_DIR", "settings.json", "settings.json",
        "settings.local.json", "UserPromptSubmit", "PreToolUse", "SessionEnd", TOOL_MATCHER,
    ),
    "codex": AgentHooks(
        "codex", "Codex CLI", ".codex", "CODEX_HOME", "hooks.json", "hooks.json", "hooks.json",
        "UserPromptSubmit", "PreToolUse", "SessionEnd", "Bash|shell|local_shell|read_file",
    ),
    "gemini": AgentHooks(
        "gemini", "Gemini CLI", ".gemini", "", "settings.json", "settings.json", "settings.json",
        "BeforeAgent", "BeforeTool", "SessionEnd",
        "read_file|read_many_files|run_shell_command|grep|search_file_content",
    ),
}


def get_agent(name: str) -> AgentHooks:
    try:
        return AGENTS[name]
    except KeyError:
        raise ValueError(f"guard supports {', '.join(AGENTS)}, not {name!r}") from None


def settings_path(scope: str = "user", cwd: Optional[Path] = None, agent: str = "claude") -> Path:
    target = get_agent(agent)
    if scope == "user":
        return target.config_dir() / target.user_file
    folder = (cwd or Path.cwd()) / target.home
    if scope == "project":
        return folder / target.project_file
    if scope == "local":
        return folder / target.local_file
    raise ValueError(f"unknown scope {scope!r} (user, project or local)")


def _quote(path: str) -> str:
    return f'"{path}"' if " " in path else path


def hook_command(event: str) -> str:
    """The command the agent runs. The installed `spillage` launcher when there is one: with
    Homebrew or pipx the package isn't importable from a bare `python -m`."""
    launcher = shutil.which("spillage")
    if launcher:
        return f"{_quote(str(Path(launcher).resolve()))} hook {event}"
    return f"{_quote(sys.executable)} -m spillage hook {event}"


def verify(event: str = "prompt") -> Optional[str]:
    """Run the hook command once the way the agent will. Returns an error message or None."""
    import subprocess

    try:
        proc = subprocess.run(hook_command(event), shell=True, input='{"prompt": "hello"}',
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return str(exc)
    if proc.returncode != 0:
        return (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip().splitlines()[-1]
    return None


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
        shutil.copymode(str(path), tmp)
    os.replace(tmp, str(path))


def _is_ours(group: Any) -> bool:
    return isinstance(group, dict) and any(
        isinstance(h, dict) and MARK in str(h.get("command", "")) for h in group.get("hooks", [])
    )


def _desired(agent: str = "claude") -> dict:
    t = get_agent(agent)
    return {
        t.prompt_event: {"hooks": [{"type": "command", "command": hook_command("prompt")}]},
        t.tool_event: {"matcher": t.tool_matcher, "hooks": [{"type": "command", "command": hook_command("tool")}]},
        t.end_event: {"hooks": [{"type": "command", "command": hook_command("session-end")}]},
    }


def install(path: Path, agent: str = "claude") -> bool:
    """Add our hooks, keep everyone else's. Returns False if they were already there as-is."""
    data = _load(path)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"'hooks' in {path} isn't an object")
    changed = False
    for event, group in _desired(agent).items():
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


def status(path: Path, agent: str = "claude") -> dict:
    events = get_agent(agent).events()
    try:
        data = _load(path)
    except ValueError:
        return dict.fromkeys(events, False)
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    return {
        event: any(_is_ours(g) for g in hooks.get(event, []) if isinstance(hooks.get(event), list))
        for event in events
    }
