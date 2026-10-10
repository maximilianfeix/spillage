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
# Our hook in any form it gets installed as: `spillage hook …`, `/path/to/spillage hook …`,
# `"C:\…\spillage.exe" hook …` on Windows, or `python -m spillage hook …`.
_HOOK_COMMAND = re.compile(r"""(?:^|[\s"'\\/])spillage(?:\.exe)?["']?\s+hook\b""", re.IGNORECASE)
ALLOW_WORD = "spillage:allow"
TOOL_MATCHER = "Read|Grep|Bash|PowerShell|NotebookRead|mcp__.*read.*"

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
    "egrep", "fgrep", "rg", "ag", "awk", "sed", "sort", "nl", "tac", "cut", "base64", "type", "jq", "yq",
    "source", ".", "python", "python3", "node", "ruby", "perl", "openssl",
    # PowerShell and cmd
    "get-content", "gc", "select-string", "sls", "import-csv", "findstr",
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
    # the whole environment from PowerShell, Python or Node
    re.compile(r"\[(?:System\.)?Environment\]::GetEnvironmentVariables\b", re.IGNORECASE),
    re.compile(r"\bprint\(\s*(?:dict\(\s*)?os\.environ\s*\)"),
    re.compile(r"\bconsole\.log\(\s*process\.env\s*\)"),
]
# PowerShell's Env: drive: `Get-ChildItem Env:` lists everything, `Get-Item Env:GITHUB_TOKEN` one value
_ENV_DRIVE = re.compile(
    r"\b(?:get-childitem|gci|dir|ls|get-item|gi|get-content|gc)\s+(?:-(?:literal)?path\s+)?[\"']?env:[\\/]?([\w*?]*)",
    re.IGNORECASE,
)
_GET_VARIABLE = re.compile(r"GetEnvironmentVariable\(\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']", re.IGNORECASE)
_READ_CALL = re.compile(r"::(?:ReadAllText|ReadAllLines|ReadAllBytes|ReadLines|OpenText)\(\s*[\"']([^\"']+)[\"']",
                        re.IGNORECASE)
# Commands whose whole job is to print their arguments, and a variable named like a secret in them.
_PRINTERS = {"echo", "printf", "print", "printenv", "write-output", "write-host"}
# `$NAME`, `${NAME}` and `$env:NAME`, but not `${NAME:+set}`, which only says whether it is set
_VARIABLE = re.compile(r"\$(?:env:)?\{?(?:env:)?([A-Za-z_][A-Za-z0-9_]*)(?!\w)(?!:\+)", re.IGNORECASE)
_SINGLE_QUOTED = re.compile(r"'[^']*'")
# TOKEN_COUNT or API_KEY_FILE describe a secret, they aren't one
_NOT_THE_VALUE = {"COUNT", "LENGTH", "LEN", "NAME", "FILE", "PATH", "DIR", "ID", "TTL", "EXPIRY", "EXPIRES", "TYPE",
                  "HEADER", "PREFIX", "ENABLED", "SET"}
_PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "ag", "findstr"}  # their first argument is what to look for
_INTERPRETERS = {"python", "python3", "node", "ruby", "perl"}
_QUOTED = re.compile(r"""["']([^"']+)["']""")
_WRAPPERS = {"sudo", "command", "exec", "time", "nice", "xargs"}
_SHELLS = {"bash", "sh", "zsh", "dash", "fish", "pwsh", "powershell", "cmd"}


def is_secret_file(path: str) -> bool:
    # lower case: macOS and Windows open `.ENV` as `.env`
    p = path.replace("\\", "/").rstrip("/").lower()
    name = p.rsplit("/", 1)[-1]
    if any(fnmatch.fnmatchcase(name, pat) for pat in SAFE_FILES):
        return False
    for pat in SECRET_FILES:
        if "/" in pat:
            if p == pat or p.endswith("/" + pat):
                return True
        elif fnmatch.fnmatchcase(name, pat):
            return True
    return False


def _names_a_secret(name: str) -> bool:
    from .envfiles import is_secret_name, name_words

    return is_secret_name(name) and not (name_words(name) & _NOT_THE_VALUE)


def _prints_secret_variable(verb: str, segment: str, words: List[str]) -> Optional[str]:
    """`echo $STRIPE_SECRET_KEY`, `printenv GITHUB_TOKEN`, `Write-Output $env:OPENAI_API_KEY`.
    Using a variable is fine (`curl -H "Authorization: Bearer $TOKEN"`), printing it is not."""
    # '$NAME' in single quotes is just text
    names = words[1:] if verb == "printenv" else _VARIABLE.findall(_SINGLE_QUOTED.sub("", segment))
    return next((name for name in names if _names_a_secret(name)), None)


def _words(command: str) -> List[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _inner_script(verb: str, words: List[str]) -> Optional[str]:
    """The script in `bash -c '…'`, `pwsh -Command "…"` or `cmd /c …`."""
    if verb.rsplit(".", 1)[0] not in _SHELLS:
        return None
    for i, word in enumerate(words[1:], 1):
        flag = word.lower()
        if flag in ("-command", "/c", "/k") or (flag.startswith("-") and not flag.startswith("--") and "c" in flag[1:]):
            return " ".join(words[i + 1 :]) or None
    return None


def risky_command(command: str, powershell: bool = False) -> Optional[str]:
    """Why a shell command would leak secrets into the conversation, or None.

    In PowerShell a backslash is part of a path and not an escape, so `powershell=True` keeps
    `C:\\Users\\me\\.ssh\\id_rsa` in one piece."""
    if powershell:
        command = command.replace("\\", "/")
    for pattern in _ENV_DUMPS:
        if pattern.search(command):
            return "it prints environment variables or stored credentials"
    for match in _ENV_DRIVE.finditer(command):
        name = match.group(1)
        if not name or "*" in name or "?" in name or _names_a_secret(name):
            return "it prints environment variables or stored credentials"
    for match in _GET_VARIABLE.finditer(command):
        if _names_a_secret(match.group(1)):
            return f"it prints {match.group(1)}, which looks like a secret"
    for match in _READ_CALL.finditer(command):
        if is_secret_file(match.group(1)):
            return f"it reads {match.group(1)}, which holds secrets"
    for segment in re.split(r"[;&|]+|\$\(|`", command):
        # `cat<.env` reads the same file as `cat < .env`
        words = _words(re.sub(r"(?<![<\d])<(?!<)", " < ", segment).strip())
        if not words:
            continue
        verb = os.path.basename(words[0]).lower()
        if verb in _WRAPPERS:
            # `sudo cat .env`, `xargs -0 cat .env`: the command is the first word that isn't an option
            words = words[1:]
            while words and words[0].startswith("-"):
                words = words[1:]
            verb = os.path.basename(words[0]).lower() if words else ""
        script = _inner_script(verb, words)
        if script and script != command:
            reason = risky_command(script, powershell or verb.startswith(("pwsh", "powershell")))
            if reason:
                return reason
            continue
        if verb in _PRINTERS or (len(words) == 1 and verb.startswith("$env:")):  # PowerShell prints a bare value
            name = _prints_secret_variable(verb, segment, words)
            if name:
                return f"it prints {name}, which looks like a secret"
        if verb not in _READERS:
            continue
        args = words[1:]
        if verb in _PATTERN_FIRST and not any(a in ("-e", "-f", "--regexp", "--file") for a in args):
            # `grep -rn credentials src/` looks for a word, it doesn't read a file of that name
            option = "/" if verb == "findstr" else "-"
            pattern = next((a for a in args if not a.startswith(option)), None)
            if pattern is not None:
                args = args[: args.index(pattern)] + args[args.index(pattern) + 1 :]
        for word in args:
            target = word.split("=", 1)[-1] if word.startswith("-") else word
            target = target.lstrip("<").rstrip(")`'\"")
            is_code = verb in _INTERPRETERS and bool(re.search(r"[\s(){};=]", word))
            if target and not target.startswith("-") and not is_code and is_secret_file(target):
                return f"it reads {target}, which holds secrets"
            if is_code:
                # a script on the command line: python -c "print(open('.env').read())". Only what it
                # has in quotes can be a file name; `config.key` is an attribute.
                for piece in _QUOTED.findall(word):
                    if is_secret_file(piece):
                        return f"it reads {piece}, which holds secrets"
    return None


# Tool names differ per agent; they all boil down to reading, searching or running a shell.
READ_TOOLS = {"Read", "NotebookRead", "read_file", "read_many_files"}
SEARCH_TOOLS = {"Grep", "grep", "search_file_content"}
SHELL_TOOLS = {"Bash", "PowerShell", "run_shell_command", "shell", "local_shell"}


def _strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _is_mcp_read(tool: str) -> bool:
    """MCP filesystem tools: mcp__filesystem__read_file (Claude, Codex), mcp_fs_read_text_file (Gemini)."""
    return tool.startswith("mcp") and bool(re.search(r"_read(_text|_multiple|_media)?_files?$", tool))


def shell_script(argv: List[str]) -> str:
    """The script inside `bash -lc '…'`, `/usr/bin/env bash -l -c '…'` and friends, else argv joined."""
    words = list(argv)
    if words and os.path.basename(words[0]) == "env":
        words = words[1:]
    if words and os.path.basename(words[0]) in ("bash", "sh", "zsh", "dash", "fish"):
        for i, word in enumerate(words[1:], 1):
            if word.startswith("-") and not word.startswith("--") and "c" in word[1:] and i + 1 < len(words):
                return words[i + 1]
    return " ".join(words)


def check_tool(tool: str, tool_input: Any) -> Optional[str]:
    if not isinstance(tool_input, dict):
        return None
    if tool in READ_TOOLS or _is_mcp_read(tool):
        for key in ("file_path", "notebook_path", "absolute_path", "path", "paths", "include"):
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
            command = shell_script([str(c) for c in command])
        if isinstance(command, str):
            return risky_command(command, powershell=tool == "PowerShell")
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
    """Which config file an agent reads hooks from, and what it calls the three events.
    Where the agent lives and what it's called come from its adapter in sources.py."""

    name: str
    folder: str  # the per-project config folder, e.g. ".claude"
    user_file: str
    project_file: str
    local_file: Optional[str]  # None: the agent has no uncommitted, per-project config
    prompt_event: str
    tool_event: str
    end_event: str
    tool_matcher: str
    comments: bool = False  # the config file may contain // comments (JSONC)

    def events(self) -> Tuple[str, str, str]:
        return (self.prompt_event, self.tool_event, self.end_event)

    @property
    def label(self) -> str:
        from .sources import get_source

        return get_source(self.name).label

    def config_dir(self) -> Path:
        from .sources import get_source

        return get_source(self.name)(Path.home()).roots()[0]

    def present(self) -> bool:
        return self.config_dir().is_dir()


AGENTS = {
    "claude": AgentHooks(
        name="claude", folder=".claude", user_file="settings.json", project_file="settings.json",
        local_file="settings.local.json", prompt_event="UserPromptSubmit", tool_event="PreToolUse",
        end_event="SessionEnd", tool_matcher=TOOL_MATCHER,
    ),
    "codex": AgentHooks(
        name="codex", folder=".codex", user_file="hooks.json", project_file="hooks.json", local_file=None,
        prompt_event="UserPromptSubmit", tool_event="PreToolUse", end_event="SessionEnd",
        tool_matcher="Bash|shell|local_shell|read_file|mcp__.*read.*",
    ),
    "gemini": AgentHooks(
        name="gemini", folder=".gemini", user_file="settings.json", project_file="settings.json", local_file=None,
        prompt_event="BeforeAgent", tool_event="BeforeTool", end_event="SessionEnd",
        tool_matcher="read_file|read_many_files|run_shell_command|grep|search_file_content|mcp_.*read.*",
        comments=True,
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
    folder = (cwd or Path.cwd()) / target.folder
    if scope == "project":
        return folder / target.project_file
    if scope == "local":
        if not target.local_file:
            raise ValueError(f"{target.label} has no uncommitted per-project config; use --scope user or project")
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


def strip_json_comments(text: str) -> str:
    """// and /* */ comments and trailing commas out of JSONC, leaving strings alone."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def has_comments(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    try:
        json.loads(text)
        return False
    except ValueError:
        return True


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        try:
            data = json.loads(strip_json_comments(text))
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


def is_hook_command(command: str) -> bool:
    return bool(_HOOK_COMMAND.search(command))


def _is_ours(group: Any) -> bool:
    return isinstance(group, dict) and any(
        isinstance(h, dict) and is_hook_command(str(h.get("command", ""))) for h in group.get("hooks", [])
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
