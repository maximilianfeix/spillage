"""Shell completion scripts, generated from the argument parser so they can't drift from it."""

from __future__ import annotations

import argparse
from typing import Dict, List, NamedTuple, Tuple

SHELLS = ("bash", "zsh", "fish")


class Option(NamedTuple):
    flags: Tuple[str, ...]
    help: str


class Command(NamedTuple):
    name: str
    help: str
    options: List[Option]
    choices: List[str]  # values of a positional with a fixed set, like `guard install`


def commands(parser: argparse.ArgumentParser) -> List[Command]:
    """Every command a person runs (those with a help text; `hook` is for the agents)."""
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    helps: Dict[str, str] = {a.dest: a.help or "" for a in sub._choices_actions}
    out = []
    for name, child in sub.choices.items():
        if name not in helps:
            continue
        options, choices = [], []
        for action in child._actions:
            if action.option_strings:
                if action.help != argparse.SUPPRESS:
                    options.append(Option(tuple(action.option_strings), (action.help or "").split(" (")[0]))
            elif action.choices:
                choices += [str(c) for c in action.choices]
        out.append(Command(name, helps[name], options, choices))
    return out


def _words(cmd: Command) -> str:
    return " ".join(cmd.choices + [flag for opt in cmd.options for flag in opt.flags])


def bash(cmds: List[Command]) -> str:
    cases = "\n".join(f'    {c.name}) words="{_words(c)}" ;;' for c in cmds)
    names = " ".join(c.name for c in cmds)
    return f"""# spillage completion for bash. Load it with:
#   eval "$(spillage completions bash)"
_spillage() {{
  local cur words
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    words="{names} --help --version"
  else
    case "${{COMP_WORDS[1]}}" in
{cases}
    *) words="" ;;
    esac
  fi
  COMPREPLY=($(compgen -W "$words" -- "$cur"))
}}
complete -o default -F _spillage spillage
"""


def _zsh_quote(text: str) -> str:
    return text.replace("'", "'\\''").replace(":", "\\:")


def zsh(cmds: List[Command]) -> str:
    described = "\n".join(f"    '{c.name}:{_zsh_quote(c.help)}'" for c in cmds)
    cases = "\n".join(f"    {c.name}) compadd -- {_words(c)} ;;" for c in cmds)
    return f"""#compdef spillage
# spillage completion for zsh. Load it with:
#   eval "$(spillage completions zsh)"
_spillage() {{
  local -a commands
  commands=(
{described}
  )
  if (( CURRENT == 2 )); then
    _describe 'command' commands
    return
  fi
  case $words[2] in
{cases}
  esac
  _files
}}
compdef _spillage spillage
"""


def _fish_quote(text: str) -> str:
    return text.replace("\\", "\\\\").replace("'", "\\'")


def fish(cmds: List[Command]) -> str:
    lines = ["# spillage completion for fish. Install it with:",
             "#   spillage completions fish > ~/.config/fish/completions/spillage.fish"]
    for c in cmds:
        lines.append(f"complete -c spillage -n __fish_use_subcommand -f -a {c.name} -d '{_fish_quote(c.help)}'")
    for c in cmds:
        seen = f"'__fish_seen_subcommand_from {c.name}'"
        if c.choices:
            lines.append(f"complete -c spillage -n {seen} -f -a '{' '.join(c.choices)}'")
        for opt in c.options:
            flags = " ".join(f"-l {f[2:]}" if f.startswith("--") else f"-s {f[1:]}" for f in opt.flags)
            lines.append(f"complete -c spillage -n {seen} {flags} -d '{_fish_quote(opt.help)}'")
    return "\n".join(lines) + "\n"


def script(shell: str, parser: argparse.ArgumentParser) -> str:
    return {"bash": bash, "zsh": zsh, "fish": fish}[shell](commands(parser))
