from __future__ import annotations

import shutil
import subprocess
import sys

import pytest

from spillage.cli import COMMANDS, build_parser, main
from spillage.completions import SHELLS, commands, script


def test_every_command_a_person_runs_is_completed():
    names = {c.name for c in commands(build_parser())}
    assert names == set(COMMANDS) - {"hook"}


@pytest.mark.parametrize("shell", SHELLS)
def test_script_knows_commands_options_and_choices(shell, capsys):
    assert main(["completions", shell]) == 0
    out = capsys.readouterr().out
    for word in ("scan", "scrub", "guard", "watch", "repo", "completions"):
        assert word in out
    assert "install uninstall status" in out
    assert ("-l min-severity" if shell == "fish" else "--min-severity") in out
    assert "hook" not in out.replace("hooks", "")


@pytest.mark.parametrize("shell", SHELLS)
def test_script_is_valid_for_its_shell(shell, tmp_path):
    exe = shutil.which(shell)
    if not exe or sys.platform == "win32":
        pytest.skip(f"{shell} is not installed")
    file = tmp_path / f"spillage.{shell}"
    file.write_text(script(shell, build_parser()), encoding="utf-8")
    done = subprocess.run([exe, "-n", str(file)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_bash_completes_commands_and_options(tmp_path):
    bash = shutil.which("bash")
    if not bash or sys.platform == "win32":
        pytest.skip("bash is not installed")
    file = tmp_path / "spillage.bash"
    file.write_text(script("bash", build_parser()), encoding="utf-8")

    def complete(*words: str) -> list:
        line = f'source "{file}"; COMP_WORDS=({" ".join(words)}); COMP_CWORD={len(words) - 1}; _spillage; ' \
               'printf "%s\\n" "${COMPREPLY[@]}"'
        return subprocess.run([bash, "-c", line], capture_output=True, text=True).stdout.split()

    assert complete("spillage", "scr") == ["scrub"]
    assert complete("spillage", "guard", "un") == ["uninstall"]
    assert "--dry-run" in complete("spillage", "scrub", "--d")


def test_mistyped_command_gets_a_suggestion(capsys):
    assert main(["scna"]) == 2
    assert "unknown command 'scna', did you mean `spillage scan`?" in capsys.readouterr().err


def test_unknown_word_points_at_help(capsys):
    assert main(["frobnicate"]) == 2
    err = capsys.readouterr().err
    assert "unknown command 'frobnicate'" in err and "--help" in err


def test_options_without_a_command_still_mean_scan(leaky_home, capsys):
    assert main(["--exit-zero", "--no-color"]) == 0
    assert "spilled" in capsys.readouterr().out
