"""guard on the command lines that came up in review: PowerShell, nested shells, one-liners."""

from __future__ import annotations

import pytest

from spillage import guard


@pytest.mark.parametrize("command", [
    r"cat C:\Users\me\.ssh\id_rsa", r"Get-Content $HOME\.aws\credentials", "Select-String -Path .env -Pattern KEY",
    "sls KEY .env", "[IO.File]::ReadAllText('.env')", "pwsh -c 'gc .env'",
    "[Environment]::GetEnvironmentVariable('OPENAI_API_KEY')", "(Get-Item Env:OPENAI_API_KEY).Value",
    "Get-ChildItem Env:*KEY*", "Get-ChildItem Env:", "gci env:", "Write-Output $env:OPENAI_API_KEY",
    "$env:ANTHROPIC_API_KEY", "[System.Environment]::GetEnvironmentVariables()",
])
def test_powershell_commands_that_print_secrets(command):
    assert guard.risky_command(command, powershell=True)
    assert guard.check_tool("PowerShell", {"command": command})


@pytest.mark.parametrize("command", [
    "xargs -0 cat .env", "xargs -I{} cat .env", "time -p cat .env", "egrep KEY .env", "bash -c 'cat .env'",
    "sh -lc 'printenv'", 'python -c "import os; print(os.environ)"', 'node -e "console.log(process.env)"',
])
def test_wrapped_commands_that_print_secrets(command):
    assert guard.risky_command(command)


@pytest.mark.parametrize("command", [
    'node -e "console.log(config.key)"', """node -e "console.log(process.env['PORT'])\"""", "echo '$API_KEY'",
    'echo "${API_KEY:+set}"', "echo $TOKEN_COUNT", "echo $API_KEY_FILE", "Get-Item Env:PATH", "bash -c 'ls -la'",
    "findstr /s TODO *.py", "Get-ChildItem", r"Get-Content C:\Users\me\project\README.md",
    """python -c "print(cfg.env, obj.pem)\"""",
])
def test_lookalikes_stay_allowed(command):
    assert guard.risky_command(command) is None
    assert guard.risky_command(command, powershell=True) is None


def test_backslashes_stay_an_escape_in_bash():
    """`cat C:\\Users\\me\\.env` in bash loses its backslashes before cat sees it; only PowerShell keeps them."""
    assert guard.check_tool("Bash", {"command": r"cat secrets\.yml"})
    assert guard.check_tool("PowerShell", {"command": r"type .\config\secrets.yml"})
