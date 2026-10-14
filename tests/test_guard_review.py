"""Ways around the tool hook that a review found, and commands it blocked for no reason."""

from __future__ import annotations

import io
import json

import pytest

from spillage import guard


@pytest.mark.parametrize("command", [
    # more than one line
    "true\ncat .env", "cd app\nprintenv", "npm test\n\nenv",
    # a glob that picks up the file
    "cat .env*", "cat .en?", "cat .e[n]v", "cat .en[v]", "head -3 config/.env.*", "cat .npmr?",
    # the same file by another spelling
    "cat ./.env", "cat config/../.env", "cat ~/.codex/./auth.json",
    # read through a redirect, whatever the command is
    "while read line; do echo $line; done < .env", "tr a-z A-Z < .env", "< .env cat", "wc -l <.env && tee out < .env",
    # git prints files too
    "git show HEAD:.env", "git show :.env", "git diff .env", "git diff --no-index /dev/null .env",
    "git grep KEY -- .env", "git -C app show main:config/.env.production", "git cat-file -p HEAD:.env",
    # where to look is not what to look for
    "rg --glob .env password .", "grep --include .env -r password .", "rg -g '.env*' KEY",
    # more tools that print a file
    "diff .env /dev/null", "paste .env", "rev .env", "fold .env", "column -t .env", "zcat .env", "dd if=.env",
    "find . -name .env -exec cat {} +", "find . -name '.env*' -exec head -1 {} ;",
    # commands that run the text they are given
    "eval 'cat .env'", 'eval "cat .env"', "watch 'ls; cat .env'", "sudo sh -c 'cd app; cat .env'",
    # one variable out of the environment
    """python -c "import os; print(os.environ['OPENAI_API_KEY'])\"""",
    """python3 -c "import os; print(os.getenv('GITHUB_TOKEN'))\"""",
    """node -e "console.log(process.env.STRIPE_SECRET_KEY)\"""", "ruby -e 'puts ENV[\"GITHUB_TOKEN\"]'",
    "export", "export -p",
    # stored credentials
    "heroku config", "heroku config:get STRIPE_SECRET_KEY -a shop", "kubectl get secret db -o yaml",
    "kubectl get secrets -n prod -o json", "kubectl config view --raw", "az account get-access-token",
    "az keyvault secret show --name db --vault-name v", "aws secretsmanager get-secret-value --secret-id db",
    "aws ssm get-parameter --name /db/pw --with-decryption", "aws sts get-session-token",
    "gcloud secrets versions access latest --secret db", "gcloud auth print-identity-token", "vault kv get secret/db",
    "vault read secret/db", "doppler secrets", "doppler secrets download --no-file", "docker compose config",
    "docker-compose config", "terraform output -json", "terraform output -raw db_password", "supabase status",
    "npm config get //registry.npmjs.org/:_authToken",
    # a command between two strings that each have a variable in them
    'echo "a $HOME" | tee out; printenv; echo "b $USER"', 'echo "$A"; cat .env; echo "$B"',
    """echo "it's fine"; cat .env""", """echo 'one' "two $X" ; env ; echo 'three'""",
])
def test_ways_around_are_closed(command):
    assert guard.risky_command(command)


@pytest.mark.parametrize("command", [
    "Invoke-Expression 'Get-Content .env'", "iex 'gc .env'", "Get-Content .env::$DATA", "Get-Content '.env.'",
    "git show HEAD:.env", "cmd /c type .env",
])
def test_ways_around_are_closed_in_powershell(command):
    assert guard.risky_command(command, powershell=True)


@pytest.mark.parametrize("command", [
    # talking about a command is not running it
    'git commit -m "block gh auth token"', "echo 'run printenv to see them'", 'echo "use gh auth token"',
    "git commit -m 'guard: stop env; printenv; set'", 'gh issue create --title "docker compose config leaks"',
    # a word that happens to be a file name
    """python -c "print('credentials')\"""", """node -e "console.log('.env')\"""",
    # writing a heredoc down is not running it
    "cat > notes.md <<'EOF'\ncat .env\nprintenv\nEOF", "cat >> README.md <<EOF\nrun: gh auth token\nEOF\nls",
    # ordinary work
    "git show HEAD:README.md", "git diff --stat", "git show HEAD:.env.example", "git log -p src/", "git grep TODO",
    "git diff .env.example", "rg --glob '*.py' password .", "grep --include '*.ts' -rn secret src/",
    "export FOO=1", "export PATH=$PATH:/opt/bin", "heroku config:set FOO=1", "doppler secrets set FOO=1",
    "kubectl get secrets", "kubectl get pods -o yaml", "kubectl config view", "terraform output", "vault status",
    "docker compose config --quiet", "docker compose config --services", "docker compose up -d",
    "aws sts get-caller-identity",
    "cat .envoy.yaml", "ls .env*", "rm -f .env.*", "cat *.md", "cat src/*", "rg TODO .*", "diff a.txt b.txt",
    "dd if=/dev/zero of=out bs=1M count=1", "find . -name '*.py' -exec cat {} +", "find . -name .env",
    "eval \"$(ssh-agent)\"", "sort < input.txt", "wc -l < README.md",
    # the end of one string is not the start of the next
    'echo "KEY=$(openssl rand -hex 32)" | sudo tee /opt/app/.env >/dev/null; sudo chmod 600 /opt/app/.env; echo "ok"',
    'TOKEN=$(printf "protocol=https\nhost=github.com\n\n" | git credential fill | sed -n "s/^password=//p")',
    """git commit -m "it's done; printenv is blocked" """, """echo "say \\"env\\"; ok" """,
    """python -c "import os; print(os.environ['HOME'])\"""", """python -c "import os; os.environ['API_KEY']\"""",
    """node -e "console.log(process.env.NODE_ENV)\"""",
])
def test_ordinary_commands_still_run(command):
    assert guard.risky_command(command) is None


def test_a_heredoc_fed_to_python_is_a_script_that_can_open_files():
    assert guard.risky_command("python - <<'EOF'\nprint(open('.env').read())\nEOF")
    assert guard.risky_command("cd app && python3 <<PY\nfrom pathlib import Path\nprint(Path('.env').read_text())\nPY")
    assert guard.risky_command("node <<'JS'\nconsole.log(require('fs').readFileSync('.npmrc', 'utf8'))\nJS")
    # a script that only mentions the name, or opens something else, runs
    assert guard.risky_command("python - <<'EOF'\nprint('remember to fill in .env')\nEOF") is None
    assert guard.risky_command("python - <<'EOF'\nprint(open('README.md').read())\nEOF") is None


def test_ssh_runs_the_quoted_word_on_the_other_machine():
    assert guard.risky_command("ssh deploy@host 'cat /srv/app/.env'")
    assert guard.risky_command('ssh -o BatchMode=yes host "cd /srv/app && printenv"')
    assert guard.risky_command("ssh host 'sudo test -f /srv/app/.env && echo there'") is None
    assert guard.risky_command("ssh host uptime") is None


def test_a_heredoc_fed_to_a_shell_is_still_a_script():
    assert guard.risky_command("bash <<'EOF'\ncat .env\nEOF")
    assert guard.risky_command("ssh host <<EOF\nls\nEOF\ncat .env")  # what comes after it counts again


@pytest.mark.parametrize("path", [
    "~/.codex/./auth.json", "app/config/../.env", "C:\\proj\\.\\.env", ".env::$DATA", ".env.", ".env ", ".ENV::$data",
    ".env*", "**/.env*", "config/.en?", ".[e]nv", ".npmr[c]",
])
def test_other_spellings_of_a_secret_file(path):
    assert guard.is_secret_file(path)


@pytest.mark.parametrize("path", [".", "..", "./", "src/.", ".*", "*", "**/*", ".e*.example", ".es*", ""])
def test_spellings_that_are_not_a_secret_file(path):
    assert not guard.is_secret_file(path)


def test_search_tools_with_a_glob_for_secret_files():
    assert guard.check_tool("Grep", {"pattern": "KEY", "glob": "**/.env*"})
    assert guard.check_tool("Grep", {"pattern": "KEY", "glob": "*.py"}) is None


def test_json_nested_too_deep_does_not_crash_the_hook():
    deep = "[" * 100_000 + "]" * 100_000
    for event in ("prompt", "tool-output", "tool-failure", "session-end"):
        assert guard.run_hook(event, io.StringIO(deep), io.StringIO(), io.StringIO()) == 0
    # a tool call that can't be read can't be checked, so it doesn't go ahead
    assert guard.run_hook("tool", io.StringIO(deep), io.StringIO(), io.StringIO()) == 2


@pytest.mark.parametrize("hooks", [
    {"PreToolUse": None}, {"PreToolUse": "x", "SessionEnd": 3}, {"UserPromptSubmit": {}},
])
def test_status_copes_with_hooks_that_are_not_lists(tmp_path, hooks):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"hooks": hooks}))
    assert not any(guard.status(path).values())
