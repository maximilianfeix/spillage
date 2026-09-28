from __future__ import annotations

import fakes
import pytest

from spillage.models import Origin
from spillage.scanner import Scanner
from spillage.sources import build_sources, known_projects


@pytest.fixture
def project(home, tmp_path, monkeypatch):
    proj = tmp_path / "work" / "shop"
    proj.mkdir(parents=True)
    home.claude_session(project=str(proj), records=[{"type": "user", "message": {"content": "hi"}}])
    monkeypatch.chdir(home.root)
    return proj


def scan(agents):
    return {f.secret: f for f in Scanner(workers=1).scan(build_sources(agents)).findings}


def test_projects_come_from_session_cwds(project, home, tmp_path):
    other = tmp_path / "api"
    other.mkdir()
    home.codex_session(cwd=str(other))
    found = known_projects(home.root)
    assert project in found and other in found and home.root in found


def test_aider_history(project):
    gh, npm, sk = fakes.github(), fakes.npm(), fakes.stripe()
    (project / ".aider.chat.history.md").write_text(
        "# aider chat started at 2026-09-20\n\n"
        f"#### deploy with {gh}\n\n"
        f"> /run cat .npmrc\n> //registry.npmjs.org/:_authToken={npm}\n\n"
        f"Sure, I'll set STRIPE_KEY to {sk} in the config.\n",
        encoding="utf-8",
    )
    (project / ".aider.input.history").write_text(f"+deploy with {gh}\n", encoding="utf-8")
    found = scan(["aider"])
    assert Origin.PROMPT in found[gh].origins and Origin.HISTORY in found[gh].origins
    assert found[npm].origins == [Origin.TOOL]
    assert found[sk].origins == [Origin.ASSISTANT]
    assert found[gh].locations[0].project == str(project)


def test_specstory_history(project):
    key, pw = fakes.anthropic(), fakes.db_password()
    hist = project / ".specstory" / "history"
    hist.mkdir(parents=True)
    (hist / "2026-09-20_10-00Z-fix-login.md").write_text(
        "# Fix login\n\n_**User**_\n\n"
        f"my key is {key}\n\n---\n\n_**Assistant**_\n\n"
        "Let me read the env.\n\n<details><summary>Read file: .env</summary>\n\n"
        f"DATABASE_URL=postgres://app:{pw}@db:5432/prod\n\n</details>\n\nDone.\n",
        encoding="utf-8",
    )
    found = scan(["specstory"])
    assert found[key].origins == [Origin.PROMPT]
    assert found[pw].origins == [Origin.TOOL]
    assert found[key].locations[0].session == "2026-09-20_10-00Z-fix-login"
    assert found[key].locations[0].project == str(project)


def test_nothing_in_projects(project):
    assert scan(["aider", "specstory"]) == {}
