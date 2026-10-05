"""How `spillage repo` results leave the program: SARIF, Markdown, and GitHub's annotations,
job summary and step outputs."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .reporters import agent_label, render


def sarif(result, root: Path, strict: bool) -> str:
    """SARIF for code scanning. With --strict, committed transcripts are alerts too, so a run that
    fails on them explains why in the Security tab."""
    ws = workspace_relative(root)
    sarif = render(result.scan, "sarif", uri=ws)
    if not (strict and result.transcripts):
        return sarif
    data = json.loads(sarif)
    run = data["runs"][0]
    run["tool"]["driver"]["rules"].append({
        "id": "committed-transcript",
        "shortDescription": {"text": "Agent transcript committed"},
        "fullDescription": {"text": "A coding agent's chat log is tracked by git; anyone who can read the repo "
                                    "can read the conversation."},
        "helpUri": "https://github.com/maximilianfeix/spillage#repo",
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security"], "precision": "very-high", "security-severity": "5.0"},
    })
    for path, agent in sorted(result.transcripts.items()):
        uri = ws(root / path)
        run["results"].append({
            "ruleId": "committed-transcript",
            "level": "error",
            "message": {"text": f"{agent_label(agent)} transcript is committed. Remove it from git and add it "
                                "to .gitignore."},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "partialFingerprints": {"spillageTranscript/v1": uri},
        })
    return json.dumps(data, indent=2, ensure_ascii=False)


def workspace_relative(root: Path):
    """Paths the way GitHub resolves them: relative to the checkout (GITHUB_WORKSPACE), or to the
    repository when run outside Actions."""
    base = Path(os.environ.get("GITHUB_WORKSPACE") or root).resolve()

    def ws(path) -> str:
        try:
            return os.path.relpath(Path(path).resolve(), base).replace(os.sep, "/")
        except ValueError:  # another drive on Windows
            return str(path)

    return ws


def github(result, root: Path, strict: bool, md: str) -> None:
    """Annotations (paths relative to the workspace, which is what GitHub resolves them
    against), the job summary, and step outputs."""
    ws = workspace_relative(Path.cwd())

    transcripts = {str((root / r).resolve()) for r in result.transcripts}
    for f in result.findings:
        for loc in f.locations:
            line = f",line={loc.line}" if loc.line else ""
            rotate = f" Rotate it: {f.rotate_url}" if f.rotate_url else ""
            in_transcript = str(Path(loc.file).resolve()) in transcripts
            where = "a committed agent transcript" if in_transcript else "a committed file"
            print(f"::error file={ws(loc.file)}{line},title=spillage: {f.rule_name}::"
                  f"{f.rule_name} ({f.masked}, {f.fingerprint}) is in {where}.{rotate}")
    if strict:
        for path, agent in result.transcripts.items():
            print(f"::warning file={ws(root / path)},title=spillage: agent transcript::"
                  f"{agent_label(agent)} transcript is committed. Add it to .gitignore.")
    for name, value in (("GITHUB_STEP_SUMMARY", md + "\n"),
                        ("GITHUB_OUTPUT", f"transcripts={len(result.transcripts)}\nsecrets={len(result.findings)}\n")):
        target = os.environ.get(name)
        if target:
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(value)
    print(f"spillage: {len(result.transcripts)} transcript(s), {len(result.findings)} secret(s)")


def markdown(result, rel) -> str:
    out = ["## spillage", ""]
    if not result.transcripts and not result.findings:
        return "\n".join(out + ["No agent transcripts committed. ✅"])
    if result.transcripts:
        out += [f"**{len(result.transcripts)} agent transcript(s) committed:**", ""]
        out += [f"- `{path}` ({agent_label(agent)})" for path, agent in sorted(result.transcripts.items())[:50]]
        out.append("")
    if result.findings:
        out += ["| Severity | What | Masked | Where | Rotate |", "| --- | --- | --- | --- | --- |"]
        for f in result.findings:
            loc = f.locations[0]
            where = f"`{rel(loc.file)}:{loc.line}`" + (f" +{len(f.locations) - 1}" if len(f.locations) > 1 else "")
            rotate = f"[rotate]({f.rotate_url})" if f.rotate_url else ""
            out.append(f"| {f.severity.label} | {f.rule_name} | `{f.masked}` | {where} | {rotate} |")
        out += ["", "Rotate these keys: the repo history keeps them even after the file is deleted."]
    else:
        out.append("No secrets in them.")
    return "\n".join(out)
