"""Detection quality and speed on a synthetic corpus, reproducible from a seed.

    python benchmarks/evaluate.py                 # 50 MB, prints a summary
    python benchmarks/evaluate.py --mb 200 --json results.json

What it builds: agent transcripts in the shapes spillage reads (Claude Code and Codex style JSONL,
Gemini style JSON, Markdown chat logs), filled with ordinary text, code, hashes, UUIDs and base64,
and with fake keys planted at known places. The keys come from tests/fakes.py, which builds them
at run time (valid checksums where a format has one), so no key exists in the repository.

Positives are the planted keys, written the ways keys really show up: pasted in a prompt, printed
by a tool (JSON-escaped, next to newlines, after a terminal colour code), repeated by the model,
inside a JSON string that is itself in a JSON string. Negatives are lookalikes that must not be
reported: GitHub tokens with a wrong checksum, documentation placeholders, the AWS example key,
git hashes, UUIDs, SHA-256 digests, base64 image data, `sk-...your-key-here`.

What the numbers mean: recall and precision on this corpus, no more. The corpus is written by
the same people who write the rules, so it shows regressions and the formats that are covered;
it does not show how spillage does on logs nobody planned for. There is no public ground truth
for real agent transcripts, and real ones can't be published.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import random
import sys
import tempfile
import time
import tracemalloc
import uuid
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "tests"))

import fakes  # noqa: E402

from spillage import __version__  # noqa: E402
from spillage.scanner import Scanner  # noqa: E402
from spillage.sources import PathSource  # noqa: E402

POSITIVES = {
    "github": fakes.github, "anthropic": fakes.anthropic, "openai": fakes.openai, "aws-key-id": fakes.aws_key_id,
    "stripe-live": fakes.stripe, "slack": fakes.slack, "google": fakes.google, "huggingface": fakes.huggingface,
    "npm": fakes.npm, "openrouter": fakes.openrouter, "sendgrid": fakes.sendgrid, "telegram": fakes.telegram,
    "discord-bot": fakes.discord_bot, "jwt": fakes.jwt, "db-url": fakes.db_url, "private-key": fakes.private_key,
    "langsmith": fakes.langsmith, "supabase": fakes.supabase_secret, "doppler": fakes.doppler,
    "vercel-blob": fakes.vercel_blob, "docker-pat": fakes.docker_pat, "heroku": fakes.heroku,
}  # fmt: skip


def negatives(rng: random.Random) -> dict:
    return {
        "github-bad-checksum": lambda: fakes.github(valid=False),
        "placeholder-openai": lambda: "sk-proj-your-key-here",
        "placeholder-anthropic": lambda: "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "aws-docs-example": lambda: "AKIAIOSFODNN7EXAMPLE",
        "git-sha": lambda: hashlib.sha1(str(rng.random()).encode()).hexdigest(),
        "sha256": lambda: hashlib.sha256(str(rng.random()).encode()).hexdigest(),
        "uuid": lambda: str(uuid.UUID(int=rng.getrandbits(128))),
        "base64-blob": lambda: base64.b64encode(rng.randbytes(300)).decode(),
        "env-template": lambda: "OPENAI_API_KEY=<your key>",
        "short-stripe": lambda: "sk_live_" + fakes.rand(6),
    }


FILLER = [
    "def handler(event, context):\n    return {'statusCode': 200}",
    "Running tests... 214 passed in 3.2s",
    "I'll update the config and run the migration next.",
    "src/app/routes.py:42: warning: unused import",
    "SELECT id, email FROM users WHERE created_at > now() - interval '7 days';",
    "npm WARN deprecated inflight@1.0.6",
    "The function returns early when the cache is warm.",
]


def _wrap(secret: str, how: str) -> str:
    """The text around a key, by the way it got into the log."""
    if how == "prompt":
        return f"here is my key {secret} can you check why the call fails"
    if how == "tool":
        return f"export TOKEN={secret}\nexit status 0"
    if how == "colour":
        return f"\x1b[32m{secret}\x1b[0m"
    if how == "nested":
        return json.dumps({"stdout": f"key={secret}"})  # a JSON string inside a JSON string
    return f"Sure, I set it to {secret} in the config."  # the model repeats it


WAYS = ("prompt", "tool", "colour", "nested", "assistant")


def build(root: Path, megabytes: int, seed: int) -> tuple:
    rng = random.Random(seed)
    fakes._rng.seed(seed)
    neg = negatives(rng)
    planted, decoys = {}, {}  # secret -> (kind, way), secret -> kind
    target = megabytes * 1024 * 1024
    written, n = 0, 0
    while written < target:
        n += 1
        shape = ("claude", "codex", "gemini", "markdown")[n % 4]
        records = []
        for i in range(rng.randint(40, 120)):
            text = rng.choice(FILLER) + " " + fakes.rand(rng.randint(0, 40))
            if rng.random() < 0.03:
                kind = rng.choice(sorted(POSITIVES))
                secret, way = POSITIVES[kind](), rng.choice(WAYS)
                planted[secret] = (kind, way)
                text = _wrap(secret, way)
            elif rng.random() < 0.05:
                kind = rng.choice(sorted(neg))
                value = neg[kind]()
                decoys[value] = kind
                text = f"value: {value}"
            records.append((i, text))
        path, data = _render(root, shape, n, records)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding="utf-8", newline="")  # the bytes as built, on Windows too
        written += len(data.encode("utf-8"))
    return planted, decoys, n, written


def _render(root: Path, shape: str, n: int, records) -> tuple:
    if shape == "claude":
        role = ("user", "assistant")
        lines = [json.dumps({"type": role[i % 2], "sessionId": f"s{n}", "cwd": "/work/app",
                             "message": {"role": role[i % 2], "content": text}}) for i, text in records]
        return root / "claude" / f"s{n}.jsonl", "\n".join(lines) + "\n"
    if shape == "codex":
        lines = [json.dumps({"type": "response_item", "payload": {"type": "function_call_output", "output": text}})
                 for _, text in records]
        return root / "codex" / f"rollout-{n}.jsonl", "\n".join(lines) + "\n"
    if shape == "gemini":
        msgs = [{"type": ("user", "gemini")[i % 2], "content": text} for i, text in records]
        return root / "gemini" / f"session-{n}.json", json.dumps({"sessionId": f"g{n}", "messages": msgs}, indent=2)
    body = "\n\n".join(f"{'_**User**_' if i % 2 == 0 else '_**Assistant**_'}\n\n{text}" for i, text in records)
    return root / "specstory" / f"chat-{n}.md", body + "\n"


def evaluate(megabytes: int, seed: int, workers: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="spillage-eval-") as tmp:
        root = Path(tmp)
        planted, decoys, files, size = build(root, megabytes, seed)
        tracemalloc.start()
        started = time.perf_counter()
        result = Scanner(workers=workers).scan([PathSource([root])])
        seconds = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    # A rule reports the part that is the secret: the password of a database URL, the body of a
    # PEM block. So a finding counts for a planted key when one holds the other.
    # A JSON string inside a JSON string keeps one level of escaping (a backslash-n for a line
    # break in a PEM block): still found, under another fingerprint.
    def same(text: str) -> str:
        return text.replace(chr(92) + "n", chr(10))

    planted = {same(k): v for k, v in planted.items()}
    found = [(same(f.secret), f.rule_id) for f in result.findings]
    hit = set()
    unexpected, fp_decoys = [], []
    for secret, rule in found:
        owners = [p for p in planted if secret in p or p in secret]
        if owners:
            hit.update(owners)
            continue
        decoy = next((kind for value, kind in decoys.items() if secret in value or value in secret), None)
        (fp_decoys.append(decoy) if decoy else unexpected.append(rule))
    tp = [p for p in planted if p in hit]
    fn = [planted[p] for p in planted if p not in hit]
    false_pos = len(fp_decoys) + len(unexpected)
    return {
        "spillage": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpus": os.cpu_count(),
        "seed": seed,
        "corpus": {"files": files, "bytes": size, "planted": len(planted), "decoys": len(decoys)},
        "seconds": round(seconds, 3),
        "mb_per_second": round(size / 2**20 / seconds, 1),
        "peak_python_memory_mb": round(peak / 2**20, 1) if workers == 1 else None,
        "recall": round(len(tp) / len(planted), 4) if planted else None,
        "precision": round(len(tp) / (len(tp) + false_pos), 4) if tp or false_pos else None,
        "false_negatives": dict(Counter(f"{kind} ({way})" for kind, way in fn)),
        "false_positives": dict(Counter(fp_decoys + [f"unplanned: {rule}" for rule in unexpected])),
        "errors": len(result.stats.errors),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--mb", type=int, default=50, help="corpus size in MB (default 50)")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--workers", type=int, default=1, help="1 also measures peak memory (default 1)")
    parser.add_argument("--json", type=Path, help="also write the results here")
    args = parser.parse_args()
    out = evaluate(args.mb, args.seed, args.workers)
    text = json.dumps(out, indent=2)
    print(text)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
