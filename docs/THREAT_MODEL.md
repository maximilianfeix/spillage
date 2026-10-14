# Threat model

What spillage defends against, what it trusts, and what it doesn't cover. Kept short on purpose:
each line points at the code that carries it, so it can be checked and kept up to date.

## What is being protected

A credential (API key, token, password from a `.env` file) that ends up in a coding agent's
conversation. Once it is in the conversation it has been sent to the model provider and written
to a transcript on disk. spillage tries to keep it out of the conversation (`guard`), find it
when it got in anyway (`scan`, `watch`, `repo`), and take it out of the files on disk (`scrub`).
Rotating the key is the only real fix once it was sent; every output says so.

## Trust boundaries

| Input | Trusted? | Why it matters |
| --- | --- | --- |
| Transcripts, databases, settings files of the agents | no | They hold text the model, tools, web pages and MCP servers wrote. Parsed with size and depth limits ([sources.py](../spillage/sources.py), [walker.py](../spillage/walker.py)); a broken file is an error for that file, not for the scan ([scanner.py](../spillage/scanner.py) `_scan_job`). |
| A hook's JSON on stdin | no | The tool input is written by the model, which a prompt injection can steer. The hooks must not fail open ([guard.py](../spillage/guard.py) `run_hook`). |
| File and folder names | no | A file can be named after the key in it. Everything that leaves the program goes through `Hider` ([models.py](../spillage/models.py)). |
| Files in a repository (`spillage repo`, the Action) | no | Same as transcripts. The Action needs only read access to the checkout; this repository's own workflows use `pull_request`, never `pull_request_target`, and pin every action to a commit. |
| `.env` files in your projects | yes, as data | Their values become exact-match rules (`KnownValueRule`); they are never printed. |
| `.spillage-baseline.json`, `.spillageignore` | yes | They decide what is reported. A pull request that edits them is visible in review. |

## Where secrets could leave, and what stops it

| Path | Protection |
| --- | --- |
| Reports (text, JSON, Markdown, HTML, SARIF, annotations) | `Finding.to_dict()` has no secret field; every format runs through `ScanResult.hide`. Tests check each format against the raw values. |
| Masked values | first ≤ 6 characters and the length (`mask`). Never enough to use a key. |
| Fingerprints | first 12 hex digits of SHA-256, unsalted, so the same key has the same id on every machine (needed for ignore files and baselines). Not reversible for a random key. For a short, guessable password from a `.env` file a fingerprint lets someone test guesses offline; that only matters where the report is public, and a public report means the file it describes is public too. |
| Exception messages | Hook messages name the error type only. SQLite errors are reduced to their type (they can quote the schema). |
| Temp files during `scrub` | created next to the target with `mkstemp` (mode 0600), hold the redacted text only, renamed over the original. |
| Baseline file | fingerprints, rule ids and file:line, passed through `Hider` before it is written. |
| Network | none. No code path opens a socket; there is no telemetry. |

## What `scrub` guarantees

- Only the matched bytes change; the result must still parse as JSON where the original did (`_still_valid`), otherwise the file is left alone and reported.
- Files written in the last minute are skipped (a running session), and a file that changed between the read and the write is left alone (`scrub`), or, for `watch --scrub` and Codex rollouts that stay open, the appended bytes are kept (`write_in_place`).
- Symlinked files are never discovered, so a link planted in an agent folder can't point scrub at another file. A hard link is replaced, not written through.
- Signed thinking blocks are left alone, since editing them breaks `--resume`; the report counts them.
- Databases are not rewritten (see [#79](https://github.com/maximilianfeix/spillage/issues/79)): the report says which ones still hold a key.
- A partial clean-up exits 2 and lists what failed.

## What the hooks guarantee

See the table under [Guard](../README.md#guard). In short: prompts and the known ways of reading
a secret are blocked before anything is sent (Claude Code, Codex, Gemini CLI); in Claude Code a
key in tool output is replaced before the model sees it; everything else is detected after the
fact. When a hook itself fails, the tool call is blocked and unreadable output withheld.

Not covered: a determined agent (`cp .env x`, then read `x`, is caught only by the output hook
in Claude Code and only for known key formats and your `.env` values), exfiltration that never
goes through the conversation (`curl -d @.env`), keys that are encoded or split, and agents that
have no hook to replace a tool's output. Use a sandbox and keep keys out of the folders an agent
works in if you need more than a guard rail.

## Resource limits

- files over 256 MB are skipped and listed, JSONL files are read in parts
- JSON nested too deep to parse is an error for that file; in a hook it blocks (tool) or names the keys (output)
- every rule is timed on adversarial input in the tests (`test_rules.py`), the JWT rule is linear
- a scan that could not read everything exits 3, not 0
