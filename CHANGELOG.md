# Changelog

## [Unreleased]

### Added
- `spillage doctor`: one screen for where you stand. Secrets in the logs, keys in agent settings, whether the guard hooks are on for every installed agent, the values it watches from your `.env` files, and transcripts committed in the current repository, each with the command that fixes it. Exits 1 while something is open; `-f json` for scripts ([#64](https://github.com/maximilianfeix/spillage/issues/64))
- `spillage completions bash|zsh|fish` prints a tab-completion script with every command, option and choice, generated from the argument parser ([#62](https://github.com/maximilianfeix/spillage/issues/62))
- a mistyped command gets a hint (`unknown command 'scna', did you mean `spillage scan`?`) instead of the usage text of `scan`
- 19 new rules, 76 in total: Docker Hub, Tailscale, Fly.io, Netlify, Render, Heroku, Pulumi, age secret keys, Azure storage account keys, RubyGems, Bitbucket app passwords, New Relic, Mapbox, Airtable, ElevenLabs, E2B, Square, Stripe webhook secrets and Slack app-level tokens ([#58](https://github.com/maximilianfeix/spillage/issues/58))
- SARIF 2.1.0 output for GitHub code scanning: `spillage scan -f sarif`, `spillage repo -f sarif` and `repo --sarif FILE`, and a `sarif` input for the Action. Severities map to SARIF levels and GitHub's security severity, one alert per secret and file, masked values only ([#48](https://github.com/maximilianfeix/spillage/issues/48))
- agent settings are scanned too (`--agent config`): MCP server definitions in `~/.claude.json`, `.mcp.json`, Cursor, Claude Desktop, Codex `config.toml`, Gemini, Qwen, Windsurf, VS Code, Cline/Roo/Kilo, OpenCode, Crush, Goose and Continue, Claude Code's allowed commands (an approved `curl -H "Authorization: …"` keeps the key in `settings.local.json`) and the old per-project prompt history in `~/.claude.json`. Claude Code's own login is left out, unless the same key also turns up somewhere else in the file. `scrub` leaves the MCP servers and commands alone and says to move the key into an environment variable instead; prompts in that old history do get redacted ([#47](https://github.com/maximilianfeix/spillage/issues/47))
- `spillage repo` and the `spillage` pre-commit hook check committed `.mcp.json`, `.claude/settings*.json` and friends; they don't count as transcripts, so `--strict` doesn't fail on a clean one

### Fixed
- Windows: `guard` didn't recognise its own hooks when they run through `spillage.exe`, so every `guard install` added them again, `guard uninstall` left them in place and `guard status` reported them missing. Running `guard install` once more cleans up the duplicates
- Windows: output piped or redirected (`spillage > report.txt`, CI logs, the `python -m spillage` hook fallback) crashed on the first ✓, since Windows writes those in cp1252. It's UTF-8 now, and a console that can't show a symbol gets a `?`
- tests run on Windows in CI, next to Linux and macOS

## [0.6.9] - 2026-09-28

### Fixed
- a scan crashed when an old session had run in a folder that's now unreadable, or when the current folder had been deleted
- project folders are found through the same Claude Code and Codex locations the scan uses, so `CLAUDE_CONFIG_DIR` next to `~/.claude` and archived Codex sessions count too; the list is computed once instead of per source
- SpecStory: the model's "Thought Process" blocks count as the model, not as tool output, and origins are looked up with an index instead of rescanning the file per match
- the test suite no longer scans the real working directory

## [0.6.8] - 2026-09-28

### Fixed
- HTML report: a file path containing `<!--<script` could keep the data block from closing and leave a blank page; every `<`, `>` and `&` in the embedded data is escaped now
- HTML report: one timestamp the browser can't parse broke the timeline and everything after it
- HTML report: `-f html -o` crashed on file names with invalid UTF-8
- HTML report: colors follow a light/dark switch while it's open, long lists don't wait seconds for their fade-in, and filtering toggles cards instead of rebuilding them on every keystroke
- `render(result, "html")` works from Python without importing the CLI first, and the template loads from zipped installs too
- a Codex session with `"cwd": null` no longer puts "null" into project names

## [0.6.7] - 2026-09-28

### Fixed
- the Sentry rule never matched (a typo in its pattern)
- about 1 in 370 real private keys was dropped because its random body happened to contain a word like "todo"
- AWS secret keys under names like `AWSSecretAccessKey` were only caught by the generic rule
- Goose, Crush and Cursor databases in WAL mode: the newest messages, still in the `-wal` file, were invisible
- a single JSONL file over 256 MB was skipped without a word; it's read in parts now, other oversized files are listed as skipped
- when several rules see the same secret, the most specific one names it (an AWS key that's also in `.env` is an "AWS secret access key", critical)
- custom rules passed to `Scanner` crashed a parallel scan
- scanning a file in parts decoded invalid bytes differently from reading it whole, which changed fingerprints
- line numbers are counted incrementally and each JSON line is parsed once, instead of once per hit

## [0.6.6] - 2026-09-28

### Fixed
- `scrub` could report success and leave a key on disk: files with Windows line endings (a multi-line key got a different fingerprint on the second read), files the key had vanished from since the scan, and symlinks (the link was replaced, the target kept the key). Scanning and scrubbing now read files through the same function, a file where nothing is found again is reported, and symlink targets are rewritten
- a single invalid UTF-8 byte made a whole file unscrubbable; bytes are now kept exactly as they were
- a file that changes while being scrubbed is left alone instead of losing what was appended
- secrets inside Claude's signed thinking blocks are left alone and reported: editing them breaks `--resume` of that session
- the JSON check could miss a broken line that contains U+2028
- Ctrl-D at the scrub prompt means no instead of a traceback

## [0.6.5] - 2026-09-28

### Fixed
- `guard status` only checks the agents installed on the machine, so it no longer fails because Codex or Gemini aren't there
- Gemini `settings.json` with comments no longer blocks `guard install` (a backup keeps the original)
- one agent with a broken config no longer stops `guard install` for the others
- more ways to read secrets are blocked: Gemini's `read_many_files` with `include`, MCP filesystem read tools (now also sent to the hook by Claude Code's matcher), and shell argv like `bash -l -c …`, `/usr/bin/env bash -c …`
- `--scope local` for Codex and Gemini used to write into the shared project config; it's refused now, since only Claude Code has a local-only file

## [0.6.4] - 2026-09-28

### Fixed
- an empty value in a `.env` file (`API_KEY=`) crashed `scan`, `scrub` and `watch`. A `.env` file that can't be parsed is now skipped instead of stopping anything

## [0.6.3] - 2026-09-28

### Fixed
- `watch` reported keys that were already in JSON, Markdown and SQLite logs whenever those files changed. It now takes a baseline at startup and only reports what's new since then
- `watch --scrub` missed a known key showing up in a second file, and replaced files with a rename, which could cut off an agent that still had the file open (Codex keeps its rollout file open). Files are now rewritten in place
- `watch` no longer reads half a line when it starts in the middle of a write, notices in-place rewrites that make a file longer, survives files vanishing or being locked, and doesn't re-list every log folder every 2 seconds or read every log at startup

## [0.6.2] - 2026-09-28

### Fixed
- `spillage repo` and the pre-commit hooks now use one list of transcript patterns (a test keeps `.pre-commit-hooks.yaml` in sync), matched on path segments: `data/rollout-metrics.jsonl` or `docs/cline_task_template.md` no longer count as transcripts, nested `.claude/` and `.codex/` logs and Cline exports do
- GitHub annotations point at the right file when the Action's `path` is a subfolder; with `all-files` a source file isn't called a transcript anymore
- the Action scans once instead of twice and can't lose its exit code
- git errors say what git said (e.g. "dubious ownership") instead of "isn't a git repository"
- `--files` outside the repository are ignored; `--strict` says why it failed

### Added
- `.spillageignore` in a repository: fingerprints to ignore there, also in CI

## [0.6.1] - 2026-09-28

### Fixed
- `.env` values: variable names are matched by whole words now (`AUTHOR_NAME` and `NEXTAUTH_URL` were treated as secrets), public keys (`NEXT_PUBLIC_…`, `…_PUBLISHABLE_…`) and plain URLs are skipped, quoted values with a trailing comment lose their quotes, multi-line values are left out instead of matching their first line
- a value ending in a backslash could be redacted into broken JSON; the escaped form is matched first now
- all values are found in one pass instead of one pass per value, and the list reaches worker processes once instead of with every file
- `env-value` works with `--rules` / `--skip-rules` and shows up in `spillage rules`; `watch` has `--no-env`
- the guard's session-end scrub also removes values from the project's `.env`

## [0.6.0] - 2026-09-28

### Added
- Your own secrets: the values in your projects' `.env` files are looked up verbatim in the logs, raw and JSON-escaped, which catches passwords and keys no pattern could. Reported by variable name and file, never by value. `--no-env` turns it off

## [0.5.1] - 2026-09-28

### Fixed
- `guard` hooks didn't run when spillage was installed with Homebrew or pipx: the hook called `python -m spillage` with an interpreter that can't import it. Hooks now call the installed `spillage` launcher, and `guard install` runs the hook once to check it works. Run `spillage guard install` again to update existing hooks

## [0.5.0] - 2026-09-28

### Added
- Qwen Code, Goose (SQLite and JSONL sessions) and Crush (per-project SQLite). SQLite databases are read with one generic, read-only reader
- Homebrew: `brew install maximilianfeix/tap/spillage`
- a website: https://maximilianfeix.github.io/spillage/

## [0.4.0] - 2026-09-28

### Added
- `spillage watch`: follows every agent's logs, reports new secrets within seconds with a desktop notification, `--scrub` cleans a file once it has been quiet for a while
- 16 rules for keys that turn up in agent sessions a lot: Claude Code OAuth tokens (`sk-ant-oat01-`), Supabase secret keys, LangSmith, Pinecone, Tavily, Firecrawl, Resend, PostHog, Vercel Blob, Google OAuth refresh and access tokens, Doppler, HashiCorp Vault, 1Password service accounts, PlanetScale, Brevo

## [0.3.0] - 2026-09-28

### Added
- `spillage repo`: agent transcripts committed to a git repository and the secrets in them. `--strict` fails on any transcript, `--all-files` scans every tracked file, `-f github` writes annotations and a job summary
- a GitHub Action (`uses: maximilianfeix/spillage@v0.3.0`) and pre-commit hooks (`spillage`, `no-agent-transcripts`)
- Aider (`.aider.chat.history.md`, `.aider.input.history`) and SpecStory (`.specstory/history/`). They write into project folders, so those are found through the working directories of your Claude Code and Codex sessions. Markdown logs get origins too: `####` lines are prompts in Aider, quoted `>` lines tool output

## [0.2.0] - 2026-09-28

### Changed
- Big session files are cut into parts at line breaks and scanned on several cores, and jobs run biggest first. 244 MB of real logs with a 109 MB session in it: 9.4 s → 3.4 s

### Added
- Cursor: chats are read from its SQLite databases (read-only, no lock). Cursor's own login and per-chat encryption keys are skipped
- `spillage guard` now also covers Codex CLI (`~/.codex/hooks.json`) and Gemini CLI (`~/.gemini/settings.json`). `install` sets up every agent it finds, `--agent` picks. Tool names from all three agents are understood (`read_file`, `run_shell_command`, argv-style `["bash", "-lc", ...]`, ...)

## [0.1.0] - 2026-09-28

### Added
- `spillage scan`: reads Claude Code, Codex CLI, Gemini CLI, OpenCode, Cline / Roo / Kilo, Continue and Copilot CLI logs
- 40 rules, from GitHub tokens (checksum-verified) to database URLs and private keys
- tells you *how* each secret got there: pasted into a prompt, printed by a tool, repeated by the model
- `check`, `agents`, `rules`, `ignore` commands, text / JSON / Markdown output
- `spillage scrub` replaces found secrets with `[REDACTED:rule:fingerprint]` markers in place. JSON stays valid, file mode, mtime and line endings are kept, files from a running session are left alone
- `-f html`: a single self-contained report (no CDN, works offline) with severity breakdown, how each secret got there, a timeline, filters and search. Light and dark
- `spillage guard install` adds three Claude Code hooks: prompts with a secret are blocked before they're sent, reading `.env` / keys / credential files is blocked (Read, Grep and Bash), and a session's transcript is scrubbed when it ends. Other hooks and settings are kept, `uninstall` removes only ours
