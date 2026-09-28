# Changelog

## [Unreleased]

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
