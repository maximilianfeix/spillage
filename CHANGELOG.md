# Changelog

## [Unreleased]

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
