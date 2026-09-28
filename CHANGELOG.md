# Changelog

## [Unreleased]

### Added
- `spillage scan`: reads Claude Code, Codex CLI, Gemini CLI, OpenCode, Cline / Roo / Kilo, Continue and Copilot CLI logs
- 40 rules, from GitHub tokens (checksum-verified) to database URLs and private keys
- tells you *how* each secret got there: pasted into a prompt, printed by a tool, repeated by the model
- `check`, `agents`, `rules`, `ignore` commands, text / JSON / Markdown output
- `spillage scrub` replaces found secrets with `[REDACTED:rule:fingerprint]` markers in place. JSON stays valid, file mode, mtime and line endings are kept, files from a running session are left alone
- `-f html`: a single self-contained report (no CDN, works offline) with severity breakdown, how each secret got there, a timeline, filters and search. Light and dark
- `spillage guard install` adds three Claude Code hooks: prompts with a secret are blocked before they're sent, reading `.env` / keys / credential files is blocked (Read, Grep and Bash), and a session's transcript is scrubbed when it ends. Other hooks and settings are kept, `uninstall` removes only ours
