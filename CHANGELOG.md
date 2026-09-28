# Changelog

## [Unreleased]

### Added
- `spillage scan`: reads Claude Code, Codex CLI, Gemini CLI, OpenCode, Cline / Roo / Kilo, Continue and Copilot CLI logs
- 40 rules, from GitHub tokens (checksum-verified) to database URLs and private keys
- tells you *how* each secret got there: pasted into a prompt, printed by a tool, repeated by the model
- `check`, `agents`, `rules`, `ignore` commands, text / JSON / Markdown output
- `spillage scrub` replaces found secrets with `[REDACTED:rule:fingerprint]` markers in place. JSON stays valid, file mode, mtime and line endings are kept, files from a running session are left alone
