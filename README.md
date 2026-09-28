# spillage

Find the secrets your coding agents spilled.

Claude Code, Codex, Gemini CLI and friends keep every conversation on your disk, in plain text. Every `.env` the agent read, every key you pasted "just to test", every `printenv` it ran. spillage scans those logs, tells you what leaked, where and how, and links you straight to the page where you rotate it.

```bash
pipx install git+https://github.com/maximilianfeix/spillage
spillage
```

No dependencies, no network, nothing leaves your machine. Secrets are only ever shown masked.

## Commands

```
spillage                  scan every agent it knows (same as `spillage scan`)
spillage scan --since 7d  only recent logs
spillage scan -f json     machine readable, also markdown
spillage check "text"     scan a string or stdin
spillage agents           which agents were found and where their logs are
spillage rules            what it looks for
spillage ignore <fp>      stop reporting a secret
```

Exit code is 1 when something was found, so it works in scripts and cron.

## License

MIT
