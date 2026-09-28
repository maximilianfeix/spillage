# Contributing

```bash
git clone https://github.com/maximilianfeix/spillage && cd spillage
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check .
```

**Never commit a real secret, not even a revoked one.** Tests build their fake keys at runtime in `tests/fakes.py`, so the strings never exist in the repo and push protection stays quiet. Please do the same.

### Adding a rule

Rules live in `spillage/rules.py`. A good rule:

- starts with a literal prefix (`ghp_`, `sk-ant-`), which keeps the regex fast on hundreds of MB of logs
- has a validator when the format allows one (checksums, decodable JWTs)
- comes with a positive test and at least one lookalike that must *not* match

### Adding an agent

Agents live in `spillage/sources.py`: a class with a `name`, a `label`, the folders to look in and glob patterns. If the format tells prompts apart from tool output, override `origin()`. Add a fake log for it to `tests/conftest.py`.
