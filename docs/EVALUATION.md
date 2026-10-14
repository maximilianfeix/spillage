# Detection quality and speed

How well spillage finds keys, and how fast, measured in a way anyone can repeat.

```bash
python benchmarks/evaluate.py                    # 50 MB, one process, also measures memory
python benchmarks/evaluate.py --workers 8        # the same corpus over 8 processes
python benchmarks/evaluate.py --mb 200 --json out.json
```

## Method

[`benchmarks/evaluate.py`](../benchmarks/evaluate.py) builds a corpus from a seed (the same seed
gives the same bytes) in the four shapes spillage reads: Claude Code style JSONL, Codex style
JSONL, Gemini style JSON and Markdown chat logs. The text around the keys is code, log lines and
random words. Then it scans the corpus the way `spillage --path` does and compares.

- **Positives:** 22 kinds of key from [`tests/fakes.py`](../tests/fakes.py) (built at run time, valid checksums where the format has one), each written five ways: pasted in a prompt, printed by a tool, after a terminal colour code, inside a JSON string that is itself in a JSON string, repeated by the model.
- **Negatives:** GitHub tokens with a wrong checksum, documentation placeholders, the AWS example key `AKIAIOSFODNN7EXAMPLE`, git hashes, SHA-256 digests, UUIDs, base64 data, `OPENAI_API_KEY=<your key>`, a Stripe key that is too short.
- A finding counts for a planted key when one contains the other: a rule reports the part that is the secret (the password in a database URL).

## What the numbers mean, and what they don't

They show regressions and which formats and spellings are covered. They are not a measure of
precision on real logs: the corpus and the rules are written by the same people, and the
negatives are the lookalikes we thought of. There is no public set of real agent transcripts
with labelled keys, and real ones can't be published. A false alarm or a missed key in your own
logs is the most useful bug report there is.

## A run

spillage 0.10.0 + the changes for 0.11, Python 3.12.10, Windows 11, 20 logical CPUs, seed 7, 14 October 2026.

| Corpus | Files | Planted | Lookalikes | Recall | Precision | Time | Throughput | Peak Python memory |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 50 MB, 1 process | 4,721 | 11,392 | 11,059 | 1.000 | 1.000 | 7.8 s | 6.4 MB/s | 15 MB |
| 50 MB, 8 processes | 4,721 | 11,392 | 11,059 | 1.000 | 1.000 | 2.4 s | 20.5 MB/s | |

For scale, a scan of the real agent history on the same machine (1,251 files, 500 MB, mostly
large JSONL sessions with few keys in them) took 8.8 s with the default of up to 8 processes.

The corpus is deliberately dense: about one key per 4 KB, in files of about 10 KB. Profiling
it shows where the time goes for many small files: two thirds in the rules' quick check for
their literal prefix (`Rule.might_match`, about 100 rules times every file), a fifth in finding
where a match sits in the JSON. Large files with few keys, which is what real transcripts look
like, spend almost all of it in the regex scan itself.

## Known gaps the corpus doesn't test

- keys split over two strings, base64- or hex-encoded keys, and letters written as `\u` escapes are not found (see the README's limits under Guard)
- a JSON string inside a JSON string keeps one level of escaping in what is reported, so a PEM key found there gets a different fingerprint from the same key found elsewhere
- the same PEM key with Windows line endings (CRLF) and with `\n` has two fingerprints
