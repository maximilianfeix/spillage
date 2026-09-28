# Security

spillage reads files that are full of secrets, so it is built to be boring:

- no dependencies, no network access, no telemetry
- secrets are never printed, logged or written to a report in full, only as a short masked prefix and a fingerprint (the first 12 hex characters of their SHA-256)
- it only writes to disk when you tell it to (`scrub`, `ignore`, `guard`)

If you find a way to make it leak what it's supposed to protect, please report it privately through [GitHub security advisories](https://github.com/maximilianfeix/spillage/security/advisories/new) instead of an issue.
