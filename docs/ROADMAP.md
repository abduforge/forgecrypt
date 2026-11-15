# ForgeCrypt Roadmap

## 2.0 GLOBAL (current)

- Streaming authenticated file format v2.
- 1 MiB chunks with per-record authentication and sequence binding.
- Authenticated final record for truncation detection.
- Streaming encrypt, decrypt, verify, and re-key.
- Bounded in-memory re-key pipeline.
- Private staged outputs with no-overwrite publishing.
- Backward support for format v1.
- English and Russian quick-start documentation.
- Linux x86_64 release automation.

## 2.1 — usability and resilience

- Progress output that never leaks passphrases or plaintext.
- Optional machine-readable operation summaries.
- Recovery-oriented diagnostics for incomplete output files.
- More fuzzing and property-based tests for parsers and record boundaries.

## 2.2 — review and portability

- Independent review of the v2 format and implementation.
- Linux ARM64 CI and release artifacts.
- Reproducible-build improvements and dependency review.

## 3.0 — only after review

- Consider additional workflows only after format v2 has received independent review.
- Any new cryptographic format requires a documented version, test vectors, and migration plan.

ForgeCrypt is a local file-encryption tool. VPN transport and peer-to-peer networking belong to ForgeVPN and must use established protocols such as WireGuard.
