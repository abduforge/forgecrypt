# Changelog

All notable changes to ForgeCrypt are documented here.

## [0.1.0] - 2026-11-15

### Added
- Rust library and Linux-first CLI for local file encryption/decryption.
- Argon2id v1.3 key derivation and XChaCha20-Poly1305 authenticated encryption.
- Versioned binary envelope with authenticated header and strict KDF-parameter validation.
- OS CSPRNG salt/nonce generation and zeroizing key/passphrase buffers.
- Interactive passphrase prompts, bounded file input, no-overwrite output, and Unix `0600` permissions.
- Unit tests for round trips, wrong passphrases, tampering, truncation, malformed headers, and size limits.
- Linux installation script and GitHub Actions CI workflow.
