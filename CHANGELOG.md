# Changelog

All notable changes to ForgeCrypt are documented here.

## [1.2.0] - 2026-11-15

### Added
- `verify <file>` authenticates an envelope without writing plaintext to disk.
- `rekey <input> <output>` changes the passphrase by creating a new envelope with fresh salt and nonce; the original remains untouched.
- Public library APIs `verify_bytes` and `reencrypt_bytes`.
- Tests for verification, incorrect credentials, re-keying, and key rotation behavior.

### Improved
- Documentation distinguishes software release 1.2.0 from compatible envelope format v1.
- CI treats Clippy warnings as errors.
- CLI help explains verification and re-key semantics.

### Compatibility
- Reads and writes the same envelope format v1 as ForgeCrypt 0.1.0. No migration is required for existing encrypted files.

## [0.1.0] - 2026-11-15

### Added
- Rust library and Linux-first CLI for local file encryption/decryption.
- Argon2id v1.3 key derivation and XChaCha20-Poly1305 authenticated encryption.
- Versioned binary envelope with authenticated header and strict KDF-parameter validation.
- OS CSPRNG salt/nonce generation and zeroizing key/passphrase buffers.
- Interactive passphrase prompts, bounded file input, no-overwrite output, and Unix `0600` permissions.
- Unit tests for round trips, wrong passphrases, tampering, truncation, malformed headers, and size limits.
- Linux installation script and GitHub Actions CI workflow.
