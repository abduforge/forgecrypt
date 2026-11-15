# ForgeCrypt 1.2.0

ForgeCrypt 1.2.0 adds authenticated verification and passphrase re-keying while retaining compatibility with the original envelope format v1 used by 0.1.0.

## Highlights

- `forgecrypt verify <file>` authenticates an encrypted envelope without writing plaintext to disk.
- `forgecrypt rekey <input> <output>` authenticates the original file and writes a new encrypted copy protected by a new passphrase, fresh salt, and fresh nonce.
- Rust library APIs: `verify_bytes` and `reencrypt_bytes`.
- Additional tests for authentication and passphrase rotation.
- Stricter GitHub Actions Clippy checks.

## Compatibility

The on-disk envelope stays at format v1. Files encrypted by ForgeCrypt 0.1.0 are intended to remain readable without migration.

## Security status

This is an experimental release and has not received an independent security audit. Use a long, unique passphrase and keep a separate backup. ForgeCrypt encrypts local files at rest; it is not a VPN tunnel or a custom network protocol.
