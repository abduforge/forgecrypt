# Security Policy

## Scope and status

ForgeCrypt is an experimental local file-encryption project. Version 2.0 introduces a new streaming container format. It has not yet received an independent cryptographic or implementation audit. Do not rely on it as the sole protection for irreplaceable, regulated, or high-value information.

## Reporting a vulnerability

Please do not publish working exploit details in a public issue. Use GitHub's private vulnerability reporting for this repository, if enabled, or contact the maintainer privately through the contact method listed on the GitHub profile. Include the affected version, platform, reproduction conditions, and impact. Do not include real passwords or sensitive files.

## Security design

- Argon2id v1.3 derives a 256-bit key using fixed parameters: 64 MiB memory, 3 iterations, 1 lane.
- XChaCha20-Poly1305 provides authenticated encryption.
- The OS CSPRNG supplies the per-file salt and each 192-bit record nonce.
- Format v2 authenticates the file header and each record's type, sequence, length, and nonce as associated data.
- An authenticated final record binds the terminal sequence and total plaintext length, making truncation detectable.
- The parser accepts only known format identifiers and fixed KDF/chunk parameters before performing Argon2 work.
- The CLI stages output with owner-only permissions and does not publish it until the operation completes successfully.
- `verify` discards plaintext in memory and creates no plaintext file.
- `rekey` uses a bounded in-memory channel for v2 and leaves the original encrypted file unchanged.
- Existing destination paths are never overwritten.

## User responsibilities and limitations

- Use a long, unique passphrase. Weak passwords can be guessed offline.
- Losing the passphrase means the data cannot be recovered.
- Keep an independent backup before deleting any original.
- File names, sizes, and filesystem metadata are not hidden.
- Decrypted data is exposed to the operating system and applications using it.
- `decrypt` stages plaintext in a mode-0600 temporary file in the destination directory. A crash or power loss may leave such a file behind. Check for `.forgecrypt-*.tmp` after interrupted operations.
- Secure deletion cannot be guaranteed on SSDs, copy-on-write filesystems, snapshots, or journaled storage.
- This project is not a VPN, a network tunnel, or a peer key-exchange protocol.

## Cryptographic review

The project uses established cryptographic primitives through established Rust crates. The file format and application integration are project code and still require independent review before any production-security claim can be made.
