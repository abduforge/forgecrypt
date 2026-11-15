# ForgeCrypt 2.0 GLOBAL

**Strong file encryption. Simple commands. Linux first.**

ForgeCrypt 2.0 is a major update focused on large-file support, streaming operation, clearer workflows, and safer output handling.

## Highlights

- **Large files:** new format v2 encrypts and decrypts in 1 MiB chunks instead of buffering an entire file in memory.
- **Authenticated records:** every chunk is authenticated and bound to its sequence number and metadata.
- **Truncation detection:** an authenticated final record protects the final chunk count and total plaintext length.
- **Verify without output:** verify a complete encrypted file without creating a plaintext file.
- **Streaming re-key:** change a passphrase using a bounded in-memory pipe, without a plaintext temporary file.
- **Safer output:** private staging files and no-overwrite publishing; failed operations do not publish the requested output.
- **Legacy support:** existing format-v1 files from 0.1.x and 1.2.x remain readable, verifiable, inspectable, and re-keyable (legacy limit: 16 MiB). Re-keying a v1 file upgrades the output to v2.
- **Friendlier CLI:** clear commands, hidden passphrase prompts, `doctor`, and updated help.
- **Documentation:** short quick-start at the top, detailed guide below, plus Russian documentation.

## Cryptography

- Argon2id v1.3 for passphrase-based key derivation.
- XChaCha20-Poly1305 for authenticated encryption.
- Fresh salt and per-record nonce from the operating-system cryptographic random generator.
- `zeroize` for sensitive buffer cleanup.

ForgeCrypt uses established cryptographic library implementations. It does not introduce a custom cipher or custom cryptographic protocol.

## Install

Download the Linux archive attached to this release, extract it, and run:

```bash
./install.sh
```

## Important

ForgeCrypt protects local files at rest. It is not a VPN or network protocol. The project has not yet received an independent security audit; treat this release as experimental and keep secure backups.
