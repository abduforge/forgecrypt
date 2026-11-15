# ForgeCrypt 1.2.0

**ForgeCrypt** is a Linux-first Rust CLI and library for authenticated encryption of small local configuration files and secrets used by the AbduForge / ForgeVPN ecosystem.

> **Status: experimental.** This project has not received an independent security audit. Do not treat it as production-grade or as the only protection for high-value secrets.

ForgeCrypt protects local files **at rest**. It is not a VPN, peer-discovery system, key-exchange protocol, or network handshake. ForgeVPN should use the established WireGuard implementation for its first network transport.

## What's new in 1.2.0

- `verify`: authenticate an encrypted file without writing plaintext to disk.
- `rekey`: change the passphrase by creating a newly encrypted output file; the source is never modified.
- Library APIs `verify_bytes` and `reencrypt_bytes`.
- Additional tests for verification, wrong passwords, re-keying, and fresh envelope randomness.
- Clearer command documentation and stricter CI linting.
- Backward compatibility with the 0.1.0 envelope format.

## Cryptographic design

| Purpose | Primitive / implementation |
|---|---|
| Password-based key derivation | Argon2id, version 1.3 |
| Authenticated encryption | XChaCha20-Poly1305 |
| Salt and nonce generation | Operating-system CSPRNG through `getrandom` |
| Key and passphrase cleanup | `zeroize` |
| Hidden interactive passphrase input | `rpassword` |

The algorithms are provided by established libraries. ForgeCrypt does not implement its own cipher, hash function, KDF, random generator, or AEAD construction.

### Envelope format v1

ForgeCrypt 1.2.0 intentionally continues to write and read the same **envelope format v1** introduced in 0.1.0. The software release number (1.2.0) is separate from the on-disk format version (1). Existing 0.1.0 encrypted files remain readable.

The binary envelope contains:

1. Eight-byte magic value `FGCRYPT\0`.
2. Format version and algorithm identifiers.
3. Fixed Argon2id parameters (64 MiB memory, 3 iterations, 1 lane).
4. A fresh 16-byte salt.
5. A fresh 24-byte XChaCha20 nonce.
6. Authenticated ciphertext and a 16-byte Poly1305 tag.

The complete header is authenticated as AEAD associated data. KDF parameters are validated against the supported values before Argon2 runs, preventing hostile files from requesting arbitrary KDF resources.

The format is intentionally fixed for compatibility. Any future incompatible format change requires a new format version and a documented migration plan.

## Requirements

- Linux (first supported target)
- Rust 1.85 or newer; current stable is recommended
- Cargo

## Build, test, and lint

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release
./target/release/forgecrypt --version
```

For a local install to `~/.local/bin`:

```bash
./install.sh
```

No root privileges are required. Ensure `~/.local/bin` is in your `PATH`.

## CLI

### Encrypt a file

Creates a new encrypted copy. ForgeCrypt asks for a new passphrase twice and does not echo it:

```bash
forgecrypt encrypt ./peer.conf ./peer.conf.fgc
```

### Decrypt a file

The plaintext is written only after authentication succeeds. The output must not already exist:

```bash
forgecrypt decrypt ./peer.conf.fgc ./peer-restored.conf
```

### Verify an encrypted file

Checks the passphrase and AEAD authentication without writing plaintext to disk:

```bash
forgecrypt verify ./peer.conf.fgc
```

This is useful for checking a backup or transfer before relying on it.

### Change the passphrase (re-key)

Authenticates the original file with the current passphrase, then asks for a new passphrase twice. A new encrypted file is created using a fresh salt and nonce. The original is not modified and the output must not already exist:

```bash
forgecrypt rekey ./peer.conf.fgc ./peer-new-key.conf.fgc
```

Keep the new passphrase safe before deleting or archiving the old encrypted file. If the new passphrase is lost, the new file cannot be recovered.

### Inspect public metadata

```bash
forgecrypt inspect ./peer.conf.fgc
```

`inspect` does not authenticate the ciphertext. Use `verify` when you need to check authenticity.

### Help and version

```bash
forgecrypt --help
forgecrypt --version
```

## Safety properties

- Passphrases are entered interactively, not passed through process arguments.
- New passphrases must contain at least 14 characters and no more than 1024 UTF-8 bytes.
- Existing output files are never overwritten (`create_new`).
- Output files are created with mode `0600` on Unix.
- Plaintext input is capped at 16 MiB; this version buffers data in memory.
- Decryption exposes no plaintext until AEAD authentication succeeds.
- `verify` discards authenticated plaintext in a zeroizing buffer and writes no plaintext file.
- `rekey` does not modify or delete the original encrypted input.
- KDF settings in an input envelope are strictly validated before derivation.

## Rust library API

```rust
use forgecrypt::{decrypt_bytes, encrypt_bytes, reencrypt_bytes, verify_bytes};
use zeroize::Zeroizing;

let old_passphrase = b"a long unique old passphrase for ForgeCrypt";
let new_passphrase = b"a different long unique passphrase for ForgeCrypt";
let plaintext = Zeroizing::new(b"private configuration".to_vec());

let encrypted = encrypt_bytes(&plaintext, old_passphrase)?;
verify_bytes(&encrypted, old_passphrase)?;
let rotated = reencrypt_bytes(&encrypted, old_passphrase, new_passphrase)?;
let opened = Zeroizing::new(decrypt_bytes(&rotated, new_passphrase)?);
assert_eq!(&opened[..], b"private configuration");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Callers should keep plaintext buffers in `zeroize::Zeroizing` where practical. Memory erasure cannot undo copies made elsewhere by the application, operating system, swap, crash dumps, or debugging tools.

## Limitations

- No independent security audit has been performed.
- A weak or reused passphrase can be guessed offline. Use a long, unique passphrase.
- Losing the passphrase means the encrypted file cannot be recovered. Keep a separate secure backup.
- `inspect` displays unauthenticated public header metadata; it does not prove payload integrity.
- File sizes and filesystem metadata (such as timestamps and filenames) are not hidden.
- It does not protect a compromised, unlocked device, malware, keyloggers, memory inspection while secrets are in use, or secrets while actively used.
- It is not streaming encryption, disk encryption, a VPN tunnel, or a peer-authentication protocol.

See [SECURITY.md](SECURITY.md), [PROJECT_PLAN.md](PROJECT_PLAN.md), and [docs/FORMAT.md](docs/FORMAT.md).
