# ForgeCrypt 0.1.0

**ForgeCrypt** is a Linux-first Rust CLI and library for encrypting small local configuration files and secrets used by the ForgeVPN project.

> **Status: experimental.** This version has not received an independent security audit. Do not treat it as production-grade or as the only protection for high-value secrets.

ForgeCrypt is not a VPN, peer-discovery system, key-exchange protocol, or network handshake. ForgeVPN should use the established WireGuard implementation for its first network transport. ForgeCrypt currently protects local files **at rest**.

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

The binary envelope contains:

1. Eight-byte magic value `FGCRYPT\0`.
2. Format version and algorithm identifiers.
3. Fixed Argon2id parameters (64 MiB memory, 3 iterations, 1 lane).
4. A fresh 16-byte salt.
5. A fresh 24-byte XChaCha20 nonce.
6. Authenticated ciphertext and a 16-byte Poly1305 tag.

The complete header is authenticated as AEAD associated data. A change to the salt, nonce, parameters, or other header bytes therefore causes decryption/authentication to fail. Parameters are checked against the exact supported values before Argon2 runs, preventing a hostile file from requesting arbitrary KDF memory or iteration counts.

The format is versioned. Do not change its layout or KDF parameters without introducing a compatible migration plan and format-version review.

## Requirements

- Linux (first supported target)
- Rust 1.85 or newer; current stable is recommended
- Cargo and a C build toolchain may be needed by transitive dependencies on some platforms

The current Rust stable release can be installed or updated with the official rustup toolchain manager. On MX Linux, after Rust is installed, verify:

```bash
rustc --version
cargo --version
```

## Build and test

```bash
cargo fmt --check
cargo test
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

Create an encrypted copy. ForgeCrypt asks for a new passphrase twice and does not echo it:

```bash
forgecrypt encrypt ./peer.conf ./peer.conf.fgc
```

Display public envelope metadata (this does not authenticate the payload):

```bash
forgecrypt inspect ./peer.conf.fgc
```

Decrypt to a new file:

```bash
forgecrypt decrypt ./peer.conf.fgc ./peer-restored.conf
```

Help and version:

```bash
forgecrypt --help
forgecrypt --version
```

### Safety properties in this version

- Passphrases are entered interactively, not passed through process arguments.
- New passphrases must be at least 14 characters and no more than 1024 UTF-8 bytes.
- Existing output files are never overwritten (`create_new`).
- Output files are created with mode `0600` on Unix.
- Plaintext input is capped at 16 MiB; this version buffers data in memory.
- No plaintext is returned from decryption unless the AEAD authentication succeeds.
- KDF settings in an input envelope are strictly validated before derivation.

## Rust library example

```rust
use forgecrypt::{decrypt_bytes, encrypt_bytes};
use zeroize::Zeroizing;

let passphrase = b"a long unique passphrase with several words";
let plaintext = Zeroizing::new(b"private configuration".to_vec());
let encrypted = encrypt_bytes(&plaintext, passphrase)?;
let opened = Zeroizing::new(decrypt_bytes(&encrypted, passphrase)?);
assert_eq!(&opened[..], b"private configuration");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Callers should keep plaintext buffers in `zeroize::Zeroizing` where practical. Memory erasure cannot undo copies made elsewhere by the application, operating system, swap, crash dumps, or debugging tools.

## Limitations

- No independent security audit has been performed.
- A weak or reused passphrase can be guessed offline. Use a long, unique passphrase.
- Losing the passphrase means the encrypted file cannot be recovered. Keep a separate secure backup of the original configuration.
- File sizes and filesystem metadata (such as timestamps and filenames) are not hidden.
- It does not protect a compromised, unlocked device, malware, keyloggers, or secrets while in active use.
- It is not streaming encryption, disk encryption, a VPN tunnel, or a peer authentication protocol.

See [SECURITY.md](SECURITY.md), [PROJECT_PLAN.md](PROJECT_PLAN.md), and [docs/FORMAT.md](docs/FORMAT.md).
