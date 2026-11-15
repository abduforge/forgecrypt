# ForgeCrypt / ForgeVPN roadmap

## ForgeCrypt 1.2.0 — current scope

- Local authenticated encryption for small config files and secrets.
- Argon2id v1.3 + XChaCha20-Poly1305.
- Fresh OS-random salt and nonce per encryption.
- Compatible, versioned envelope format v1.
- Hidden terminal passphrase input, no-clobber output, Unix mode `0600`, 16 MiB input cap.
- `verify` authenticates an envelope without writing plaintext to disk.
- `rekey` creates a new encrypted copy under a new passphrase without altering the original.
- Rust library APIs for encryption, decryption, verification, and re-encryption.

## Next development steps

1. Build on the target MX Linux device and run formatting, tests, and Clippy.
2. Add stable format test vectors and fuzz the envelope parser.
3. Produce and review a Cargo lockfile from a verified build.
4. Obtain independent code and cryptographic review before treating it as security-critical.
5. Keep WireGuard as ForgeVPN's network tunnel and peer session protocol initially.
6. Design device identity, enrollment, revocation, key rotation, peer coordination, and NAT traversal separately.
7. Do not design a custom authenticated network handshake until a written threat model, formal protocol analysis, test vectors, and independent review exist.

## Non-goals for 1.2.0

- VPN tunnel creation or routing.
- Peer discovery or NAT traversal.
- Password storage service or general-purpose password manager.
- Large-file or streaming encryption.
- Custom cryptographic primitives or a custom network protocol.
