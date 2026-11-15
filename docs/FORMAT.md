# ForgeCrypt Container Formats

## Format v2 (streaming)

All integers are unsigned, big-endian. The file is a header followed by data records and exactly one authenticated final record. No bytes may follow the final record.

### Header (43 bytes)

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 8 | Magic | `FGCRYP2\0` |
| 8 | 1 | Format version | `2` |
| 9 | 1 | KDF identifier | `1` = Argon2id v1.3 |
| 10 | 1 | Cipher identifier | `1` = XChaCha20-Poly1305 |
| 11 | 4 | Argon2 memory | `65536` KiB |
| 15 | 4 | Argon2 iterations | `3` |
| 19 | 4 | Argon2 parallelism | `1` |
| 23 | 4 | Chunk size | `1048576` bytes |
| 27 | 16 | Salt | fresh OS-generated random bytes |

The parser rejects unknown algorithms and any KDF or chunk parameters other than the fixed values above before deriving a key. The header is authenticated as associated data on every record.

### Record header (37 bytes)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Record type: `0` data, `1` final |
| 1 | 8 | Zero-based record sequence |
| 9 | 4 | Plaintext length |
| 13 | 24 | Fresh OS-generated XChaCha20 nonce |

A data record has a plaintext length from 1 through 1 MiB and is followed by `length + 16` bytes of ciphertext and Poly1305 tag. All data records except the last must be exactly 1 MiB. The sequence starts at zero and increases by one.

The AEAD associated data for a data record is the exact 43-byte file header concatenated with the exact 37-byte record header.

The final record has type `1`, the next expected sequence number, and a plaintext length of zero. It is followed by a 16-byte authentication tag for an empty plaintext. Its associated data is the file header, final record header, and the total plaintext length encoded as an unsigned 64-bit big-endian integer. The reader requires EOF immediately after this tag. This record detects truncation, record omission, reordering, and trailing data.

### Key derivation and encryption

Argon2id v1.3 derives a 32-byte key from the passphrase and the header salt using the fixed parameters above. Each record uses a distinct 24-byte nonce obtained from the operating-system CSPRNG. XChaCha20-Poly1305 authenticates both ciphertext and associated data.

The application version (for example, 2.0.0) is independent from the on-disk format version (2).

## Format v1 (legacy)

ForgeCrypt 0.1.x and 1.2.x use the `FGCRYPT\0` byte envelope described in the original v1 specification. ForgeCrypt 2.0 retains v1 decryption, verification, inspection, and re-key support. The v1 implementation buffers complete inputs and is limited to 16 MiB. New encryptions use v2.

## Important implementation note

The generic Rust `decrypt_reader` API may write authenticated chunks to its provided writer before the final record is checked. Callers that need all-or-nothing output must stage data in a private temporary file and publish only after success. The CLI does this. The format and implementation have not yet received an independent audit.
