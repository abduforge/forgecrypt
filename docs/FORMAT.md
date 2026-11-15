# ForgeCrypt envelope format v1

ForgeCrypt software release 1.2.0 continues to use envelope format v1 for compatibility with files created by release 0.1.0. These are separate version numbers.

All integer fields are unsigned big-endian. Byte offsets are zero-based.

| Offset | Length | Field | Format-v1 value |
|---:|---:|---|---|
| 0 | 8 | Magic | `FGCRYPT\\0` |
| 8 | 1 | Format version | `1` |
| 9 | 1 | KDF ID | `1` = Argon2id |
| 10 | 1 | Cipher ID | `1` = XChaCha20-Poly1305 |
| 11 | 4 | Argon2 memory cost | `65536` KiB |
| 15 | 4 | Argon2 iterations | `3` |
| 19 | 4 | Argon2 parallelism | `1` |
| 23 | 16 | Salt | random from OS CSPRNG |
| 39 | 24 | XChaCha nonce | random from OS CSPRNG |
| 63 | variable | Ciphertext | plaintext plus 16-byte Poly1305 tag |

The fixed header is 63 bytes. The header bytes from offsets 0 through 62 are used as AEAD associated data. The minimum valid serialized envelope is 79 bytes (header plus authentication tag). Plaintext is limited to 16 MiB.

A parser must reject unknown versions, suite identifiers, and KDF parameters before key derivation. It must also reject files shorter than the header plus tag and files larger than the format limit. Header inspection alone does not authenticate the ciphertext; the `verify` command performs AEAD authentication.

Any incompatible change to the field layout, KDF parameters, or cipher suite requires a new format version and a migration strategy. Never reinterpret a format-v1 identifier.
