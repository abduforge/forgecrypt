//! ForgeCrypt: streaming authenticated file encryption for Linux.
//!
//! This crate uses established implementations of Argon2id and XChaCha20-Poly1305.
//! New file operations use the chunked stream format in [`stream`]. The older v1
//! byte-envelope API remains available for backward compatibility.
//! This crate does not implement a cipher, random generator, hash function, key
//! exchange, peer-authentication protocol, or VPN transport.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use std::fmt;
use zeroize::Zeroizing;

pub mod stream;

const MAGIC: &[u8; 8] = b"FGCRYPT\0";
const FORMAT_VERSION: u8 = 1;
const KDF_ID_ARGON2ID: u8 = 1;
const CIPHER_ID_XCHACHA20_POLY1305: u8 = 1;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const PASSPHRASE_MAX_BYTES: usize = 1024;

// These format-v1 parameters are deliberately fixed and authenticated.
// The limits prevent a hostile envelope from requesting arbitrary KDF resources.
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;

const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = MAGIC_OFFSET + MAGIC.len();
const KDF_ID_OFFSET: usize = VERSION_OFFSET + 1;
const CIPHER_ID_OFFSET: usize = KDF_ID_OFFSET + 1;
const MEMORY_OFFSET: usize = CIPHER_ID_OFFSET + 1;
const ITERATIONS_OFFSET: usize = MEMORY_OFFSET + 4;
const PARALLELISM_OFFSET: usize = ITERATIONS_OFFSET + 4;
const SALT_OFFSET: usize = PARALLELISM_OFFSET + 4;
const NONCE_OFFSET: usize = SALT_OFFSET + SALT_LEN;
const HEADER_LEN: usize = NONCE_OFFSET + NONCE_LEN;

/// Maximum plaintext supported by the legacy byte-envelope format v1 (16 MiB).
/// Format v2 in [`stream`] supports large files using bounded-memory chunks.
pub const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum serialized legacy v1 envelope size, including header and authentication tag.
pub const MAX_ENVELOPE_BYTES: usize = HEADER_LEN + MAX_PLAINTEXT_BYTES + TAG_LEN;

/// Errors returned by ForgeCrypt operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForgeCryptError {
    /// Input exceeded the configured size limit.
    InputTooLarge,
    /// A passphrase was empty or exceeded the supported byte length.
    InvalidPassphrase,
    /// Envelope was malformed or truncated.
    InvalidEnvelope,
    /// Envelope format version is not supported.
    UnsupportedVersion(u8),
    /// Envelope uses an unsupported KDF or cipher identifier.
    UnsupportedSuite,
    /// Envelope contains unsupported KDF settings.
    UnsupportedParameters,
    /// Key derivation failed.
    KeyDerivationFailed,
    /// Operating-system random number generation failed.
    RandomGenerationFailed,
    /// Authentication failed: wrong passphrase or modified envelope.
    AuthenticationFailed,
    /// An I/O operation failed.
    Io(String),
    /// A stream record is malformed, reordered, or violates format rules.
    InvalidStreamRecord,
    /// The authenticated final record is missing or the stream is truncated.
    TruncatedStream,
    /// Unexpected bytes follow the authenticated final record.
    TrailingData,
    /// The stream length or sequence number overflowed.
    LengthOverflow,
    /// A background worker failed during streaming re-key.
    WorkerFailed,
}

impl fmt::Display for ForgeCryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => write!(f, "input exceeds the 16 MiB legacy format limit"),
            Self::InvalidPassphrase => write!(f, "passphrase must be 1–1024 bytes"),
            Self::InvalidEnvelope => write!(f, "invalid or truncated ForgeCrypt envelope"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported ForgeCrypt format version: {v}"),
            Self::UnsupportedSuite => write!(f, "unsupported cryptographic suite"),
            Self::UnsupportedParameters => write!(f, "unsupported ForgeCrypt KDF parameters"),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
            Self::RandomGenerationFailed => write!(f, "secure random generation failed"),
            Self::AuthenticationFailed => {
                write!(
                    f,
                    "authentication failed (wrong passphrase or modified file)"
                )
            }
            Self::Io(message) => write!(f, "I/O error: {message}"),
            Self::InvalidStreamRecord => {
                write!(f, "invalid or out-of-order encrypted stream record")
            }
            Self::TruncatedStream => write!(
                f,
                "encrypted stream is truncated or missing its final record"
            ),
            Self::TrailingData => {
                write!(f, "unexpected data follows the authenticated final record")
            }
            Self::LengthOverflow => write!(f, "encrypted stream exceeds supported length"),
            Self::WorkerFailed => write!(f, "streaming re-key worker failed"),
        }
    }
}

impl std::error::Error for ForgeCryptError {}

/// Public, non-secret metadata parsed from an envelope header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeInfo {
    /// Envelope format version.
    pub version: u8,
    /// Argon2id memory cost in KiB.
    pub kdf_memory_kib: u32,
    /// Argon2id iteration count.
    pub kdf_iterations: u32,
    /// Argon2id parallelism.
    pub kdf_parallelism: u32,
    /// Salt length in bytes.
    pub salt_bytes: usize,
    /// XChaCha20 nonce length in bytes.
    pub nonce_bytes: usize,
    /// Ciphertext length, including the AEAD tag.
    pub ciphertext_bytes: usize,
}

/// Encrypts a byte slice using a passphrase and the format-v1 cryptographic suite.
///
/// Fresh salt and nonce values are read from the operating system CSPRNG for each
/// operation. The complete header is authenticated as AEAD associated data.
/// Callers handling sensitive plaintext should keep their input in a zeroizing
/// buffer where practical; Rust cannot erase copies made by other code.
pub fn encrypt_bytes(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, ForgeCryptError> {
    validate_lengths(plaintext.len(), passphrase)?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| ForgeCryptError::RandomGenerationFailed)?;
    getrandom::fill(&mut nonce).map_err(|_| ForgeCryptError::RandomGenerationFailed)?;

    let header = make_header(&salt, &nonce);
    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| ForgeCryptError::KeyDerivationFailed)?;

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| ForgeCryptError::AuthenticationFailed)?;

    let mut envelope = Vec::with_capacity(header.len() + ciphertext.len());
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Decrypts an envelope and returns plaintext only after AEAD authentication succeeds.
///
/// The returned `Vec<u8>` contains plaintext. Callers should wrap it in
/// `zeroize::Zeroizing` or otherwise erase it when it is no longer needed.
pub fn decrypt_bytes(envelope: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, ForgeCryptError> {
    inspect_envelope(envelope)?;
    if passphrase.is_empty() || passphrase.len() > PASSPHRASE_MAX_BYTES {
        return Err(ForgeCryptError::InvalidPassphrase);
    }

    let header = &envelope[..HEADER_LEN];
    let salt = &header[SALT_OFFSET..NONCE_OFFSET];
    let nonce = &header[NONCE_OFFSET..HEADER_LEN];
    let key = derive_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| ForgeCryptError::KeyDerivationFailed)?;

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &envelope[HEADER_LEN..],
                aad: header,
            },
        )
        .map_err(|_| ForgeCryptError::AuthenticationFailed)?;

    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(ForgeCryptError::InputTooLarge);
    }
    Ok(plaintext)
}

/// Authenticates an encrypted envelope without returning its plaintext.
///
/// The plaintext is held in a zeroizing buffer and discarded before this function
/// returns. The returned metadata is public and does not contain secret material.
pub fn verify_bytes(envelope: &[u8], passphrase: &[u8]) -> Result<EnvelopeInfo, ForgeCryptError> {
    let info = inspect_envelope(envelope)?;
    let plaintext = Zeroizing::new(decrypt_bytes(envelope, passphrase)?);
    drop(plaintext);
    Ok(info)
}

/// Re-encrypts an envelope under a new passphrase.
///
/// The old envelope is authenticated before any new ciphertext is produced. A fresh
/// random salt and nonce are generated by [`encrypt_bytes`]. The plaintext is held in
/// a zeroizing buffer and is never written to a temporary file.
pub fn reencrypt_bytes(
    envelope: &[u8],
    old_passphrase: &[u8],
    new_passphrase: &[u8],
) -> Result<Vec<u8>, ForgeCryptError> {
    let plaintext = Zeroizing::new(decrypt_bytes(envelope, old_passphrase)?);
    encrypt_bytes(&plaintext, new_passphrase)
}

/// Parses and validates the public envelope header without authenticating its payload.
///
/// This function is suitable only for display/diagnostics. It does not prove that the
/// payload is genuine; use [`decrypt_bytes`] to authenticate it.
pub fn inspect_envelope(envelope: &[u8]) -> Result<EnvelopeInfo, ForgeCryptError> {
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err(ForgeCryptError::InvalidEnvelope);
    }
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(ForgeCryptError::InputTooLarge);
    }
    if &envelope[MAGIC_OFFSET..VERSION_OFFSET] != MAGIC {
        return Err(ForgeCryptError::InvalidEnvelope);
    }

    let version = envelope[VERSION_OFFSET];
    if version != FORMAT_VERSION {
        return Err(ForgeCryptError::UnsupportedVersion(version));
    }
    if envelope[KDF_ID_OFFSET] != KDF_ID_ARGON2ID
        || envelope[CIPHER_ID_OFFSET] != CIPHER_ID_XCHACHA20_POLY1305
    {
        return Err(ForgeCryptError::UnsupportedSuite);
    }

    let memory = read_u32(envelope, MEMORY_OFFSET)?;
    let iterations = read_u32(envelope, ITERATIONS_OFFSET)?;
    let parallelism = read_u32(envelope, PARALLELISM_OFFSET)?;
    if memory != KDF_MEMORY_KIB || iterations != KDF_ITERATIONS || parallelism != KDF_PARALLELISM {
        return Err(ForgeCryptError::UnsupportedParameters);
    }

    Ok(EnvelopeInfo {
        version,
        kdf_memory_kib: memory,
        kdf_iterations: iterations,
        kdf_parallelism: parallelism,
        salt_bytes: SALT_LEN,
        nonce_bytes: NONCE_LEN,
        ciphertext_bytes: envelope.len() - HEADER_LEN,
    })
}

fn validate_lengths(plaintext_len: usize, passphrase: &[u8]) -> Result<(), ForgeCryptError> {
    if plaintext_len > MAX_PLAINTEXT_BYTES {
        return Err(ForgeCryptError::InputTooLarge);
    }
    if passphrase.is_empty() || passphrase.len() > PASSPHRASE_MAX_BYTES {
        return Err(ForgeCryptError::InvalidPassphrase);
    }
    Ok(())
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, ForgeCryptError> {
    let bytes: [u8; 4] = input
        .get(offset..offset + 4)
        .ok_or(ForgeCryptError::InvalidEnvelope)?
        .try_into()
        .map_err(|_| ForgeCryptError::InvalidEnvelope)?;
    Ok(u32::from_be_bytes(bytes))
}

fn make_header(salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.push(KDF_ID_ARGON2ID);
    header.push(CIPHER_ID_XCHACHA20_POLY1305);
    header.extend_from_slice(&KDF_MEMORY_KIB.to_be_bytes());
    header.extend_from_slice(&KDF_ITERATIONS.to_be_bytes());
    header.extend_from_slice(&KDF_PARALLELISM.to_be_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);
    debug_assert_eq!(header.len(), HEADER_LEN);
    header
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, ForgeCryptError> {
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|_| ForgeCryptError::KeyDerivationFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, &mut key[..])
        .map_err(|_| ForgeCryptError::KeyDerivationFailed)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSWORD: &[u8] = b"correct horse battery staple - ForgeCrypt unit test";

    #[test]
    fn encrypt_decrypt_round_trip_binary_payload() {
        let message = b"[Interface]\nPrivateKey = example-secret\n\0\xff";
        let envelope = encrypt_bytes(message, TEST_PASSWORD).expect("encryption should work");
        let opened = decrypt_bytes(&envelope, TEST_PASSWORD).expect("decryption should work");
        assert_eq!(opened, message);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let envelope = encrypt_bytes(b"", TEST_PASSWORD).expect("empty data can be encrypted");
        let opened = decrypt_bytes(&envelope, TEST_PASSWORD).expect("decryption should work");
        assert!(opened.is_empty());
    }

    #[test]
    fn wrong_passphrase_fails_authentication() {
        let envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        assert_eq!(
            decrypt_bytes(&envelope, b"a different passphrase"),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn modified_ciphertext_fails_authentication() {
        let mut envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        let last = envelope.len() - 1;
        envelope[last] ^= 0x40;
        assert_eq!(
            decrypt_bytes(&envelope, TEST_PASSWORD),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn modified_salt_fails_authentication() {
        let mut envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        envelope[SALT_OFFSET] ^= 0x01;
        assert_eq!(
            decrypt_bytes(&envelope, TEST_PASSWORD),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn modified_nonce_fails_authentication() {
        let mut envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        envelope[NONCE_OFFSET] ^= 0x01;
        assert_eq!(
            decrypt_bytes(&envelope, TEST_PASSWORD),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn appended_bytes_fail_authentication() {
        let mut envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        envelope.push(0);
        assert_eq!(
            decrypt_bytes(&envelope, TEST_PASSWORD),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn unsupported_kdf_parameters_are_rejected_before_derivation() {
        let mut envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        envelope[MEMORY_OFFSET] ^= 0x01;
        assert_eq!(
            inspect_envelope(&envelope),
            Err(ForgeCryptError::UnsupportedParameters)
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        envelope[VERSION_OFFSET] = FORMAT_VERSION + 1;
        assert_eq!(
            inspect_envelope(&envelope),
            Err(ForgeCryptError::UnsupportedVersion(FORMAT_VERSION + 1))
        );
    }

    #[test]
    fn unsupported_suite_is_rejected() {
        let mut envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        envelope[CIPHER_ID_OFFSET] = 99;
        assert_eq!(
            inspect_envelope(&envelope),
            Err(ForgeCryptError::UnsupportedSuite)
        );
    }

    #[test]
    fn truncated_envelope_is_rejected() {
        assert_eq!(
            decrypt_bytes(b"FGCRYPT", TEST_PASSWORD),
            Err(ForgeCryptError::InvalidEnvelope)
        );
    }

    #[test]
    fn empty_and_oversized_passphrases_are_rejected() {
        assert_eq!(
            encrypt_bytes(b"secret", b""),
            Err(ForgeCryptError::InvalidPassphrase)
        );
        assert_eq!(
            encrypt_bytes(b"secret", &[b'x'; PASSPHRASE_MAX_BYTES + 1]),
            Err(ForgeCryptError::InvalidPassphrase)
        );
    }

    #[test]
    fn oversized_plaintext_is_rejected_before_kdf() {
        let oversized = vec![0u8; MAX_PLAINTEXT_BYTES + 1];
        assert_eq!(
            encrypt_bytes(&oversized, TEST_PASSWORD),
            Err(ForgeCryptError::InputTooLarge)
        );
    }

    #[test]
    fn independent_encryptions_use_fresh_header_randomness() {
        let first = encrypt_bytes(b"same input", TEST_PASSWORD).expect("encryption should work");
        let second = encrypt_bytes(b"same input", TEST_PASSWORD).expect("encryption should work");
        assert_ne!(&first[..HEADER_LEN], &second[..HEADER_LEN]);
        assert_ne!(first, second);
    }

    #[test]
    fn inspection_reports_public_format_parameters() {
        let envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        let info = inspect_envelope(&envelope).expect("header should be valid");
        assert_eq!(info.version, 1);
        assert_eq!(info.kdf_memory_kib, 65_536);
        assert_eq!(info.kdf_iterations, 3);
        assert_eq!(info.kdf_parallelism, 1);
        assert_eq!(info.salt_bytes, 16);
        assert_eq!(info.nonce_bytes, 24);
        assert_eq!(info.ciphertext_bytes, b"secret".len() + TAG_LEN);
    }

    #[test]
    fn verify_authenticates_without_changing_envelope() {
        let envelope =
            encrypt_bytes(b"verified secret", TEST_PASSWORD).expect("encryption should work");
        let info = verify_bytes(&envelope, TEST_PASSWORD).expect("verification should succeed");
        assert_eq!(info.version, FORMAT_VERSION);
        assert_eq!(info.ciphertext_bytes, b"verified secret".len() + TAG_LEN);
    }

    #[test]
    fn verify_rejects_wrong_passphrase() {
        let envelope =
            encrypt_bytes(b"verified secret", TEST_PASSWORD).expect("encryption should work");
        assert_eq!(
            verify_bytes(&envelope, b"incorrect passphrase"),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn reencrypt_changes_key_and_preserves_plaintext() {
        let old_password = TEST_PASSWORD;
        let new_password = b"a new and different passphrase for ForgeCrypt";
        let envelope =
            encrypt_bytes(b"secret configuration", old_password).expect("encryption should work");
        let reencrypted = reencrypt_bytes(&envelope, old_password, new_password)
            .expect("re-encryption should work");

        assert_eq!(
            decrypt_bytes(&reencrypted, new_password).expect("new password should work"),
            b"secret configuration"
        );
        assert_eq!(
            decrypt_bytes(&reencrypted, old_password),
            Err(ForgeCryptError::AuthenticationFailed)
        );
        assert_ne!(&envelope[..HEADER_LEN], &reencrypted[..HEADER_LEN]);
    }

    #[test]
    fn reencrypt_rejects_wrong_old_passphrase() {
        let envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        assert_eq!(
            reencrypt_bytes(
                &envelope,
                b"wrong old passphrase",
                b"a sufficiently long new passphrase"
            ),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn reencrypt_rejects_invalid_new_passphrase() {
        let envelope = encrypt_bytes(b"secret", TEST_PASSWORD).expect("encryption should work");
        assert_eq!(
            reencrypt_bytes(&envelope, TEST_PASSWORD, b""),
            Err(ForgeCryptError::InvalidPassphrase)
        );
    }

    #[test]
    fn parser_rejects_short_inputs_without_panicking() {
        for length in 0..(HEADER_LEN + TAG_LEN) {
            let sample = vec![0xA5; length];
            assert!(inspect_envelope(&sample).is_err());
        }
    }
}
