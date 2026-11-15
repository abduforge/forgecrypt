//! Chunked authenticated file format v2.
//!
//! The file header and every record header are authenticated as AEAD associated
//! data. Every data record has an independent OS-generated XChaCha20 nonce, and
//! an authenticated terminal record makes truncation detectable.

use crate::ForgeCryptError;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use zeroize::Zeroizing;

pub const STREAM_MAGIC: &[u8; 8] = b"FGCRYP2\0";
pub const STREAM_FORMAT_VERSION: u8 = 2;
pub const STREAM_CHUNK_SIZE: usize = 1024 * 1024;

const KDF_ID_ARGON2ID: u8 = 1;
const CIPHER_ID_XCHACHA20_POLY1305: u8 = 1;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;
const PASSPHRASE_MAX_BYTES: usize = 1024;

const HEADER_LEN: usize = 8 + 1 + 1 + 1 + 4 + 4 + 4 + 4 + SALT_LEN;
const RECORD_HEADER_LEN: usize = 1 + 8 + 4 + NONCE_LEN;
const RECORD_DATA: u8 = 0;
const RECORD_FINAL: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamInfo {
    pub version: u8,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub chunk_size: usize,
    pub salt_bytes: usize,
}

fn io_error(error: io::Error) -> ForgeCryptError {
    ForgeCryptError::Io(error.to_string())
}

fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), ForgeCryptError> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            ForgeCryptError::TruncatedStream
        } else {
            io_error(error)
        }
    })
}

fn read_header<R: Read>(reader: &mut R) -> Result<([u8; HEADER_LEN], StreamInfo), ForgeCryptError> {
    let mut header = [0u8; HEADER_LEN];
    read_exact(reader, &mut header)?;

    if &header[..8] != STREAM_MAGIC {
        return Err(ForgeCryptError::InvalidEnvelope);
    }
    if header[8] != STREAM_FORMAT_VERSION {
        return Err(ForgeCryptError::UnsupportedVersion(header[8]));
    }
    if header[9] != KDF_ID_ARGON2ID || header[10] != CIPHER_ID_XCHACHA20_POLY1305 {
        return Err(ForgeCryptError::UnsupportedSuite);
    }

    let memory = u32::from_be_bytes(
        header[11..15]
            .try_into()
            .map_err(|_| ForgeCryptError::InvalidEnvelope)?,
    );
    let iterations = u32::from_be_bytes(
        header[15..19]
            .try_into()
            .map_err(|_| ForgeCryptError::InvalidEnvelope)?,
    );
    let parallelism = u32::from_be_bytes(
        header[19..23]
            .try_into()
            .map_err(|_| ForgeCryptError::InvalidEnvelope)?,
    );
    let chunk_size = u32::from_be_bytes(
        header[23..27]
            .try_into()
            .map_err(|_| ForgeCryptError::InvalidEnvelope)?,
    ) as usize;

    // Never let an input file choose arbitrary Argon2 resource requirements.
    if memory != KDF_MEMORY_KIB || iterations != KDF_ITERATIONS || parallelism != KDF_PARALLELISM {
        return Err(ForgeCryptError::UnsupportedParameters);
    }
    if chunk_size != STREAM_CHUNK_SIZE {
        return Err(ForgeCryptError::UnsupportedParameters);
    }

    Ok((
        header,
        StreamInfo {
            version: STREAM_FORMAT_VERSION,
            kdf_memory_kib: memory,
            kdf_iterations: iterations,
            kdf_parallelism: parallelism,
            chunk_size,
            salt_bytes: SALT_LEN,
        },
    ))
}

pub fn inspect_stream_header<R: Read>(reader: &mut R) -> Result<StreamInfo, ForgeCryptError> {
    read_header(reader).map(|(_, info)| info)
}

fn make_header(salt: &[u8; SALT_LEN]) -> [u8; HEADER_LEN] {
    let mut header = [0u8; HEADER_LEN];
    let mut cursor = 0;
    header[cursor..cursor + 8].copy_from_slice(STREAM_MAGIC);
    cursor += 8;
    header[cursor] = STREAM_FORMAT_VERSION;
    cursor += 1;
    header[cursor] = KDF_ID_ARGON2ID;
    cursor += 1;
    header[cursor] = CIPHER_ID_XCHACHA20_POLY1305;
    cursor += 1;
    for value in [
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        STREAM_CHUNK_SIZE as u32,
    ] {
        header[cursor..cursor + 4].copy_from_slice(&value.to_be_bytes());
        cursor += 4;
    }
    header[cursor..cursor + SALT_LEN].copy_from_slice(salt);
    header
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, ForgeCryptError> {
    if passphrase.is_empty() || passphrase.len() > PASSPHRASE_MAX_BYTES {
        return Err(ForgeCryptError::InvalidPassphrase);
    }
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

fn record_header(
    kind: u8,
    sequence: u64,
    plaintext_len: u32,
    nonce: &[u8; NONCE_LEN],
) -> [u8; RECORD_HEADER_LEN] {
    let mut header = [0u8; RECORD_HEADER_LEN];
    header[0] = kind;
    header[1..9].copy_from_slice(&sequence.to_be_bytes());
    header[9..13].copy_from_slice(&plaintext_len.to_be_bytes());
    header[13..].copy_from_slice(nonce);
    header
}

fn associated_data(
    header: &[u8; HEADER_LEN],
    record: &[u8; RECORD_HEADER_LEN],
    total: Option<u64>,
) -> Vec<u8> {
    let extra_len = if total.is_some() { 8 } else { 0 };
    let mut aad = Vec::with_capacity(HEADER_LEN + RECORD_HEADER_LEN + extra_len);
    aad.extend_from_slice(header);
    aad.extend_from_slice(record);
    if let Some(total) = total {
        aad.extend_from_slice(&total.to_be_bytes());
    }
    aad
}

fn new_nonce() -> Result<[u8; NONCE_LEN], ForgeCryptError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| ForgeCryptError::RandomGenerationFailed)?;
    Ok(nonce)
}

fn make_cipher(key: &[u8; KEY_LEN]) -> Result<XChaCha20Poly1305, ForgeCryptError> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| ForgeCryptError::KeyDerivationFailed)
}

/// Encrypts an arbitrary-length reader into chunked format v2.
///
/// Each 1 MiB data chunk is independently authenticated. A final authenticated
/// record protects the stream length and detects truncation. The caller must ensure
/// that a partially written destination is not published if this function fails.
pub fn encrypt_reader<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    passphrase: &[u8],
) -> Result<u64, ForgeCryptError> {
    if passphrase.is_empty() || passphrase.len() > PASSPHRASE_MAX_BYTES {
        return Err(ForgeCryptError::InvalidPassphrase);
    }
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| ForgeCryptError::RandomGenerationFailed)?;
    let header = make_header(&salt);
    let key = derive_key(passphrase, &salt)?;
    let cipher = make_cipher(&key)?;
    writer.write_all(&header).map_err(io_error)?;

    let mut chunk = Zeroizing::new(vec![0u8; STREAM_CHUNK_SIZE]);
    let mut sequence = 0u64;
    let mut total = 0u64;

    loop {
        let mut filled = 0usize;
        while filled < chunk.len() {
            let count = reader.read(&mut chunk[filled..]).map_err(io_error)?;
            if count == 0 {
                break;
            }
            filled += count;
        }
        if filled == 0 {
            break;
        }

        let next_total = total
            .checked_add(filled as u64)
            .ok_or(ForgeCryptError::LengthOverflow)?;
        let nonce = new_nonce()?;
        let record = record_header(RECORD_DATA, sequence, filled as u32, &nonce);
        let aad = associated_data(&header, &record, None);
        let encrypted = cipher
            .encrypt(
                &XNonce::try_from(&nonce[..]).map_err(|_| ForgeCryptError::InvalidStreamRecord)?,
                Payload {
                    msg: &chunk[..filled],
                    aad: &aad,
                },
            )
            .map_err(|_| ForgeCryptError::AuthenticationFailed)?;
        writer.write_all(&record).map_err(io_error)?;
        writer.write_all(&encrypted).map_err(io_error)?;
        total = next_total;
        sequence = sequence
            .checked_add(1)
            .ok_or(ForgeCryptError::LengthOverflow)?;
    }

    // The authenticated terminal record makes missing/truncated endings detectable.
    let nonce = new_nonce()?;
    let record = record_header(RECORD_FINAL, sequence, 0, &nonce);
    let aad = associated_data(&header, &record, Some(total));
    let final_tag = cipher
        .encrypt(
            &XNonce::try_from(&nonce[..]).map_err(|_| ForgeCryptError::InvalidStreamRecord)?,
            Payload {
                msg: &[],
                aad: &aad,
            },
        )
        .map_err(|_| ForgeCryptError::AuthenticationFailed)?;
    writer.write_all(&record).map_err(io_error)?;
    writer.write_all(&final_tag).map_err(io_error)?;
    writer.flush().map_err(io_error)?;
    Ok(total)
}

/// Decrypts stream format v2. The destination may receive authenticated chunks
/// before the terminal record is checked; use a private temporary file and publish
/// it only after success (the CLI does this).
pub fn decrypt_reader<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    passphrase: &[u8],
) -> Result<u64, ForgeCryptError> {
    let (header, _) = read_header(&mut reader)?;
    let salt = &header[27..27 + SALT_LEN];
    let key = derive_key(passphrase, salt)?;
    let cipher = make_cipher(&key)?;
    let mut expected_sequence = 0u64;
    let mut total = 0u64;
    let mut saw_short_chunk = false;

    loop {
        let mut record = [0u8; RECORD_HEADER_LEN];
        let mut first = [0u8; 1];
        let count = reader.read(&mut first).map_err(io_error)?;
        if count == 0 {
            return Err(ForgeCryptError::TruncatedStream);
        }
        record[0] = first[0];
        read_exact(&mut reader, &mut record[1..])?;

        let kind = record[0];
        let sequence = u64::from_be_bytes(
            record[1..9]
                .try_into()
                .map_err(|_| ForgeCryptError::InvalidStreamRecord)?,
        );
        let length = u32::from_be_bytes(
            record[9..13]
                .try_into()
                .map_err(|_| ForgeCryptError::InvalidStreamRecord)?,
        ) as usize;
        let nonce: [u8; NONCE_LEN] = record[13..]
            .try_into()
            .map_err(|_| ForgeCryptError::InvalidStreamRecord)?;
        if sequence != expected_sequence {
            return Err(ForgeCryptError::InvalidStreamRecord);
        }

        match kind {
            RECORD_DATA => {
                if !(1..=STREAM_CHUNK_SIZE).contains(&length) || saw_short_chunk {
                    return Err(ForgeCryptError::InvalidStreamRecord);
                }
                let mut ciphertext = vec![0u8; length + TAG_LEN];
                read_exact(&mut reader, &mut ciphertext)?;
                let aad = associated_data(&header, &record, None);
                let plaintext = Zeroizing::new(
                    cipher
                        .decrypt(
                            &XNonce::try_from(&nonce[..])
                                .map_err(|_| ForgeCryptError::InvalidStreamRecord)?,
                            Payload {
                                msg: &ciphertext,
                                aad: &aad,
                            },
                        )
                        .map_err(|_| ForgeCryptError::AuthenticationFailed)?,
                );
                if plaintext.len() != length {
                    return Err(ForgeCryptError::InvalidStreamRecord);
                }
                writer.write_all(&plaintext).map_err(io_error)?;
                total = total
                    .checked_add(length as u64)
                    .ok_or(ForgeCryptError::LengthOverflow)?;
                saw_short_chunk = length < STREAM_CHUNK_SIZE;
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .ok_or(ForgeCryptError::LengthOverflow)?;
            }
            RECORD_FINAL => {
                if length != 0 {
                    return Err(ForgeCryptError::InvalidStreamRecord);
                }
                let mut final_tag = [0u8; TAG_LEN];
                read_exact(&mut reader, &mut final_tag)?;
                let aad = associated_data(&header, &record, Some(total));
                let final_plaintext = cipher
                    .decrypt(
                        &XNonce::try_from(&nonce[..])
                            .map_err(|_| ForgeCryptError::InvalidStreamRecord)?,
                        Payload {
                            msg: &final_tag,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| ForgeCryptError::AuthenticationFailed)?;
                if !final_plaintext.is_empty() {
                    return Err(ForgeCryptError::InvalidStreamRecord);
                }
                let mut trailing = [0u8; 1];
                if reader.read(&mut trailing).map_err(io_error)? != 0 {
                    return Err(ForgeCryptError::TrailingData);
                }
                writer.flush().map_err(io_error)?;
                return Ok(total);
            }
            _ => return Err(ForgeCryptError::InvalidStreamRecord),
        }
    }
}

/// Authenticates a complete stream without retaining plaintext or writing it anywhere.
pub fn verify_reader<R: Read>(reader: R, passphrase: &[u8]) -> Result<u64, ForgeCryptError> {
    decrypt_reader(reader, io::sink(), passphrase)
}

struct PipeWriter {
    sender: SyncSender<Zeroizing<Vec<u8>>>,
}
impl Write for PipeWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.sender
            .send(Zeroizing::new(buffer.to_vec()))
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "re-encryption worker stopped")
            })?;
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PipeReader {
    receiver: Receiver<Zeroizing<Vec<u8>>>,
    current: Zeroizing<Vec<u8>>,
    position: usize,
}
impl Read for PipeReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if self.position < self.current.len() {
                let count = buffer.len().min(self.current.len() - self.position);
                buffer[..count]
                    .copy_from_slice(&self.current[self.position..self.position + count]);
                self.position += count;
                return Ok(count);
            }
            match self.receiver.recv() {
                Ok(next) => {
                    self.current = next;
                    self.position = 0;
                }
                Err(_) => return Ok(0),
            }
        }
    }
}

/// Re-encrypts a v2 stream without writing plaintext to disk. A bounded in-memory
/// pipe keeps memory use small; the destination must still be staged by the caller.
pub fn rekey_reader<R: Read, W: Write + Send>(
    reader: R,
    writer: W,
    old_passphrase: &[u8],
    new_passphrase: &[u8],
) -> Result<u64, ForgeCryptError> {
    if new_passphrase.is_empty() || new_passphrase.len() > PASSPHRASE_MAX_BYTES {
        return Err(ForgeCryptError::InvalidPassphrase);
    }
    let old = Zeroizing::new(old_passphrase.to_vec());
    let new = Zeroizing::new(new_passphrase.to_vec());
    let (sender, receiver) = mpsc::sync_channel::<Zeroizing<Vec<u8>>>(2);
    thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let pipe = PipeReader {
                receiver,
                current: Zeroizing::new(Vec::new()),
                position: 0,
            };
            encrypt_reader(pipe, writer, &new)
        });

        let decrypt_result = decrypt_reader(reader, PipeWriter { sender }, &old);
        let encrypt_result = worker.join().map_err(|_| ForgeCryptError::WorkerFailed)?;
        match decrypt_result {
            Err(error) => Err(error),
            Ok(_) => encrypt_result,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const PASSWORD: &[u8] = b"a long unique passphrase used only in ForgeCrypt tests";

    fn round_trip(data: &[u8]) {
        let mut encrypted = Vec::new();
        let written = encrypt_reader(Cursor::new(data), &mut encrypted, PASSWORD).unwrap();
        assert_eq!(written, data.len() as u64);
        let mut decrypted = Vec::new();
        let read = decrypt_reader(Cursor::new(&encrypted), &mut decrypted, PASSWORD).unwrap();
        assert_eq!(read, data.len() as u64);
        assert_eq!(decrypted, data);
        assert_eq!(
            verify_reader(Cursor::new(&encrypted), PASSWORD).unwrap(),
            data.len() as u64
        );
    }

    #[test]
    fn empty_stream_round_trip() {
        round_trip(b"");
    }

    #[test]
    fn small_stream_round_trip() {
        round_trip(b"ForgeCrypt GLOBAL stream test");
    }

    #[test]
    fn multi_chunk_stream_round_trip() {
        let data: Vec<u8> = (0..(STREAM_CHUNK_SIZE * 2 + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        round_trip(&data);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let mut encrypted = Vec::new();
        encrypt_reader(Cursor::new(b"secret"), &mut encrypted, PASSWORD).unwrap();
        assert_eq!(
            verify_reader(Cursor::new(encrypted), b"not the password"),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn missing_final_record_is_detected() {
        let mut encrypted = Vec::new();
        encrypt_reader(Cursor::new(b"secret"), &mut encrypted, PASSWORD).unwrap();
        encrypted.truncate(encrypted.len() - (RECORD_HEADER_LEN + TAG_LEN));
        assert_eq!(
            verify_reader(Cursor::new(encrypted), PASSWORD),
            Err(ForgeCryptError::TruncatedStream)
        );
    }

    #[test]
    fn appended_data_is_rejected() {
        let mut encrypted = Vec::new();
        encrypt_reader(Cursor::new(b"secret"), &mut encrypted, PASSWORD).unwrap();
        encrypted.push(0);
        assert_eq!(
            verify_reader(Cursor::new(encrypted), PASSWORD),
            Err(ForgeCryptError::TrailingData)
        );
    }

    #[test]
    fn reordered_record_sequence_is_rejected() {
        let data = vec![0x31u8; STREAM_CHUNK_SIZE + 5];
        let mut encrypted = Vec::new();
        encrypt_reader(Cursor::new(&data), &mut encrypted, PASSWORD).unwrap();
        // The first record begins immediately after the fixed file header.
        encrypted[HEADER_LEN + 1] = 0;
        encrypted[HEADER_LEN + 8] = 1;
        assert_eq!(
            verify_reader(Cursor::new(encrypted), PASSWORD),
            Err(ForgeCryptError::InvalidStreamRecord)
        );
    }

    #[test]
    fn modified_ciphertext_is_rejected() {
        let mut encrypted = Vec::new();
        encrypt_reader(Cursor::new(b"secret"), &mut encrypted, PASSWORD).unwrap();
        encrypted[HEADER_LEN + RECORD_HEADER_LEN] ^= 0x80;
        assert_eq!(
            verify_reader(Cursor::new(encrypted), PASSWORD),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn modified_header_is_rejected() {
        let mut encrypted = Vec::new();
        encrypt_reader(Cursor::new(b"secret"), &mut encrypted, PASSWORD).unwrap();
        encrypted[27] ^= 0x01;
        assert_eq!(
            verify_reader(Cursor::new(encrypted), PASSWORD),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn rekey_stream_preserves_data_and_changes_password() {
        let data = vec![0x5Au8; STREAM_CHUNK_SIZE + 17];
        let mut encrypted = Vec::new();
        encrypt_reader(Cursor::new(&data), &mut encrypted, PASSWORD).unwrap();
        let new_password = b"a completely different long passphrase for testing";
        let mut rotated = Vec::new();
        rekey_reader(Cursor::new(encrypted), &mut rotated, PASSWORD, new_password).unwrap();
        assert_eq!(
            verify_reader(Cursor::new(&rotated), new_password).unwrap(),
            data.len() as u64
        );
        assert_eq!(
            verify_reader(Cursor::new(&rotated), PASSWORD),
            Err(ForgeCryptError::AuthenticationFailed)
        );
    }
}
