use forgecrypt::{
    decrypt_bytes, encrypt_bytes, inspect_envelope, MAX_ENVELOPE_BYTES, MAX_PLAINTEXT_BYTES,
};
use std::{
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    process,
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MIN_PASSPHRASE_CHARS: usize = 14;
const MAX_PASSPHRASE_BYTES: usize = 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("forgecrypt: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, input, output] if command == "encrypt" => encrypt_file(input, output),
        [command, input, output] if command == "decrypt" => decrypt_file(input, output),
        [command, input] if command == "inspect" => inspect_file(input),
        [flag] if flag == "--version" || flag == "version" => {
            println!("ForgeCrypt {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [flag] if flag == "--help" || flag == "help" => {
            print_help();
            Ok(())
        }
        _ => {
            print_help();
            Err("invalid command; use --help".into())
        }
    }
}

fn encrypt_file(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let plaintext = Zeroizing::new(read_bounded(input, MAX_PLAINTEXT_BYTES)?);
    let passphrase = read_new_passphrase()?;
    let envelope = encrypt_bytes(&plaintext, passphrase.as_bytes())?;
    write_new_private_file(output, &envelope)?;
    println!("Encrypted file created: {output}");
    println!("Format: ForgeCrypt v1 · Argon2id · XChaCha20-Poly1305");
    Ok(())
}

fn decrypt_file(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let envelope = read_bounded(input, MAX_ENVELOPE_BYTES)?;
    let passphrase = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
    let plaintext = Zeroizing::new(decrypt_bytes(&envelope, passphrase.as_bytes())?);
    write_new_private_file(output, &plaintext)?;
    println!("Decrypted file created: {output}");
    Ok(())
}

fn inspect_file(input: &str) -> Result<(), Box<dyn Error>> {
    let envelope = read_bounded(input, MAX_ENVELOPE_BYTES)?;
    let info = inspect_envelope(&envelope)?;
    println!("ForgeCrypt envelope (public header only)");
    println!("  Format version : {}", info.version);
    println!("  KDF            : Argon2id v1.3");
    println!("  KDF memory     : {} KiB", info.kdf_memory_kib);
    println!("  KDF iterations : {}", info.kdf_iterations);
    println!("  KDF parallelism: {}", info.kdf_parallelism);
    println!("  Cipher         : XChaCha20-Poly1305");
    println!("  Salt / nonce   : {} / {} bytes", info.salt_bytes, info.nonce_bytes);
    println!("  Ciphertext     : {} bytes", info.ciphertext_bytes);
    println!("Note: this command does not authenticate or decrypt the payload.");
    Ok(())
}

fn read_new_passphrase() -> Result<Zeroizing<String>, Box<dyn Error>> {
    let first = Zeroizing::new(rpassword::prompt_password(
        "New passphrase (14+ characters): ",
    )?);
    if first.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(format!(
            "passphrase must contain at least {MIN_PASSPHRASE_CHARS} characters"
        )
        .into());
    }
    if first.len() > MAX_PASSPHRASE_BYTES {
        return Err(format!("passphrase must not exceed {MAX_PASSPHRASE_BYTES} UTF-8 bytes").into());
    }

    let second = Zeroizing::new(rpassword::prompt_password("Repeat passphrase: ")?);
    if first.as_str() != second.as_str() {
        return Err("passphrases do not match".into());
    }
    Ok(first)
}

fn read_bounded(path: &str, limit: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must be a regular file",
        ));
    }
    let size = file.metadata()?.len();
    if size > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds the {limit} byte limit"),
        ));
    }

    let mut data = Vec::with_capacity(size as usize);
    file.take((limit as u64) + 1).read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds the {limit} byte limit"),
        ));
    }
    Ok(data)
}

fn write_new_private_file(path: &str, data: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(Path::new(path))?;
    let result = file.write_all(data).and_then(|_| file.sync_all());
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn print_help() {
    println!(
        "ForgeCrypt {}\n\nUSAGE:\n  forgecrypt encrypt <input> <output>\n  forgecrypt decrypt <input> <output>\n  forgecrypt inspect <file>\n  forgecrypt --version\n  forgecrypt --help\n\nNOTES:\n  - Passphrases are requested interactively, never as CLI arguments.\n  - Existing output files are never overwritten.\n  - Output files are created with owner-only permissions on Unix.\n  - Maximum plaintext size: 16 MiB.\n  - This protects local files at rest; it is not a VPN tunnel or network handshake.",
        env!("CARGO_PKG_VERSION")
    );
}
