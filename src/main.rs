use forgecrypt::{
    MAX_ENVELOPE_BYTES, decrypt_bytes, inspect_envelope,
    stream::{self, STREAM_MAGIC},
    verify_bytes,
};
use std::{
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MIN_PASSPHRASE_CHARS: usize = 14;
const MAX_PASSPHRASE_BYTES: usize = 1024;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

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
        [command, input] if command == "verify" => verify_file(input),
        [command, input, output] if command == "rekey" => rekey_file(input, output),
        [command, input] if command == "inspect" => inspect_file(input),
        [command] if command == "doctor" => {
            doctor();
            Ok(())
        }
        [flag] if flag == "--version" || flag == "version" => {
            println!("ForgeCrypt {} GLOBAL", env!("CARGO_PKG_VERSION"));
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
    let source = open_regular_file(input)?;
    let passphrase = read_new_passphrase()?;
    let mut destination = TempOutput::new(output)?;
    let bytes = stream::encrypt_reader(source, destination.file_mut(), passphrase.as_bytes())?;
    destination.commit()?;
    println!("Encrypted file created: {output}");
    println!("Format: ForgeCrypt v2 · Argon2id · XChaCha20-Poly1305");
    println!("Processed: {}", format_bytes(bytes));
    Ok(())
}

fn decrypt_file(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let passphrase = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
    let mut destination = TempOutput::new(output)?;
    let bytes = if is_stream_v2(input)? {
        let source = open_regular_file(input)?;
        stream::decrypt_reader(source, destination.file_mut(), passphrase.as_bytes())?
    } else {
        let envelope = read_bounded(input, MAX_ENVELOPE_BYTES)?;
        let plaintext = Zeroizing::new(decrypt_bytes(&envelope, passphrase.as_bytes())?);
        destination.file_mut().write_all(&plaintext)?;
        plaintext.len() as u64
    };
    destination.commit()?;
    println!("Decrypted file created: {output}");
    println!("Authenticated data: {}", format_bytes(bytes));
    Ok(())
}

fn verify_file(input: &str) -> Result<(), Box<dyn Error>> {
    let passphrase = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
    let bytes = if is_stream_v2(input)? {
        stream::verify_reader(open_regular_file(input)?, passphrase.as_bytes())?
    } else {
        let envelope = read_bounded(input, MAX_ENVELOPE_BYTES)?;
        let info = verify_bytes(&envelope, passphrase.as_bytes())?;
        info.ciphertext_bytes.saturating_sub(16) as u64
    };
    println!("Authentication successful: {input}");
    println!("Verified data: {}", format_bytes(bytes));
    println!("No plaintext file was written.");
    Ok(())
}

fn rekey_file(input: &str, output: &str) -> Result<(), Box<dyn Error>> {
    let old_passphrase = Zeroizing::new(rpassword::prompt_password("Current passphrase: ")?);
    let new_passphrase = read_new_passphrase()?;
    let mut destination = TempOutput::new(output)?;
    let bytes = if is_stream_v2(input)? {
        stream::rekey_reader(
            open_regular_file(input)?,
            destination.file_mut(),
            old_passphrase.as_bytes(),
            new_passphrase.as_bytes(),
        )?
    } else {
        let envelope = read_bounded(input, MAX_ENVELOPE_BYTES)?;
        // Legacy v1 files are capped at 16 MiB. Re-keying them writes the
        // current streaming v2 format so the resulting file is ready for large-file tooling.
        let plaintext = Zeroizing::new(decrypt_bytes(&envelope, old_passphrase.as_bytes())?);
        let plain_len = plaintext.len() as u64;
        stream::encrypt_reader(
            io::Cursor::new(&plaintext[..]),
            destination.file_mut(),
            new_passphrase.as_bytes(),
        )?;
        plain_len
    };
    destination.commit()?;
    println!("Re-keyed encrypted file created: {output}");
    println!("Processed: {}", format_bytes(bytes));
    println!("The original file was not modified.");
    Ok(())
}

fn inspect_file(input: &str) -> Result<(), Box<dyn Error>> {
    if is_stream_v2(input)? {
        let mut source = open_regular_file(input)?;
        let info = stream::inspect_stream_header(&mut source)?;
        println!("ForgeCrypt stream envelope (public header only)");
        println!("  Format version : {}", info.version);
        println!("  KDF            : Argon2id v1.3");
        println!("  KDF memory     : {} KiB", info.kdf_memory_kib);
        println!("  KDF iterations : {}", info.kdf_iterations);
        println!("  KDF parallelism: {}", info.kdf_parallelism);
        println!("  Cipher         : XChaCha20-Poly1305");
        println!("  Chunk size     : {} KiB", info.chunk_size / 1024);
        println!("  Salt            : {} bytes", info.salt_bytes);
    } else {
        let envelope = read_bounded(input, MAX_ENVELOPE_BYTES)?;
        let info = inspect_envelope(&envelope)?;
        println!("ForgeCrypt legacy envelope (public header only)");
        println!("  Format version : {}", info.version);
        println!("  KDF            : Argon2id v1.3");
        println!("  KDF memory     : {} KiB", info.kdf_memory_kib);
        println!("  KDF iterations : {}", info.kdf_iterations);
        println!("  Cipher         : XChaCha20-Poly1305");
        println!("  Payload        : {} bytes", info.ciphertext_bytes);
    }
    println!("Note: inspect reads public metadata only; use verify to authenticate the payload.");
    Ok(())
}

fn doctor() {
    println!(
        "ForgeCrypt {} GLOBAL — environment check",
        env!("CARGO_PKG_VERSION")
    );
    println!("  Operating system : {}", env::consts::OS);
    println!("  Architecture     : {}", env::consts::ARCH);
    println!("  Rust package     : compiled successfully");
    println!("  Stream format    : v2 (1 MiB authenticated chunks)");
    println!("  Legacy format    : v1 reader enabled (16 MiB maximum)");
    println!("  Output policy    : never overwrite existing files");
    println!("  Plaintext policy : publish only after full stream authentication");
}

fn read_new_passphrase() -> Result<Zeroizing<String>, Box<dyn Error>> {
    let first = Zeroizing::new(rpassword::prompt_password(
        "New passphrase (14+ characters): ",
    )?);
    if first.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(
            format!("passphrase must contain at least {MIN_PASSPHRASE_CHARS} characters").into(),
        );
    }
    if first.len() > MAX_PASSPHRASE_BYTES {
        return Err(
            format!("passphrase must not exceed {MAX_PASSPHRASE_BYTES} UTF-8 bytes").into(),
        );
    }
    let second = Zeroizing::new(rpassword::prompt_password("Repeat passphrase: ")?);
    if first.as_str() != second.as_str() {
        return Err("passphrases do not match".into());
    }
    Ok(first)
}

fn open_regular_file(path: &str) -> io::Result<File> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must be a regular file",
        ));
    }
    Ok(file)
}

fn is_stream_v2(path: &str) -> io::Result<bool> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 8];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(&magic == STREAM_MAGIC),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

fn read_bounded(path: &str, limit: usize) -> io::Result<Vec<u8>> {
    let file = open_regular_file(path)?;
    let size = file.metadata()?.len();
    if size > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy file exceeds the {limit} byte limit"),
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

/// Stages output in a private file beside the target. A hard link publishes it
/// without replacing an existing target, and only after all processing succeeds.
struct TempOutput {
    temp_path: PathBuf,
    target: PathBuf,
    file: Option<File>,
    committed: bool,
}

impl TempOutput {
    fn new(target: &str) -> io::Result<Self> {
        let target = PathBuf::from(target);
        let parent = target
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !parent.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "output directory does not exist",
            ));
        }
        for _ in 0..16 {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
            let mut suffix = String::with_capacity(32);
            for byte in random {
                suffix.push(HEX_DIGITS[(byte >> 4) as usize] as char);
                suffix.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
            }
            let temp_path = parent.join(format!(".forgecrypt-{suffix}.tmp"));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            match options.open(&temp_path) {
                Ok(file) => {
                    return Ok(Self {
                        temp_path,
                        target,
                        file: Some(file),
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary output file",
        ))
    }

    fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("temporary file is open until commit")
    }

    fn commit(mut self) -> io::Result<()> {
        let file = self
            .file
            .take()
            .expect("temporary file is open until commit");
        file.sync_all()?;
        drop(file);
        // hard_link fails when the target already exists, preventing accidental overwrite.
        fs::hard_link(&self.temp_path, &self.target)?;
        if let Err(error) = fs::remove_file(&self.temp_path) {
            eprintln!("warning: output was published but temporary link cleanup failed: {error}");
        }
        self.committed = true;
        if let Some(parent) = self
            .target
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            if let Ok(directory) = File::open(parent) {
                if let Err(error) = directory.sync_all() {
                    eprintln!("warning: output is published but directory sync failed: {error}");
                }
            }
        }
        Ok(())
    }
}

impl Drop for TempOutput {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.file.take());
            let _cleanup_result = fs::remove_file(&self.temp_path);
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut index = 0;
    while value >= 1024.0 && index < UNITS.len() - 1 {
        value /= 1024.0;
        index += 1;
    }
    format!("{value:.2} {}", UNITS[index])
}

fn print_help() {
    println!(
        "ForgeCrypt {} GLOBAL\n\nA simple, authenticated file-encryption tool for Linux.\n\nUSAGE:\n  forgecrypt encrypt <input> <output>  Encrypt any-size regular file\n  forgecrypt decrypt <input> <output>  Authenticate and decrypt a file\n  forgecrypt verify <file>             Verify without writing plaintext\n  forgecrypt rekey <input> <output>    Change passphrase without disk plaintext\n  forgecrypt inspect <file>            Show public format metadata\n  forgecrypt doctor                    Show build/runtime capabilities\n  forgecrypt --version                 Show version\n  forgecrypt --help                    Show this help\n\nSECURITY:\n  - Passphrases are prompted interactively, never accepted as CLI arguments.\n  - New passphrases must be at least 14 characters.\n  - New outputs are never allowed to overwrite existing files.\n  - Output is staged with owner-only permissions and published after success.\n  - Format v2 uses 1 MiB independently authenticated chunks and a final record.\n  - Format v1 files from ForgeCrypt 0.1/1.2 remain readable (16 MiB limit).\n  - Encryption is local file protection, not a VPN or network handshake.\n\nEXAMPLES:\n  forgecrypt encrypt ./private.conf ./private.conf.fgc\n  forgecrypt verify ./private.conf.fgc\n  forgecrypt decrypt ./private.conf.fgc ./private-restored.conf\n  forgecrypt rekey ./private.conf.fgc ./private-new-key.fgc",
        env!("CARGO_PKG_VERSION")
    );
}
