use clap::{Parser, ValueHint};
use std::fs;
use std::path::PathBuf;

mod encrypt;
mod decrypt;
mod error;
mod debug;

use error::CipherError;

const DEFAULT_OUTPUT: &str = "console";

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[arg(long)]
    text: Option<String>,
    #[arg(long)]
    key: String,
    #[arg(long, value_hint = ValueHint::FilePath)]
    decode: Option<PathBuf>,
    #[arg(long, value_hint = ValueHint::FilePath, default_value = DEFAULT_OUTPUT)]
    output: PathBuf,
    #[arg(long)]
    salt: Option<String>,
    #[arg(long)]
    debug: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), CipherError> {
    let cli = Cli::parse();

    if cli.debug {
        debug::dprint(cli.debug, "CLI arguments", &cli);
    }

    if let Some(file_path) = cli.decode {
        if cli.debug {
            debug::dprint(cli.debug, "Decoding file", &file_path);
        }

        let ciphertext = fs::read_to_string(&file_path).map_err(|_| CipherError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File '{}' not found", file_path.display()),
        )))?;

        if cli.debug {
            debug::dprint(cli.debug, "Ciphertext read from file", &ciphertext);
        }

        if ciphertext.is_empty() {
            if cli.debug {
                debug::dprint(cli.debug, "Ciphertext is empty", "");
            }
            return Err(CipherError::EmptyFile);
        }

        let decrypted = decrypt::decrypt(&ciphertext, cli.key.as_bytes(), cli.debug)?;

        if cli.debug {
            debug::dprint(cli.debug, "Decrypted text", &decrypted);
        }

        if cli.output == PathBuf::from(DEFAULT_OUTPUT) {
            println!("{}", decrypted);
        } else {
            if cli.debug {
                debug::dprint(cli.debug, "Writing decrypted text to file", &cli.output);
            }
            fs::write(cli.output, &decrypted)?;
        }
    } else {
        let text = cli.text.ok_or(CipherError::InvalidFormat("Text is required for encryption".to_string()))?;
        let salt_bytes = cli.salt.map(|s| s.into_bytes());

        if cli.debug {
            debug::dprint(cli.debug, "Text to encrypt", &text);
            if let Some(salt) = &salt_bytes {
                debug::dprint(cli.debug, "Salt", &salt);
            } else {
                debug::dprint(cli.debug, "No salt provided, generating random salt", "");
            }
        }

        let encrypted = encrypt::encrypt(&text, cli.key.as_bytes(), salt_bytes, cli.debug)?;

        if cli.debug {
            debug::dprint(cli.debug, "Encrypted text", &encrypted);
        }

        if cli.output == PathBuf::from(DEFAULT_OUTPUT) {
            println!("{}", encrypted);
        } else {
            if cli.debug {
                debug::dprint(cli.debug, "Writing encrypted text to file", &cli.output);
            }
            fs::write(cli.output, &encrypted)?;
        }
    }

    Ok(())
}
