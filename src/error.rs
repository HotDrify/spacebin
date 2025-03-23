use thiserror::Error;
use hex::FromHexError;
use std::array::TryFromSliceError;

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Invalid key length")]
    InvalidKey,
    #[error("Hex conversion error: {0}")]
    HexError(#[from] FromHexError),
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("Invalid ciphertext format: {0}")]
    InvalidFormat(String),
    #[error("Decryption integrity check failed")]
    IntegrityError,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Slice conversion error: {0}")]
    SliceError(#[from] TryFromSliceError),
    #[error("File is empty")]
    EmptyFile,
    #[error("Invalid characters in ciphertext: {0}")]
    InvalidCharacters(String),
}
