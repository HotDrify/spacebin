use hex;
use crate::error::CipherError;
use crate::debug;

const SALT_LENGTH: usize = 8;
const CHECKSUM_LENGTH: usize = 4;

pub fn clean_ciphertext(ciphertext: &str) -> String {
    ciphertext
        .chars()
        .filter(|&c| c == ' ' || c == '\t')
        .collect()
}

pub fn decrypt(ciphertext: &str, key: &[u8], debug: bool) -> Result<String, CipherError> {
    if ciphertext.is_empty() {
        return Err(CipherError::EmptyFile);
    }

    let cleaned_ciphertext = clean_ciphertext(ciphertext);
    debug::dprint(debug, "Cleaned ciphertext", &cleaned_ciphertext);

    if cleaned_ciphertext.is_empty() {
        return Err(CipherError::InvalidFormat("Ciphertext contains no valid characters (only spaces and tabs are allowed)".to_string()));
    }

    let mut bits = Vec::new();
    for c in cleaned_ciphertext.chars() {
        let bit = match c {
            ' ' => 0,
            '\t' => 1,
            _ => return Err(CipherError::InvalidCharacters(format!("Invalid character: '{}'", c))),
        };
        bits.push(bit);
    }

    debug::dprint(debug, "Bits", &bits);

    if bits.len() % 4 != 0 {
        return Err(CipherError::InvalidFormat(format!(
            "Number of bits ({}) is not a multiple of 4",
            bits.len()
        )));
    }

    let mut hex_str = String::new();
    for chunk in bits.chunks_exact(4) {
        let val = chunk[0] << 3 | chunk[1] << 2 | chunk[2] << 1 | chunk[3];
        hex_str.push_str(&format!("{:x}", val));
    }

    debug::dprint(debug, "Hex string", &hex_str);

    let bytes = hex::decode(hex_str)?;
    debug::dprint(debug, "Decoded bytes", &bytes);
    
    if bytes.len() <= SALT_LENGTH + CHECKSUM_LENGTH {
        return Err(CipherError::InvalidFormat("Invalid ciphertext length".to_string()));
    }
    
    let salt_pos = bytes.len() - SALT_LENGTH;
    let checksum_pos = salt_pos - CHECKSUM_LENGTH;
    let encrypted_data = &bytes[..checksum_pos];
    let checksum = u32::from_be_bytes(bytes[checksum_pos..salt_pos].try_into()?);
    let _salt = &bytes[salt_pos..];
    
    debug::dprint(debug, "Encrypted data", &encrypted_data);
    debug::dprint(debug, "Checksum", &checksum);
    debug::dprint(debug, "Salt", &_salt);

    if crc32fast::hash(encrypted_data) != checksum {
        return Err(CipherError::IntegrityError);
    }
    
    let extended_key = extend_key(key, encrypted_data.len());
    debug::dprint(debug, "Extended key", &extended_key);

    let decrypted_data: Vec<u8> = encrypted_data.iter().zip(extended_key.iter()).map(|(d, k)| d ^ k).collect();
    debug::dprint(debug, "Decrypted data", &decrypted_data);

    let text_bytes = &decrypted_data[..decrypted_data.len() - SALT_LENGTH];
    
    Ok(String::from_utf8(text_bytes.to_vec())?)
}

fn extend_key(key: &[u8], length: usize) -> Vec<u8> {
    let mut extended = Vec::with_capacity(length);
    for i in 0..length {
        extended.push(key[i % key.len()]);
    }
    extended
}
