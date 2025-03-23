use rand::Rng;
use hex;
use crate::error::CipherError;
use crate::debug;

const SALT_LENGTH: usize = 8;

pub fn encrypt(text: &str, key: &[u8], salt: Option<Vec<u8>>, debug: bool) -> Result<String, CipherError> {
    if key.is_empty() {
        return Err(CipherError::InvalidKey);
    }

    let salt = salt.unwrap_or_else(|| (0..SALT_LENGTH).map(|_| rand::thread_rng().gen()).collect());
    
    debug::dprint(debug, "Salt", &salt);

    let mut data = text.as_bytes().to_vec();
    data.extend_from_slice(&salt);
    
    debug::dprint(debug, "Data with salt", &data);

    let extended_key = extend_key(key, data.len());
    debug::dprint(debug, "Extended key", &extended_key);

    let encrypted_data: Vec<u8> = data.iter().zip(extended_key.iter()).map(|(d, k)| d ^ k).collect();
    debug::dprint(debug, "Encrypted data", &encrypted_data);

    let checksum = crc32fast::hash(&encrypted_data);
    debug::dprint(debug, "Checksum", &checksum);

    let mut final_data = encrypted_data.clone();
    final_data.extend_from_slice(&checksum.to_be_bytes());
    final_data.extend_from_slice(&salt);
    
    debug::dprint(debug, "Final data", &final_data);

    let hex_str = hex::encode(final_data);
    debug::dprint(debug, "Hex string", &hex_str);

    let mut space_str = String::new();
    for c in hex_str.chars() {
        let val = c.to_digit(16).unwrap() as u8;
        for i in 0..4 {
            let bit = (val >> (3 - i)) & 1;
            space_str.push(if bit == 0 { ' ' } else { '\t' });
        }
    }
    
    debug::dprint(debug, "Space string", &space_str);

    Ok(space_str)
}

fn extend_key(key: &[u8], length: usize) -> Vec<u8> {
    let mut extended = Vec::with_capacity(length);
    for i in 0..length {
        extended.push(key[i % key.len()]);
    }
    extended
}
