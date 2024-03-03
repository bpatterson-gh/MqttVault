//  MQTT Vault :: MQTT Client :: JSON Helper :: File Encryption - Utilities for encrypting text

use chacha20poly1305::aead::generic_array::typenum::U32;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sha3::{Digest, Keccak256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// Creates a GenericArray with the specified size and value
// Values less than $size bytes will be padded with their SHA-3 hash
// Values larger than $size bytes will be truncated
macro_rules! bytearray {
    ($val:tt, $size:literal) => {{
        let mut new_val: [u8; $size] = [0; $size];
        if $val.len() < $size {
            let offset = $val.len();
            for i in 0..offset {
                new_val[i] = $val[i];
            }
            let mut hasher = Keccak256::new();
            hasher.update(&new_val);
            let hash = hasher.finalize();
            for i in offset..$size {
                new_val[i] = hash[i]; // Don't bother starting at hash[0]
            }
        } else {
            for i in 0..$size {
                new_val[i] = $val[i];
            }
        }
        GenericArray::clone_from_slice(&new_val)
    }};
}

pub struct Crypter {
    aead: XChaCha20Poly1305,
}

impl Crypter {
    // Construct a Crypter
    pub fn new(encryption_key: &str) -> Crypter {
        let encryption_key = encryption_key.as_bytes();
        let key_bytes: GenericArray<u8, U32> = bytearray!(encryption_key, 32);
        Crypter {
            aead: XChaCha20Poly1305::new(&Key::from(key_bytes)),
        }
    }

    // Create a new Nonce for encrypting
    // Nonce is a combination of the current time and path hash
    fn new_nonce(&self, path: &PathBuf) -> Result<XNonce, String> {
        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(ts) => ts,
            Err(e) => e.duration(),
        }
        .as_nanos()
        .to_le_bytes();
        let mut hasher = Keccak256::new();
        match path.to_str() {
            Some(p) => {
                hasher.update(p.as_bytes());
                let nonce_bytes = [&timestamp, hasher.finalize().as_slice()].concat();
                Ok(bytearray!(nonce_bytes, 24))
            }
            None => Err(format!("The path {} is not valid UTF-8", &path.display())),
        }
    }

    // Encrypt some text
    // Nonce is placed at the front of the encrypted data
    pub fn encrypt(&self, path: &PathBuf, text: &str) -> Result<Vec<u8>, String> {
        let nonce = self.new_nonce(path)?;
        let encrypted = self.aead.encrypt(&nonce, text.as_bytes());
        match encrypted {
            Ok(enc) => Ok(Vec::from([&nonce, enc.as_slice()].concat())),
            Err(_) => Err(String::new()),
        }
    }

    // Decrypt some bytes
    // Expects the Nonce to be at the front
    pub fn decrypt(&self, bytes: &[u8]) -> Result<String, String> {
        let mut nonce: [u8; 24] = [0; 24];
        let mut text_vec: Vec<u8> = Vec::new();
        if bytes.len() < 25 {
            return Err(String::from("The file is too small. Nothing to decrypt."));
        }
        for i in 0..24 {
            nonce[i] = bytes[i];
        }
        for i in 24..bytes.len() {
            text_vec.push(bytes[i]);
        }
        let text_bytes = self
            .aead
            .decrypt(&GenericArray::from_slice(&nonce), text_vec.as_ref());
        match text_bytes {
            Ok(tb) => match std::str::from_utf8(&tb) {
                Ok(decrypted) => Ok(String::from(decrypted)),
                Err(e) => Err(format!("Failed to convert decrypted data to UTF-8: {}", e)),
            },
            Err(_) => Err(String::from("Is the encryption key correct?")),
        }
    }
}

//  Copyright ©️ Bruce Patterson 2022-2024

//  This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.
