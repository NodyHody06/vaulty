use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::models::EncryptedVault;

#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

pub fn derive_key_with_params(
    master_password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<[u8; 32]> {
    let params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| anyhow!("Invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {e}"))?;
    Ok(key)
}

fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    derive_key_with_params(master_password, salt, KdfParams::default())
}

pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedVault> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    Ok(EncryptedVault {
        salt: base64::engine::general_purpose::STANDARD.encode([]), // unused placeholder for legacy compatibility
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        data: base64::engine::general_purpose::STANDARD.encode(ciphertext),
    })
}

pub fn decrypt_with_key(key: &[u8; 32], enc: &EncryptedVault) -> Result<Vec<u8>> {
    let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(&enc.nonce)?;
    let ciphertext = base64::engine::general_purpose::STANDARD.decode(&enc.data)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed. Wrong password?"))
}

// Legacy password-based encryption (kept for migration)
pub fn encrypt_with_password(master_password: &str, plaintext: &[u8]) -> Result<EncryptedVault> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(master_password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    Ok(EncryptedVault {
        salt: base64::engine::general_purpose::STANDARD.encode(salt),
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        data: base64::engine::general_purpose::STANDARD.encode(ciphertext),
    })
}

pub fn decrypt_with_password(master_password: &str, enc: &EncryptedVault) -> Result<Vec<u8>> {
    let salt = base64::engine::general_purpose::STANDARD.decode(&enc.salt)?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(&enc.nonce)?;
    let ciphertext = base64::engine::general_purpose::STANDARD.decode(&enc.data)?;

    let key = derive_key(master_password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed. Wrong password?"))
}
