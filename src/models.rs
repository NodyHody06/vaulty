use serde::{Deserialize, Serialize};
use rand::RngCore;

pub fn new_uuid() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    // set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let hex: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!(
        "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        hex[0], hex[1], hex[2], hex[3], hex[4], hex[5], hex[6], hex[7], hex[8], hex[9], hex[10],
        hex[11], hex[12], hex[13], hex[14], hex[15]
    )
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    #[serde(default = "new_uuid")]
    pub id: String,
    pub name: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Note {
    #[serde(default = "new_uuid")]
    pub id: String,
    pub title: String,
    pub content: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedVault {
    pub salt: String,
    pub nonce: String,
    pub data: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Vault {
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub notes: Vec<Note>,
}

#[derive(Serialize, Deserialize)]
pub struct Meta {
    pub master_hash: String,
}
