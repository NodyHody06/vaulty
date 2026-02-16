use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use base64::Engine;
use dirs;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    decrypt_with_key, decrypt_with_password, derive_key_with_params, encrypt_with_key, KdfParams,
};
use crate::models::{EncryptedVault, Meta, Vault};

pub const VAULT_DIR: &str = ".terminal-vault";
pub const VAULT_FILE: &str = "vault.json";
pub const LOCK_FILE: &str = "lock.json";
pub const META_FILE: &str = "meta.json";
pub const CONFIG_FILE: &str = "config.json";
const KEYRING_SERVICE: &str = "terminal-vault";
const KEYRING_USER: &str = "vault-key";
const KEYRING_REV_USER: &str = "vault-revision";
const VAULT_FORMAT_VERSION: u8 = 2;
const KDF_SALT_LEN: usize = 16;

#[derive(Serialize, Deserialize)]
struct LockState {
    unlock_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub vault_dir: String,
}

#[derive(Serialize, Deserialize)]
struct KdfSpec {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Serialize, Deserialize)]
struct WrappedVaultFile {
    version: u8,
    kdf: KdfSpec,
    kdf_salt: String,
    wrapped_key: EncryptedVault,
    vault: EncryptedVault,
}

pub fn default_base_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(VAULT_DIR))
}

pub fn config_path() -> Result<PathBuf> {
    Ok(default_base_dir()?.join(CONFIG_FILE))
}

pub fn load_config() -> Result<Option<Config>> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)?;
    let cfg: Config = serde_json::from_str(&raw)?;
    Ok(Some(cfg))
}

pub fn save_config(base_dir: &Path) -> Result<()> {
    let cfg = Config {
        vault_dir: base_dir
            .to_str()
            .ok_or_else(|| anyhow!("Invalid base dir path"))?
            .to_string(),
    };
    if let Some(parent) = config_path()?.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            restrict_dir(parent)?;
        }
    }
    let data = serde_json::to_string_pretty(&cfg)?;
    let path = config_path()?;
    atomic_write(path.as_path(), data.as_bytes())?;
    restrict_file(path.as_path())?;
    Ok(())
}

fn configured_base_dir() -> Result<PathBuf> {
    if let Some(cfg) = load_config()? {
        return validate_configured_vault_dir(Path::new(&cfg.vault_dir));
    }
    default_base_dir()
}

pub fn vault_path() -> Result<PathBuf> {
    Ok(configured_base_dir()?.join(VAULT_FILE))
}

pub fn lock_path() -> Result<PathBuf> {
    Ok(configured_base_dir()?.join(LOCK_FILE))
}

pub fn meta_path() -> Result<PathBuf> {
    Ok(configured_base_dir()?.join(META_FILE))
}

pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            restrict_dir(parent)?;
        } else {
            restrict_dir(parent)?; // tighten if already there
        }
        Ok(())
    } else {
        Err(anyhow!("Invalid vault path"))
    }
}

pub fn is_wrapped_vault_file(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&raw)?;
    Ok(
        value.get("version").is_some()
            && value.get("kdf").is_some()
            && value.get("kdf_salt").is_some()
            && value.get("wrapped_key").is_some()
            && value.get("vault").is_some(),
    )
}

pub fn load_vault(path: &Path, master_password: &str) -> Result<Vault> {
    let raw = fs::read_to_string(path)?;
    let wrapped: WrappedVaultFile = serde_json::from_str(&raw)?;
    if wrapped.version != VAULT_FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported vault format version: {}",
            wrapped.version
        ));
    }
    let salt = base64::engine::general_purpose::STANDARD
        .decode(wrapped.kdf_salt)
        .map_err(|e| anyhow!("Invalid vault salt encoding: {e}"))?;
    let params = KdfParams {
        m_cost: wrapped.kdf.m_cost,
        t_cost: wrapped.kdf.t_cost,
        p_cost: wrapped.kdf.p_cost,
    };
    let kek = derive_key_with_params(master_password, &salt, params)?;
    let dek = decrypt_with_key(&kek, &wrapped.wrapped_key)?;
    let dek: [u8; 32] = dek
        .try_into()
        .map_err(|_| anyhow!("Invalid wrapped key length in vault"))?;
    let decrypted = decrypt_with_key(&dek, &wrapped.vault)?;
    let vault: Vault = serde_json::from_slice(&decrypted)?;
    Ok(vault)
}

pub fn load_vault_with_key(path: &Path, key: &[u8; 32]) -> Result<Vault> {
    let raw = fs::read_to_string(path)?;
    let enc: EncryptedVault = serde_json::from_str(&raw)?;
    let decrypted = decrypt_with_key(key, &enc)?;
    let vault: Vault = serde_json::from_slice(&decrypted)?;
    Ok(vault)
}

pub fn save_vault(path: &Path, vault: &Vault, master_password: &str) -> Result<()> {
    let mut salt = [0u8; KDF_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let params = KdfParams::default();
    let kek = derive_key_with_params(master_password, &salt, params)?;

    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);

    let wrapped_key = encrypt_with_key(&kek, &dek)?;
    let plaintext = serde_json::to_vec(vault)?;
    let enc_vault = encrypt_with_key(&dek, &plaintext)?;
    let wrapped = WrappedVaultFile {
        version: VAULT_FORMAT_VERSION,
        kdf: KdfSpec {
            m_cost: params.m_cost,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
        },
        kdf_salt: base64::engine::general_purpose::STANDARD.encode(salt),
        wrapped_key,
        vault: enc_vault,
    };
    let serialized = serde_json::to_string_pretty(&wrapped)?;
    atomic_write(path, serialized.as_bytes())?;
    restrict_file(path)?;
    Ok(())
}

pub fn load_vault_legacy(path: &Path, master_password: &str) -> Result<Vault> {
    let raw = fs::read_to_string(path)?;
    let enc: EncryptedVault = serde_json::from_str(&raw)?;
    let decrypted = decrypt_with_password(master_password, &enc)?;
    let vault: Vault = serde_json::from_slice(&decrypted)?;
    Ok(vault)
}

fn unix_now() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("Clock error: {e}"))?;
    Ok(now.as_secs())
}

pub fn load_lock(path: &Path) -> Result<Option<u64>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)?;
    let lock: LockState = serde_json::from_str(&raw)?;
    Ok(Some(lock.unlock_at))
}

pub fn save_lock(path: &Path, unlock_at: u64) -> Result<()> {
    let lock = LockState { unlock_at };
    let data = serde_json::to_string_pretty(&lock)?;
    atomic_write(path, data.as_bytes())?;
    restrict_file(path)?;
    Ok(())
}

pub fn clear_lock(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn ensure_lock_not_active(lock_path: &Path) -> Result<()> {
    if let Some(until) = load_lock(lock_path)? {
        let now = unix_now()?;
        if now < until {
            let remaining = until - now;
            println!("Vault is locked due to failed attempts. Try again in {remaining} seconds.");
            std::process::exit(1);
        } else {
            // expired; clear it
            clear_lock(lock_path)?;
        }
    }
    Ok(())
}

pub fn set_lock(lock_path: &Path, duration_secs: u64) -> Result<()> {
    let unlock_at = unix_now()? + duration_secs;
    save_lock(lock_path, unlock_at)?;
    println!("Too many failed attempts. Locked for {duration_secs} seconds.");
    std::process::exit(1);
}

pub fn load_meta(path: &Path) -> Result<Option<Meta>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)?;
    let meta: Meta = serde_json::from_str(&raw)?;
    Ok(Some(meta))
}

pub fn save_meta(path: &Path, meta: &Meta) -> Result<()> {
    let data = serde_json::to_string_pretty(meta)?;
    atomic_write(path, data.as_bytes())?;
    restrict_file(path)?;
    Ok(())
}

pub fn load_wrapped_key() -> Result<Option<[u8; 32]>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)?;
    match entry.get_password() {
        Ok(stored) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(stored)
                .map_err(|e| anyhow!("Failed to decode wrapped key: {e}"))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("Stored wrapped key has invalid length"))?;
            Ok(Some(arr))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow!("Keyring read error: {e}")),
    }
}

pub fn store_wrapped_key(key: &[u8; 32]) -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    entry
        .set_password(&encoded)
        .map_err(|e| anyhow!("Keyring write error: {e}"))
}

pub fn load_trusted_revision() -> Result<Option<u64>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_REV_USER)?;
    match entry.get_password() {
        Ok(stored) => {
            let parsed = stored
                .parse::<u64>()
                .map_err(|e| anyhow!("Invalid trusted revision in keyring: {e}"))?;
            Ok(Some(parsed))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow!("Keyring read error: {e}")),
    }
}

pub fn store_trusted_revision(revision: u64) -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_REV_USER)?;
    entry
        .set_password(&revision.to_string())
        .map_err(|e| anyhow!("Keyring write error: {e}"))
}

fn validate_configured_vault_dir(raw: &Path) -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        home.join(raw)
    };

    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(anyhow!(
            "Configured vault path is invalid: parent traversal is not allowed"
        ));
    }
    if !candidate.starts_with(&home) {
        return Err(anyhow!(
            "Configured vault path must be inside home directory ({})",
            home.display()
        ));
    }

    // Resolve symlinks when possible to prevent escaping home via symlink targets.
    let home_real = fs::canonicalize(&home).unwrap_or(home.clone());
    if candidate.exists() {
        let real = fs::canonicalize(&candidate)?;
        if !real.starts_with(&home_real) {
            return Err(anyhow!(
                "Configured vault path resolves outside home directory ({})",
                home.display()
            ));
        }
    } else if let Some(parent) = candidate.parent() {
        if parent.exists() {
            let real_parent = fs::canonicalize(parent)?;
            if !real_parent.starts_with(&home_real) {
                return Err(anyhow!(
                    "Configured vault parent resolves outside home directory ({})",
                    home.display()
                ));
            }
        }
    }

    Ok(candidate)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow!("Invalid target path"))?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
        restrict_dir(parent)?;
    }

    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|e| anyhow!("Atomic write failed: {}", e.error))?;
    Ok(())
}

fn restrict_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, perms)?;
        }
    }
    // On non-Unix platforms we skip explicit chmod; rely on platform defaults.
    Ok(())
}

fn restrict_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(path, perms)?;
        }
    }
    Ok(())
}
