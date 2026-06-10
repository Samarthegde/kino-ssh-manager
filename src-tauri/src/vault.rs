use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PortForward {
    pub id: String,
    pub label: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

/// Flat credential storage — password and SSH key are always independent fields.
/// `default_auth` is the method used when connecting without an explicit override.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Host {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    /// "Password" or "SshKey"
    pub default_auth: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    /// Optional passphrase for an encrypted private key / .pem file.
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub port_forwards: Vec<PortForward>,
    /// Ids of library snippets to run automatically on connect, in order.
    #[serde(default)]
    pub on_connect_snippets: Vec<String>,
    /// Optional accent color (CSS hex) used to tag the host/tab, e.g. "#f38ba8" for prod.
    #[serde(default)]
    pub color: Option<String>,
    /// Free-form notes for this connection.
    #[serde(default)]
    pub notes: Option<String>,
    /// Group or folder tag for organization.
    #[serde(default)]
    pub group: Option<String>,
    /// Operating system tag, e.g. "linux", "ubuntu", "windows", "macos".
    /// Drives the OS icon shown in the host list.
    #[serde(default)]
    pub os: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedFile {
    pub version: u8,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn vault_path() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ssh-manager")
        .join("vault.enc")
}

pub fn vault_exists() -> bool {
    vault_path().exists()
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn save_encrypted<T: Serialize + ?Sized>(
    path: &PathBuf,
    data: &T,
    key: &[u8; 32],
    salt: &[u8; 16],
) -> Result<(), String> {
    let plaintext = serde_json::to_vec(data).map_err(|e| e.to_string())?;
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|e| e.to_string())?;

    let enc_file = EncryptedFile {
        version: 1,
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    };

    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    let json = serde_json::to_vec(&enc_file).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn load_encrypted<T: serde::de::DeserializeOwned>(
    path: &PathBuf,
    key: &[u8; 32],
) -> Result<T, String> {
    if !path.exists() {
        return Err("File does not exist".to_string());
    }
    let bytes = std::fs::read(path).map_err(|e| format!("Cannot read file: {}", e))?;
    let enc_file: EncryptedFile =
        serde_json::from_slice(&bytes).map_err(|e| format!("Corrupt file: {}", e))?;

    let nonce_bytes = STANDARD
        .decode(&enc_file.nonce)
        .map_err(|e| e.to_string())?;
    let ciphertext = STANDARD
        .decode(&enc_file.ciphertext)
        .map_err(|e| e.to_string())?;

    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| "Decryption failed".to_string())?;

    let data: T = serde_json::from_slice(&plaintext).map_err(|e| format!("Corrupt data: {}", e))?;
    plaintext.zeroize();
    Ok(data)
}

pub fn save_vault(hosts: &[Host], key: &[u8; 32], salt: &[u8; 16]) -> Result<(), String> {
    save_encrypted(&vault_path(), &hosts, key, salt)
}

/// The OpenSSH public key to hand to `userauth_pubkey_memory`, if we can obtain
/// one. Prefer a stored public key; otherwise derive it from the private key.
///
/// libssh2 can fail to derive the public key from an in-memory OpenSSH-format
/// private key (notably ed25519) on some backends — passing the public key
/// explicitly avoids that. The OpenSSH private-key format embeds the public key
/// in the clear, so derivation works even for encrypted keys without the
/// passphrase. Returns `None` for formats we can't parse (e.g. legacy RSA PEM),
/// in which case the caller falls back to letting libssh2 derive it.
pub fn resolve_public_key(host: &Host) -> Option<String> {
    if let Some(stored) = host.public_key.as_deref() {
        let trimmed = stored.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let private = host.private_key.as_deref()?;
    let parsed = ssh_key::PrivateKey::from_openssh(private).ok()?;
    parsed.public_key().to_openssh().ok()
}

/// Decrypted hosts plus the derived key and salt used to encrypt them.
pub type VaultData = (Vec<Host>, [u8; 32], [u8; 16]);

pub fn load_vault(password: &str) -> Result<VaultData, String> {
    let path = vault_path();
    let bytes = std::fs::read(&path).map_err(|e| format!("Cannot read vault: {}", e))?;
    let enc_file: EncryptedFile =
        serde_json::from_slice(&bytes).map_err(|e| format!("Corrupt vault: {}", e))?;

    let salt_vec = STANDARD.decode(&enc_file.salt).map_err(|e| e.to_string())?;
    let salt: [u8; 16] = salt_vec
        .try_into()
        .map_err(|_| "Invalid salt length in vault".to_string())?;

    let nonce_bytes = STANDARD
        .decode(&enc_file.nonce)
        .map_err(|e| e.to_string())?;
    let ciphertext = STANDARD
        .decode(&enc_file.ciphertext)
        .map_err(|e| e.to_string())?;

    let key = derive_key(password, &salt)?;
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|_| "Wrong password or corrupt vault".to_string())?;

    let hosts: Vec<Host> =
        serde_json::from_slice(&plaintext).map_err(|e| format!("Corrupt vault data: {}", e))?;
    plaintext.zeroize();

    Ok((hosts, key, salt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hosts() -> Vec<Host> {
        vec![Host {
            id: "1".into(),
            name: "web".into(),
            hostname: "10.0.0.1".into(),
            port: 22,
            username: "root".into(),
            default_auth: "Password".into(),
            password: Some("hunter2".into()),
            private_key: None,
            public_key: None,
            passphrase: None,
            port_forwards: vec![],
            on_connect_snippets: vec![],
            color: None,
            notes: None,
            group: None,
            os: None,
        }]
    }

    #[test]
    fn derive_key_is_deterministic_and_salt_sensitive() {
        let salt_a = [1u8; 16];
        let salt_b = [2u8; 16];
        let k1 = derive_key("correct horse", &salt_a).unwrap();
        let k2 = derive_key("correct horse", &salt_a).unwrap();
        let k3 = derive_key("correct horse", &salt_b).unwrap();
        assert_eq!(k1, k2, "same password + salt must derive the same key");
        assert_ne!(k1, k3, "a different salt must derive a different key");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let salt = [7u8; 16];
        let key = derive_key("master", &salt).unwrap();

        save_encrypted(&path, &sample_hosts(), &key, &salt).unwrap();
        let loaded: Vec<Host> = load_encrypted(&path, &key).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "web");
        assert_eq!(loaded[0].password.as_deref(), Some("hunter2"));
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        let salt = [7u8; 16];
        let key = derive_key("right", &salt).unwrap();
        let wrong = derive_key("wrong", &salt).unwrap();

        save_encrypted(&path, &sample_hosts(), &key, &salt).unwrap();
        let res: Result<Vec<Host>, String> = load_encrypted(&path, &wrong);
        assert!(res.is_err(), "decryption with the wrong key must fail");
    }

    #[test]
    fn each_save_uses_a_fresh_nonce() {
        // Same key + plaintext must still produce different ciphertext (random nonce),
        // otherwise GCM nonce reuse would be catastrophic.
        let dir = tempfile::tempdir().unwrap();
        let p1 = dir.path().join("a.enc");
        let p2 = dir.path().join("b.enc");
        let salt = [9u8; 16];
        let key = derive_key("master", &salt).unwrap();
        save_encrypted(&p1, &sample_hosts(), &key, &salt).unwrap();
        save_encrypted(&p2, &sample_hosts(), &key, &salt).unwrap();

        let a: EncryptedFile = serde_json::from_slice(&std::fs::read(&p1).unwrap()).unwrap();
        let b: EncryptedFile = serde_json::from_slice(&std::fs::read(&p2).unwrap()).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn host_deserializes_with_defaults() {
        // Older/minimal vault entries must still load — fields added later default cleanly.
        let json = r#"{"id":"x","name":"n","hostname":"h","port":22,"username":"u","default_auth":"Password"}"#;
        let h: Host = serde_json::from_str(json).unwrap();
        assert!(h.password.is_none());
        assert!(h.port_forwards.is_empty());
        assert!(h.on_connect_snippets.is_empty());
        assert!(h.color.is_none());
        // Fields added later must default cleanly so existing vaults keep loading.
        assert!(h.notes.is_none());
    }

    #[test]
    fn resolve_public_key_derives_from_private_when_not_stored() {
        let kp = crate::keygen::generate_ed25519().unwrap();
        let mut h = sample_hosts().remove(0);
        h.private_key = Some(kp.private_key);
        h.public_key = None;
        let derived = resolve_public_key(&h).expect("should derive a public key");
        assert!(derived.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn resolve_public_key_prefers_stored() {
        let mut h = sample_hosts().remove(0);
        h.public_key = Some("ssh-ed25519 STORED comment".into());
        h.private_key = None;
        assert_eq!(
            resolve_public_key(&h).as_deref(),
            Some("ssh-ed25519 STORED comment")
        );
    }
}
