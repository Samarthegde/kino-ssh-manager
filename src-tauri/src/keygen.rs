use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, LineEnding, PrivateKey};

#[derive(Serialize, Deserialize, Clone)]
pub struct SshKeyPair {
    pub private_key: String,
    pub public_key: String,
}

pub fn generate_ed25519() -> Result<SshKeyPair, String> {
    let private_key =
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|e| e.to_string())?;

    let private_pem = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|e| e.to_string())?
        .to_string();

    let public_openssh = private_key
        .public_key()
        .to_openssh()
        .map_err(|e| e.to_string())?;

    Ok(SshKeyPair {
        private_key: private_pem,
        public_key: public_openssh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_ed25519_pair() {
        let kp = generate_ed25519().unwrap();
        assert!(kp.private_key.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(kp.public_key.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn generated_keys_are_unique() {
        let a = generate_ed25519().unwrap();
        let b = generate_ed25519().unwrap();
        assert_ne!(a.public_key, b.public_key);
    }
}
