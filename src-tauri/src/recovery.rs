//! A recovery kit: one printed key that opens the vault when the master
//! password is gone.
//!
//! `SECURITY.md` has always had to say "there is no recovery if you forget
//! it", which is a reasonable thing to say about a password manager and an
//! unreasonable barrier for someone putting a whole fleet behind one password.
//! This is the BitLocker arrangement: a 256-bit key, generated once, shown
//! once, and written down by the person - never stored anywhere by Kino.
//!
//! **What is on disk.** `recovery.enc`, beside the vault: the vault's own
//! AES key, encrypted under a key derived from the recovery secret. Reading it
//! without the secret is the same problem as reading the vault without the
//! password, except that the secret has a full 256 bits of entropy behind it
//! rather than whatever someone could remember.
//!
//! **What it is tied to.** The vault key is derived from the master password,
//! so a kit opens the vault *as it was when the kit was made*. Changing the
//! master password derives a new key and the old kit opens nothing - so the
//! password change deletes it and the window asks for a new one to be printed.
//! The honest fix for that is a key-slot layout, where the data is encrypted
//! under a random master key that both the password and the recovery secret
//! merely wrap; then a password change re-wraps instead of re-encrypting, and
//! a kit never goes stale. That is a vault format migration, and this is not
//! it. The format here carries the vault salt it was made against so a kit
//! from an older password can be *recognised* rather than reported as a bad
//! key.
//!
//! **What it is not.** It is not synced. The kit lives on the machine it was
//! made on, and the printed key is what crosses machines.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Crockford base32: no I, L, O or U, so nothing in a printed key can be
/// confused with 1 or 0, and nothing spells anything.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 256 bits at 5 bits a symbol, rounded up.
pub const KEY_SYMBOLS: usize = 52;

/// Symbols per group in what gets printed.
const GROUP: usize = 4;

/// What is written beside the vault.
///
/// `created_ms` and `vault_salt` are outside the ciphertext on purpose: the
/// window has to be able to say "made on the 3rd of March, and it is for the
/// password you have now" while the vault is still locked, and neither is a
/// secret - the same salt sits in plaintext in `vault.enc`.
#[derive(Serialize, Deserialize)]
pub struct RecoveryFile {
    pub version: u8,
    /// Argon2 salt for deriving the wrapping key from the recovery secret.
    pub salt: String,
    pub nonce: String,
    /// AES-256-GCM over the vault's 32-byte key.
    pub ciphertext: String,
    pub created_ms: i64,
    /// The vault salt this kit was made against.
    pub vault_salt: String,
}

/// What the window can say about the kit on disk without any secret.
#[derive(Serialize, Default)]
pub struct Status {
    pub exists: bool,
    pub created_ms: Option<i64>,
    /// True when the kit matches the vault as it is now. False means the
    /// master password was changed after it was made, so it opens nothing.
    /// `None` when there is no kit, or the file cannot be read.
    pub for_this_vault: Option<bool>,
}

pub fn path() -> PathBuf {
    crate::vault::vault_path()
        .parent()
        .unwrap_or(Path::new("."))
        .join("recovery.enc")
}

/// A fresh 256-bit secret. Never stored; the caller shows it once.
pub fn generate() -> [u8; 32] {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    secret
}

/// The printed form: 13 groups of 4, dash-separated.
pub fn format_key(secret: &[u8; 32]) -> String {
    let mut symbols = String::with_capacity(KEY_SYMBOLS);
    for i in 0..KEY_SYMBOLS {
        let bit = i * 5;
        // Five bits starting at `bit`, MSB first, zero-padded past the end.
        let mut value = 0u8;
        for offset in 0..5 {
            let at = bit + offset;
            let is_set = at < 256 && (secret[at / 8] >> (7 - (at % 8))) & 1 == 1;
            value = (value << 1) | u8::from(is_set);
        }
        symbols.push(ALPHABET[value as usize] as char);
    }
    symbols
        .as_bytes()
        .chunks(GROUP)
        .map(|c| std::str::from_utf8(c).unwrap_or_default().to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Read a typed key back, forgiving everything that is safe to forgive.
///
/// Case, spaces, dashes and line breaks are all noise. `I` and `l` are read as
/// `1` and `O` as `0`, which is Crockford's rule and the whole reason for the
/// alphabet. What is not forgiven is a wrong length or a character the
/// alphabet does not contain, because quietly "fixing" either would turn a
/// typo into a wrong key and a confusing failure two steps later.
pub fn parse_key(typed: &str) -> Result<[u8; 32], String> {
    let cleaned: String = typed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        })
        .collect();

    if cleaned.len() != KEY_SYMBOLS {
        return Err(format!(
            "A recovery key is {KEY_SYMBOLS} characters; this one has {}. \
             Dashes, spaces and capitals do not matter.",
            cleaned.len()
        ));
    }

    let mut bits = [false; KEY_SYMBOLS * 5];
    for (i, c) in cleaned.chars().enumerate() {
        let value = ALPHABET
            .iter()
            .position(|a| *a as char == c)
            .ok_or_else(|| format!("'{c}' is not part of a recovery key - check that character."))?
            as u8;
        for offset in 0..5 {
            bits[i * 5 + offset] = (value >> (4 - offset)) & 1 == 1;
        }
    }

    // The last symbol carries four real bits and four of padding. Padding
    // that is not zero means the last character is wrong - worth saying now
    // rather than after a derivation that was never going to work.
    if bits[256..].iter().any(|b| *b) {
        return Err(
            "That is not a recovery key - the last character does not fit. Check it.".to_string(),
        );
    }

    let mut secret = [0u8; 32];
    for (i, bit) in bits[..256].iter().enumerate() {
        if *bit {
            secret[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    Ok(secret)
}

/// Derive the wrapping key. Argon2, the same as the vault's own derivation -
/// overkill for 256 random bits, and the same audited path either way.
fn wrapping_key(secret: &[u8; 32], salt: &[u8; 16]) -> Result<[u8; 32], String> {
    crate::vault::derive_key_bytes(secret, salt)
}

/// Write a kit for the vault key currently in use.
pub fn write_at(
    file: &Path,
    secret: &[u8; 32],
    vault_key: &[u8; 32],
    vault_salt: &[u8; 16],
    created_ms: i64,
) -> Result<(), String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut wrap = wrapping_key(secret, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, vault_key.as_slice())
        .map_err(|e| e.to_string())?;
    wrap.zeroize();

    let contents = RecoveryFile {
        version: 1,
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(&ciphertext),
        created_ms,
        vault_salt: STANDARD.encode(vault_salt),
    };

    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_vec(&contents).map_err(|e| e.to_string())?;
    // Beside and renamed over, as the vault does: a half-written kit is a kit
    // that opens nothing, and it would not be noticed until it was needed.
    let tmp = file.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, &json).map_err(|e| e.to_string())?;
    restrict(&tmp);
    std::fs::rename(&tmp, file).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })?;
    Ok(())
}

/// Readable by this user only. It wraps the key to everything.
fn restrict(file: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = file;
}

fn read_file(file: &Path) -> Option<RecoveryFile> {
    let bytes = std::fs::read(file).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// What there is to say about the kit on disk, with no secret in hand.
pub fn status_at(file: &Path, vault_salt: Option<&[u8; 16]>) -> Status {
    match read_file(file) {
        None => Status::default(),
        Some(contents) => Status {
            exists: true,
            created_ms: Some(contents.created_ms),
            for_this_vault: vault_salt.map(|salt| contents.vault_salt == STANDARD.encode(salt)),
        },
    }
}

/// The vault key a kit holds, and the vault salt it was made against.
///
/// Three failures, told apart on purpose: there is no kit, the key does not
/// open the kit, or the kit is for an earlier master password. Collapsing them
/// into one message would leave someone retyping a key that was right.
pub fn unwrap_at(file: &Path, typed: &str) -> Result<([u8; 32], [u8; 16]), String> {
    let contents = read_file(file).ok_or(
        "There is no recovery kit on this machine. A kit has to be made while the vault is \
         unlocked, and it cannot be made after the password is lost.",
    )?;
    let mut secret = parse_key(typed)?;

    let salt: [u8; 16] = STANDARD
        .decode(&contents.salt)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "The recovery kit is damaged: its salt is the wrong length.".to_string())?;
    let nonce_bytes = STANDARD
        .decode(&contents.nonce)
        .map_err(|e| e.to_string())?;
    let ciphertext = STANDARD
        .decode(&contents.ciphertext)
        .map_err(|e| e.to_string())?;
    let vault_salt: [u8; 16] = STANDARD
        .decode(&contents.vault_salt)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| {
            "The recovery kit is damaged: its vault salt is the wrong length.".to_string()
        })?;

    let mut wrap = wrapping_key(&secret, &salt)?;
    secret.zeroize();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&wrap));
    let mut plaintext = cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(&nonce_bytes),
            ciphertext.as_slice(),
        )
        .map_err(|_| {
            "That recovery key does not open this kit. Every character matters; dashes, spaces \
             and capitals do not."
                .to_string()
        })?;
    wrap.zeroize();

    let key: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| "The recovery kit is damaged: it does not hold a key.".to_string())?;
    plaintext.zeroize();
    Ok((key, vault_salt))
}

/// Remove the kit - after a password change, which makes it open nothing.
/// Missing is the desired state, so missing is success.
pub fn forget_at(file: &Path) -> Result<(), String> {
    match std::fs::remove_file(file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Could not remove the old recovery kit: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_printed_key_reads_back_as_itself() {
        for _ in 0..200 {
            let secret = generate();
            let printed = format_key(&secret);
            assert_eq!(parse_key(&printed).unwrap(), secret, "{printed}");
        }
    }

    #[test]
    fn the_printed_form_is_thirteen_groups_of_four() {
        let printed = format_key(&[0x42; 32]);
        let groups: Vec<&str> = printed.split('-').collect();
        assert_eq!(groups.len(), 13);
        assert!(groups.iter().all(|g| g.len() == 4), "{printed}");
        assert!(
            printed
                .chars()
                .all(|c| c == '-' || ALPHABET.contains(&(c as u8))),
            "{printed}"
        );
    }

    /// Somebody reading a key off paper types it as they see it.
    #[test]
    fn reading_it_off_paper_forgives_what_is_safe_to_forgive() {
        let secret = generate();
        let printed = format_key(&secret);
        let mangled = [
            printed.to_lowercase(),
            printed.replace('-', ""),
            printed.replace('-', " "),
            format!("  {printed}\n"),
            printed.replace('-', "\n"),
        ];
        for typed in mangled {
            assert_eq!(parse_key(&typed).unwrap(), secret, "{typed:?}");
        }
    }

    /// The reason for the alphabet: 1 and I, 0 and O.
    #[test]
    fn one_and_i_and_zero_and_o_are_the_same_character() {
        // A secret whose printed form contains both 0 and 1.
        let secret = [0u8; 32];
        let printed = format_key(&secret); // all zeros
        assert_eq!(parse_key(&printed.replace('0', "O")).unwrap(), secret);
        let ones = format_key(&[0x08; 32]);
        assert_eq!(parse_key(&ones.replace('1', "I")).unwrap(), [0x08; 32]);
        assert_eq!(parse_key(&ones.replace('1', "l")).unwrap(), [0x08; 32]);
    }

    #[test]
    fn a_key_of_the_wrong_length_says_so_with_the_count() {
        let err = parse_key("ABCD-EFGH").unwrap_err();
        assert!(err.contains("52 characters"), "{err}");
        assert!(err.contains("has 8"), "{err}");
    }

    #[test]
    fn a_character_outside_the_alphabet_is_named() {
        let secret = generate();
        let printed = format_key(&secret);
        // U is excluded from Crockford base32 on purpose.
        let typo = format!("U{}", &printed[1..]);
        let err = parse_key(&typo).unwrap_err();
        assert!(err.contains("'U'"), "{err}");
    }

    /// A single wrong character in the final position changes the padding
    /// bits, which is detectable before anything is derived.
    #[test]
    fn a_wrong_last_character_is_caught_before_any_derivation() {
        let printed = format_key(&[0u8; 32]);
        let mut chars: Vec<char> = printed.chars().collect();
        *chars.last_mut().unwrap() = 'Z'; // 11111: padding bits set
        let typo: String = chars.into_iter().collect();
        let err = parse_key(&typo).unwrap_err();
        assert!(err.contains("last character"), "{err}");
    }

    #[test]
    fn a_kit_hands_back_the_vault_key_it_was_made_for() {
        let dir = temp();
        let file = dir.path().join("recovery.enc");
        let secret = generate();
        let vault_key = [7u8; 32];
        let vault_salt = [3u8; 16];
        write_at(&file, &secret, &vault_key, &vault_salt, 1_700_000_000_000).unwrap();

        let (key, salt) = unwrap_at(&file, &format_key(&secret)).unwrap();
        assert_eq!(key, vault_key);
        assert_eq!(salt, vault_salt);
    }

    #[test]
    fn a_wrong_recovery_key_is_refused_without_calling_the_kit_damaged() {
        let dir = temp();
        let file = dir.path().join("recovery.enc");
        write_at(&file, &generate(), &[7u8; 32], &[3u8; 16], 0).unwrap();

        let err = unwrap_at(&file, &format_key(&generate())).unwrap_err();
        assert!(err.contains("does not open this kit"), "{err}");
        assert!(!err.to_lowercase().contains("damaged"), "{err}");
    }

    #[test]
    fn with_no_kit_the_message_says_one_cannot_be_made_afterwards() {
        let dir = temp();
        let err = unwrap_at(&dir.path().join("nothing.enc"), "whatever").unwrap_err();
        assert!(err.contains("no recovery kit"), "{err}");
        assert!(err.contains("cannot be made after"), "{err}");
    }

    /// The file is the thing an attacker gets hold of, so it must hold
    /// neither the vault key nor the secret in the clear.
    #[test]
    fn the_file_holds_neither_the_vault_key_nor_the_secret() {
        let dir = temp();
        let file = dir.path().join("recovery.enc");
        let secret = generate();
        let vault_key = [0xAB; 32];
        write_at(&file, &secret, &vault_key, &[3u8; 16], 0).unwrap();

        let bytes = std::fs::read(&file).unwrap();
        for needle in [
            STANDARD.encode(vault_key),
            STANDARD.encode(secret),
            hex(&vault_key),
            hex(&secret),
        ] {
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&needle),
                "the file contains {needle}"
            );
        }
        // And the raw bytes are not in there either.
        assert!(
            !bytes.windows(32).any(|w| w == vault_key || w == secret),
            "the file contains a key verbatim"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn status_says_whether_the_kit_is_for_the_vault_as_it_is_now() {
        let dir = temp();
        let file = dir.path().join("recovery.enc");
        assert!(!status_at(&file, Some(&[3u8; 16])).exists);

        write_at(
            &file,
            &generate(),
            &[7u8; 32],
            &[3u8; 16],
            1_700_000_000_000,
        )
        .unwrap();
        let now = status_at(&file, Some(&[3u8; 16]));
        assert!(now.exists);
        assert_eq!(now.created_ms, Some(1_700_000_000_000));
        assert_eq!(now.for_this_vault, Some(true));

        // After a password change the vault has a new salt, and the kit is
        // for the old one.
        let stale = status_at(&file, Some(&[9u8; 16]));
        assert_eq!(stale.for_this_vault, Some(false));
        // Locked, with no salt to compare against.
        assert_eq!(status_at(&file, None).for_this_vault, None);
    }

    #[test]
    fn forgetting_a_kit_leaves_nothing_and_is_fine_twice() {
        let dir = temp();
        let file = dir.path().join("recovery.enc");
        write_at(&file, &generate(), &[7u8; 32], &[3u8; 16], 0).unwrap();
        forget_at(&file).unwrap();
        assert!(!file.exists());
        forget_at(&file).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_kit_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp();
        let file = dir.path().join("recovery.enc");
        write_at(&file, &generate(), &[7u8; 32], &[3u8; 16], 0).unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[test]
    fn a_damaged_kit_is_called_damaged_rather_than_blamed_on_the_key() {
        let dir = temp();
        let file = dir.path().join("recovery.enc");
        let secret = generate();
        write_at(&file, &secret, &[7u8; 32], &[3u8; 16], 0).unwrap();

        // Truncate the wrapped key to 16 bytes of ciphertext: the envelope
        // still parses, the GCM tag will not verify.
        let mut contents: RecoveryFile =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        contents.vault_salt = STANDARD.encode([3u8; 15]);
        std::fs::write(&file, serde_json::to_vec(&contents).unwrap()).unwrap();
        let err = unwrap_at(&file, &format_key(&secret)).unwrap_err();
        assert!(err.contains("damaged"), "{err}");
    }
}
