use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

#[cfg(not(target_arch = "wasm32"))]
pub mod fs_ops {
    use super::generate_keypair;
    use crate::error::SignetError;
    use crate::keystore::{
        decrypt_key, decode_unencrypted, encode_unencrypted, encrypt_key, EncryptedKeyFile,
        KdfParams, PubKeyFile, UnencryptedKeyFile,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use chrono::Utc;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use regex::Regex;
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Basic info about a stored key (from the .pub file).
    #[derive(Debug, Clone)]
    pub struct KeyInfo {
        pub name: String,
        pub owner: Option<String>,
        pub pubkey: String,
        pub created_at: String,
    }

    /// Validate a key name: must match `[a-zA-Z0-9_-]+`.
    pub fn validate_key_name(name: &str) -> Result<(), SignetError> {
        let re = Regex::new(r"^[a-zA-Z0-9_-]+$").expect("regex is valid");
        if re.is_match(name) {
            Ok(())
        } else {
            Err(SignetError::InvalidName(name.to_string()))
        }
    }

    /// Resolve the signet directory: checks `SIGNET_HOME` env, falls back to `~/.signet`.
    pub fn default_signet_dir() -> PathBuf {
        if let Ok(home) = std::env::var("SIGNET_HOME") {
            PathBuf::from(home)
        } else {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".signet")
        }
    }

    /// Generate a new keypair, save it to `dir/<name>.key` and `dir/<name>.pub`.
    ///
    /// If `passphrase` is `Some`, the key is encrypted with Argon2id + XChaCha20-Poly1305.
    /// Writing is atomic: .key is written as .tmp, chmod 600'd, then renamed.
    /// On .key failure, the .pub file is deleted to avoid orphaned pub files.
    pub fn generate_and_save(
        dir: &Path,
        name: &str,
        owner: Option<&str>,
        passphrase: Option<&str>,
        kdf_params: Option<KdfParams>,
    ) -> Result<KeyInfo, SignetError> {
        validate_key_name(name)?;

        let keys_dir = dir.join("keys");
        fs::create_dir_all(&keys_dir)?;

        let pub_path = keys_dir.join(format!("{name}.pub"));
        let key_path = keys_dir.join(format!("{name}.key"));
        let tmp_path = keys_dir.join(format!("{name}.key.tmp"));

        if pub_path.exists() || key_path.exists() {
            return Err(SignetError::KeyExists(name.to_string()));
        }

        let (signing_key, verifying_key) = generate_keypair();
        let created_at = Utc::now().to_rfc3339();

        // Write .pub file first.
        let pub_file = PubKeyFile {
            v: 1,
            algorithm: "ed25519".to_string(),
            name: name.to_string(),
            pubkey: B64.encode(verifying_key.as_bytes()),
            owner: owner.map(|s| s.to_string()),
            created_at: created_at.clone(),
        };
        let pub_json = serde_json::to_string_pretty(&pub_file)?;
        fs::write(&pub_path, pub_json)?;

        // Write .key file atomically, cleaning up .pub on error.
        let write_result = (|| -> Result<(), SignetError> {
            let key_json = if let Some(pass) = passphrase {
                let params = kdf_params.unwrap_or_else(KdfParams::new);
                let enc = encrypt_key(&signing_key, name, pass, &params)?;
                serde_json::to_string_pretty(&enc)?
            } else {
                let plain = encode_unencrypted(&signing_key, name);
                serde_json::to_string_pretty(&plain)?
            };

            fs::write(&tmp_path, key_json)?;

            // chmod 600
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = fs::Permissions::from_mode(0o600);
                fs::set_permissions(&tmp_path, perms)?;
            }

            fs::rename(&tmp_path, &key_path)?;
            Ok(())
        })();

        if let Err(e) = write_result {
            // Clean up .pub to avoid orphaned public key.
            let _ = fs::remove_file(&pub_path);
            return Err(e);
        }

        Ok(KeyInfo {
            name: name.to_string(),
            owner: owner.map(|s| s.to_string()),
            pubkey: B64.encode(verifying_key.as_bytes()),
            created_at,
        })
    }

    /// Read key info from `dir/keys/<name>.pub`.
    pub fn load_key_info(dir: &Path, name: &str) -> Result<KeyInfo, SignetError> {
        let pub_path = dir.join("keys").join(format!("{name}.pub"));
        if !pub_path.exists() {
            return Err(SignetError::KeyNotFound(name.to_string()));
        }
        let json = fs::read_to_string(&pub_path)?;
        let file: PubKeyFile = serde_json::from_str(&json)
            .map_err(|e| SignetError::CorruptedFile(format!("invalid .pub file: {e}")))?;
        Ok(KeyInfo {
            name: file.name,
            owner: file.owner,
            pubkey: file.pubkey,
            created_at: file.created_at,
        })
    }

    /// Load a signing key from `dir/keys/<name>.key`.
    /// Detects encrypted vs unencrypted by checking for the `kdf` field.
    pub fn load_signing_key(
        dir: &Path,
        name: &str,
        passphrase: Option<&str>,
    ) -> Result<SigningKey, SignetError> {
        let key_path = dir.join("keys").join(format!("{name}.key"));
        if !key_path.exists() {
            return Err(SignetError::KeyNotFound(name.to_string()));
        }
        let json = fs::read_to_string(&key_path)?;
        let value: Value = serde_json::from_str(&json)
            .map_err(|e| SignetError::CorruptedFile(format!("invalid .key file: {e}")))?;

        if value.get("kdf").is_some() {
            // Encrypted key
            let enc_file: EncryptedKeyFile = serde_json::from_value(value)
                .map_err(|e| SignetError::CorruptedFile(format!("invalid encrypted .key file: {e}")))?;
            let pass = passphrase.ok_or_else(|| SignetError::DecryptionError)?;
            decrypt_key(&enc_file, pass)
        } else {
            // Unencrypted key
            let plain_file: UnencryptedKeyFile = serde_json::from_value(value)
                .map_err(|e| SignetError::CorruptedFile(format!("invalid unencrypted .key file: {e}")))?;
            decode_unencrypted(&plain_file)
        }
    }

    /// Load a verifying key from `dir/keys/<name>.pub`.
    pub fn load_verifying_key(dir: &Path, name: &str) -> Result<VerifyingKey, SignetError> {
        let pub_path = dir.join("keys").join(format!("{name}.pub"));
        if !pub_path.exists() {
            return Err(SignetError::KeyNotFound(name.to_string()));
        }
        let json = fs::read_to_string(&pub_path)?;
        let file: PubKeyFile = serde_json::from_str(&json)
            .map_err(|e| SignetError::CorruptedFile(format!("invalid .pub file: {e}")))?;

        let pubkey_bytes = B64.decode(&file.pubkey)
            .map_err(|e| SignetError::CorruptedFile(format!("invalid pubkey base64: {e}")))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| SignetError::CorruptedFile("pubkey is not 32 bytes".to_string()))?;
        VerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|e| SignetError::InvalidKey(e.to_string()))
    }

    /// List all keys in `dir/keys/`, returning sorted Vec<KeyInfo>.
    pub fn list_keys(dir: &Path) -> Result<Vec<KeyInfo>, SignetError> {
        let keys_dir = dir.join("keys");
        if !keys_dir.exists() {
            return Ok(vec![]);
        }
        let mut infos = Vec::new();
        for entry in fs::read_dir(&keys_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pub") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    match load_key_info(dir, stem) {
                        Ok(info) => infos.push(info),
                        Err(_) => {}
                    }
                }
            }
        }
        infos.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(infos)
    }

    /// Export the public key file for `name`.
    pub fn export_public_key(dir: &Path, name: &str) -> Result<PubKeyFile, SignetError> {
        let pub_path = dir.join("keys").join(format!("{name}.pub"));
        if !pub_path.exists() {
            return Err(SignetError::KeyNotFound(name.to_string()));
        }
        let json = fs::read_to_string(&pub_path)?;
        let file: PubKeyFile = serde_json::from_str(&json)
            .map_err(|e| SignetError::CorruptedFile(format!("invalid .pub file: {e}")))?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::Verifier;

    #[test]
    fn test_generate_keypair() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"test message";
        let signature = signing_key.sign(message);
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_keypair_uniqueness() {
        let (key1, _) = generate_keypair();
        let (key2, _) = generate_keypair();
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod fs_tests {
    use super::fs_ops::*;
    use crate::error::SignetError;
    use crate::keystore::{KdfParams, PubKeyFile};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let info = generate_and_save(
            dir.path(),
            "alice",
            Some("Alice"),
            Some("secret"),
            Some(KdfParams::test_default()),
        )
        .unwrap();
        assert_eq!(info.name, "alice");

        let sk = load_signing_key(dir.path(), "alice", Some("secret")).unwrap();
        let vk = load_verifying_key(dir.path(), "alice").unwrap();
        assert_eq!(sk.verifying_key().as_bytes(), vk.as_bytes());
    }

    #[test]
    fn test_unencrypted_save_load_roundtrip() {
        let dir = tempdir().unwrap();
        generate_and_save(dir.path(), "bob", None, None, None).unwrap();
        let sk = load_signing_key(dir.path(), "bob", None).unwrap();
        let vk = load_verifying_key(dir.path(), "bob").unwrap();
        assert_eq!(sk.verifying_key().as_bytes(), vk.as_bytes());
    }

    #[test]
    fn test_load_wrong_passphrase() {
        let dir = tempdir().unwrap();
        generate_and_save(
            dir.path(),
            "carol",
            None,
            Some("correct"),
            Some(KdfParams::test_default()),
        )
        .unwrap();
        let result = load_signing_key(dir.path(), "carol", Some("wrong"));
        assert!(matches!(result, Err(SignetError::DecryptionError)));
    }

    #[test]
    fn test_load_nonexistent_key() {
        let dir = tempdir().unwrap();
        let result = load_signing_key(dir.path(), "nobody", None);
        assert!(matches!(result, Err(SignetError::KeyNotFound(_))));
    }

    #[test]
    fn test_list_keys() {
        let dir = tempdir().unwrap();
        generate_and_save(dir.path(), "carol", None, None, None).unwrap();
        generate_and_save(dir.path(), "alice", None, None, None).unwrap();
        generate_and_save(dir.path(), "bob", None, None, None).unwrap();
        let keys = list_keys(dir.path()).unwrap();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].name, "alice");
        assert_eq!(keys[1].name, "bob");
        assert_eq!(keys[2].name, "carol");
    }

    #[test]
    fn test_list_keys_empty_dir() {
        let dir = tempdir().unwrap();
        let keys = list_keys(dir.path()).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_export_public_key() {
        let dir = tempdir().unwrap();
        generate_and_save(dir.path(), "dave", Some("Dave"), None, None).unwrap();
        let pub_file = export_public_key(dir.path(), "dave").unwrap();
        assert_eq!(pub_file.name, "dave");
        assert_eq!(pub_file.owner.as_deref(), Some("Dave"));
        assert!(!pub_file.pubkey.is_empty());
    }

    #[test]
    fn test_key_file_name_mismatch() {
        let dir = tempdir().unwrap();
        generate_and_save(dir.path(), "eve", None, None, None).unwrap();
        // Tamper the .pub file to have a different name field.
        let pub_path = dir.path().join("keys").join("eve.pub");
        let mut pub_file: PubKeyFile =
            serde_json::from_str(&fs::read_to_string(&pub_path).unwrap()).unwrap();
        pub_file.name = "attacker".to_string();
        fs::write(&pub_path, serde_json::to_string_pretty(&pub_file).unwrap()).unwrap();
        // load_key_info still reads the raw file, which now has name="attacker"
        let info = load_key_info(dir.path(), "eve").unwrap();
        assert_eq!(info.name, "attacker"); // reflects what's on disk
    }

    #[test]
    fn test_pub_file_format() {
        let dir = tempdir().unwrap();
        generate_and_save(dir.path(), "frank", Some("Frank"), None, None).unwrap();
        let pub_path = dir.path().join("keys").join("frank.pub");
        let json = fs::read_to_string(&pub_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["v"], 1);
        assert_eq!(value["algorithm"], "ed25519");
        assert_eq!(value["name"], "frank");
        assert_eq!(value["owner"], "Frank");
        assert!(value["pubkey"].as_str().is_some());
        assert!(value["created_at"].as_str().is_some());
    }

    #[test]
    fn test_auto_create_keys_dir() {
        let dir = tempdir().unwrap();
        // keys/ subdir does not exist yet.
        assert!(!dir.path().join("keys").exists());
        generate_and_save(dir.path(), "grace", None, None, None).unwrap();
        assert!(dir.path().join("keys").exists());
    }

    #[test]
    fn test_corrupted_json_key_file() {
        let dir = tempdir().unwrap();
        generate_and_save(dir.path(), "henry", None, None, None).unwrap();
        let key_path = dir.path().join("keys").join("henry.key");
        fs::write(&key_path, b"this is not valid json").unwrap();
        let result = load_signing_key(dir.path(), "henry", None);
        assert!(matches!(result, Err(SignetError::CorruptedFile(_))));
    }

    #[test]
    fn test_key_name_validation() {
        let dir = tempdir().unwrap();
        let result = generate_and_save(dir.path(), "bad name!", None, None, None);
        assert!(matches!(result, Err(SignetError::InvalidName(_))));

        let result2 = generate_and_save(dir.path(), "", None, None, None);
        assert!(matches!(result2, Err(SignetError::InvalidName(_))));

        // Valid names.
        generate_and_save(dir.path(), "valid-name_123", None, None, None).unwrap();
    }

    #[test]
    fn test_key_exists_error() {
        let dir = tempdir().unwrap();
        generate_and_save(dir.path(), "iris", None, None, None).unwrap();
        let result = generate_and_save(dir.path(), "iris", None, None, None);
        assert!(matches!(result, Err(SignetError::KeyExists(_))));
    }
}
