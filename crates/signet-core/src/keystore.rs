#![cfg(not(target_arch = "wasm32"))]

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::SignetError;

/// KDF parameters for Argon2id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub t: u32,
    pub m: u32,
    pub p: u32,
}

impl KdfParams {
    /// Production-grade parameters: t=3, m=65536 (64MB), p=1.
    pub fn new() -> Self {
        KdfParams {
            t: 3,
            m: 65536,
            p: 1,
        }
    }

    /// Fast parameters for tests only (insecure).
    pub fn test_default() -> Self {
        KdfParams { t: 1, m: 64, p: 1 }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::new()
    }
}

/// An encrypted key file stored on disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    pub v: u32,
    pub algorithm: String,
    pub name: String,
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub salt: String,
    pub cipher: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// An unencrypted key file stored on disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct UnencryptedKeyFile {
    pub v: u32,
    pub algorithm: String,
    pub name: String,
    pub seed: String,
}

/// A public key file stored on disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct PubKeyFile {
    pub v: u32,
    pub algorithm: String,
    pub name: String,
    pub pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub created_at: String,
}

/// Encrypt a signing key with Argon2id + XChaCha20-Poly1305.
pub fn encrypt_key(
    signing_key: &SigningKey,
    name: &str,
    passphrase: &str,
    kdf_params: &KdfParams,
) -> Result<EncryptedKeyFile, SignetError> {
    // Generate random salt (16 bytes) and nonce (24 bytes).
    let salt_bytes: [u8; 16] = {
        use chacha20poly1305::aead::rand_core::RngCore;
        let mut s = [0u8; 16];
        OsRng.fill_bytes(&mut s);
        s
    };
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    // Derive 32-byte key with Argon2id.
    let derived_key = derive_key(passphrase, &salt_bytes, kdf_params)?;
    let cipher_key = Key::from_slice(&derived_key);
    let cipher = XChaCha20Poly1305::new(cipher_key);

    // Build AAD from canonicalized header metadata.
    let aad = build_aad(name, kdf_params)?;

    // The plaintext is the 32-byte seed.
    let seed = signing_key.to_bytes();

    let ciphertext = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: &seed,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| SignetError::DecryptionError)?;

    Ok(EncryptedKeyFile {
        v: 1,
        algorithm: "ed25519".to_string(),
        name: name.to_string(),
        kdf: "argon2id".to_string(),
        kdf_params: kdf_params.clone(),
        salt: B64.encode(salt_bytes),
        cipher: "xchacha20poly1305".to_string(),
        nonce: B64.encode(nonce.as_slice()),
        ciphertext: B64.encode(&ciphertext),
    })
}

/// Decrypt a signing key from an EncryptedKeyFile.
pub fn decrypt_key(file: &EncryptedKeyFile, passphrase: &str) -> Result<SigningKey, SignetError> {
    let salt_bytes = B64
        .decode(&file.salt)
        .map_err(|e| SignetError::CorruptedFile(format!("invalid salt base64: {e}")))?;
    let nonce_bytes = B64
        .decode(&file.nonce)
        .map_err(|e| SignetError::CorruptedFile(format!("invalid nonce base64: {e}")))?;
    let ciphertext = B64
        .decode(&file.ciphertext)
        .map_err(|e| SignetError::CorruptedFile(format!("invalid ciphertext base64: {e}")))?;

    if nonce_bytes.len() != 24 {
        return Err(SignetError::CorruptedFile(format!(
            "invalid nonce length: expected 24, got {}",
            nonce_bytes.len()
        )));
    }
    let nonce = XNonce::from_slice(&nonce_bytes);
    let derived_key = derive_key(passphrase, &salt_bytes, &file.kdf_params)?;
    let cipher_key = Key::from_slice(&derived_key);
    let cipher = XChaCha20Poly1305::new(cipher_key);

    let aad = build_aad(&file.name, &file.kdf_params)?;

    let seed_bytes = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| SignetError::DecryptionError)?;

    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| SignetError::CorruptedFile("seed is not 32 bytes".to_string()))?;

    Ok(SigningKey::from_bytes(&seed))
}

/// Encode a signing key without encryption.
pub fn encode_unencrypted(signing_key: &SigningKey, name: &str) -> UnencryptedKeyFile {
    UnencryptedKeyFile {
        v: 1,
        algorithm: "ed25519".to_string(),
        name: name.to_string(),
        seed: B64.encode(signing_key.to_bytes()),
    }
}

/// Decode an unencrypted key file into a SigningKey.
pub fn decode_unencrypted(file: &UnencryptedKeyFile) -> Result<SigningKey, SignetError> {
    let seed_bytes = B64
        .decode(&file.seed)
        .map_err(|e| SignetError::CorruptedFile(format!("invalid seed base64: {e}")))?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| SignetError::CorruptedFile("seed is not 32 bytes".to_string()))?;
    Ok(SigningKey::from_bytes(&seed))
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn derive_key(passphrase: &str, salt: &[u8], params: &KdfParams) -> Result<[u8; 32], SignetError> {
    let argon2_params = Params::new(params.m, params.t, params.p, Some(32))
        .map_err(|e| SignetError::CorruptedFile(format!("invalid argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|e| SignetError::CorruptedFile(format!("argon2 failed: {e}")))?;
    Ok(output)
}

fn build_aad(name: &str, kdf_params: &KdfParams) -> Result<String, SignetError> {
    let header = json!({
        "v": 1,
        "algorithm": "ed25519",
        "name": name,
        "kdf": "argon2id",
        "kdf_params": {
            "m": kdf_params.m,
            "p": kdf_params.p,
            "t": kdf_params.t
        },
        "cipher": "xchacha20poly1305"
    });
    crate::canonical::canonicalize(&header)
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::SigningKey as DalekSigningKey;
    use rand::rngs::OsRng as RandOsRng;

    fn random_signing_key() -> SigningKey {
        DalekSigningKey::generate(&mut RandOsRng)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sk = random_signing_key();
        let params = KdfParams::test_default();
        let file = encrypt_key(&sk, "test-key", "hunter2", &params).unwrap();
        let recovered = decrypt_key(&file, "hunter2").unwrap();
        assert_eq!(sk.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_wrong_passphrase() {
        let sk = random_signing_key();
        let params = KdfParams::test_default();
        let file = encrypt_key(&sk, "test-key", "correct", &params).unwrap();
        let result = decrypt_key(&file, "wrong");
        assert!(matches!(result, Err(SignetError::DecryptionError)));
    }

    #[test]
    fn test_unencrypted_roundtrip() {
        let sk = random_signing_key();
        let file = encode_unencrypted(&sk, "plain-key");
        let recovered = decode_unencrypted(&file).unwrap();
        assert_eq!(sk.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let sk = random_signing_key();
        let params = KdfParams::test_default();
        let mut file = encrypt_key(&sk, "test-key", "pass", &params).unwrap();
        // Corrupt the ciphertext by changing a byte.
        let mut ct = B64.decode(&file.ciphertext).unwrap();
        ct[0] ^= 0xFF;
        file.ciphertext = B64.encode(&ct);
        let result = decrypt_key(&file, "pass");
        assert!(matches!(result, Err(SignetError::DecryptionError)));
    }
}
