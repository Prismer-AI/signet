use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
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
