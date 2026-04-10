#[derive(Debug, thiserror::Error)]
pub enum SignetError {
    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("signature verification failed")]
    SignatureMismatch,

    #[error("failed to canonicalize JSON: {0}")]
    CanonicalizeError(String),

    #[error("invalid receipt: {0}")]
    InvalidReceipt(String),

    #[error("serialization error: {0}")]
    SerializeError(#[from] serde_json::Error),

    #[error("delegation scope violation: {0}")]
    ScopeViolation(String),

    #[error("delegation chain invalid: {0}")]
    ChainError(String),

    #[error("delegation token expired at {0}")]
    DelegationExpired(String),

    #[error("action not authorized: {0}")]
    Unauthorized(String),

    #[error("policy violation: {0}")]
    PolicyViolation(String),

    #[error("policy parse error: {0}")]
    PolicyParseError(String),

    #[error("action requires human approval: {0}")]
    RequiresApproval(String),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("key already exists: {0}")]
    KeyExists(String),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("invalid key name: {0} (must match [a-zA-Z0-9_-]+)")]
    InvalidName(String),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("decryption failed: wrong passphrase or corrupted key")]
    DecryptionError,

    #[cfg(not(target_arch = "wasm32"))]
    #[error("corrupted key file: {0}")]
    CorruptedFile(String),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("corrupted audit record: {0}")]
    CorruptedRecord(String),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("unsupported key format: {0}")]
    UnsupportedFormat(String),
}
