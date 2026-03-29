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
}
