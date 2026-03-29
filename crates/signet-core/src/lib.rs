pub mod canonical;
pub mod error;
pub mod identity;
pub mod receipt;
pub mod sign;
pub mod verify;

#[cfg(not(target_arch = "wasm32"))]
pub mod keystore;

#[cfg(not(target_arch = "wasm32"))]
pub mod audit;

pub use error::SignetError;
pub use identity::generate_keypair;
pub use receipt::{Action, Receipt, Signer};
pub use sign::sign;
pub use verify::verify;

#[cfg(not(target_arch = "wasm32"))]
pub use identity::fs_ops::{
    KeyInfo, default_signet_dir, validate_key_name, generate_and_save,
    load_key_info, load_signing_key, load_verifying_key, list_keys, export_public_key,
};

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::receipt::Action;
    use serde_json::json;

    pub fn test_action() -> Action {
        Action {
            tool: "github_create_issue".to_string(),
            params: json!({"title": "fix bug", "body": "details"}),
            params_hash: String::new(),
            target: "mcp://github.local".to_string(),
            transport: "stdio".to_string(),
        }
    }
}
