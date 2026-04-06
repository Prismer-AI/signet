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
pub use receipt::{
    Action, BilateralReceipt, CompoundReceipt, Receipt, Response, ServerInfo, Signer,
};
pub use sign::{sign, sign_bilateral, sign_compound};
pub use verify::{
    verify, verify_any, verify_bilateral, verify_bilateral_with_options, verify_compound,
    BilateralVerifyOptions,
};

#[cfg(not(target_arch = "wasm32"))]
pub use identity::fs_ops::{
    default_signet_dir, export_public_key, generate_and_save, list_keys, load_key_info,
    load_signing_key, load_verifying_key, validate_key_name, KeyInfo,
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
            session: None,
            call_id: None,
            response_hash: None,
        }
    }
}
