pub mod canonical;
pub mod error;
pub mod identity;
pub mod receipt;
pub mod sign;
pub mod verify;

pub use error::SignetError;
pub use identity::generate_keypair;
pub use receipt::{Action, Receipt, Signer};
pub use sign::sign;
pub use verify::verify;

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
