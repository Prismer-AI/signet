use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub tool: String,
    pub params: serde_json::Value,
    pub params_hash: String,
    pub target: String,
    pub transport: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signer {
    pub pubkey: String,
    pub name: String,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub v: u8,
    pub id: String,
    pub action: Action,
    pub signer: Signer,
    pub ts: String,
    pub nonce: String,
    pub sig: String,
}
