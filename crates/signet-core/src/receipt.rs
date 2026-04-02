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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub content_hash: String, // sha256(JCS(response_content))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundReceipt {
    pub v: u8,               // always 2
    pub id: String,
    pub action: Action,      // same type as v1
    pub response: Response,
    pub signer: Signer,      // same type as v1
    pub ts_request: String,
    pub ts_response: String,
    pub nonce: String,
    pub sig: String,
}
