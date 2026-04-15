use crate::delegation::Authorization;
use crate::policy::PolicyAttestation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub tool: String,
    pub params: serde_json::Value,
    pub params_hash: String,
    pub target: String,
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    /// Workflow-level trace ID for grouping related tool calls.
    /// Inside the signature scope — the causal link is cryptographically attested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Receipt ID of the parent action (for causal chaining within a workflow).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyAttestation>,
    pub ts: String,
    /// Optional expiration time (RFC 3339). Inside the signature scope.
    /// Absent = no expiration declared (backward compatible with pre-exp receipts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
    pub nonce: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub content_hash: String, // sha256(JCS(response_content))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundReceipt {
    pub v: u8, // always 2
    pub id: String,
    pub action: Action, // same type as v1
    pub response: Response,
    pub signer: Signer, // same type as v1
    pub ts_request: String,
    pub ts_response: String,
    pub nonce: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub pubkey: String, // "ed25519:<base64>"
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BilateralReceipt {
    pub v: u8, // always 3
    pub id: String,
    pub agent_receipt: Receipt, // embedded v1 receipt verbatim
    pub response: Response,
    pub server: ServerInfo,
    pub ts_response: String,
    pub nonce: String,
    pub sig: String, // server signs entire v3 body
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>, // unsigned, outside sig scope
}
