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

/// Final status of the action covered by a v2 compound or v3 bilateral
/// receipt. Distinguishes "intent was signed" from "what happened next".
///
/// v1 (unilateral) receipts deliberately do NOT carry an outcome — they
/// represent intent only. Only v2/v3 receipts can include an outcome,
/// because both versions are produced AFTER execution and have a
/// `Response` envelope to attach it to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    /// Signature and policy verified; not yet executed.
    /// (Reserved — typical v2/v3 receipts skip straight to executed/failed.)
    Verified,
    /// Policy or pre-execution check rejected the action.
    /// `reason` SHOULD be set.
    Rejected,
    /// Action was executed and produced a response.
    Executed,
    /// Execution started but failed. `error` SHOULD be set.
    Failed,
}

/// Optional outcome attached to a v2/v3 receipt response envelope.
/// Inside the signature scope — tampering invalidates the receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outcome {
    pub status: OutcomeStatus,
    /// Human-readable rejection reason (when status == rejected).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Error type or message (when status == failed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Outcome {
    pub fn executed() -> Self {
        Self {
            status: OutcomeStatus::Executed,
            reason: None,
            error: None,
        }
    }
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            status: OutcomeStatus::Rejected,
            reason: Some(reason.into()),
            error: None,
        }
    }
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            status: OutcomeStatus::Failed,
            reason: None,
            error: Some(error.into()),
        }
    }
    pub fn verified() -> Self {
        Self {
            status: OutcomeStatus::Verified,
            reason: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub content_hash: String, // sha256(JCS(response_content))
    /// Optional final outcome. Inside the signature scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
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
