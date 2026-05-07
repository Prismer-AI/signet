use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use signet_core::audit::{self, AuditFilter};

use super::AppState;

const MAX_LIMIT: usize = 10_000;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/records", get(get_records))
        .route("/chain-status", get(get_chain_status))
        .route("/verify-signatures", get(get_verify_signatures))
        .route("/stats", get(get_stats))
}

#[derive(Deserialize)]
struct RecordQuery {
    since: Option<String>,
    tool: Option<String>,
    signer: Option<String>,
    limit: Option<usize>,
    trusted_agent_key: Option<String>,
    trusted_server_key: Option<String>,
}

fn build_filter(q: &RecordQuery) -> Result<AuditFilter, AppError> {
    let since = q
        .since
        .as_deref()
        .map(audit::parse_since)
        .transpose()
        .map_err(|e| AppError::bad_request(format!("{e}")))?;
    Ok(AuditFilter {
        since,
        tool: q.tool.clone(),
        signer: q.signer.clone(),
        limit: Some(q.limit.unwrap_or(200).clamp(1, MAX_LIMIT)),
    })
}

fn resolve_pubkey(dir: &std::path::Path, key_ref: &str) -> Result<VerifyingKey, AppError> {
    let key_path = std::path::Path::new(key_ref);
    if key_ref.ends_with(".pub") || key_path.exists() {
        let content =
            fs::read_to_string(key_ref).map_err(|e| AppError::bad_request(format!("{e}")))?;
        let pub_file: signet_core::keystore::PubKeyFile =
            serde_json::from_str(&content).map_err(|e| AppError::bad_request(format!("{e}")))?;
        let b64 = pub_file
            .pubkey
            .strip_prefix("ed25519:")
            .unwrap_or(&pub_file.pubkey);
        let bytes = BASE64
            .decode(b64)
            .map_err(|e| AppError::bad_request(format!("{e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AppError::bad_request("pubkey is not 32 bytes".to_string()))?;
        return VerifyingKey::from_bytes(&arr).map_err(|e| AppError::bad_request(format!("{e}")));
    }

    if let Ok(vk) = signet_core::load_verifying_key(dir, key_ref) {
        return Ok(vk);
    }

    let b64 = key_ref.strip_prefix("ed25519:").unwrap_or(key_ref);
    let bytes = BASE64.decode(b64).map_err(|e| {
        AppError::bad_request(format!(
            "'{}' is not a key name or valid base64: {}",
            key_ref, e
        ))
    })?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppError::bad_request("pubkey is not 32 bytes".to_string()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| AppError::bad_request(format!("{e}")))
}

fn split_key_refs(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or("")
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn resolve_pubkeys(
    dir: &std::path::Path,
    key_refs: &[String],
) -> Result<Vec<VerifyingKey>, AppError> {
    key_refs
        .iter()
        .map(|key| resolve_pubkey(dir, key))
        .collect()
}

fn build_verify_options(
    dir: &std::path::Path,
    q: &RecordQuery,
) -> Result<audit::AuditVerifyOptions, AppError> {
    let trusted_agent_keys = split_key_refs(q.trusted_agent_key.as_deref());
    let trusted_server_keys = split_key_refs(q.trusted_server_key.as_deref());
    Ok(audit::AuditVerifyOptions {
        trusted_agent_pubkeys: resolve_pubkeys(dir, &trusted_agent_keys)?,
        trusted_server_pubkeys: resolve_pubkeys(dir, &trusted_server_keys)?,
    })
}

async fn get_records(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RecordQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let dir = state.signet_dir.clone();
    let filter = build_filter(&q)?;
    let records = tokio::task::spawn_blocking(move || audit::query(&dir, &filter))
        .await
        .map_err(|e| AppError::internal(format!("task join: {e}")))?
        .map_err(|e| AppError::internal(format!("{e}")))?;
    Ok(Json(
        serde_json::to_value(records).map_err(|e| AppError::internal(format!("{e}")))?,
    ))
}

async fn get_chain_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let dir = state.signet_dir.clone();
    let status = tokio::task::spawn_blocking(move || audit::verify_chain(&dir))
        .await
        .map_err(|e| AppError::internal(format!("task join: {e}")))?
        .map_err(|e| AppError::internal(format!("{e}")))?;
    Ok(Json(
        serde_json::to_value(status).map_err(|e| AppError::internal(format!("{e}")))?,
    ))
}

async fn get_verify_signatures(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RecordQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let dir = state.signet_dir.clone();
    let filter = build_filter(&q)?;
    let options = build_verify_options(&dir, &q)?;
    let result = tokio::task::spawn_blocking(move || {
        audit::verify_signatures_with_options(&dir, &filter, &options)
    })
    .await
    .map_err(|e| AppError::internal(format!("task join: {e}")))?
    .map_err(|e| AppError::internal(format!("{e}")))?;
    Ok(Json(
        serde_json::to_value(result).map_err(|e| AppError::internal(format!("{e}")))?,
    ))
}

#[derive(Serialize)]
struct Stats {
    total_records: usize,
    truncated: bool,
    by_tool: HashMap<String, usize>,
    by_signer: HashMap<String, usize>,
    by_record_type: HashMap<String, usize>,
    by_outcome: HashMap<String, usize>,
    by_version: HashMap<String, usize>,
    by_authorization: HashMap<String, usize>,
    by_policy_decision: HashMap<String, usize>,
    earliest: Option<String>,
    latest: Option<String>,
}

fn stats_signer_name(receipt: &serde_json::Value) -> Option<&str> {
    audit::extract_signer_name(receipt)
}

async fn get_stats(State(state): State<Arc<AppState>>) -> Result<Json<Stats>, AppError> {
    let dir = state.signet_dir.clone();
    let mut records = tokio::task::spawn_blocking(move || {
        let filter = AuditFilter {
            limit: Some(MAX_LIMIT + 1),
            ..Default::default()
        };
        audit::query(&dir, &filter)
    })
    .await
    .map_err(|e| AppError::internal(format!("task join: {e}")))?
    .map_err(|e| AppError::internal(format!("{e}")))?;

    let truncated = records.len() > MAX_LIMIT;
    if truncated {
        records.truncate(MAX_LIMIT);
    }
    let mut by_tool: HashMap<String, usize> = HashMap::new();
    let mut by_signer: HashMap<String, usize> = HashMap::new();
    let mut by_record_type: HashMap<String, usize> = HashMap::new();
    let mut by_outcome: HashMap<String, usize> = HashMap::new();
    let mut by_version: HashMap<String, usize> = HashMap::new();
    let mut by_authorization: HashMap<String, usize> = HashMap::new();
    let mut by_policy_decision: HashMap<String, usize> = HashMap::new();
    let mut earliest: Option<String> = None;
    let mut latest: Option<String> = None;

    for record in &records {
        let r = &record.receipt;
        if let Some(tool) = audit::extract_tool(r) {
            *by_tool.entry(tool.to_string()).or_default() += 1;
        }
        if let Some(name) = stats_signer_name(r) {
            *by_signer.entry(name.to_string()).or_default() += 1;
        }
        *by_record_type
            .entry(audit::extract_record_type(r).to_string())
            .or_default() += 1;
        if let Some(status) = audit::extract_outcome_status(r) {
            *by_outcome.entry(status.to_string()).or_default() += 1;
        }
        if let Some(v) = r.get("v").and_then(|v| v.as_u64()) {
            *by_version.entry(format!("v{v}")).or_default() += 1;
        }
        // Track delegated vs direct signing
        if audit::extract_record_type(r) == "receipt" {
            let has_auth = r.get("authorization").is_some();
            let auth_label = if has_auth { "delegated" } else { "direct" };
            *by_authorization.entry(auth_label.to_string()).or_default() += 1;
        }
        if let Some(decision) = audit::extract_policy_decision(r) {
            *by_policy_decision.entry(decision.to_string()).or_default() += 1;
        }
        if let Some(ts) = audit::extract_timestamp(r) {
            if earliest.as_ref().is_none_or(|e| ts < e.as_str()) {
                earliest = Some(ts.to_string());
            }
            if latest.as_ref().is_none_or(|l| ts > l.as_str()) {
                latest = Some(ts.to_string());
            }
        }
    }

    Ok(Json(Stats {
        total_records: records.len(),
        truncated,
        by_tool,
        by_signer,
        by_record_type,
        by_outcome,
        by_version,
        by_authorization,
        by_policy_decision,
        earliest,
        latest,
    }))
}

struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(message: String) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn internal(message: String) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use serde_json::Value;
    use tower::util::ServiceExt;

    fn bilateral_fixture(dir: &std::path::Path) -> (String, String) {
        let (agent_key, agent_vk) = signet_core::generate_keypair();
        let (server_key, server_vk) = signet_core::generate_keypair();
        let action = signet_core::Action {
            tool: "echo".to_string(),
            params: serde_json::json!({"message":"hello"}),
            params_hash: String::new(),
            target: "mcp://echo".to_string(),
            transport: "stdio".to_string(),
            session: None,
            call_id: None,
            response_hash: None,
            trace_id: None,
            parent_receipt_id: None,
        };
        let receipt = signet_core::sign(&agent_key, &action, "agent", "").unwrap();
        let bilateral = signet_core::sign_bilateral(
            &server_key,
            &receipt,
            &serde_json::json!({"ok": true}),
            "server",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
        .unwrap();
        signet_core::audit::append(dir, &serde_json::to_value(&bilateral).unwrap()).unwrap();
        (
            format!("ed25519:{}", BASE64.encode(agent_vk.as_bytes())),
            format!("ed25519:{}", BASE64.encode(server_vk.as_bytes())),
        )
    }

    fn stats_fixture(dir: &std::path::Path) {
        let (agent_key, _) = signet_core::generate_keypair();
        let (server_key, _) = signet_core::generate_keypair();
        let action = signet_core::Action {
            tool: "payments.refund".to_string(),
            params: serde_json::json!({"order_id":"ord_123","amount":49}),
            params_hash: String::new(),
            target: "mcp://payments".to_string(),
            transport: "stdio".to_string(),
            session: None,
            call_id: None,
            response_hash: None,
            trace_id: Some("tr_stats".to_string()),
            parent_receipt_id: None,
        };
        let receipt = signet_core::sign(&agent_key, &action, "agent", "").unwrap();
        signet_core::audit::append(dir, &serde_json::to_value(&receipt).unwrap()).unwrap();

        let bilateral = signet_core::sign_bilateral_with_outcome(
            &server_key,
            &receipt,
            &serde_json::json!({"blocked": true}),
            "server",
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            Some(signet_core::Outcome::requires_approval(
                "manager approval required",
            )),
        )
        .unwrap();
        signet_core::audit::append(dir, &serde_json::to_value(&bilateral).unwrap()).unwrap();

        let eval = signet_core::policy::PolicyEvalResult {
            decision: signet_core::policy::RuleAction::Deny,
            matched_rules: vec!["deny-refund".to_string()],
            winning_rule: Some("deny-refund".to_string()),
            reason: "refund exceeds threshold".to_string(),
            evaluated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            policy_name: "payments-prod".to_string(),
            policy_hash: "sha256:feedface".to_string(),
        };
        signet_core::audit::append_violation(dir, &action, "agent", &eval).unwrap();
    }

    #[tokio::test]
    async fn verify_signatures_api_warns_without_trust_anchors() {
        let dir = tempfile::tempdir().unwrap();
        bilateral_fixture(dir.path());
        let app = routes().with_state(Arc::new(AppState {
            signet_dir: dir.path().to_path_buf(),
            dev: false,
        }));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/verify-signatures")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["valid"].as_u64(), Some(1));
        assert_eq!(json["warnings"].as_array().map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn verify_signatures_api_accepts_trusted_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (agent_pubkey, server_pubkey) = bilateral_fixture(dir.path());
        let app = routes().with_state(Arc::new(AppState {
            signet_dir: dir.path().to_path_buf(),
            dev: false,
        }));

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/verify-signatures?trusted_agent_key={}&trusted_server_key={}",
                        agent_pubkey
                            .replace('+', "%2B")
                            .replace('/', "%2F")
                            .replace('=', "%3D"),
                        server_pubkey
                            .replace('+', "%2B")
                            .replace('/', "%2F")
                            .replace('=', "%3D")
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["valid"].as_u64(), Some(1));
        assert_eq!(json["warnings"].as_array().map(Vec::len), Some(0));
    }

    #[tokio::test]
    async fn verify_signatures_api_rejects_invalid_trusted_key() {
        let dir = tempfile::tempdir().unwrap();
        bilateral_fixture(dir.path());
        let app = routes().with_state(Arc::new(AppState {
            signet_dir: dir.path().to_path_buf(),
            dev: false,
        }));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/verify-signatures?trusted_server_key=not-a-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn stats_api_includes_outcomes_and_record_types() {
        let dir = tempfile::tempdir().unwrap();
        stats_fixture(dir.path());
        let app = routes().with_state(Arc::new(AppState {
            signet_dir: dir.path().to_path_buf(),
            dev: false,
        }));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total_records"].as_u64(), Some(3));
        assert_eq!(json["by_record_type"]["receipt"].as_u64(), Some(2));
        assert_eq!(json["by_record_type"]["policy_violation"].as_u64(), Some(1));
        assert_eq!(json["by_outcome"]["requires_approval"].as_u64(), Some(1));
        assert_eq!(json["by_policy_decision"]["deny"].as_u64(), Some(1));
    }
}
