use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
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
        limit: Some(q.limit.unwrap_or(200).min(MAX_LIMIT)),
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
    Ok(Json(serde_json::to_value(records).map_err(|e| AppError::internal(format!("{e}")))?))
}

async fn get_chain_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let dir = state.signet_dir.clone();
    let status = tokio::task::spawn_blocking(move || audit::verify_chain(&dir))
        .await
        .map_err(|e| AppError::internal(format!("task join: {e}")))?
        .map_err(|e| AppError::internal(format!("{e}")))?;
    Ok(Json(serde_json::to_value(status).map_err(|e| AppError::internal(format!("{e}")))?))
}

async fn get_verify_signatures(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RecordQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let dir = state.signet_dir.clone();
    let filter = build_filter(&q)?;
    let result = tokio::task::spawn_blocking(move || audit::verify_signatures(&dir, &filter))
        .await
        .map_err(|e| AppError::internal(format!("task join: {e}")))?
        .map_err(|e| AppError::internal(format!("{e}")))?;
    Ok(Json(serde_json::to_value(result).map_err(|e| AppError::internal(format!("{e}")))?))
}

#[derive(Serialize)]
struct Stats {
    total_records: usize,
    truncated: bool,
    by_tool: HashMap<String, usize>,
    by_signer: HashMap<String, usize>,
    by_version: HashMap<String, usize>,
    earliest: Option<String>,
    latest: Option<String>,
}

async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Stats>, AppError> {
    let dir = state.signet_dir.clone();
    let records = tokio::task::spawn_blocking(move || {
        let filter = AuditFilter {
            limit: Some(MAX_LIMIT),
            ..Default::default()
        };
        audit::query(&dir, &filter)
    })
    .await
    .map_err(|e| AppError::internal(format!("task join: {e}")))?
    .map_err(|e| AppError::internal(format!("{e}")))?;

    let truncated = records.len() >= MAX_LIMIT;
    let mut by_tool: HashMap<String, usize> = HashMap::new();
    let mut by_signer: HashMap<String, usize> = HashMap::new();
    let mut by_version: HashMap<String, usize> = HashMap::new();
    let mut earliest: Option<String> = None;
    let mut latest: Option<String> = None;

    for record in &records {
        let r = &record.receipt;
        if let Some(tool) = audit::extract_tool(r) {
            *by_tool.entry(tool.to_string()).or_default() += 1;
        }
        if let Some(name) = audit::extract_signer_name(r) {
            *by_signer.entry(name.to_string()).or_default() += 1;
        }
        if let Some(v) = r.get("v").and_then(|v| v.as_u64()) {
            *by_version.entry(format!("v{v}")).or_default() += 1;
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
        by_version,
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
        Self { status: StatusCode::BAD_REQUEST, message }
    }

    fn internal(message: String) -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, message }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, Json(body)).into_response()
    }
}
