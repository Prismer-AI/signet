use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use signet_core::audit::{self, AuditFilter};

use super::AppState;

pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
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
        .map_err(|e| AppError(anyhow::anyhow!("{e}")))?;
    Ok(AuditFilter {
        since,
        tool: q.tool.clone(),
        signer: q.signer.clone(),
        limit: q.limit,
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
        .map_err(|e| AppError(anyhow::anyhow!("task join: {e}")))??;
    Ok(Json(serde_json::to_value(records)?))
}

async fn get_chain_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let dir = state.signet_dir.clone();
    let status = tokio::task::spawn_blocking(move || audit::verify_chain(&dir))
        .await
        .map_err(|e| AppError(anyhow::anyhow!("task join: {e}")))??;
    Ok(Json(serde_json::to_value(status)?))
}

async fn get_verify_signatures(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RecordQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let dir = state.signet_dir.clone();
    let filter = build_filter(&q)?;
    let result = tokio::task::spawn_blocking(move || audit::verify_signatures(&dir, &filter))
        .await
        .map_err(|e| AppError(anyhow::anyhow!("task join: {e}")))??;
    Ok(Json(serde_json::to_value(result)?))
}

#[derive(Serialize)]
struct Stats {
    total_records: usize,
    by_tool: HashMap<String, usize>,
    by_signer: HashMap<String, usize>,
    by_version: HashMap<u8, usize>,
    earliest: Option<String>,
    latest: Option<String>,
}

async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Stats>, AppError> {
    let dir = state.signet_dir.clone();
    let records = tokio::task::spawn_blocking(move || {
        let filter = AuditFilter {
            limit: Some(10_000),
            ..Default::default()
        };
        audit::query(&dir, &filter)
    })
    .await
    .map_err(|e| AppError(anyhow::anyhow!("task join: {e}")))??;

    let mut by_tool: HashMap<String, usize> = HashMap::new();
    let mut by_signer: HashMap<String, usize> = HashMap::new();
    let mut by_version: HashMap<u8, usize> = HashMap::new();
    let mut earliest: Option<String> = None;
    let mut latest: Option<String> = None;

    for record in &records {
        let r = &record.receipt;
        if let Some(tool) = r.get("action").and_then(|a| a.get("tool")).and_then(|t| t.as_str()) {
            *by_tool.entry(tool.to_string()).or_default() += 1;
        }
        if let Some(name) = r.get("signer").and_then(|s| s.get("name")).and_then(|n| n.as_str()) {
            *by_signer.entry(name.to_string()).or_default() += 1;
        }
        if let Some(v) = r.get("v").and_then(|v| v.as_u64()) {
            *by_version.entry(v as u8).or_default() += 1;
        }
        if let Some(ts) = r.get("ts").and_then(|t| t.as_str()) {
            if earliest.as_ref().map_or(true, |e| ts < e.as_str()) {
                earliest = Some(ts.to_string());
            }
            if latest.as_ref().map_or(true, |l| ts > l.as_str()) {
                latest = Some(ts.to_string());
            }
        }
    }

    Ok(Json(Stats {
        total_records: records.len(),
        by_tool,
        by_signer,
        by_version,
        earliest,
        latest,
    }))
}

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({ "error": self.0.to_string() });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        AppError(err.into())
    }
}
