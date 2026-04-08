use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};

use super::AppState;

const INDEX_HTML: &str = include_str!("../../static/index.html");

pub async fn handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.dev {
        let path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static/index.html");
        match std::fs::read_to_string(&path) {
            Ok(html) => Html(html).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    } else {
        Html(INDEX_HTML.to_string()).into_response()
    }
}
