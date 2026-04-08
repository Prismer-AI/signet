mod api;
mod static_files;

use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub signet_dir: PathBuf,
    pub dev: bool,
}

pub fn router(state: AppState) -> axum::Router {
    let shared = Arc::new(state);
    axum::Router::new()
        .nest("/api", api::routes(shared.clone()))
        .fallback(static_files::handler)
        .with_state(shared)
}
