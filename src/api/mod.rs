pub mod routes;
pub mod models;
pub mod errors;
pub mod auth;

use std::sync::Arc;
use axum::Router;
use dashmap::DashMap;
use tokio::sync::RwLock;
use crate::db::Database;
use crate::errors::SekuraError;
use crate::pipeline::state::PipelineState;
use tokio_util::sync::CancellationToken;
use tokio::task::JoinHandle;
use crate::pipeline::state::PipelineSummary;

pub struct PipelineHandle {
    pub state: Arc<RwLock<PipelineState>>,
    pub cancel_token: CancellationToken,
}

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub active_scans: Arc<DashMap<String, Arc<PipelineHandle>>>,
    pub max_concurrent_scans: usize,
}

pub async fn create_app_state(db_path: &str, max_workers: usize) -> Result<AppState, SekuraError> {
    let db = Database::new(db_path)?;
    Ok(AppState {
        db,
        active_scans: Arc::new(DashMap::new()),
        max_concurrent_scans: max_workers,
    })
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", axum::routing::get(routes::health::health_check))
        .route("/api/scans", axum::routing::post(routes::scans::create_scan).get(routes::scans::list_scans))
        .route("/api/scans/{id}", axum::routing::get(routes::scans::get_scan).delete(routes::scans::delete_scan))
        .route("/api/scans/{id}/status", axum::routing::get(routes::status::get_status))
        .route("/api/scans/{id}/report", axum::routing::get(routes::reports::get_report))
        .route("/api/scans/{id}/findings", axum::routing::get(routes::scans::get_findings))
        .route("/api/scans/{id}/stop", axum::routing::post(routes::scans::stop_scan))
        .route("/api/settings", axum::routing::get(routes::settings::get_settings).put(routes::settings::update_settings))
        .with_state(state)
}
