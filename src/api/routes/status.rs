use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use crate::api::AppState;

pub async fn get_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check active scans first
    if let Some(handle) = state.active_scans.get(&id) {
        let pipeline_state = handle.state.read().await;
        return Ok(Json(json!({
            "id": id,
            "status": format!("{:?}", pipeline_state.status).to_lowercase(),
            "current_phase": pipeline_state.current_phase.map(|p| p.to_string()),
            "current_agents": pipeline_state.current_agents,
            "completed_agents": pipeline_state.completed_agents,
            "elapsed_ms": (chrono::Utc::now() - pipeline_state.start_time).num_milliseconds(),
            "error": pipeline_state.error,
        })));
    }

    // Fall back to database
    match state.db.get_scan(&id) {
        Ok(Some(scan)) => Ok(Json(json!({
            "id": id,
            "status": scan["status"],
            "current_phase": scan["current_phase"],
            "completed_agents": [],
            "error": scan["error"],
        }))),
        Ok(None) => Err((StatusCode::NOT_FOUND, Json(json!({"error": "Scan not found"})))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()})))),
    }
}
