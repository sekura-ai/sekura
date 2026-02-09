use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use crate::api::AppState;

pub async fn get_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check if report exists on disk
    let report_path = std::path::PathBuf::from("./results")
        .join(&id)
        .join("deliverables")
        .join("comprehensive_security_assessment_report.md");

    if report_path.exists() {
        match tokio::fs::read_to_string(&report_path).await {
            Ok(content) => Ok(Json(json!({
                "id": id,
                "report": content,
                "format": "markdown",
            }))),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()})))),
        }
    } else {
        match state.db.get_scan(&id) {
            Ok(Some(scan)) if scan["status"] == "completed" => {
                Err((StatusCode::NOT_FOUND, Json(json!({"error": "Report file not found"}))))
            }
            Ok(Some(_)) => {
                Err((StatusCode::CONFLICT, Json(json!({"error": "Scan not yet completed"}))))
            }
            _ => Err((StatusCode::NOT_FOUND, Json(json!({"error": "Scan not found"})))),
        }
    }
}
