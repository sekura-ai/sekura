use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use crate::api::AppState;
use crate::api::models::CreateScanRequest;

#[derive(Deserialize)]
pub struct ListQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn create_scan(
    State(state): State<AppState>,
    Json(req): Json<CreateScanRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let scan_id = uuid::Uuid::new_v4().to_string();

    state.db.create_scan(
        &scan_id,
        &req.target,
        req.repo_path.as_deref(),
        req.intensity.as_deref().unwrap_or("standard"),
        req.provider.as_deref().unwrap_or("anthropic"),
        req.model.as_deref(),
        None,
        req.webhook_url.as_deref(),
    ).map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": e.to_string()})),
    ))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": scan_id,
            "status": "queued",
            "target": req.target,
        })),
    ))
}

pub async fn list_scans(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let limit = query.limit.unwrap_or(20);
    let offset = query.offset.unwrap_or(0);

    let scans = state.db.list_scans(limit, offset)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

    Ok(Json(json!({ "scans": scans, "total": scans.len() })))
}

pub async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match state.db.get_scan(&id) {
        Ok(Some(scan)) => Ok(Json(scan)),
        Ok(None) => Err((StatusCode::NOT_FOUND, Json(json!({"error": "Scan not found"})))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()})))),
    }
}

pub async fn delete_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match state.db.delete_scan(&id) {
        Ok(true) => Ok(Json(json!({"deleted": true}))),
        Ok(false) => Err((StatusCode::NOT_FOUND, Json(json!({"error": "Scan not found"})))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()})))),
    }
}

pub async fn stop_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Some(handle) = state.active_scans.get(&id) {
        handle.cancel_token.cancel();
        Ok(Json(json!({"stopped": true})))
    } else {
        Err((StatusCode::NOT_FOUND, Json(json!({"error": "No active scan found"}))))
    }
}

pub async fn get_findings(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // First check the scan exists
    match state.db.get_scan(&id) {
        Ok(None) => return Err((StatusCode::NOT_FOUND, Json(json!({"error": "Scan not found"})))),
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()})))),
        Ok(Some(_)) => {}
    }

    // Try to read findings from disk (consistent with REPL /report findings)
    let findings_path = std::path::PathBuf::from("./results")
        .join(&id)
        .join("deliverables")
        .join("findings.json");

    if findings_path.exists() {
        match tokio::fs::read_to_string(&findings_path).await {
            Ok(content) => {
                match serde_json::from_str::<Vec<Value>>(&content) {
                    Ok(findings) => {
                        let total = findings.len();
                        Ok(Json(json!({"findings": findings, "total": total})))
                    }
                    Err(_) => Ok(Json(json!({"findings": [], "total": 0}))),
                }
            }
            Err(_) => Ok(Json(json!({"findings": [], "total": 0}))),
        }
    } else {
        Ok(Json(json!({"findings": [], "total": 0})))
    }
}
