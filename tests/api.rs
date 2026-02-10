use axum::http::StatusCode;
use axum::body::Body;
use http_body_util::BodyExt;
use tower::ServiceExt;
use serde_json::{json, Value};
use sekura::db::Database;
use sekura::api::{build_router, AppState};
use std::sync::Arc;
use dashmap::DashMap;

fn create_test_state() -> AppState {
    let db = Database::in_memory().unwrap();
    AppState {
        db,
        active_scans: Arc::new(DashMap::new()),
        max_concurrent_scans: 4,
    }
}

fn app(state: &AppState) -> axum::Router {
    build_router(state.clone())
}

fn make_request(method: &str, uri: &str, body: Option<Value>) -> axum::http::Request<Body> {
    let builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    match body {
        Some(b) => builder.body(Body::from(serde_json::to_string(&b).unwrap())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

async fn response_json(response: axum::http::Response<Body>) -> Value {
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    if bytes.is_empty() {
        panic!("Empty response body. Status: {}, Headers: {:?}", parts.status, parts.headers);
    }
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("JSON parse error: {}. Body: {:?}", e, String::from_utf8_lossy(&bytes)))
}

#[tokio::test]
async fn test_health_endpoint() {
    let state = create_test_state();
    let req = make_request("GET", "/api/health", None);
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response_json(response).await;
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["service"], "sekura");
}

#[tokio::test]
async fn test_create_and_get_scan() {
    let state = create_test_state();

    // Create scan
    let req = make_request("POST", "/api/scans", Some(json!({
        "target": "http://example.com"
    })));
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response_json(response).await;
    let scan_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["status"], "queued");
    assert_eq!(body["target"], "http://example.com");

    // Get scan
    let req = make_request("GET", &format!("/api/scans/{}", scan_id), None);
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response_json(response).await;
    assert_eq!(body["id"], scan_id);
    assert_eq!(body["target"], "http://example.com");
}

#[tokio::test]
async fn test_list_scans() {
    let state = create_test_state();

    // Create two scans
    for target in &["http://a.com", "http://b.com"] {
        let req = make_request("POST", "/api/scans", Some(json!({ "target": target })));
        let response = app(&state).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    // List scans
    let req = make_request("GET", "/api/scans", None);
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response_json(response).await;
    let scans = body["scans"].as_array().unwrap();
    assert_eq!(scans.len(), 2);
}

#[tokio::test]
async fn test_delete_scan() {
    let state = create_test_state();

    // Create scan
    let req = make_request("POST", "/api/scans", Some(json!({ "target": "http://del.com" })));
    let response = app(&state).oneshot(req).await.unwrap();
    let body = response_json(response).await;
    let scan_id = body["id"].as_str().unwrap().to_string();

    // Delete scan
    let req = make_request("DELETE", &format!("/api/scans/{}", scan_id), None);
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // GET should return 404
    let req = make_request("GET", &format!("/api/scans/{}", scan_id), None);
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_scan_not_found() {
    let state = create_test_state();
    let req = make_request("GET", "/api/scans/nonexistent-id", None);
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = response_json(response).await;
    assert_eq!(body["error"], "Scan not found");
}

#[tokio::test]
async fn test_get_findings_empty() {
    let state = create_test_state();

    // Create scan
    let req = make_request("POST", "/api/scans", Some(json!({ "target": "http://findings.com" })));
    let response = app(&state).oneshot(req).await.unwrap();
    let body = response_json(response).await;
    let scan_id = body["id"].as_str().unwrap().to_string();

    // Get findings (should be empty - no findings.json on disk)
    let req = make_request("GET", &format!("/api/scans/{}/findings", scan_id), None);
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response_json(response).await;
    assert_eq!(body["total"], 0);
    assert!(body["findings"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_get_findings_not_found() {
    let state = create_test_state();
    let req = make_request("GET", "/api/scans/nonexistent/findings", None);
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_settings() {
    let state = create_test_state();
    let req = make_request("GET", "/api/settings", None);
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response_json(response).await;
    assert!(body.is_object());
}

#[tokio::test]
async fn test_update_settings() {
    let state = create_test_state();

    // Update settings
    let req = make_request("PUT", "/api/settings", Some(json!({
        "provider": "openai",
        "model": "gpt-4"
    })));
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Get settings to verify
    let req = make_request("GET", "/api/settings", None);
    let response = app(&state).oneshot(req).await.unwrap();
    let body = response_json(response).await;
    assert_eq!(body["provider"], "openai");
    assert_eq!(body["model"], "gpt-4");
}

#[tokio::test]
async fn test_stop_scan_not_found() {
    let state = create_test_state();
    let req = make_request("POST", "/api/scans/nonexistent/stop", None);
    let response = app(&state).oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
