use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
    Json,
};
use serde_json::json;

pub async fn api_auth_middleware(
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Check for API token if SEKURA_API_TOKEN is set
    if let Ok(expected_token) = std::env::var("SEKURA_API_TOKEN") {
        if !expected_token.is_empty() {
            let auth_header = request.headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok());

            match auth_header {
                Some(header) if header.starts_with("Bearer ") => {
                    let token = &header[7..];
                    if token != expected_token {
                        return Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid API token"}))));
                    }
                }
                _ => {
                    return Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "Missing Authorization header"}))));
                }
            }
        }
    }

    Ok(next.run(request).await)
}
