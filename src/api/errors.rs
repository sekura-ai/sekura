use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use crate::errors::SekuraError;

impl IntoResponse for SekuraError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            SekuraError::Config(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            SekuraError::Authentication(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            SekuraError::Permission(_) => (StatusCode::FORBIDDEN, self.to_string()),
            SekuraError::InvalidTarget(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        (status, Json(json!({"error": message}))).into_response()
    }
}
