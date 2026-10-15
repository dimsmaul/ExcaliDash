use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

use crate::state::AppState;

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "database": "ok"})),
        ),
        Err(err) => {
            tracing::error!(%err, "health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status": "error", "database": "unavailable"})),
            )
        }
    }
}
