//! Health, per-user Excalidraw library, and the update-check endpoint.

use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};

use crate::{
    auth::middleware::RequireUser,
    drawing::parse_json_field,
    error::{AppError, AppResult},
    state::AppState,
    time::NOW_UTC,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/library", get(get_library).put(put_library))
        .route("/system/update", get(system_update))
}

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

fn library_id(user_id: &str) -> String {
    format!("user_{user_id}")
}

/// `GET /library`
async fn get_library(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
) -> AppResult<Json<Value>> {
    let items: Option<String> = sqlx::query_scalar(r#"SELECT items FROM "Library" WHERE id = $1"#)
        .bind(library_id(&user.id))
        .fetch_optional(&state.db)
        .await?;
    let items = items.map_or(json!([]), |raw| parse_json_field(&raw, json!([])));
    Ok(Json(json!({ "items": items })))
}

/// `PUT /library` `{items: []}`
async fn put_library(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    let items = body
        .and_then(|Json(b)| b.get("items").filter(|i| i.is_array()).cloned())
        .ok_or_else(|| {
            AppError::json(
                StatusCode::BAD_REQUEST,
                json!({ "error": "Items must be an array" }),
            )
        })?;
    let stored: String = sqlx::query_scalar(&format!(
        r#"INSERT INTO "Library" (id, items, "createdAt", "updatedAt") VALUES ($1, $2, {NOW_UTC}, {NOW_UTC})
           ON CONFLICT (id) DO UPDATE SET items = EXCLUDED.items, "updatedAt" = {NOW_UTC}
           RETURNING items"#
    ))
    .bind(library_id(&user.id))
    .bind(items.to_string())
    .fetch_one(&state.db)
    .await?;
    Ok(Json(
        json!({ "items": parse_json_field(&stored, json!([])) }),
    ))
}

/// `GET /system/update`: outbound release checks are disabled in this backend.
async fn system_update(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let channel = match query.get("channel").map(|c| c.trim().to_lowercase()) {
        Some(c) if c == "prerelease" => "prerelease",
        _ => "stable",
    };
    Json(json!({
        "channel": channel, "outboundEnabled": false, "latestVersion": null,
        "latestUrl": null, "publishedAt": null, "isUpdateAvailable": null,
        "currentVersion": env!("CARGO_PKG_VERSION"),
    }))
}
