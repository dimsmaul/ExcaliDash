use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use chrono::NaiveDateTime;
use serde_json::{json, Value};

use super::middleware::{optional_user, RequireUser, UserCtx};
use crate::{
    config::AuthMode,
    error::{AppError, AppResult},
    state::AppState,
    time::iso,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/status", get(status))
        .route("/auth/me", get(me))
}

fn auth_enabled(state: &AppState) -> bool {
    state.cfg.auth_mode == AuthMode::OidcEnforced
}

/// Node `ensureAuthEnabled`.
fn ensure_auth_enabled(state: &AppState) -> AppResult<()> {
    if auth_enabled(state) {
        Ok(())
    } else {
        Err(AppError::status(
            StatusCode::NOT_FOUND,
            "Not found",
            "Authentication is disabled",
        ))
    }
}

/// Node `buildAuthStatusPayload` for the two supported modes.
async fn status(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let enabled = auth_enabled(&state);
    let user = if enabled {
        optional_user(&state, &headers).await.user
    } else {
        None
    };
    let provider = state
        .cfg
        .oidc
        .as_ref()
        .map_or("OIDC", |o| o.provider_name.as_str());
    Json(json!({
        "enabled": enabled,
        "authenticated": user.is_some(),
        "authEnabled": enabled,
        "authMode": if enabled { "oidc_enforced" } else { "disabled" },
        "oidcEnabled": enabled,
        "oidcEnforced": enabled,
        "oidcProvider": provider,
        "oidcJitProvisioningEnabled": enabled,
        "registrationEnabled": false,
        "bootstrapRequired": false,
        "authOnboardingRequired": false,
        "authOnboardingMode": null,
        "authOnboardingRecommended": null,
        "passwordPolicy": {
            "minLength": 12, "maxLength": 100, "requireUppercase": true,
            "requireLowercase": true, "requireNumber": true, "requireSymbol": true
        },
        "user": user.map(|u: UserCtx| json!({
            "id": u.id, "username": u.username, "email": u.email,
            "name": u.name, "role": u.role, "mustResetPassword": u.must_reset_password
        })),
    }))
}

#[derive(sqlx::FromRow)]
struct MeRow {
    id: String,
    username: Option<String>,
    email: String,
    name: String,
    role: String,
    #[sqlx(rename = "mustResetPassword")]
    must_reset_password: bool,
    #[sqlx(rename = "createdAt")]
    created_at: NaiveDateTime,
    #[sqlx(rename = "updatedAt")]
    updated_at: NaiveDateTime,
}

async fn me(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
) -> AppResult<Json<Value>> {
    ensure_auth_enabled(&state)?;
    let row: Option<MeRow> = sqlx::query_as(
        r#"SELECT id, username, email, name, role, "mustResetPassword", "createdAt", "updatedAt"
           FROM "User" WHERE id = $1"#,
    )
    .bind(&user.id)
    .fetch_optional(&state.db)
    .await?;
    let row =
        row.ok_or_else(|| AppError::status(StatusCode::NOT_FOUND, "Not found", "User not found"))?;
    Ok(Json(json!({
        "user": {
            "id": row.id, "username": row.username, "email": row.email,
            "name": row.name, "role": row.role,
            "mustResetPassword": row.must_reset_password,
            "createdAt": iso(row.created_at), "updatedAt": iso(row.updated_at),
        }
    })))
}
