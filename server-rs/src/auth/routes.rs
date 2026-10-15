use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::NaiveDateTime;
use serde_json::{json, Value};

use super::{
    cookies::{clear_cookie, read_cookie, set_cookie, ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE},
    csrf,
    jwt::{self, hash_token, TokenPair},
    middleware::{optional_user, RequireUser, UserCtx},
    oidc, preferences,
};
use crate::{
    config::AuthMode,
    error::{AppError, AppResult},
    state::AppState,
    time::{iso, NOW_UTC},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/status", get(status))
        .route("/auth/me", get(me))
        .route("/auth/oidc/start", get(oidc::start))
        .route("/auth/oidc/callback", get(oidc::callback))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route(
            "/auth/preferences",
            get(get_preferences).put(put_preferences),
        )
}

fn with_cookies(mut res: Response, cookies: &[String]) -> Response {
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(cookie) {
            res.headers_mut().append(SET_COOKIE, value);
        }
    }
    res
}

fn unauthorized(message: &str) -> AppError {
    AppError::status(StatusCode::UNAUTHORIZED, "Unauthorized", message)
}

fn internal(message: &str) -> AppError {
    AppError::status(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal server error",
        message,
    )
}

/// `POST /auth/refresh` with rotation (Node coreRoutes `/refresh`).
async fn refresh(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let result = async {
        ensure_auth_enabled(&state)?;
        csrf::require(&state.cfg, &headers)?;
        let old = read_cookie(&headers, REFRESH_TOKEN_COOKIE)
            .ok_or_else(|| unauthorized("Refresh token required"))?;
        let claims = jwt::verify_any(&state.cfg, &old)
            .ok_or_else(|| unauthorized("Invalid or expired refresh token"))?;
        if claims.token_type != "refresh" {
            return Err(unauthorized("Invalid token type"));
        }
        let user: Option<(String, String, bool)> =
            sqlx::query_as(r#"SELECT id, email, "isActive" FROM "User" WHERE id = $1"#)
                .bind(&claims.user_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|_| unauthorized("Invalid or expired refresh token"))?;
        let (user_id, email) = match user {
            Some((id, email, true)) => (id, email),
            _ => return Err(unauthorized("User account not found or inactive")),
        };
        rotate_refresh_token(&state, &user_id, &email, &old).await
    }
    .await;
    match result {
        Ok(pair) => with_cookies(
            Json(json!({ "ok": true })).into_response(),
            &[
                set_cookie(
                    &headers,
                    ACCESS_TOKEN_COOKIE,
                    &pair.access,
                    state.cfg.jwt_access_ttl,
                ),
                set_cookie(
                    &headers,
                    REFRESH_TOKEN_COOKIE,
                    &pair.refresh,
                    state.cfg.jwt_refresh_ttl,
                ),
            ],
        ),
        Err(err) => err.into_response(),
    }
}

async fn rotate_refresh_token(
    state: &AppState,
    user_id: &str,
    email: &str,
    old_token: &str,
) -> AppResult<TokenPair> {
    let failed = |err: sqlx::Error| {
        tracing::error!(%err, "refresh token rotation error");
        internal("Failed to rotate refresh token")
    };
    let mut tx = state.db.begin().await.map_err(failed)?;
    let stored: Option<(String, String, bool, bool)> = sqlx::query_as(&format!(
        r#"SELECT id, "userId", revoked, "expiresAt" < {NOW_UTC}
           FROM "RefreshToken" WHERE token = $1 OR token = $2 LIMIT 1"#
    ))
    .bind(old_token)
    .bind(hash_token(old_token))
    .fetch_optional(&mut *tx)
    .await
    .map_err(failed)?;
    let id = match stored {
        Some((id, owner, false, false)) if owner == user_id => id,
        Some((_, owner, false, true)) if owner == user_id => {
            return Err(unauthorized("Refresh token has expired"))
        }
        _ => return Err(unauthorized("Invalid or revoked refresh token")),
    };
    let revoked =
        sqlx::query(r#"UPDATE "RefreshToken" SET revoked = true WHERE id = $1 AND NOT revoked"#)
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(failed)?;
    if revoked.rows_affected() != 1 {
        return Err(unauthorized("Invalid or revoked refresh token"));
    }
    let pair = jwt::issue_pair(&state.cfg, user_id, email);
    oidc::store_refresh_token(&mut *tx, user_id, &pair.refresh, state.cfg.jwt_refresh_ttl)
        .await
        .map_err(failed)?;
    tx.commit().await.map_err(failed)?;
    Ok(pair)
}

/// `POST /auth/logout`: clears cookies and revokes the user's refresh tokens.
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let result = async {
        ensure_auth_enabled(&state)?;
        csrf::require(&state.cfg, &headers)?;
        if let Some(user) = optional_user(&state, &headers).await.user {
            sqlx::query(
                r#"UPDATE "RefreshToken" SET revoked = true WHERE "userId" = $1 AND NOT revoked"#,
            )
            .bind(&user.id)
            .execute(&state.db)
            .await
            .map_err(|err| {
                tracing::error!(%err, "logout error");
                internal("Failed to logout")
            })?;
        }
        Ok::<_, AppError>(())
    }
    .await;
    match result {
        Ok(()) => with_cookies(
            Json(json!({ "ok": true })).into_response(),
            &[
                clear_cookie(&headers, ACCESS_TOKEN_COOKIE),
                clear_cookie(&headers, REFRESH_TOKEN_COOKIE),
            ],
        ),
        Err(err) => err.into_response(),
    }
}

/// The user's stored preferences JSON (None when never saved); 404 if the user is gone.
async fn stored_preferences(state: &AppState, user_id: &str) -> AppResult<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as(r#"SELECT preferences FROM "User" WHERE id = $1"#)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    match row {
        Some((prefs,)) => Ok(prefs),
        None => Err(AppError::status(
            StatusCode::NOT_FOUND,
            "Not found",
            "User not found",
        )),
    }
}

/// `GET /auth/preferences`
async fn get_preferences(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
) -> AppResult<Json<Value>> {
    ensure_auth_enabled(&state)?;
    let stored = stored_preferences(&state, &user.id).await?;
    Ok(Json(
        json!({ "preferences": preferences::parse_stored(stored.as_deref()) }),
    ))
}

/// `PUT /auth/preferences`: validated partial update merged into the stored object.
async fn put_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireUser(user): RequireUser,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    ensure_auth_enabled(&state)?;
    csrf::require(&state.cfg, &headers)?;
    let update = body
        .and_then(|Json(value)| preferences::validate(&value))
        .ok_or_else(|| {
            AppError::status(
                StatusCode::BAD_REQUEST,
                "Validation error",
                "Invalid preferences",
            )
        })?;
    let mut merged =
        preferences::parse_stored(stored_preferences(&state, &user.id).await?.as_deref());
    merged.extend(update);
    let merged = Value::Object(merged);
    sqlx::query(&format!(
        r#"UPDATE "User" SET preferences = $2, "updatedAt" = {NOW_UTC} WHERE id = $1"#
    ))
    .bind(&user.id)
    .bind(merged.to_string())
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "preferences": merged })))
}

fn auth_enabled(state: &AppState) -> bool {
    state.cfg.auth_mode == AuthMode::OidcEnforced
}

/// Node `ensureAuthEnabled`.
pub(crate) fn ensure_auth_enabled(state: &AppState) -> AppResult<()> {
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
