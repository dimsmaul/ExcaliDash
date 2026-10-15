use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts, HeaderMap, StatusCode},
};
use sqlx::PgPool;

use super::{
    cookies::{read_cookie, ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE},
    jwt,
};
use crate::{config::AuthMode, error::AppError, state::AppState, time::NOW_UTC};

pub const BOOTSTRAP_USER_ID: &str = "bootstrap-admin";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserCtx {
    pub id: String,
    pub username: Option<String>,
    pub email: String,
    pub name: String,
    pub role: String,
    #[sqlx(rename = "mustResetPassword")]
    pub must_reset_password: bool,
}

/// Authenticated user, or 401 (Node `requireAuth`).
pub struct RequireUser(pub UserCtx);

/// Node `optionalAuth`: `auth_error` is set when a token was presented but
/// invalid, or the access token is missing while a refresh cookie exists.
pub struct OptionalUser {
    pub user: Option<UserCtx>,
    pub auth_error: bool,
}

const USER_COLUMNS: &str = r#"id, username, email, name, role, "mustResetPassword""#;

/// Node `getBootstrapActingUser`: upsert of the shared user used when auth is disabled.
pub async fn bootstrap_user(db: &PgPool) -> Result<UserCtx, sqlx::Error> {
    sqlx::query_as(&format!(
        r#"INSERT INTO "User" (id, email, username, "passwordHash", name, role, "mustResetPassword", "isActive", "createdAt", "updatedAt")
           VALUES ($1, 'bootstrap@excalidash.local', NULL, '', 'Bootstrap Admin', 'ADMIN', true, false, {NOW_UTC}, {NOW_UTC})
           ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id
           RETURNING {USER_COLUMNS}"#
    ))
    .bind(BOOTSTRAP_USER_ID)
    .fetch_one(db)
    .await
}

async fn find_active_user(db: &PgPool, id: &str) -> Result<Option<UserCtx>, sqlx::Error> {
    sqlx::query_as(&format!(
        r#"SELECT {USER_COLUMNS} FROM "User" WHERE id = $1 AND "isActive""#
    ))
    .bind(id)
    .fetch_optional(db)
    .await
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(auth) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        let parts: Vec<&str> = auth.split(' ').collect();
        if parts.len() == 2 && parts[0] == "Bearer" {
            return (!parts[1].is_empty()).then(|| parts[1].to_string());
        }
    }
    read_cookie(headers, ACCESS_TOKEN_COOKIE)
}

fn unauthorized(message: &str) -> AppError {
    AppError::status(StatusCode::UNAUTHORIZED, "Unauthorized", message)
}

pub async fn require_user(state: &AppState, headers: &HeaderMap) -> Result<UserCtx, AppError> {
    if state.cfg.auth_mode == AuthMode::Disabled {
        return bootstrap_user(&state.db).await.map_err(AppError::from);
    }
    let token =
        extract_token(headers).ok_or_else(|| unauthorized("Authentication token required"))?;
    let claims = jwt::verify_access(&state.cfg, &token)
        .ok_or_else(|| unauthorized("Invalid or expired token"))?;
    find_active_user(&state.db, &claims.user_id)
        .await?
        .ok_or_else(|| unauthorized("User account not found or inactive"))
}

pub async fn optional_user(state: &AppState, headers: &HeaderMap) -> OptionalUser {
    let none = |auth_error| OptionalUser {
        user: None,
        auth_error,
    };
    if state.cfg.auth_mode == AuthMode::Disabled {
        return match bootstrap_user(&state.db).await {
            Ok(user) => OptionalUser {
                user: Some(user),
                auth_error: false,
            },
            Err(err) => {
                tracing::error!(%err, "bootstrap user lookup failed");
                none(false)
            }
        };
    }
    let Some(token) = extract_token(headers) else {
        return none(read_cookie(headers, REFRESH_TOKEN_COOKIE).is_some());
    };
    let Some(claims) = jwt::verify_access(&state.cfg, &token) else {
        return none(true);
    };
    match find_active_user(&state.db, &claims.user_id).await {
        Ok(user) => OptionalUser {
            user,
            auth_error: false,
        },
        Err(err) => {
            tracing::error!(%err, "optional auth lookup failed");
            none(false)
        }
    }
}

impl FromRequestParts<AppState> for RequireUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        require_user(state, &parts.headers).await.map(RequireUser)
    }
}

impl FromRequestParts<AppState> for OptionalUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(optional_user(state, &parts.headers).await)
    }
}
