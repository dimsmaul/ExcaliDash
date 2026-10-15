//! Per-user drawing sharing (backend/src/routes/dashboard/drawingSharingRoutes.ts,
//! drawingSharedVisibilityRoutes.ts). Link shares are out of scope (always `[]`).

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, patch, post},
    Json, Router,
};
use chrono::NaiveDateTime;
use serde_json::{json, Value};

use crate::{
    auth::middleware::RequireUser,
    authz::Access,
    error::{AppError, AppResult},
    socket,
    state::AppState,
    time::{iso, NOW_UTC},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/drawings/{id}/share-resolve", get(share_resolve))
        .route("/drawings/{id}/sharing", get(sharing))
        .route("/drawings/{id}/permissions", post(upsert_permission))
        .route(
            "/drawings/{id}/permissions/{perm_id}",
            delete(revoke_permission),
        )
        .route("/drawings/{id}/shared-visibility", patch(shared_visibility))
}

fn error(status: StatusCode, message: &str) -> AppError {
    AppError::json(status, json!({ "error": message }))
}

/// 404 unless the caller owns the drawing.
async fn require_owner(state: &AppState, id: &str, user_id: &str) -> AppResult<()> {
    let owner: Option<String> =
        sqlx::query_scalar(r#"SELECT "userId" FROM "Drawing" WHERE id = $1"#)
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    if owner.as_deref() == Some(user_id) {
        Ok(())
    } else {
        Err(error(StatusCode::NOT_FOUND, "Drawing not found"))
    }
}

/// `GET /drawings/{id}/share-resolve?q=` (owner only, ≥3 chars, max 10)
async fn share_resolve(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    let q = query
        .get("q")
        .map(|q| q.trim().to_lowercase())
        .unwrap_or_default();
    if q.chars().count() < 3 {
        return Ok(Json(json!({ "users": [] })));
    }
    require_owner(&state, &id, &user.id).await?;
    let users: Vec<(String, String, String)> = sqlx::query_as(
        r#"SELECT id, name, email FROM "User"
           WHERE "isActive" AND id <> $1
             AND (strpos(email, $2) > 0 OR strpos(name, $2) > 0 OR strpos(COALESCE(username, ''), $2) > 0)
           LIMIT 10"#,
    )
    .bind(&user.id)
    .bind(&q)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "users": users.into_iter()
            .map(|(id, name, email)| json!({ "id": id, "name": name, "email": email }))
            .collect::<Vec<_>>()
    })))
}

#[derive(sqlx::FromRow)]
struct PermissionRow {
    id: String,
    #[sqlx(rename = "granteeUserId")]
    grantee_user_id: String,
    permission: String,
    #[sqlx(rename = "createdAt")]
    created_at: NaiveDateTime,
    #[sqlx(rename = "updatedAt")]
    updated_at: NaiveDateTime,
    grantee_name: String,
    grantee_email: String,
}

impl PermissionRow {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id, "granteeUserId": self.grantee_user_id, "permission": self.permission,
            "createdAt": iso(self.created_at), "updatedAt": iso(self.updated_at),
            "granteeUser": {
                "id": self.grantee_user_id, "name": self.grantee_name, "email": self.grantee_email
            },
        })
    }
}

const PERMISSION_SELECT: &str = r#"SELECT p.id, p."granteeUserId", p.permission, p."createdAt", p."updatedAt",
       u.name AS grantee_name, u.email AS grantee_email
FROM "DrawingPermission" p JOIN "User" u ON u.id = p."granteeUserId""#;

/// `GET /drawings/{id}/sharing` (owner only)
async fn sharing(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    require_owner(&state, &id, &user.id).await?;
    let rows: Vec<PermissionRow> = sqlx::query_as(&format!(
        r#"{PERMISSION_SELECT} WHERE p."drawingId" = $1 ORDER BY p."createdAt" DESC"#
    ))
    .bind(&id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "permissions": rows.iter().map(PermissionRow::to_json).collect::<Vec<_>>(),
        "linkShares": [],
    })))
}

/// `POST /drawings/{id}/permissions` `{granteeUserId, permission}` (owner only, upsert)
async fn upsert_permission(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    require_owner(&state, &id, &user.id).await?;
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let grantee = body
        .get("granteeUserId")
        .and_then(Value::as_str)
        .filter(|g| !g.is_empty());
    let permission = body
        .get("permission")
        .and_then(Value::as_str)
        .and_then(Access::from_grant);
    let (Some(grantee), Some(permission)) = (grantee, permission) else {
        return Err(AppError::status(
            StatusCode::BAD_REQUEST,
            "Validation error",
            "Invalid grantee or permission",
        ));
    };
    if grantee == user.id {
        return Err(AppError::status(
            StatusCode::BAD_REQUEST,
            "Validation error",
            "Cannot share with yourself",
        ));
    }
    let active: Option<bool> = sqlx::query_scalar(r#"SELECT "isActive" FROM "User" WHERE id = $1"#)
        .bind(grantee)
        .fetch_optional(&state.db)
        .await?;
    if active != Some(true) {
        return Err(error(StatusCode::NOT_FOUND, "User not found"));
    }
    let perm_id: String = sqlx::query_scalar(&format!(
        r#"INSERT INTO "DrawingPermission" (id, "drawingId", "granteeUserId", permission, "createdByUserId", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, {NOW_UTC}, {NOW_UTC})
           ON CONFLICT ("drawingId", "granteeUserId")
           DO UPDATE SET permission = EXCLUDED.permission, "createdByUserId" = EXCLUDED."createdByUserId", "updatedAt" = {NOW_UTC}
           RETURNING id"#
    ))
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&id)
    .bind(grantee)
    .bind(permission.as_str())
    .bind(&user.id)
    .fetch_one(&state.db)
    .await?;
    let saved: PermissionRow = sqlx::query_as(&format!(r#"{PERMISSION_SELECT} WHERE p.id = $1"#))
        .bind(&perm_id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(json!({ "permission": saved.to_json() })))
}

/// `DELETE /drawings/{id}/permissions/{permId}` (owner only), then kick revoked sockets.
async fn revoke_permission(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path((id, perm_id)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    require_owner(&state, &id, &user.id).await?;
    sqlx::query(r#"DELETE FROM "DrawingPermission" WHERE id = $1 AND "drawingId" = $2"#)
        .bind(&perm_id)
        .bind(&id)
        .execute(&state.db)
        .await?;
    socket::revalidate_drawing_access(&state, &id).await;
    Ok(Json(json!({ "success": true })))
}

/// `PATCH /drawings/{id}/shared-visibility` `{hidden}` on the caller's own grant.
async fn shared_visibility(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    let hidden = body
        .and_then(|Json(b)| b.get("hidden").and_then(Value::as_bool))
        .ok_or_else(|| {
            AppError::status(
                StatusCode::BAD_REQUEST,
                "Validation error",
                "`hidden` must be a boolean",
            )
        })?;
    let updated = sqlx::query(
        r#"UPDATE "DrawingPermission" SET hidden = $3 WHERE "drawingId" = $1 AND "granteeUserId" = $2"#,
    )
    .bind(&id)
    .bind(&user.id)
    .bind(hidden)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(error(StatusCode::NOT_FOUND, "Shared drawing not found"));
    }
    Ok(Json(json!({ "success": true, "hidden": hidden })))
}
