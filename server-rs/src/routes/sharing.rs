//! Per-user drawing sharing (backend/src/routes/dashboard/drawingSharingRoutes.ts,
//! drawingSharedVisibilityRoutes.ts). Link shares are out of scope (always `[]`).

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, patch, post},
    Json, Router,
};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{json, Value};

use crate::{
    auth::{jwt::hash_token, middleware::RequireUser},
    authz::Access,
    config::Config,
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
        .route("/drawings/{id}/link-shares", post(create_link_share))
        .route(
            "/drawings/{id}/link-shares/{share_id}",
            delete(revoke_link_share),
        )
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
    let links: Vec<LinkShareRow> = sqlx::query_as(&format!(
        r#"{LINK_SHARE_SELECT} WHERE "drawingId" = $1 ORDER BY "createdAt" DESC"#
    ))
    .bind(&id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "permissions": rows.iter().map(PermissionRow::to_json).collect::<Vec<_>>(),
        "linkShares": links.iter().map(|l| l.to_json(true)).collect::<Vec<_>>(),
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

#[derive(sqlx::FromRow)]
struct LinkShareRow {
    id: String,
    permission: String,
    #[sqlx(rename = "expiresAt")]
    expires_at: Option<NaiveDateTime>,
    #[sqlx(rename = "revokedAt")]
    revoked_at: Option<NaiveDateTime>,
    #[sqlx(rename = "createdAt")]
    created_at: NaiveDateTime,
    #[sqlx(rename = "updatedAt")]
    updated_at: NaiveDateTime,
    #[sqlx(rename = "lastUsedAt")]
    last_used_at: Option<NaiveDateTime>,
}

const LINK_SHARE_SELECT: &str = r#"SELECT id, permission, "expiresAt", "revokedAt", "createdAt", "updatedAt", "lastUsedAt"
FROM "DrawingLinkShare""#;

impl LinkShareRow {
    /// `/sharing` lists include `updatedAt`/`lastUsedAt`; the create response does not.
    fn to_json(&self, full: bool) -> Value {
        let mut value = json!({
            "id": self.id, "permission": self.permission,
            "expiresAt": self.expires_at.map(iso), "revokedAt": self.revoked_at.map(iso),
            "createdAt": iso(self.created_at),
        });
        if full {
            value["updatedAt"] = json!(iso(self.updated_at));
            value["lastUsedAt"] = json!(self.last_used_at.map(iso));
        }
        value
    }
}

/// `POST /drawings/{id}/link-shares` `{permission, expiresAt?}` (owner only): replaces any
/// active "anyone with the link" policy. The link is the drawing URL itself; the token
/// hash only satisfies the schema.
async fn create_link_share(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    require_owner(&state, &id, &user.id).await?;
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let permission = body
        .get("permission")
        .and_then(Value::as_str)
        .and_then(Access::from_grant)
        .ok_or_else(|| {
            AppError::status(
                StatusCode::BAD_REQUEST,
                "Validation error",
                "Invalid permission",
            )
        })?;
    let expires_at = link_expiry(&body, permission, Utc::now(), &state.cfg).map_err(|message| {
        AppError::status(StatusCode::BAD_REQUEST, "Validation error", message)
    })?;

    let mut tx = state.db.begin().await?;
    sqlx::query(&format!(
        r#"UPDATE "DrawingLinkShare" SET "revokedAt" = {NOW_UTC}, "updatedAt" = {NOW_UTC}
           WHERE "drawingId" = $1 AND "revokedAt" IS NULL"#
    ))
    .bind(&id)
    .execute(&mut *tx)
    .await?;
    let share: LinkShareRow = sqlx::query_as(&format!(
        r#"INSERT INTO "DrawingLinkShare" (id, "drawingId", permission, "tokenHash", "expiresAt", "createdByUserId", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, $6, {NOW_UTC}, {NOW_UTC})
           RETURNING id, permission, "expiresAt", "revokedAt", "createdAt", "updatedAt", "lastUsedAt""#
    ))
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&id)
    .bind(permission.as_str())
    .bind(hash_token(&uuid::Uuid::new_v4().to_string()))
    .bind(expires_at.map(|t| t.naive_utc()))
    .bind(&user.id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "share": share.to_json(false) })))
}

/// `DELETE /drawings/{id}/link-shares/{shareId}` (owner only), then kick sockets that
/// only had access through the link.
async fn revoke_link_share(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path((id, share_id)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    require_owner(&state, &id, &user.id).await?;
    sqlx::query(&format!(
        r#"UPDATE "DrawingLinkShare" SET "revokedAt" = {NOW_UTC}, "updatedAt" = {NOW_UTC}
           WHERE id = $1 AND "drawingId" = $2 AND "revokedAt" IS NULL"#
    ))
    .bind(&share_id)
    .bind(&id)
    .execute(&state.db)
    .await?;
    socket::revalidate_drawing_access(&state, &id).await;
    Ok(Json(json!({ "success": true })))
}

/// Node link-share expiry rules: explicit `null` never expires; a timestamp must be at
/// least a minute ahead (edit links capped at the max TTL); absent → per-permission default.
pub fn link_expiry(
    body: &Value,
    permission: Access,
    now: DateTime<Utc>,
    cfg: &Config,
) -> Result<Option<DateTime<Utc>>, &'static str> {
    let max = chrono::Duration::from_std(cfg.link_share_max_ttl).unwrap_or(chrono::Duration::MAX);
    let cap = |ttl: chrono::Duration| {
        if permission == Access::Edit {
            ttl.min(max)
        } else {
            ttl
        }
    };
    match body.get("expiresAt") {
        Some(Value::Null) => Ok(None),
        None => {
            let default = match permission {
                Access::Edit => cfg.link_share_edit_ttl,
                _ => cfg.link_share_view_ttl,
            };
            let default = chrono::Duration::from_std(default).unwrap_or(chrono::Duration::MAX);
            Ok(Some(now + cap(default)))
        }
        Some(value) => {
            let requested = value
                .as_str()
                .map(str::trim)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .ok_or("Invalid expiry")?
                .with_timezone(&Utc);
            let ttl = requested - now;
            if ttl < chrono::Duration::seconds(60) {
                return Err("Expiry must be at least 1 minute in the future");
            }
            Ok(Some(now + cap(ttl)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 15, 12, 0, 0).unwrap()
    }

    #[test]
    fn defaults_per_permission() {
        let cfg = Config::for_tests();
        assert_eq!(
            link_expiry(&json!({}), Access::View, now(), &cfg),
            Ok(Some(now() + chrono::Duration::days(30)))
        );
        assert_eq!(
            link_expiry(&json!({}), Access::Edit, now(), &cfg),
            Ok(Some(now() + chrono::Duration::days(7)))
        );
    }

    #[test]
    fn explicit_null_never_expires() {
        let cfg = Config::for_tests();
        assert_eq!(
            link_expiry(&json!({"expiresAt": null}), Access::Edit, now(), &cfg),
            Ok(None)
        );
    }

    #[test]
    fn requested_expiry_is_bounded() {
        let cfg = Config::for_tests();
        let in_a_year = "2027-10-15T12:00:00.000Z";
        assert_eq!(
            link_expiry(&json!({"expiresAt": in_a_year}), Access::View, now(), &cfg),
            Ok(Some(Utc.with_ymd_and_hms(2027, 10, 15, 12, 0, 0).unwrap()))
        );
        assert_eq!(
            link_expiry(&json!({"expiresAt": in_a_year}), Access::Edit, now(), &cfg),
            Ok(Some(now() + chrono::Duration::days(90))),
            "edit links are capped"
        );
        assert_eq!(
            link_expiry(
                &json!({"expiresAt": "2026-10-15T12:00:30Z"}),
                Access::View,
                now(),
                &cfg
            ),
            Err("Expiry must be at least 1 minute in the future")
        );
        for bad in [
            json!({"expiresAt": "soon"}),
            json!({"expiresAt": ""}),
            json!({"expiresAt": 5}),
        ] {
            assert_eq!(
                link_expiry(&bad, Access::View, now(), &cfg),
                Err("Invalid expiry"),
                "{bad}"
            );
        }
    }
}
