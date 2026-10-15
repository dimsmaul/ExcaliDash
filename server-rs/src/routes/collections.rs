//! Collections CRUD and collection shares (backend/src/routes/dashboard/collections.ts).

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, patch},
    Json, Router,
};
use chrono::NaiveDateTime;
use serde_json::{json, Map, Value};

use crate::{
    auth::middleware::RequireUser,
    authz::{ensure_trash_collection, is_trash_id, trash_id},
    error::{AppError, AppResult},
    sanitize,
    state::AppState,
    time::{iso, NOW_UTC},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/collections", get(list).post(create))
        .route(
            "/collections/{id}",
            axum::routing::put(rename).delete(remove),
        )
        .route("/collections/{id}/shares", get(list_shares).post(add_share))
        .route(
            "/collections/{id}/shares/{user_id}",
            patch(update_share).delete(remove_share),
        )
        .route("/collections/{id}/share-resolve", get(share_resolve))
}

/// Node `collectionNameSchema` (trimmed, 1..=100) followed by `sanitizeText(name, 100)`.
pub fn validate_name(body: &Value) -> Option<String> {
    let name = body.get("name")?.as_str()?.trim();
    (1..=100)
        .contains(&name.chars().count())
        .then(|| sanitize::text(name, 100))
}

fn invalid_name() -> AppError {
    AppError::status(
        StatusCode::BAD_REQUEST,
        "Validation error",
        "Collection name must be between 1 and 100 characters",
    )
}

fn error(status: StatusCode, message: &str) -> AppError {
    AppError::json(status, json!({ "error": message }))
}

fn not_found() -> AppError {
    error(StatusCode::NOT_FOUND, "Collection not found")
}

#[derive(sqlx::FromRow)]
struct CollectionRow {
    id: String,
    name: String,
    #[sqlx(rename = "userId")]
    user_id: String,
    #[sqlx(rename = "createdAt")]
    created_at: NaiveDateTime,
    #[sqlx(rename = "updatedAt")]
    updated_at: NaiveDateTime,
}

impl CollectionRow {
    fn to_json(&self) -> Map<String, Value> {
        let Value::Object(map) = json!({
            "id": self.id, "name": self.name, "userId": self.user_id,
            "createdAt": iso(self.created_at), "updatedAt": iso(self.updated_at),
        }) else {
            unreachable!()
        };
        map
    }
}

const COLLECTION_COLUMNS: &str = r#"id, name, "userId", "createdAt", "updatedAt""#;

async fn owned_collection(state: &AppState, id: &str, user_id: &str) -> AppResult<CollectionRow> {
    sqlx::query_as(&format!(
        r#"SELECT {COLLECTION_COLUMNS} FROM "Collection" WHERE id = $1 AND "userId" = $2"#
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(not_found)
}

/// `GET /collections`: owned (trash as id "trash") followed by collections shared with the user.
async fn list(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
) -> AppResult<Json<Value>> {
    let trash = trash_id(&user.id);
    let mut conn = state.db.acquire().await?;
    ensure_trash_collection(&mut conn, &user.id).await?;

    let owned: Vec<CollectionRow> = sqlx::query_as(&format!(
        r#"SELECT {COLLECTION_COLUMNS} FROM "Collection" WHERE "userId" = $1 ORDER BY "createdAt" DESC"#
    ))
    .bind(&user.id)
    .fetch_all(&mut *conn)
    .await?;
    let shared_ids: HashSet<String> = sqlx::query_scalar(
        r#"SELECT DISTINCT s."collectionId" FROM "CollectionShare" s
           JOIN "Collection" c ON c.id = s."collectionId" WHERE c."userId" = $1"#,
    )
    .bind(&user.id)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let has_internal_trash = owned.iter().any(|c| c.id == trash);

    let mut out: Vec<Value> = owned
        .iter()
        .filter(|c| !(has_internal_trash && c.id == "trash"))
        .map(|c| {
            let mut map = c.to_json();
            map.insert("sharedRole".into(), Value::Null);
            map.insert("isOwner".into(), true.into());
            if c.id == trash {
                map.insert("id".into(), "trash".into());
                map.insert("name".into(), "Trash".into());
                map.insert("isShared".into(), false.into());
            } else {
                map.insert("isShared".into(), shared_ids.contains(&c.id).into());
            }
            Value::Object(map)
        })
        .collect();

    #[derive(sqlx::FromRow)]
    struct SharedRow {
        #[sqlx(flatten)]
        collection: CollectionRow,
        role: String,
        owner_name: String,
        owner_email: String,
    }
    let shared: Vec<SharedRow> = sqlx::query_as(
        r#"SELECT c.id, c.name, c."userId", c."createdAt", c."updatedAt", s.role,
                  u.name AS owner_name, u.email AS owner_email
           FROM "CollectionShare" s
           JOIN "Collection" c ON c.id = s."collectionId"
           JOIN "User" u ON u.id = c."userId"
           WHERE s."granteeUserId" = $1"#,
    )
    .bind(&user.id)
    .fetch_all(&mut *conn)
    .await?;
    out.extend(shared.into_iter().map(|row| {
        let mut map = row.collection.to_json();
        map.insert(
            "user".into(),
            json!({ "id": row.collection.user_id, "name": row.owner_name, "email": row.owner_email }),
        );
        map.insert("sharedRole".into(), row.role.into());
        map.insert("isOwner".into(), false.into());
        Value::Object(map)
    }));
    Ok(Json(Value::Array(out)))
}

/// `POST /collections`
async fn create(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    let name = body
        .and_then(|Json(b)| validate_name(&b))
        .ok_or_else(invalid_name)?;
    let row: CollectionRow = sqlx::query_as(&format!(
        r#"INSERT INTO "Collection" (id, name, "userId", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, {NOW_UTC}, {NOW_UTC}) RETURNING {COLLECTION_COLUMNS}"#
    ))
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&name)
    .bind(&user.id)
    .fetch_one(&state.db)
    .await?;
    let mut map = row.to_json();
    map.insert("sharedRole".into(), Value::Null);
    map.insert("isOwner".into(), true.into());
    Ok(Json(Value::Object(map)))
}

/// `PUT /collections/{id}` (owner only)
async fn rename(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    if is_trash_id(&id, &user.id) {
        return Err(AppError::status(
            StatusCode::BAD_REQUEST,
            "Validation error",
            "Trash collection cannot be renamed",
        ));
    }
    owned_collection(&state, &id, &user.id).await?;
    let name = body
        .and_then(|Json(b)| validate_name(&b))
        .ok_or_else(invalid_name)?;
    let row: CollectionRow = sqlx::query_as(&format!(
        r#"UPDATE "Collection" SET name = $3, "updatedAt" = {NOW_UTC}
           WHERE id = $1 AND "userId" = $2 RETURNING {COLLECTION_COLUMNS}"#
    ))
    .bind(&id)
    .bind(&user.id)
    .bind(&name)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(not_found)?;
    Ok(Json(Value::Object(row.to_json())))
}

/// `DELETE /collections/{id}` (owner only): drawings fall back to "no collection".
async fn remove(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    if is_trash_id(&id, &user.id) {
        return Err(AppError::status(
            StatusCode::BAD_REQUEST,
            "Validation error",
            "Trash collection cannot be deleted",
        ));
    }
    owned_collection(&state, &id, &user.id).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query(&format!(
        r#"UPDATE "Drawing" SET "collectionId" = NULL, "updatedAt" = {NOW_UTC}
           WHERE "collectionId" = $1 AND "userId" = $2"#
    ))
    .bind(&id)
    .bind(&user.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(r#"DELETE FROM "CollectionShare" WHERE "collectionId" = $1"#)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(r#"DELETE FROM "Collection" WHERE id = $1 AND "userId" = $2"#)
        .bind(&id)
        .bind(&user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "success": true })))
}

#[derive(sqlx::FromRow)]
struct ShareRow {
    id: String,
    #[sqlx(rename = "collectionId")]
    collection_id: String,
    #[sqlx(rename = "granteeUserId")]
    grantee_user_id: String,
    role: String,
    #[sqlx(rename = "createdByUserId")]
    created_by_user_id: String,
    #[sqlx(rename = "createdAt")]
    created_at: NaiveDateTime,
    #[sqlx(rename = "updatedAt")]
    updated_at: NaiveDateTime,
    grantee_name: String,
    grantee_email: String,
}

impl ShareRow {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id, "collectionId": self.collection_id,
            "granteeUserId": self.grantee_user_id, "role": self.role,
            "createdByUserId": self.created_by_user_id,
            "createdAt": iso(self.created_at), "updatedAt": iso(self.updated_at),
            "granteeUser": {
                "id": self.grantee_user_id, "name": self.grantee_name, "email": self.grantee_email
            },
        })
    }
}

const SHARE_SELECT: &str = r#"SELECT s.id, s."collectionId", s."granteeUserId", s.role, s."createdByUserId",
       s."createdAt", s."updatedAt", u.name AS grantee_name, u.email AS grantee_email
FROM "CollectionShare" s JOIN "User" u ON u.id = s."granteeUserId""#;

/// `GET /collections/{id}/shares` (owner only)
async fn list_shares(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    owned_collection(&state, &id, &user.id).await?;
    let shares: Vec<ShareRow> = sqlx::query_as(&format!(
        r#"{SHARE_SELECT} WHERE s."collectionId" = $1 ORDER BY s."createdAt" ASC"#
    ))
    .bind(&id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        json!({ "shares": shares.iter().map(ShareRow::to_json).collect::<Vec<_>>() }),
    ))
}

fn role_of(body: &Value) -> Option<&str> {
    body.get("role")
        .and_then(Value::as_str)
        .filter(|r| matches!(*r, "view" | "edit"))
}

/// `POST /collections/{id}/shares` `{identifier, role}`: upsert by email/username/name.
async fn add_share(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let identifier = body
        .get("identifier")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let (Some(identifier), Some(role)) = (identifier, role_of(&body)) else {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "identifier and role (view|edit) are required",
        ));
    };
    owned_collection(&state, &id, &user.id).await?;
    let grantee: Option<String> = sqlx::query_scalar(
        r#"SELECT id FROM "User"
           WHERE "isActive" AND (email = $1 OR username = $2 OR name = $2) LIMIT 1"#,
    )
    .bind(identifier.to_lowercase())
    .bind(identifier)
    .fetch_optional(&state.db)
    .await?;
    let grantee = grantee.ok_or_else(|| error(StatusCode::NOT_FOUND, "User not found"))?;
    if grantee == user.id {
        return Err(error(StatusCode::BAD_REQUEST, "Cannot share with yourself"));
    }
    let share_id: String = sqlx::query_scalar(&format!(
        r#"INSERT INTO "CollectionShare" (id, "collectionId", "granteeUserId", role, "createdByUserId", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, {NOW_UTC}, {NOW_UTC})
           ON CONFLICT ("collectionId", "granteeUserId")
           DO UPDATE SET role = EXCLUDED.role, "updatedAt" = {NOW_UTC}
           RETURNING id"#
    ))
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&id)
    .bind(&grantee)
    .bind(role)
    .bind(&user.id)
    .fetch_one(&state.db)
    .await?;
    let share: ShareRow = sqlx::query_as(&format!(r#"{SHARE_SELECT} WHERE s.id = $1"#))
        .bind(&share_id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(json!({ "share": share.to_json() })))
}

/// `PATCH /collections/{id}/shares/{userId}` `{role}`
async fn update_share(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path((id, grantee)): Path<(String, String)>,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let role = role_of(&body)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "role must be view or edit"))?;
    owned_collection(&state, &id, &user.id).await?;
    let updated = sqlx::query(&format!(
        r#"UPDATE "CollectionShare" SET role = $3, "updatedAt" = {NOW_UTC}
           WHERE "collectionId" = $1 AND "granteeUserId" = $2"#
    ))
    .bind(&id)
    .bind(&grantee)
    .bind(role)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(error(StatusCode::NOT_FOUND, "Share not found"));
    }
    Ok(Json(json!({ "success": true })))
}

/// `DELETE /collections/{id}/shares/{userId}`
async fn remove_share(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path((id, grantee)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    owned_collection(&state, &id, &user.id).await?;
    sqlx::query(
        r#"DELETE FROM "CollectionShare" WHERE "collectionId" = $1 AND "granteeUserId" = $2"#,
    )
    .bind(&id)
    .bind(&grantee)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "success": true })))
}

/// `GET /collections/{id}/share-resolve?q=` (≥2 chars, max 8, excludes self and grantees)
async fn share_resolve(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    let q = query.get("q").map(|q| q.trim()).unwrap_or_default();
    if q.chars().count() < 2 {
        return Ok(Json(json!({ "users": [] })));
    }
    owned_collection(&state, &id, &user.id).await?;
    let users: Vec<(String, String, String)> = sqlx::query_as(
        r#"SELECT u.id, u.name, u.email FROM "User" u
           WHERE u."isActive" AND u.id <> $2
             AND u.id NOT IN (SELECT "granteeUserId" FROM "CollectionShare" WHERE "collectionId" = $1)
             AND (strpos(u.email, $3) > 0 OR strpos(u.name, $3) > 0 OR strpos(COALESCE(u.username, ''), $3) > 0)
           LIMIT 8"#,
    )
    .bind(&id)
    .bind(&user.id)
    .bind(q)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "users": users.into_iter()
            .map(|(id, name, email)| json!({ "id": id, "name": name, "email": email }))
            .collect::<Vec<_>>()
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_validation_matches_node_schema() {
        assert_eq!(
            validate_name(&json!({"name": "  Plans "})).as_deref(),
            Some("Plans")
        );
        assert_eq!(
            validate_name(&json!({"name": "<i>x</i><script>y</script>"})).as_deref(),
            Some("<i>x</i>")
        );
        assert_eq!(
            validate_name(&json!({"name": "é".repeat(100)})).map(|n| n.chars().count()),
            Some(100)
        );
        assert_eq!(validate_name(&json!({"name": "é".repeat(101)})), None);
        assert_eq!(validate_name(&json!({"name": "   "})), None);
        assert_eq!(validate_name(&json!({"name": 5})), None);
        assert_eq!(validate_name(&json!({})), None);
    }
}
