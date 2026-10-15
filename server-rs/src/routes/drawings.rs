//! Drawing CRUD (backend/src/routes/dashboard/drawing*Routes.ts).

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Map, Value};
use sqlx::{Postgres, QueryBuilder};

use crate::{
    auth::middleware::{OptionalUser, RequireUser},
    authz::{
        drawing_access, ensure_trash_collection, is_trash_id, to_internal_collection_id,
        to_public_collection_id, trash_id, Access,
    },
    drawing::{
        apply_scene_update, find_drawing, is_valid_import, parse_create, parse_json_field,
        parse_update, qualified_columns, update_drawing, DrawingChanges, DrawingRow, SceneError,
        SceneMutation, VersionGuard, DRAWING_COLUMNS,
    },
    error::{AppError, AppResult},
    files_store::{self, file_url, rewrite_preview},
    state::AppState,
    time::NOW_UTC,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/drawings", get(list).post(create))
        .route("/drawings/shared", get(list_shared))
        .route("/drawings/{id}", get(read).put(update).delete(remove))
        .route("/drawings/{id}/preview", get(preview))
        .route("/drawings/{id}/duplicate", post(duplicate))
}

const DEFAULT_PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 200;

/// JS `Number.parseInt(raw, 10)`: optional sign and leading digits, ignoring the rest.
pub fn js_parse_int(raw: &str) -> Option<i64> {
    let s = raw.trim_start();
    let (sign, digits) = match s.as_bytes().first() {
        Some(b'-') => (-1, &s[1..]),
        Some(b'+') => (1, &s[1..]),
        _ => (1, s),
    };
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    digits[..end].parse::<i64>().ok().map(|n| sign * n)
}

#[derive(Debug, PartialEq)]
pub struct ListParams {
    pub search: Option<String>,
    pub collection: Option<String>,
    pub include_data: bool,
    pub sort_column: &'static str,
    pub descending: bool,
    pub limit: i64,
    pub offset: i64,
}

/// Query parsing shared by `/drawings` and `/drawings/shared`.
pub fn list_params(query: &HashMap<String, String>) -> ListParams {
    let get = |key: &str| query.get(key).map(String::as_str);
    let (sort_column, by_name) = match get("sortField") {
        Some("name") => ("name", true),
        Some("createdAt") => (r#""createdAt""#, false),
        _ => (r#""updatedAt""#, false),
    };
    let descending = match get("sortDirection") {
        Some("asc") => false,
        Some("desc") => true,
        _ => !by_name,
    };
    ListParams {
        search: get("search")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        collection: get("collectionId")
            .filter(|c| !c.is_empty())
            .map(str::to_string),
        include_data: get("includeData")
            .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1"),
        sort_column,
        descending,
        limit: get("limit")
            .and_then(js_parse_int)
            .map_or(DEFAULT_PAGE_SIZE, |n| n.clamp(1, MAX_PAGE_SIZE)),
        offset: get("offset").and_then(js_parse_int).map_or(0, |n| n.max(0)),
    }
}

fn error(status: StatusCode, message: &str) -> AppError {
    AppError::json(status, json!({ "error": message }))
}

fn drawing_not_found() -> AppError {
    AppError::status(
        StatusCode::NOT_FOUND,
        "Drawing not found",
        "Drawing does not exist",
    )
}

/// Node `respondWithAuthErrorIfPresent`, else the not-found response.
fn access_denied(auth: &OptionalUser) -> AppError {
    if auth.auth_error {
        AppError::status(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "Invalid or expired token",
        )
    } else {
        drawing_not_found()
    }
}

async fn access_for(state: &AppState, auth: &OptionalUser, id: &str) -> AppResult<Option<Access>> {
    Ok(drawing_access(&state.db, auth.user.as_ref().map(|u| u.id.as_str()), id).await?)
}

/// Which drawings a list request covers.
enum ListScope<'a> {
    /// The user's own drawings outside trash.
    Default { user_id: &'a str },
    /// The user's own drawings in no collection.
    NoCollection { user_id: &'a str },
    /// The user's trash (internal and legacy ids).
    Trash { user_id: &'a str },
    /// Every drawing in a collection the user owns or was shared.
    Collection { collection_id: &'a str },
    /// Drawings shared directly with the user (not hidden, not via a shared collection).
    SharedWithMe { user_id: &'a str },
}

fn push_scope(
    builder: &mut QueryBuilder<'_, Postgres>,
    scope: &ListScope<'_>,
    search: Option<&str>,
) {
    match scope {
        ListScope::Default { user_id } => {
            builder
                .push(r#" WHERE d."userId" = "#)
                .push_bind(user_id.to_string())
                .push(r#" AND (d."collectionId" IS NULL OR d."collectionId" NOT IN ("#)
                .push_bind(trash_id(user_id))
                .push(", 'trash'))");
        }
        ListScope::NoCollection { user_id } => {
            builder
                .push(r#" WHERE d."userId" = "#)
                .push_bind(user_id.to_string())
                .push(r#" AND d."collectionId" IS NULL"#);
        }
        ListScope::Trash { user_id } => {
            builder
                .push(r#" WHERE d."userId" = "#)
                .push_bind(user_id.to_string())
                .push(r#" AND d."collectionId" IN ("#)
                .push_bind(trash_id(user_id))
                .push(", 'trash')");
        }
        ListScope::Collection { collection_id } => {
            builder
                .push(r#" WHERE d."collectionId" = "#)
                .push_bind(collection_id.to_string());
        }
        ListScope::SharedWithMe { user_id } => {
            builder
                .push(r#" WHERE d."userId" <> "#)
                .push_bind(user_id.to_string())
                .push(r#" AND EXISTS (SELECT 1 FROM "DrawingPermission" p WHERE p."drawingId" = d.id AND p."granteeUserId" = "#)
                .push_bind(user_id.to_string())
                .push(r#" AND NOT p.hidden) AND (d."collectionId" IS NULL OR d."collectionId" NOT IN (SELECT s."collectionId" FROM "CollectionShare" s WHERE s."granteeUserId" = "#)
                .push_bind(user_id.to_string())
                .push("))");
        }
    }
    if let Some(term) = search {
        builder
            .push(" AND strpos(d.name, ")
            .push_bind(term.to_string())
            .push(") > 0");
    }
}

#[derive(sqlx::FromRow)]
struct ListRow {
    #[sqlx(flatten)]
    drawing: DrawingRow,
    creator_name: Option<String>,
    permission: Option<String>,
}

async fn query_list(
    state: &AppState,
    scope: &ListScope<'_>,
    params: &ListParams,
    viewer_id: &str,
) -> AppResult<(Vec<ListRow>, i64)> {
    let mut rows = QueryBuilder::<Postgres>::new(format!(
        r#"SELECT {}, u.name AS creator_name,
                  (SELECT p.permission FROM "DrawingPermission" p WHERE p."drawingId" = d.id AND p."granteeUserId" = "#,
        qualified_columns("d")
    ));
    rows.push_bind(viewer_id.to_string())
        .push(r#") AS permission FROM "Drawing" d LEFT JOIN "User" u ON u.id = d."userId""#);
    push_scope(&mut rows, scope, params.search.as_deref());
    rows.push(format!(
        " ORDER BY d.{} {}, d.id LIMIT ",
        params.sort_column,
        if params.descending { "DESC" } else { "ASC" }
    ))
    .push_bind(params.limit)
    .push(" OFFSET ")
    .push_bind(params.offset);
    let drawings: Vec<ListRow> = rows.build_query_as().fetch_all(&state.db).await?;

    let mut count = QueryBuilder::<Postgres>::new(r#"SELECT COUNT(*) FROM "Drawing" d"#);
    push_scope(&mut count, scope, params.search.as_deref());
    let total: i64 = count.build_query_scalar().fetch_one(&state.db).await?;
    Ok((drawings, total))
}

fn summary_json(
    row: &ListRow,
    collection_id: Option<String>,
    include_data: bool,
) -> Map<String, Value> {
    let d = &row.drawing;
    let mut map = if include_data {
        d.to_json(collection_id)
    } else {
        let Value::Object(map) = json!({
            "id": d.id, "name": d.name, "collectionId": collection_id, "version": d.version,
            "createdAt": crate::time::iso(d.created_at), "updatedAt": crate::time::iso(d.updated_at),
            "userId": d.user_id,
        }) else {
            unreachable!()
        };
        map
    };
    map.insert("creatorName".into(), json!(row.creator_name));
    map
}

fn list_response(rows: Vec<Value>, total: i64, params: &ListParams) -> Json<Value> {
    Json(json!({
        "drawings": rows, "totalCount": total,
        "limit": params.limit, "offset": params.offset,
    }))
}

/// `GET /drawings`
async fn list(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Query(query): Query<HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    let params = list_params(&query);
    let scope = match params.collection.as_deref() {
        None => ListScope::Default { user_id: &user.id },
        Some("null") => ListScope::NoCollection { user_id: &user.id },
        Some("trash") => ListScope::Trash { user_id: &user.id },
        Some(collection_id) => {
            let visible: bool = sqlx::query_scalar(
                r#"SELECT EXISTS (SELECT 1 FROM "Collection" c WHERE c.id = $1 AND (c."userId" = $2
                     OR EXISTS (SELECT 1 FROM "CollectionShare" s WHERE s."collectionId" = c.id AND s."granteeUserId" = $2)))"#,
            )
            .bind(collection_id)
            .bind(&user.id)
            .fetch_one(&state.db)
            .await?;
            if !visible {
                return Err(error(StatusCode::NOT_FOUND, "Collection not found"));
            }
            ListScope::Collection { collection_id }
        }
    };
    let (rows, total) = query_list(&state, &scope, &params, &user.id).await?;
    let drawings = rows
        .iter()
        .map(|row| {
            let public = to_public_collection_id(row.drawing.collection_id.as_deref(), &user.id);
            Value::Object(summary_json(row, public, params.include_data))
        })
        .collect();
    Ok(list_response(drawings, total, &params))
}

/// `GET /drawings/shared`
async fn list_shared(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Query(query): Query<HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    let params = list_params(&query);
    let scope = ListScope::SharedWithMe { user_id: &user.id };
    let (rows, total) = query_list(&state, &scope, &params, &user.id).await?;
    let drawings = rows
        .iter()
        .map(|row| {
            let mut map = summary_json(row, None, params.include_data);
            let level = row
                .permission
                .as_deref()
                .and_then(Access::from_grant)
                .unwrap_or(Access::View);
            map.insert("accessLevel".into(), level.as_str().into());
            Value::Object(map)
        })
        .collect();
    Ok(list_response(drawings, total, &params))
}

/// `GET /drawings/{id}/preview` (ETag-cacheable).
async fn preview(
    State(state): State<AppState>,
    auth: OptionalUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    if access_for(&state, &auth, &id).await?.is_none() {
        return Err(access_denied(&auth));
    }
    let row: Option<(Option<String>, chrono::NaiveDateTime)> =
        sqlx::query_as(r#"SELECT preview, "updatedAt" FROM "Drawing" WHERE id = $1"#)
            .bind(&id)
            .fetch_optional(&state.db)
            .await?;
    let (preview, updated_at) = row.ok_or_else(drawing_not_found)?;
    let updated_ms = updated_at.and_utc().timestamp_millis();
    let etag = format!("W/\"preview-{id}-{updated_ms}\"");
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|v| v.as_bytes() == etag.as_bytes());
    let mut res = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        Json(json!({ "preview": preview, "updatedAt": updated_ms })).into_response()
    };
    let h = res.headers_mut();
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=0, must-revalidate"),
    );
    if let Ok(value) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, value);
    }
    Ok(res)
}

/// `GET /drawings/{id}`
async fn read(
    State(state): State<AppState>,
    auth: OptionalUser,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let access = access_for(&state, &auth, &id)
        .await?
        .ok_or_else(|| access_denied(&auth))?;
    let mut conn = state.db.acquire().await?;
    let drawing = find_drawing(&mut conn, &id)
        .await?
        .ok_or_else(drawing_not_found)?;
    let is_owner = auth.user.as_ref().is_some_and(|u| u.id == drawing.user_id);
    let collection = if is_owner {
        to_public_collection_id(drawing.collection_id.as_deref(), &drawing.user_id)
    } else {
        None
    };
    let mut map = drawing.to_json(collection);
    map.insert("accessLevel".into(), access.as_str().into());
    Ok(Json(Value::Object(map)))
}

/// `POST /drawings`
async fn create(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    let body = body.map(|Json(b)| b).unwrap_or(Value::Null);
    let max = state.cfg.file_upload_max_bytes;
    let imported = headers
        .get("x-imported-file")
        .is_some_and(|v| v.as_bytes() == b"true");
    if imported && !is_valid_import(&body, max) {
        return Err(AppError::status(
            StatusCode::BAD_REQUEST,
            "Invalid imported drawing file",
            "The imported file contains potentially malicious content or invalid structure",
        ));
    }
    let payload = parse_create(&body, max)?;

    let target = payload
        .collection_id
        .as_deref()
        .map(|raw| to_internal_collection_id(raw, &user.id));
    match target.as_deref() {
        Some(id) if !is_trash_id(id, &user.id) => {
            let owner: Option<String> =
                sqlx::query_scalar(r#"SELECT "userId" FROM "Collection" WHERE id = $1"#)
                    .bind(id)
                    .fetch_optional(&state.db)
                    .await?;
            let owner =
                owner.ok_or_else(|| error(StatusCode::NOT_FOUND, "Collection not found"))?;
            if owner != user.id && !has_edit_share(&state, id, &user.id).await? {
                return Err(error(
                    StatusCode::FORBIDDEN,
                    "No edit access to this collection",
                ));
            }
        }
        _ if payload.collection_id.as_deref() == Some("trash") => {
            let mut conn = state.db.acquire().await?;
            ensure_trash_collection(&mut conn, &user.id).await?;
        }
        _ => {}
    }

    let id = uuid::Uuid::new_v4().to_string();
    let original_files = payload.files.clone().unwrap_or_else(|| json!({}));
    let files = files_store::intern(&state.db, &id, &original_files).await?;
    let preview = payload
        .preview
        .as_deref()
        .map(|p| rewrite_preview(p, &original_files, &files));
    let inserted: Result<DrawingRow, sqlx::Error> = sqlx::query_as(&format!(
        r#"INSERT INTO "Drawing" (id, name, elements, "appState", files, preview, version, "userId", "collectionId", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8, {NOW_UTC}, {NOW_UTC})
           RETURNING {DRAWING_COLUMNS}"#
    ))
    .bind(&id)
    .bind(payload.name.as_deref().unwrap_or("Untitled Drawing"))
    .bind(Value::Array(payload.elements).to_string())
    .bind(payload.app_state.to_string())
    .bind(files.to_string())
    .bind(preview)
    .bind(&user.id)
    .bind(&target)
    .fetch_one(&state.db)
    .await;
    let drawing = match inserted {
        Ok(drawing) => drawing,
        Err(err) => {
            if let Ok(mut conn) = state.db.acquire().await {
                let _ = files_store::delete_for_drawing(&mut conn, &id).await;
            }
            return Err(err.into());
        }
    };
    let public = to_public_collection_id(drawing.collection_id.as_deref(), &user.id);
    Ok(Json(Value::Object(drawing.to_json(public))))
}

async fn has_edit_share(state: &AppState, collection_id: &str, user_id: &str) -> AppResult<bool> {
    Ok(sqlx::query_scalar(
        r#"SELECT EXISTS (SELECT 1 FROM "CollectionShare"
             WHERE "collectionId" = $1 AND "granteeUserId" = $2 AND role = 'edit')"#,
    )
    .bind(collection_id)
    .bind(user_id)
    .fetch_one(&state.db)
    .await?)
}

fn version_conflict(current: Option<i32>) -> AppError {
    AppError::json(
        StatusCode::CONFLICT,
        json!({
            "error": "Conflict", "code": "VERSION_CONFLICT",
            "message": "Drawing has changed since this editor state was loaded.",
            "currentVersion": current,
        }),
    )
}

/// Room broadcast after a committed scene save so late joiners converge.
async fn broadcast_persisted_scene(state: &AppState, drawing: &DrawingRow) {
    let elements = parse_json_field(&drawing.elements, json!([]));
    let order: Vec<Value> = elements
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("id").filter(|id| id.is_string()).cloned())
        .collect();
    let payload = json!({
        "drawingId": drawing.id, "persisted": true, "elements": elements,
        "files": parse_json_field(&drawing.files, json!({})), "elementOrder": order,
    });
    if let Some(ns) = state.io.of("/") {
        if let Err(err) = ns
            .to(format!("drawing_{}", drawing.id))
            .emit("element-update", &payload)
            .await
        {
            tracing::warn!(%err, "element-update broadcast failed");
        }
    }
}

/// `PUT /drawings/{id}`
async fn update(
    State(state): State<AppState>,
    auth: OptionalUser,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    let access = access_for(&state, &auth, &id)
        .await?
        .filter(|a| a.can_edit())
        .ok_or_else(|| access_denied(&auth))?;
    let existing = {
        let mut conn = state.db.acquire().await?;
        find_drawing(&mut conn, &id)
            .await?
            .ok_or_else(|| error(StatusCode::NOT_FOUND, "Drawing not found"))?
    };
    let body = body.map(|Json(b)| b).unwrap_or(Value::Null);
    let payload = parse_update(&body, state.cfg.file_upload_max_bytes)?;
    let scene = payload.is_scene_update();
    if scene && payload.version.is_some_and(|v| v != existing.version) {
        return Err(version_conflict(Some(existing.version)));
    }

    let owner = existing.user_id.clone();
    let acting = auth.user.as_ref().map_or(owner.clone(), |u| u.id.clone());
    let mut changes = DrawingChanges {
        name: payload.name.clone(),
        elements: payload
            .elements
            .clone()
            .map(|e| Value::Array(e).to_string()),
        app_state: payload.app_state.as_ref().map(Value::to_string),
        ..Default::default()
    };

    let mut processed_files = None;
    let mut required_file_ids = Vec::new();
    if let Some(files) = &payload.files {
        let known = files_store::list_file_ids(&state.db, &id).await?;
        let processed = files_store::intern(&state.db, &id, files).await?;
        for (file_id, entry) in processed.as_object().into_iter().flatten() {
            let after = entry.get("dataURL").and_then(Value::as_str);
            let before = files
                .get(file_id)
                .and_then(|f| f.get("dataURL"))
                .and_then(Value::as_str);
            let interned_now = before.is_some_and(|b| b.starts_with("data:"))
                && after.is_some()
                && after != before;
            if known.contains(file_id)
                || after == Some(file_url(&id, file_id).as_str())
                || interned_now
            {
                required_file_ids.push(file_id.clone());
            }
        }
        processed_files = Some(processed);
    }
    if let Some(preview) = &payload.preview {
        changes.preview = Some(match (preview, &processed_files, &payload.files) {
            (Some(p), Some(processed), Some(original)) => {
                Some(rewrite_preview(p, original, processed))
            }
            (p, _, _) => p.clone(),
        });
    }

    if let Some(target) = &payload.collection_id {
        if access != Access::Owner {
            return Err(AppError::status(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "Only the owner can move drawings between collections",
            ));
        }
        changes.collection_id = Some(match target.as_deref() {
            Some("trash") => {
                let mut conn = state.db.acquire().await?;
                ensure_trash_collection(&mut conn, &owner).await?;
                Some(trash_id(&owner))
            }
            Some(collection_id) => {
                let owned: bool = sqlx::query_scalar(
                    r#"SELECT EXISTS (SELECT 1 FROM "Collection" WHERE id = $1 AND "userId" = $2)"#,
                )
                .bind(collection_id)
                .bind(&acting)
                .fetch_one(&state.db)
                .await?;
                if !owned && !has_edit_share(&state, collection_id, &acting).await? {
                    return Err(error(StatusCode::NOT_FOUND, "Collection not found"));
                }
                Some(collection_id.to_string())
            }
            None => None,
        });
    }

    let updated = if scene {
        let guard = match payload.version {
            Some(v) => VersionGuard::Exact(v),
            None => VersionGuard::Optimistic { retries: 2 },
        };
        let mutation = SceneMutation {
            changes,
            incoming_files: processed_files,
            required_file_ids,
        };
        match apply_scene_update(&state.db, &id, guard, &mutation).await {
            Ok(drawing) => drawing,
            Err(SceneError::Conflict) => {
                let latest: Option<i32> =
                    sqlx::query_scalar(r#"SELECT version FROM "Drawing" WHERE id = $1"#)
                        .bind(&id)
                        .fetch_optional(&state.db)
                        .await?;
                return Err(version_conflict(latest));
            }
            Err(SceneError::Db(err)) => return Err(err.into()),
        }
    } else {
        update_drawing(&state.db, &id, &changes)
            .await?
            .ok_or_else(|| error(StatusCode::NOT_FOUND, "Drawing not found"))?
    };

    if scene {
        broadcast_persisted_scene(&state, &updated).await;
    }
    let public = to_public_collection_id(updated.collection_id.as_deref(), &owner);
    let mut map = updated.to_json(public);
    map.insert("accessLevel".into(), access.as_str().into());
    Ok(Json(Value::Object(map)))
}

async fn owned_drawing(state: &AppState, id: &str, user_id: &str) -> AppResult<Option<DrawingRow>> {
    Ok(sqlx::query_as(&format!(
        r#"SELECT {DRAWING_COLUMNS} FROM "Drawing" WHERE id = $1 AND "userId" = $2"#
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?)
}

/// `DELETE /drawings/{id}` (owner only)
async fn remove(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    owned_drawing(&state, &id, &user.id)
        .await?
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "Drawing not found"))?;
    let mut tx = state.db.begin().await?;
    files_store::delete_for_drawing(&mut tx, &id).await?;
    let deleted = sqlx::query(r#"DELETE FROM "Drawing" WHERE id = $1 AND "userId" = $2"#)
        .bind(&id)
        .bind(&user.id)
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(error(StatusCode::NOT_FOUND, "Drawing not found"));
    }
    tx.commit().await?;
    Ok(Json(json!({ "success": true })))
}

/// `POST /drawings/{id}/duplicate` (owner only)
async fn duplicate(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let original = owned_drawing(&state, &id, &user.id)
        .await?
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "Original drawing not found"))?;
    let mut tx = state.db.begin().await?;
    let mut collection_id = original.collection_id.clone();
    if collection_id
        .as_deref()
        .is_some_and(|c| is_trash_id(c, &user.id))
    {
        ensure_trash_collection(&mut tx, &user.id).await?;
        collection_id = Some(trash_id(&user.id));
    }
    let new_id = uuid::Uuid::new_v4().to_string();
    let original_files = parse_json_field(&original.files, json!({}));
    let files =
        files_store::copy_for_duplicate(&mut tx, &original.id, &new_id, &original_files).await?;
    let preview = original
        .preview
        .as_deref()
        .map(|p| rewrite_preview(p, &original_files, &files));
    let drawing: DrawingRow = sqlx::query_as(&format!(
        r#"INSERT INTO "Drawing" (id, name, elements, "appState", files, preview, version, "userId", "collectionId", "createdAt", "updatedAt")
           VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8, {NOW_UTC}, {NOW_UTC})
           RETURNING {DRAWING_COLUMNS}"#
    ))
    .bind(&new_id)
    .bind(format!("{} (Copy)", original.name))
    .bind(&original.elements)
    .bind(&original.app_state)
    .bind(files.to_string())
    .bind(preview)
    .bind(&user.id)
    .bind(&collection_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let public = to_public_collection_id(drawing.collection_id.as_deref(), &user.id);
    Ok(Json(Value::Object(drawing.to_json(public))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parse_int_like_js() {
        assert_eq!(js_parse_int("10"), Some(10));
        assert_eq!(js_parse_int(" 7abc"), Some(7));
        assert_eq!(js_parse_int("-3"), Some(-3));
        assert_eq!(js_parse_int("+4"), Some(4));
        assert_eq!(js_parse_int("abc"), None);
        assert_eq!(js_parse_int(""), None);
        assert_eq!(js_parse_int("1.9"), Some(1));
    }

    #[test]
    fn list_param_defaults() {
        assert_eq!(
            list_params(&q(&[])),
            ListParams {
                search: None,
                collection: None,
                include_data: false,
                sort_column: r#""updatedAt""#,
                descending: true,
                limit: 50,
                offset: 0,
            }
        );
    }

    #[test]
    fn list_param_parsing_and_clamping() {
        let p = list_params(&q(&[
            ("search", "  plan "),
            ("collectionId", "c1"),
            ("includeData", "TRUE"),
            ("sortField", "name"),
            ("limit", "500"),
            ("offset", "-5"),
        ]));
        assert_eq!(p.search.as_deref(), Some("plan"));
        assert_eq!(p.collection.as_deref(), Some("c1"));
        assert!(p.include_data);
        assert_eq!(p.sort_column, "name");
        assert!(!p.descending, "name sorts ascending by default");
        assert_eq!(p.limit, 200);
        assert_eq!(p.offset, 0);

        let p = list_params(&q(&[
            ("sortField", "createdAt"),
            ("sortDirection", "asc"),
            ("limit", "0"),
            ("includeData", "1"),
            ("search", "  "),
        ]));
        assert_eq!(p.sort_column, r#""createdAt""#);
        assert!(!p.descending);
        assert_eq!(p.limit, 1);
        assert!(p.include_data);
        assert_eq!(p.search, None);
        assert_eq!(
            list_params(&q(&[("sortField", "bogus"), ("limit", "abc")])).limit,
            50
        );
    }
}
