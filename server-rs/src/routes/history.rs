//! Drawing version history (backend/src/routes/dashboard/drawingHistoryRoutes.ts).

use std::{collections::HashMap, time::Duration};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::NaiveDateTime;
use serde_json::{json, Value};
use sqlx::PgPool;

use crate::{
    auth::middleware::OptionalUser,
    authz::{drawing_access, Access},
    drawing::{
        apply_scene_update, find_drawing, parse_json_field, DrawingChanges, SceneError,
        SceneMutation, VersionGuard,
    },
    error::{AppError, AppResult},
    snapshot_codec,
    state::AppState,
    time::{iso, NOW_UTC},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/drawings/{id}/history", get(list))
        .route("/drawings/{id}/history/{snapshot_id}", get(read))
        .route(
            "/drawings/{id}/history/{snapshot_id}/restore",
            post(restore),
        )
}

/// JS `Number(raw)` restricted to safe integers (`""` → 0); None if not an integer.
pub fn js_safe_int(raw: &str) -> Option<i64> {
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some(0);
    }
    let n: f64 = trimmed.parse().ok()?;
    (n.is_finite() && n.fract() == 0.0 && n.abs() <= MAX_SAFE).then_some(n as i64)
}

/// `(limit, offset)` for the history list, or None for Node's 400 response.
pub fn history_page(limit: Option<&str>, offset: Option<&str>) -> Option<(i64, i64)> {
    let limit = limit.map_or(Some(50), js_safe_int).filter(|l| *l >= 1)?;
    let offset = offset.map_or(Some(0), js_safe_int).filter(|o| *o >= 0)?;
    Some((limit.min(200), offset))
}

/// Hourly sweep: delete snapshots older than `retention`.
pub async fn delete_old_snapshots(db: &PgPool, retention: Duration) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(&format!(
        r#"DELETE FROM "DrawingSnapshot" WHERE "createdAt" < {NOW_UTC} - make_interval(secs => $1)"#
    ))
    .bind(retention.as_secs_f64())
    .execute(db)
    .await?
    .rows_affected())
}

fn error(status: StatusCode, message: &str) -> AppError {
    AppError::json(status, json!({ "error": message }))
}

/// Access check shared by the three routes (history uses a bare "Drawing not found").
async fn require_access(
    state: &AppState,
    auth: &OptionalUser,
    id: &str,
    edit: bool,
) -> AppResult<Access> {
    let access = drawing_access(&state.db, auth.user.as_ref().map(|u| u.id.as_str()), id).await?;
    match access {
        Some(a) if !edit || a.can_edit() => Ok(a),
        _ if auth.auth_error => Err(AppError::status(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "Invalid or expired token",
        )),
        _ => Err(error(StatusCode::NOT_FOUND, "Drawing not found")),
    }
}

/// `GET /drawings/{id}/history`
async fn list(
    State(state): State<AppState>,
    auth: OptionalUser,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> AppResult<Json<Value>> {
    require_access(&state, &auth, &id, false).await?;
    let (limit, offset) = history_page(
        query.get("limit").map(String::as_str),
        query.get("offset").map(String::as_str),
    )
    .ok_or_else(|| error(StatusCode::BAD_REQUEST, "Invalid history pagination"))?;
    let rows: Vec<(String, i32, NaiveDateTime)> = sqlx::query_as(
        r#"SELECT id, version, "createdAt" FROM "DrawingSnapshot" WHERE "drawingId" = $1
           ORDER BY "createdAt" DESC, version DESC LIMIT $2 OFFSET $3"#,
    )
    .bind(&id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    let total: i64 =
        sqlx::query_scalar(r#"SELECT COUNT(*) FROM "DrawingSnapshot" WHERE "drawingId" = $1"#)
            .bind(&id)
            .fetch_one(&state.db)
            .await?;
    let snapshots: Vec<Value> = rows
        .into_iter()
        .map(|(id, version, created)| json!({ "id": id, "version": version, "createdAt": iso(created) }))
        .collect();
    Ok(Json(json!({ "snapshots": snapshots, "totalCount": total })))
}

#[derive(sqlx::FromRow)]
struct SnapshotRow {
    id: String,
    #[sqlx(rename = "drawingId")]
    drawing_id: String,
    version: i32,
    elements: String,
    #[sqlx(rename = "appState")]
    app_state: String,
    files: String,
    #[sqlx(rename = "createdAt")]
    created_at: NaiveDateTime,
}

/// Decoded `(elements, appState, files)` text of a snapshot.
type DecodedScene = (String, String, String);

impl SnapshotRow {
    fn decode(&self) -> Result<DecodedScene, AppError> {
        let decode = |field: &str| {
            snapshot_codec::decode(field)
                .map_err(|_| AppError::Internal("SNAPSHOT_DECODE_FAILED".into()))
        };
        Ok((
            decode(&self.elements)?,
            decode(&self.app_state)?,
            decode(&self.files)?,
        ))
    }
}

async fn find_snapshot(
    state: &AppState,
    drawing_id: &str,
    snapshot_id: &str,
) -> AppResult<SnapshotRow> {
    sqlx::query_as(
        r#"SELECT id, "drawingId", version, elements, "appState", files, "createdAt"
           FROM "DrawingSnapshot" WHERE id = $1 AND "drawingId" = $2"#,
    )
    .bind(snapshot_id)
    .bind(drawing_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| error(StatusCode::NOT_FOUND, "Snapshot not found"))
}

/// `GET /drawings/{id}/history/{snapshotId}`
async fn read(
    State(state): State<AppState>,
    auth: OptionalUser,
    Path((id, snapshot_id)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    require_access(&state, &auth, &id, false).await?;
    let snapshot = find_snapshot(&state, &id, &snapshot_id).await?;
    let (elements, app_state, files) = snapshot.decode()?;
    Ok(Json(json!({
        "id": snapshot.id, "drawingId": snapshot.drawing_id, "version": snapshot.version,
        "elements": parse_json_field(&elements, json!([])),
        "appState": parse_json_field(&app_state, json!({})),
        "files": parse_json_field(&files, json!({})),
        "createdAt": iso(snapshot.created_at),
    })))
}

/// True when the decoded text is restorable (array / object / object).
fn is_restorable(elements: &str, app_state: &str, files: &str) -> bool {
    let parse = |s: &str| serde_json::from_str::<Value>(s).ok();
    matches!(
        (parse(elements), parse(app_state), parse(files)),
        (
            Some(Value::Array(_)),
            Some(Value::Object(_)),
            Some(Value::Object(_))
        )
    )
}

/// `POST /drawings/{id}/history/{snapshotId}/restore`: snapshot the current state,
/// then apply the old one under the save path's version guard.
async fn restore(
    State(state): State<AppState>,
    auth: OptionalUser,
    Path((id, snapshot_id)): Path<(String, String)>,
) -> AppResult<Json<Value>> {
    let access = require_access(&state, &auth, &id, true).await?;
    let drawing = {
        let mut conn = state.db.acquire().await?;
        find_drawing(&mut conn, &id)
            .await?
            .ok_or_else(|| error(StatusCode::NOT_FOUND, "Drawing not found"))?
    };
    let snapshot = find_snapshot(&state, &id, &snapshot_id).await?;
    let (elements, app_state, files) = snapshot.decode()?;
    if !is_restorable(&elements, &app_state, &files) {
        return Err(AppError::status(
            StatusCode::BAD_REQUEST,
            "Invalid drawing history snapshot",
            "The snapshot cannot be restored without losing drawing data.",
        ));
    }
    let mutation = SceneMutation {
        changes: DrawingChanges {
            elements: Some(elements),
            app_state: Some(app_state),
            files: Some(files),
            preview: Some(None),
            ..Default::default()
        },
        ..Default::default()
    };
    let updated = match apply_scene_update(
        &state.db,
        &id,
        VersionGuard::Exact(drawing.version),
        &mutation,
    )
    .await
    {
        Ok(updated) => updated,
        Err(SceneError::Conflict) => {
            return Err(AppError::json(
                StatusCode::CONFLICT,
                json!({
                    "error": "Drawing changed during restore; please try again",
                    "code": "VERSION_CONFLICT",
                }),
            ))
        }
        Err(SceneError::Db(err)) => return Err(err.into()),
    };
    let collection = updated.collection_id.clone();
    let mut map = updated.to_json(collection);
    map.insert("accessLevel".into(), access.as_str().into());
    Ok(Json(Value::Object(map)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_number_semantics() {
        assert_eq!(js_safe_int("5"), Some(5));
        assert_eq!(js_safe_int(" 7 "), Some(7));
        assert_eq!(js_safe_int(""), Some(0));
        assert_eq!(js_safe_int("3.0"), Some(3));
        assert_eq!(js_safe_int("1.5"), None);
        assert_eq!(js_safe_int("abc"), None);
        assert_eq!(js_safe_int("9007199254740993"), None);
    }

    #[test]
    fn pagination_rules() {
        assert_eq!(history_page(None, None), Some((50, 0)));
        assert_eq!(history_page(Some("500"), Some("10")), Some((200, 10)));
        assert_eq!(history_page(Some("0"), None), None);
        assert_eq!(history_page(Some(""), None), None);
        assert_eq!(history_page(None, Some("-1")), None);
        assert_eq!(history_page(Some("x"), None), None);
    }

    #[test]
    fn restorable_shapes() {
        assert!(is_restorable("[]", "{}", "{}"));
        assert!(!is_restorable("{}", "{}", "{}"));
        assert!(!is_restorable("[]", "[]", "{}"));
        assert!(!is_restorable("[]", "{}", "not json"));
    }
}
