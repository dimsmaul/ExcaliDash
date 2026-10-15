//! Drawing rows, request payload validation (Node drawingCreate/UpdateSchema) and the
//! versioned scene update transaction (backend/src/routes/dashboard/sceneUpdate.ts).

use axum::http::StatusCode;
use chrono::NaiveDateTime;
use serde_json::{json, Map, Value};
use sqlx::{PgConnection, PgPool, Postgres, QueryBuilder};

use crate::{
    error::AppError,
    sanitize::{self, SanitizeError},
    snapshot_codec,
    time::{iso, NOW_UTC},
};

/// Why a drawing payload was rejected.
#[derive(Debug, PartialEq)]
pub enum PayloadError {
    /// Node `respondWithValidationErrors` (production body).
    Validation,
    /// Node `DrawingSanitizationError` (400/413, message names the file).
    File { status: u16, message: String },
}

impl From<SanitizeError> for PayloadError {
    fn from(err: SanitizeError) -> Self {
        match err {
            SanitizeError::Invalid => PayloadError::Validation,
            SanitizeError::File {
                status, message, ..
            } => PayloadError::File { status, message },
        }
    }
}

impl From<PayloadError> for AppError {
    fn from(err: PayloadError) -> Self {
        match err {
            PayloadError::Validation => AppError::status(
                StatusCode::BAD_REQUEST,
                "Validation error",
                "Invalid request data",
            ),
            PayloadError::File { status, message } => AppError::json(
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                json!({ "error": "Request error", "message": message }),
            ),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct CreatePayload {
    pub name: Option<String>,
    pub collection_id: Option<String>,
    pub elements: Vec<Value>,
    pub app_state: Value,
    pub files: Option<Value>,
    pub preview: Option<String>,
}

#[derive(Debug, Default, PartialEq)]
pub struct UpdatePayload {
    pub name: Option<String>,
    /// `Some(None)` = explicit null (move out of any collection).
    pub collection_id: Option<Option<String>>,
    pub elements: Option<Vec<Value>>,
    pub app_state: Option<Value>,
    pub files: Option<Value>,
    /// `Some(None)` = explicit null (clear preview).
    pub preview: Option<Option<String>>,
    pub version: Option<i32>,
}

impl UpdatePayload {
    pub fn is_scene_update(&self) -> bool {
        self.elements.is_some() || self.app_state.is_some() || self.files.is_some()
    }
}

/// The shared `drawingBaseSchema` fields plus `files`, as present in the body.
struct BaseFields {
    name: Option<String>,
    collection_id: Option<Option<String>>,
    preview: Option<Option<String>>,
    files: Option<Value>,
}

fn parse_base(
    body: &serde_json::Map<String, Value>,
    max_file_bytes: usize,
) -> Result<BaseFields, PayloadError> {
    let name = match body.get("name") {
        None => None,
        Some(Value::String(s)) if (1..=255).contains(&s.trim().chars().count()) => {
            Some(s.trim().to_string())
        }
        Some(_) => return Err(PayloadError::Validation),
    };
    let collection_id = match body.get("collectionId") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(s)) if !s.trim().is_empty() => Some(Some(s.trim().to_string())),
        Some(_) => return Err(PayloadError::Validation),
    };
    let preview = match body.get("preview") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(Value::String(s)) => Some(Some(sanitize::svg(s))),
        Some(_) => return Err(PayloadError::Validation),
    };
    let files = match body.get("files") {
        None | Some(Value::Null) => None,
        Some(v @ Value::Object(_)) => Some(sanitize::files(v, max_file_bytes)?),
        Some(_) => return Err(PayloadError::Validation),
    };
    Ok(BaseFields {
        name,
        collection_id,
        preview,
        files,
    })
}

fn parse_elements(value: &Value) -> Result<Vec<Value>, PayloadError> {
    value
        .as_array()
        .ok_or(PayloadError::Validation)?
        .iter()
        .map(|e| sanitize::element(e).ok_or(PayloadError::Validation))
        .collect()
}

fn parse_app_state(value: &Value) -> Result<Value, PayloadError> {
    sanitize::app_state(value).ok_or(PayloadError::Validation)
}

/// Node `drawingCreateSchema` + `sanitizeDrawingData`.
pub fn parse_create(body: &Value, max_file_bytes: usize) -> Result<CreatePayload, PayloadError> {
    let obj = body.as_object().ok_or(PayloadError::Validation)?;
    let elements = obj
        .get("elements")
        .map(parse_elements)
        .transpose()?
        .unwrap_or_default();
    let app_state = obj
        .get("appState")
        .map(parse_app_state)
        .transpose()?
        .unwrap_or_else(|| json!({}));
    let base = parse_base(obj, max_file_bytes)?;
    Ok(CreatePayload {
        name: base.name,
        collection_id: base.collection_id.flatten(),
        elements,
        app_state,
        files: base.files,
        preview: base.preview.flatten(),
    })
}

/// Node `drawingUpdateSchema` + `sanitizeDrawingUpdateData`.
pub fn parse_update(body: &Value, max_file_bytes: usize) -> Result<UpdatePayload, PayloadError> {
    let obj = body.as_object().ok_or(PayloadError::Validation)?;
    let version = match obj.get("version") {
        None => None,
        Some(v) => Some(
            v.as_i64()
                .filter(|n| *n > 0)
                .and_then(|n| i32::try_from(n).ok())
                .ok_or(PayloadError::Validation)?,
        ),
    };
    let base = parse_base(obj, max_file_bytes)?;
    Ok(UpdatePayload {
        name: base.name,
        collection_id: base.collection_id,
        elements: obj.get("elements").map(parse_elements).transpose()?,
        app_state: obj.get("appState").map(parse_app_state).transpose()?,
        files: base.files,
        preview: base.preview,
        version,
    })
}

/// Node `validateImportedDrawing` (used for `x-imported-file: true` creates).
pub fn is_valid_import(body: &Value, max_file_bytes: usize) -> bool {
    let Some(elements) = body.get("elements").and_then(Value::as_array) else {
        return false;
    };
    elements.len() <= 10_000
        && body.get("appState").is_some_and(Value::is_object)
        && parse_create(body, max_file_bytes).is_ok()
}

/// Node `isBlankFileEntry`: missing, not an object, or no non-empty `dataURL`.
fn is_blank_file_entry(entry: Option<&Value>) -> bool {
    entry
        .and_then(|e| e.get("dataURL"))
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
}

/// Node `mergeFilesUnion`: incoming entries win, except a blank one never
/// clobbers an existing entry that still has content.
pub fn merge_files_union(existing: &Value, incoming: &Value) -> Value {
    let mut merged = existing.as_object().cloned().unwrap_or_default();
    for (file_id, entry) in incoming.as_object().into_iter().flatten() {
        let keeps_existing = is_blank_file_entry(Some(entry))
            && merged.contains_key(file_id)
            && !is_blank_file_entry(merged.get(file_id));
        if !keeps_existing {
            merged.insert(file_id.clone(), entry.clone());
        }
    }
    Value::Object(merged)
}

/// Node `parseJsonField`: JSON text, or the fallback when it does not parse.
pub fn parse_json_field(raw: &str, fallback: Value) -> Value {
    serde_json::from_str(raw).unwrap_or(fallback)
}

pub const DRAWING_COLUMNS: &str = r#"id, name, elements, "appState", files, preview, version, "userId", "collectionId", "createdAt", "updatedAt""#;

/// `DRAWING_COLUMNS` qualified with a table alias, for joins.
pub fn qualified_columns(alias: &str) -> String {
    DRAWING_COLUMNS
        .split(", ")
        .map(|column| format!("{alias}.{column}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A `"Drawing"` row with its JSON fields still as stored text.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DrawingRow {
    pub id: String,
    pub name: String,
    pub elements: String,
    #[sqlx(rename = "appState")]
    pub app_state: String,
    pub files: String,
    pub preview: Option<String>,
    pub version: i32,
    #[sqlx(rename = "userId")]
    pub user_id: String,
    #[sqlx(rename = "collectionId")]
    pub collection_id: Option<String>,
    #[sqlx(rename = "createdAt")]
    pub created_at: NaiveDateTime,
    #[sqlx(rename = "updatedAt")]
    pub updated_at: NaiveDateTime,
}

impl DrawingRow {
    /// Full drawing JSON (Prisma row spread) with parsed scene fields and the given
    /// public collection id.
    pub fn to_json(&self, collection_id: Option<String>) -> Map<String, Value> {
        let Value::Object(map) = json!({
            "id": self.id, "name": self.name,
            "elements": parse_json_field(&self.elements, json!([])),
            "appState": parse_json_field(&self.app_state, json!({})),
            "files": parse_json_field(&self.files, json!({})),
            "preview": self.preview, "version": self.version, "userId": self.user_id,
            "collectionId": collection_id,
            "createdAt": iso(self.created_at), "updatedAt": iso(self.updated_at),
        }) else {
            unreachable!()
        };
        map
    }
}

pub async fn find_drawing(
    conn: &mut PgConnection,
    id: &str,
) -> Result<Option<DrawingRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        r#"SELECT {DRAWING_COLUMNS} FROM "Drawing" WHERE id = $1"#
    ))
    .bind(id)
    .fetch_optional(conn)
    .await
}

/// Column writes for a drawing update (absent = unchanged).
#[derive(Debug, Default, Clone)]
pub struct DrawingChanges {
    pub name: Option<String>,
    pub elements: Option<String>,
    pub app_state: Option<String>,
    pub preview: Option<Option<String>>,
    pub collection_id: Option<Option<String>>,
    /// Replace `files` verbatim (history restore).
    pub files: Option<String>,
}

/// A scene write: column changes plus files to union-merge into the current set.
#[derive(Debug, Default, Clone)]
pub struct SceneMutation {
    pub changes: DrawingChanges,
    pub incoming_files: Option<Value>,
    /// Interned references whose bytes must still exist when the scene commits.
    pub required_file_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum VersionGuard {
    /// The client's loaded version; any other current version is a conflict.
    Exact(i32),
    /// Use whatever version is current, retrying this many times on a race.
    Optimistic { retries: u32 },
}

#[derive(Debug)]
pub enum SceneError {
    Conflict,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for SceneError {
    fn from(err: sqlx::Error) -> Self {
        SceneError::Db(err)
    }
}

fn push_changes(builder: &mut QueryBuilder<'_, Postgres>, changes: &DrawingChanges) {
    if let Some(name) = &changes.name {
        builder.push(", name = ").push_bind(name.clone());
    }
    if let Some(elements) = &changes.elements {
        builder.push(", elements = ").push_bind(elements.clone());
    }
    if let Some(app_state) = &changes.app_state {
        builder
            .push(r#", "appState" = "#)
            .push_bind(app_state.clone());
    }
    if let Some(preview) = &changes.preview {
        builder.push(", preview = ").push_bind(preview.clone());
    }
    if let Some(collection_id) = &changes.collection_id {
        builder
            .push(r#", "collectionId" = "#)
            .push_bind(collection_id.clone());
    }
    if let Some(files) = &changes.files {
        builder.push(", files = ").push_bind(files.clone());
    }
}

/// Plain column update (no version bump, no snapshot), e.g. rename or move.
pub async fn update_drawing(
    db: &PgPool,
    id: &str,
    changes: &DrawingChanges,
) -> Result<Option<DrawingRow>, sqlx::Error> {
    let mut builder = QueryBuilder::new(format!(r#"UPDATE "Drawing" SET "updatedAt" = {NOW_UTC}"#));
    push_changes(&mut builder, changes);
    builder
        .push(" WHERE id = ")
        .push_bind(id.to_string())
        .push(format!(" RETURNING {DRAWING_COLUMNS}"));
    builder.build_query_as().fetch_optional(db).await
}

/// Node `applySceneUpdateTx`: in one transaction, snapshot the current scene, apply
/// the mutation, union-merge files and bump `version` guarded by the expected version.
pub async fn apply_scene_update(
    db: &PgPool,
    drawing_id: &str,
    guard: VersionGuard,
    mutation: &SceneMutation,
) -> Result<DrawingRow, SceneError> {
    let attempts = match guard {
        VersionGuard::Exact(_) => 1,
        VersionGuard::Optimistic { retries } => retries + 1,
    };
    for attempt in 0..attempts {
        match try_scene_update(db, drawing_id, guard, mutation).await {
            Err(SceneError::Conflict) if attempt + 1 < attempts => continue,
            result => return result,
        }
    }
    Err(SceneError::Conflict)
}

async fn try_scene_update(
    db: &PgPool,
    drawing_id: &str,
    guard: VersionGuard,
    mutation: &SceneMutation,
) -> Result<DrawingRow, SceneError> {
    let mut tx = db.begin().await?;
    let current = find_drawing(&mut tx, drawing_id)
        .await?
        .ok_or(SceneError::Conflict)?;
    let expected = match guard {
        VersionGuard::Exact(v) if v != current.version => return Err(SceneError::Conflict),
        VersionGuard::Exact(v) => v,
        VersionGuard::Optimistic { .. } => current.version,
    };

    if !mutation.required_file_ids.is_empty() {
        let required: Vec<String> = mutation.required_file_ids.clone();
        let stored: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM "DrawingFile" WHERE "drawingId" = $1 AND "fileId" = ANY($2)"#,
        )
        .bind(drawing_id)
        .bind(&required)
        .fetch_one(&mut *tx)
        .await?;
        let unique: std::collections::HashSet<&String> = required.iter().collect();
        if stored as usize != unique.len() {
            return Err(SceneError::Conflict);
        }
    }

    sqlx::query(&format!(
        r#"INSERT INTO "DrawingSnapshot" (id, "drawingId", version, elements, "appState", files, "createdAt")
           VALUES ($1, $2, $3, $4, $5, $6, {NOW_UTC})"#
    ))
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(drawing_id)
    .bind(current.version)
    .bind(snapshot_codec::encode(&current.elements))
    .bind(snapshot_codec::encode(&current.app_state))
    .bind(snapshot_codec::encode(&current.files))
    .execute(&mut *tx)
    .await?;

    let mut changes = mutation.changes.clone();
    if let Some(incoming) = &mutation.incoming_files {
        let existing = parse_json_field(&current.files, json!({}));
        changes.files = Some(merge_files_union(&existing, incoming).to_string());
    }
    let mut builder = QueryBuilder::new(format!(
        r#"UPDATE "Drawing" SET version = version + 1, "updatedAt" = {NOW_UTC}"#
    ));
    push_changes(&mut builder, &changes);
    builder
        .push(" WHERE id = ")
        .push_bind(drawing_id.to_string())
        .push(" AND version = ")
        .push_bind(expected)
        .push(format!(" RETURNING {DRAWING_COLUMNS}"));
    let updated: Option<DrawingRow> = builder.build_query_as().fetch_optional(&mut *tx).await?;
    let updated = updated.ok_or(SceneError::Conflict)?;
    tx.commit().await?;
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 1024;
    const PNG: &str = "data:image/png;base64,iVBORw0KGgo=";

    #[test]
    fn create_defaults_and_sanitizes() {
        let p = parse_create(&json!({}), MAX).unwrap();
        assert_eq!(p.name, None);
        assert_eq!(p.elements, Vec::<Value>::new());
        assert_eq!(p.app_state, json!({}));
        assert_eq!(p.files, None);

        let p = parse_create(
            &json!({
                "name": "  Board ", "collectionId": " c1 ",
                "elements": [{"id": "e", "type": "text", "text": "a\u{0}b", "link": "javascript:x"}],
                "appState": {"viewBackgroundColor": "#fff"},
                "files": {"f1": {"dataURL": PNG}, "bad id": {"dataURL": PNG}},
                "preview": "<svg><script>x</script><rect></rect></svg>",
                "unknownField": 1
            }),
            MAX,
        )
        .unwrap();
        assert_eq!(p.name.as_deref(), Some("Board"));
        assert_eq!(p.collection_id.as_deref(), Some("c1"));
        assert_eq!(p.elements[0]["text"], "ab");
        assert_eq!(p.elements[0]["link"], "");
        assert!(p.files.as_ref().unwrap().get("bad id").is_none());
        assert!(!p.preview.as_ref().unwrap().contains("script"));
    }

    #[test]
    fn create_rejects_invalid_shapes() {
        for bad in [
            json!({"name": "   "}),
            json!({"name": "x".repeat(256)}),
            json!({"name": 5}),
            json!({"collectionId": ""}),
            json!({"elements": {}}),
            json!({"elements": [{"x": "1"}]}),
            json!({"appState": {"zoom": {"value": 0}}}),
            json!({"files": []}),
            json!({"preview": 5}),
            json!([]),
        ] {
            assert_eq!(
                parse_create(&bad, MAX),
                Err(PayloadError::Validation),
                "{bad}"
            );
        }
    }

    #[test]
    fn create_reports_file_errors_with_status() {
        let err = parse_create(&json!({"files": {"f1": {"dataURL": PNG}}}), 4).unwrap_err();
        assert!(matches!(err, PayloadError::File { status: 413, .. }));
    }

    #[test]
    fn update_tracks_presence_and_nulls() {
        let p = parse_update(&json!({"name": "N"}), MAX).unwrap();
        assert!(!p.is_scene_update());
        assert_eq!(p.name.as_deref(), Some("N"));
        assert_eq!(p.collection_id, None);

        let p = parse_update(
            &json!({"collectionId": null, "preview": null, "files": null}),
            MAX,
        )
        .unwrap();
        assert_eq!(p.collection_id, Some(None));
        assert_eq!(p.preview, Some(None));
        assert!(!p.is_scene_update(), "files: null is treated as absent");

        let p = parse_update(&json!({"elements": [], "version": 3}), MAX).unwrap();
        assert!(p.is_scene_update());
        assert_eq!(p.version, Some(3));
        assert_eq!(p.app_state, None);

        let p = parse_update(&json!({"preview": "<svg onload=\"x\"></svg>"}), MAX).unwrap();
        assert!(!p.preview.unwrap().unwrap().contains("onload"));

        for bad in [
            json!({"version": 0}),
            json!({"version": 1.5}),
            json!({"version": "2"}),
        ] {
            assert_eq!(
                parse_update(&bad, MAX),
                Err(PayloadError::Validation),
                "{bad}"
            );
        }
    }

    #[test]
    fn import_validation() {
        assert!(is_valid_import(
            &json!({"elements": [], "appState": {}}),
            MAX
        ));
        assert!(!is_valid_import(
            &json!({"elements": [], "appState": null}),
            MAX
        ));
        assert!(!is_valid_import(&json!({"appState": {}}), MAX));
        assert!(!is_valid_import(
            &json!({"elements": [{"x": "bad"}], "appState": {}}),
            MAX
        ));
        let many: Vec<Value> = (0..10_001).map(|_| json!({})).collect();
        assert!(!is_valid_import(
            &json!({"elements": many, "appState": {}}),
            MAX
        ));
        assert!(!is_valid_import(
            &json!({"elements": [], "appState": {}, "files": {"f": {"dataURL": "data:text/html;base64,AA=="}}}),
            MAX
        ));
    }

    #[test]
    fn merge_union_never_blanks_existing_content() {
        let existing = json!({"a": {"dataURL": "/api/files/d/a"}, "b": {"dataURL": "x"}});
        let incoming =
            json!({"a": {"dataURL": ""}, "b": {"dataURL": "y"}, "c": {"dataURL": "z"}, "d": null});
        let merged = merge_files_union(&existing, &incoming);
        assert_eq!(merged["a"]["dataURL"], "/api/files/d/a");
        assert_eq!(merged["b"]["dataURL"], "y");
        assert_eq!(merged["c"]["dataURL"], "z");
        assert_eq!(
            merged["d"],
            Value::Null,
            "blank entry for an unknown id is kept"
        );
        let merged = merge_files_union(
            &json!({"a": {"dataURL": ""}}),
            &json!({"a": {"mimeType": "x"}}),
        );
        assert_eq!(
            merged["a"],
            json!({"mimeType": "x"}),
            "blank may replace blank"
        );
    }

    #[test]
    fn json_field_fallback() {
        assert_eq!(parse_json_field("[1]", json!([])), json!([1]));
        assert_eq!(parse_json_field("not json", json!({})), json!({}));
    }
}
