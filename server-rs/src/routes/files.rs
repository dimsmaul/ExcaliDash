//! Drawing image files in Postgres (backend/src/routes/files.ts, db storage mode).

use axum::{
    body::Bytes,
    extract::{rejection::BytesRejection, DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
    Json, Router,
};
use serde_json::{json, Value};

use crate::{
    auth::middleware::{OptionalUser, RequireUser},
    authz::drawing_access,
    error::{AppError, AppResult},
    files_store::{self, file_url},
    state::AppState,
};

/// Node `MIME_TO_EXT` keys, in Node's order (used in the 415 message).
const IMAGE_MIME_TYPES: [&str; 7] = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/bmp",
    "image/svg+xml",
];

pub fn router(upload_limit_bytes: usize) -> Router<AppState> {
    Router::new()
        .route("/files/config", get(config))
        .route(
            "/drawings/{drawing_id}/files/{file_id}",
            put(upload).layer(DefaultBodyLimit::max(upload_limit_bytes)),
        )
        .route("/files/{drawing_id}/{file_id}", get(download))
}

/// Node `isValidIdSegment`.
fn is_valid_segment(value: &str) -> bool {
    (1..=200).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn error(status: StatusCode, message: &str) -> AppError {
    AppError::json(status, json!({ "error": message }))
}

fn check_segments(drawing_id: &str, file_id: &str) -> AppResult<()> {
    if is_valid_segment(drawing_id) && is_valid_segment(file_id) {
        Ok(())
    } else {
        Err(error(StatusCode::BAD_REQUEST, "Invalid id segment"))
    }
}

/// `GET /files/config`
async fn config(RequireUser(_): RequireUser) -> Json<Value> {
    Json(json!({ "s3Enabled": false }))
}

/// `PUT /drawings/{drawingId}/files/{fileId}`: raw image bytes, idempotent per id.
async fn upload(
    State(state): State<AppState>,
    RequireUser(user): RequireUser,
    Path((drawing_id, file_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> AppResult<Json<Value>> {
    let body = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            AppError::status(
                StatusCode::PAYLOAD_TOO_LARGE,
                "File too large",
                &format!(
                    "Uploaded file exceeds the {}MB limit. Raise FILE_UPLOAD_MAX_MB to accept larger images.",
                    state.cfg.file_upload_max_bytes / (1024 * 1024)
                ),
            )
        } else {
            AppError::Internal(rejection.to_string())
        }
    })?;
    check_segments(&drawing_id, &file_id)?;
    let can_edit = drawing_access(&state.db, Some(&user.id), &drawing_id)
        .await?
        .is_some_and(|a| a.can_edit());
    if !can_edit {
        return Err(error(StatusCode::NOT_FOUND, "Drawing not found"));
    }
    let mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(|v| v.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if !IMAGE_MIME_TYPES.contains(&mime.as_str()) {
        return Err(AppError::status(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Unsupported media type",
            &format!(
                "Content-Type must be one of: {}",
                IMAGE_MIME_TYPES.join(", ")
            ),
        ));
    }
    if body.is_empty() {
        return Err(AppError::status(
            StatusCode::BAD_REQUEST,
            "Empty request body",
            "Send the raw image bytes as the request body.",
        ));
    }
    let mut conn = state.db.acquire().await?;
    files_store::store_once(&mut conn, &drawing_id, &file_id, &mime, &body).await?;
    Ok(Json(
        json!({ "url": file_url(&drawing_id, &file_id), "fileId": file_id }),
    ))
}

/// `GET /files/{drawingId}/{fileId}`: bytes with an immutable ETag.
async fn download(
    State(state): State<AppState>,
    auth: OptionalUser,
    Path((drawing_id, file_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    check_segments(&drawing_id, &file_id)?;
    let not_found = || error(StatusCode::NOT_FOUND, "File not found");
    let viewer = auth.user.as_ref().map(|u| u.id.as_str());
    if drawing_access(&state.db, viewer, &drawing_id)
        .await?
        .is_none()
    {
        return Err(not_found());
    }
    let row: Option<(String, String, Option<Vec<u8>>)> = sqlx::query_as(
        r#"SELECT storage, "mimeType", data FROM "DrawingFile" WHERE "drawingId" = $1 AND "fileId" = $2"#,
    )
    .bind(&drawing_id)
    .bind(&file_id)
    .fetch_optional(&state.db)
    .await?;
    let (mime, data) = match row {
        Some((storage, mime, Some(data))) if storage == "db" => (mime, data),
        _ => return Err(not_found()),
    };
    let etag = format!("\"{file_id}\"");
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|v| v.as_bytes() == etag.as_bytes());
    let mut res = if not_modified {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        let mut res = data.into_response();
        if let Ok(value) = HeaderValue::from_str(&mime) {
            res.headers_mut().insert(header::CONTENT_TYPE, value);
        }
        res
    };
    let h = res.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, value);
    }
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=31536000, immutable"),
    );
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_segments_match_node_guard() {
        assert!(is_valid_segment("abc-DEF_123"));
        assert!(!is_valid_segment(""));
        assert!(!is_valid_segment("a.b"));
        assert!(!is_valid_segment("../x"));
        assert!(!is_valid_segment(&"a".repeat(201)));
    }
}
