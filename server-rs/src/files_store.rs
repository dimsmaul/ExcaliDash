//! Drawing image bytes in `"DrawingFile"` (db storage only), ports of
//! backend/src/fileProcessing.ts and backend/src/drawingFileStore.ts.

use std::collections::HashSet;

use base64::{
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use serde_json::Value;
use sqlx::{PgConnection, PgPool};

use crate::time::NOW_UTC;

const LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Node `decodeDataURL`: `(mimeType, bytes)` of a base64 data URL.
pub fn decode_data_url(data_url: &str) -> Option<(String, Vec<u8>)> {
    let rest = data_url.strip_prefix("data:")?;
    let (mime, body) = rest.split_once(";base64,")?;
    if mime.is_empty() || mime.contains(';') || body.is_empty() {
        return None;
    }
    let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let bytes = LENIENT_BASE64.decode(compact).ok()?;
    Some((mime.to_string(), bytes))
}

/// Node `rewritePreviewForInternedFiles`: swap each rewritten dataURL inside the preview SVG.
pub fn rewrite_preview(preview: &str, original: &Value, processed: &Value) -> String {
    let mut rewritten = preview.to_string();
    for (file_id, done) in processed.as_object().into_iter().flatten() {
        let before = original
            .get(file_id)
            .and_then(|f| f.get("dataURL"))
            .and_then(Value::as_str);
        let after = done.get("dataURL").and_then(Value::as_str);
        if let (Some(before), Some(after)) = (before, after) {
            if before != after && !before.is_empty() {
                rewritten = rewritten.replace(before, after);
            }
        }
    }
    rewritten
}

/// `/api/files/<drawingId>/<fileId>`
pub fn file_url(drawing_id: &str, file_id: &str) -> String {
    format!("/api/files/{drawing_id}/{file_id}")
}

fn is_valid_file_id(file_id: &str) -> bool {
    (1..=200).contains(&file_id.len())
        && file_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// SQL predicate: the row actually holds bytes (Node `hasDrawingFileContent`).
const HAS_CONTENT: &str = r#"((storage = 's3' AND COALESCE("s3Key", '') <> '') OR (storage = 'db' AND data IS NOT NULL))"#;

/// Node `storeDrawingFileOnce` (db storage): never replaces bytes already stored for
/// this immutable `(drawingId, fileId)`; returns the stored MIME type.
pub async fn store_once(
    conn: &mut PgConnection,
    drawing_id: &str,
    file_id: &str,
    mime_type: &str,
    bytes: &[u8],
) -> Result<String, sqlx::Error> {
    sqlx::query(&format!(
        r#"INSERT INTO "DrawingFile" ("drawingId", "fileId", "mimeType", "sizeBytes", storage, "s3Key", data, "createdAt")
           VALUES ($1, $2, $3, $4, 'db', NULL, $5, {NOW_UTC})
           ON CONFLICT ("drawingId", "fileId") DO NOTHING"#
    ))
    .bind(drawing_id)
    .bind(file_id)
    .bind(mime_type)
    .bind(bytes.len() as i32)
    .bind(bytes)
    .execute(&mut *conn)
    .await?;
    sqlx::query(&format!(
        r#"UPDATE "DrawingFile" SET "mimeType" = $3, "sizeBytes" = $4, storage = 'db', "s3Key" = NULL, data = $5
           WHERE "drawingId" = $1 AND "fileId" = $2 AND NOT {HAS_CONTENT}"#
    ))
    .bind(drawing_id)
    .bind(file_id)
    .bind(mime_type)
    .bind(bytes.len() as i32)
    .bind(bytes)
    .execute(&mut *conn)
    .await?;
    sqlx::query_scalar(
        r#"SELECT "mimeType" FROM "DrawingFile" WHERE "drawingId" = $1 AND "fileId" = $2"#,
    )
    .bind(drawing_id)
    .bind(file_id)
    .fetch_one(&mut *conn)
    .await
}

/// Node `internDrawingFiles`: store base64 images and replace them by `/api/files/..` refs.
/// Entries that are already references are left alone; invalid ids are dropped.
pub async fn intern(db: &PgPool, drawing_id: &str, files: &Value) -> Result<Value, sqlx::Error> {
    let Some(entries) = files.as_object() else {
        return Ok(files.clone());
    };
    let mut conn = db.acquire().await?;
    let mut result = entries.clone();
    for (file_id, file) in entries {
        if !is_valid_file_id(file_id) {
            result.remove(file_id);
            continue;
        }
        let Some((mime, bytes)) = file
            .get("dataURL")
            .and_then(Value::as_str)
            .filter(|url| url.starts_with("data:"))
            .and_then(decode_data_url)
        else {
            continue;
        };
        let existing: Option<String> = sqlx::query_scalar(&format!(
            r#"SELECT "mimeType" FROM "DrawingFile" WHERE "drawingId" = $1 AND "fileId" = $2 AND {HAS_CONTENT}"#
        ))
        .bind(drawing_id)
        .bind(file_id)
        .fetch_optional(&mut *conn)
        .await?;
        let stored_mime = match existing {
            Some(mime) => mime,
            None => store_once(&mut conn, drawing_id, file_id, &mime, &bytes).await?,
        };
        let mut entry = file.as_object().cloned().unwrap_or_default();
        entry.insert("mimeType".into(), stored_mime.into());
        entry.insert("dataURL".into(), file_url(drawing_id, file_id).into());
        result.insert(file_id.clone(), Value::Object(entry));
    }
    Ok(Value::Object(result))
}

/// File ids currently stored for a drawing.
pub async fn list_file_ids(db: &PgPool, drawing_id: &str) -> Result<HashSet<String>, sqlx::Error> {
    Ok(
        sqlx::query_scalar(r#"SELECT "fileId" FROM "DrawingFile" WHERE "drawingId" = $1"#)
            .bind(drawing_id)
            .fetch_all(db)
            .await?
            .into_iter()
            .collect(),
    )
}

/// Node `cloneS3FileReferences` (db mode): copy every stored file row to the new
/// drawing and point the copied `files` entries at it.
pub async fn copy_for_duplicate(
    conn: &mut PgConnection,
    source_id: &str,
    target_id: &str,
    files: &Value,
) -> Result<Value, sqlx::Error> {
    let copied: Vec<String> = sqlx::query_scalar(&format!(
        r#"INSERT INTO "DrawingFile" ("drawingId", "fileId", "mimeType", "sizeBytes", storage, "s3Key", data, "createdAt")
           SELECT $2, "fileId", "mimeType", "sizeBytes", 'db', NULL, data, {NOW_UTC}
           FROM "DrawingFile" WHERE "drawingId" = $1
           ON CONFLICT ("drawingId", "fileId") DO UPDATE
             SET storage = 'db', "s3Key" = NULL, data = EXCLUDED.data,
                 "mimeType" = EXCLUDED."mimeType", "sizeBytes" = EXCLUDED."sizeBytes"
           RETURNING "fileId""#
    ))
    .bind(source_id)
    .bind(target_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut result = files.as_object().cloned().unwrap_or_default();
    for file_id in copied {
        if let Some(Value::Object(entry)) = result.get_mut(&file_id) {
            entry.insert("dataURL".into(), file_url(target_id, &file_id).into());
        }
    }
    Ok(Value::Object(result))
}

/// `"DrawingFile"` has no FK to `"Drawing"`, so deletes must remove the rows explicitly.
pub async fn delete_for_drawing(
    conn: &mut PgConnection,
    drawing_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(r#"DELETE FROM "DrawingFile" WHERE "drawingId" = $1"#)
        .bind(drawing_id)
        .execute(conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decodes_base64_data_urls() {
        let (mime, bytes) = decode_data_url("data:image/png;base64,aGVs\nbG8=").unwrap();
        assert_eq!(mime, "image/png");
        assert_eq!(bytes, b"hello");
        assert_eq!(
            decode_data_url("data:image/png;base64,aGVsbG8").unwrap().1,
            b"hello"
        );
        assert!(decode_data_url("data:image/png,raw").is_none());
        assert!(decode_data_url("https://x").is_none());
    }

    #[test]
    fn rewrites_only_changed_data_urls() {
        let preview = r#"<svg><image href="data:image/png;base64,AAA="></image><image href="keep"></image></svg>"#;
        let original =
            json!({"f1": {"dataURL": "data:image/png;base64,AAA="}, "f2": {"dataURL": "keep"}});
        let processed = json!({"f1": {"dataURL": "/api/files/d1/f1"}, "f2": {"dataURL": "keep"}});
        assert_eq!(
            rewrite_preview(preview, &original, &processed),
            r#"<svg><image href="/api/files/d1/f1"></image><image href="keep"></image></svg>"#
        );
        assert_eq!(rewrite_preview("", &original, &processed), "");
    }
}
