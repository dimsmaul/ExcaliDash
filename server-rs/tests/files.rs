mod common;

use common::{seed_drawing, seed_drawing_permission, seed_user, spawn_app, unreachable_pool};
use excalidash_server::config::Config;
use reqwest::Method;
use serde_json::{json, Value};
use sqlx::PgPool;

const PNG_BYTES: &[u8] = b"\x89PNG\r\n\x1a\nfake";

#[tokio::test]
async fn invalid_id_segments_are_rejected_before_any_lookup() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app
        .request(Method::GET, "/files/bad.id/f1")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(
        res.json::<Value>().await.unwrap(),
        json!({"error": "Invalid id segment"})
    );
}

#[tokio::test]
async fn files_config_requires_auth() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app
        .request(Method::GET, "/files/config")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

async fn setup(pool: &PgPool) {
    seed_user(pool, "u1", "u1@example.com", "Alice", true).await;
    seed_user(pool, "u2", "u2@example.com", "Bob", true).await;
    seed_user(pool, "u3", "u3@example.com", "Carol", true).await;
    seed_drawing(pool, "d1", "u1", None).await;
    seed_drawing_permission(pool, "d1", "u2", "view").await;
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn upload_and_download_round_trip(pool: PgPool) {
    setup(&pool).await;
    let app = spawn_app(pool.clone()).await;

    let res = app
        .as_user(Method::GET, "/files/config", "u1")
        .await
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.json::<Value>().await.unwrap(),
        json!({"s3Enabled": false})
    );

    let res = app
        .as_user(Method::PUT, "/drawings/d1/files/f1", "u1")
        .await
        .header("Content-Type", "image/png")
        .body(PNG_BYTES)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.json::<Value>().await.unwrap(),
        json!({"url": "/api/files/d1/f1", "fileId": "f1"})
    );

    let res = app
        .as_user(Method::PUT, "/drawings/d1/files/f1", "u1")
        .await
        .header("Content-Type", "image/png")
        .body(&b"different bytes"[..])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "re-upload is an idempotent no-op");

    let res = app
        .as_user(Method::GET, "/files/d1/f1", "u2")
        .await
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "image/png");
    assert_eq!(res.headers()["etag"], "\"f1\"");
    assert_eq!(
        res.headers()["cache-control"],
        "private, max-age=31536000, immutable"
    );
    assert!(res.headers().get("content-security-policy").is_some());
    assert_eq!(
        res.bytes().await.unwrap().as_ref(),
        PNG_BYTES,
        "first bytes win"
    );

    let res = app
        .as_user(Method::GET, "/files/d1/f1", "u2")
        .await
        .header("If-None-Match", "\"f1\"")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 304);

    let res = app
        .as_user(Method::GET, "/files/d1/f1", "u3")
        .await
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(
        res.json::<Value>().await.unwrap(),
        json!({"error": "File not found"})
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn upload_validation(pool: PgPool) {
    setup(&pool).await;
    let mut cfg = Config::for_tests();
    cfg.file_upload_max_bytes = 4;
    let app = common::spawn_app_with(cfg, pool).await;
    let put = |user: &'static str, content_type: &'static str, body: &'static [u8]| {
        let app = &app;
        async move {
            let res = app
                .as_user(Method::PUT, "/drawings/d1/files/f1", user)
                .await
                .header("Content-Type", content_type)
                .body(body)
                .send()
                .await
                .unwrap();
            (res.status().as_u16(), res.json::<Value>().await.unwrap())
        }
    };
    let (status, body) = put("u2", "image/png", b"abc").await;
    assert_eq!(
        (status, body),
        (404, json!({"error": "Drawing not found"})),
        "view-only cannot upload"
    );
    let (status, body) = put("u1", "text/html", b"abc").await;
    assert_eq!(status, 415);
    assert_eq!(body["error"], "Unsupported media type");
    let (status, body) = put("u1", "image/png", b"").await;
    assert_eq!(
        (status, body["error"].clone()),
        (400, json!("Empty request body"))
    );
    let (status, body) = put("u1", "image/png", b"too large").await;
    assert_eq!(status, 413);
    assert_eq!(body["error"], "File too large");
}
