mod common;

use common::{spawn_app, unreachable_pool};
use serde_json::{json, Value};
use sqlx::PgPool;

const CSP: &str = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; connect-src 'self'";

#[tokio::test]
async fn health_reports_unavailable_database() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app.client.get(app.url("/health")).send().await.unwrap();
    assert_eq!(res.status(), 503);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"status": "error", "database": "unavailable"}));
}

#[tokio::test]
async fn responses_carry_security_headers() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app.client.get(app.url("/health")).send().await.unwrap();
    let h = res.headers();
    assert_eq!(h["content-security-policy"], CSP);
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(
        h["strict-transport-security"],
        "max-age=31536000; includeSubDomains; preload"
    );
}

#[tokio::test]
async fn cors_allows_configured_origin_with_credentials() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app
        .client
        .request(reqwest::Method::OPTIONS, app.url("/drawings"))
        .header("Origin", "http://localhost:6767")
        .header("Access-Control-Request-Method", "PUT")
        .header(
            "Access-Control-Request-Headers",
            "content-type,x-csrf-token",
        )
        .send()
        .await
        .unwrap();
    let h = res.headers();
    assert_eq!(h["access-control-allow-origin"], "http://localhost:6767");
    assert_eq!(h["access-control-allow-credentials"], "true");
    let allowed = h["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .to_lowercase();
    assert!(allowed.contains("x-csrf-token"), "{allowed}");
    assert!(allowed.contains("x-imported-file"), "{allowed}");
}

#[tokio::test]
async fn cors_ignores_unknown_origin() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app
        .client
        .get(app.url("/health"))
        .header("Origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert!(res.headers().get("access-control-allow-origin").is_none());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn health_ok(pool: PgPool) {
    let app = spawn_app(pool).await;
    let res = app.client.get(app.url("/health")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"status": "ok", "database": "ok"}));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn migrations_create_tables(pool: PgPool) {
    for table in ["\"Drawing\"", "\"DrawingFile\"", "\"DrawingSnapshot\""] {
        let exists: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(exists.is_some(), "missing table {table}");
    }
}
