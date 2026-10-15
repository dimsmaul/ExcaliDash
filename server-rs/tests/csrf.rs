mod common;

use common::{spawn_app, unreachable_pool, TestApp};
use serde_json::{json, Value};

async fn fetch_token(app: &TestApp) -> String {
    let res = app.client.get(app.url("/csrf-token")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["header"], "x-csrf-token");
    body["token"].as_str().unwrap().to_string()
}

async fn post(app: &TestApp, path: &str, headers: &[(&str, &str)]) -> (u16, Value) {
    let mut req = app.client.post(app.url(path));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn token_endpoint_sets_client_cookie_once() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app.client.get(app.url("/csrf-token")).send().await.unwrap();
    let cookie = res.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.starts_with("excalidash-csrf-client="), "{cookie}");
    assert!(
        cookie.contains("Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000"),
        "{cookie}"
    );
    let again = app.client.get(app.url("/csrf-token")).send().await.unwrap();
    assert!(again.headers().get("set-cookie").is_none());
}

#[tokio::test]
async fn mutation_without_token_is_rejected() {
    let app = spawn_app(unreachable_pool()).await;
    let (status, body) = post(&app, "/collections", &[]).await;
    assert_eq!(status, 403);
    assert_eq!(
        body,
        json!({"error": "CSRF token missing", "message": "Missing x-csrf-token header"})
    );
}

#[tokio::test]
async fn tampered_token_is_rejected() {
    let app = spawn_app(unreachable_pool()).await;
    let token = fetch_token(&app).await;
    let tampered = format!("{}x", &token[..token.len() - 1]);
    let (status, body) = post(&app, "/collections", &[("x-csrf-token", &tampered)]).await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "CSRF token invalid");
}

#[tokio::test]
async fn token_from_another_client_is_rejected() {
    let app = spawn_app(unreachable_pool()).await;
    let other = spawn_app(unreachable_pool()).await;
    let token = fetch_token(&other).await;
    let _ = fetch_token(&app).await;
    let (status, body) = post(&app, "/collections", &[("x-csrf-token", &token)]).await;
    assert_eq!(status, 403);
    assert_eq!(body["error"], "CSRF token invalid");
}

#[tokio::test]
async fn foreign_origin_is_rejected() {
    let app = spawn_app(unreachable_pool()).await;
    let token = fetch_token(&app).await;
    let (status, body) = post(
        &app,
        "/collections",
        &[("x-csrf-token", &token), ("Origin", "https://evil.example")],
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(
        body,
        json!({"error": "CSRF origin mismatch", "message": "Origin not allowed"})
    );
}

#[tokio::test]
async fn foreign_referer_is_rejected() {
    let app = spawn_app(unreachable_pool()).await;
    let token = fetch_token(&app).await;
    let (status, body) = post(
        &app,
        "/collections",
        &[
            ("x-csrf-token", &token),
            ("Referer", "https://evil.example/page"),
        ],
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(
        body,
        json!({"error": "CSRF referer mismatch", "message": "Referer not allowed"})
    );
}

#[tokio::test]
async fn valid_token_passes_through() {
    let app = spawn_app(unreachable_pool()).await;
    let token = fetch_token(&app).await;
    let (status, _) = post(
        &app,
        "/no-such-route",
        &[
            ("x-csrf-token", &token),
            ("Origin", "http://localhost:6767"),
        ],
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn auth_paths_are_exempt() {
    let app = spawn_app(unreachable_pool()).await;
    let (status, _) = post(&app, "/auth/no-such-route", &[]).await;
    assert_eq!(status, 404);
}
