mod common;

use common::{seed_user, set_cookies, spawn_app, spawn_app_with, unreachable_pool};
use excalidash_server::{
    auth::{jwt, oidc::store_refresh_token},
    config::{AuthMode, Config},
};
use reqwest::Method;
use serde_json::{json, Value};
use sqlx::PgPool;

fn cookie_header(parts: &[&str]) -> String {
    parts.join("; ")
}

#[tokio::test]
async fn refresh_requires_csrf() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app
        .request(Method::POST, "/auth/refresh")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["error"], "CSRF token missing");
}

#[tokio::test]
async fn refresh_without_cookie_is_unauthorized() {
    let app = spawn_app(unreachable_pool()).await;
    let csrf = app.csrf().await;
    let res = app
        .request(Method::POST, "/auth/refresh")
        .header("x-csrf-token", &csrf.token)
        .header("Cookie", &csrf.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!({"error": "Unauthorized", "message": "Refresh token required"})
    );
}

#[tokio::test]
async fn refresh_rejects_access_token_and_garbage() {
    let app = spawn_app(unreachable_pool()).await;
    let csrf = app.csrf().await;
    let pair = jwt::issue_pair(&Config::for_tests(), "u1", "alice@example.com");
    for (token, message) in [
        (pair.access.as_str(), "Invalid token type"),
        ("garbage", "Invalid or expired refresh token"),
    ] {
        let res = app
            .request(Method::POST, "/auth/refresh")
            .header("x-csrf-token", &csrf.token)
            .header(
                "Cookie",
                cookie_header(&[&csrf.cookie, &format!("excalidash-refresh-token={token}")]),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["message"], message);
    }
}

#[tokio::test]
async fn logout_without_session_clears_cookies() {
    let app = spawn_app(unreachable_pool()).await;
    let csrf = app.csrf().await;
    let res = app
        .request(Method::POST, "/auth/logout")
        .header("x-csrf-token", &csrf.token)
        .header("Cookie", &csrf.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let cookies = set_cookies(&res);
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("excalidash-access-token=; Max-Age=0")));
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("excalidash-refresh-token=; Max-Age=0")));
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"ok": true}));
}

#[tokio::test]
async fn session_routes_are_404_when_auth_disabled() {
    let mut cfg = Config::for_tests();
    cfg.auth_mode = AuthMode::Disabled;
    cfg.oidc = None;
    let app = spawn_app_with(cfg, unreachable_pool()).await;
    let res = app
        .request(Method::POST, "/auth/refresh")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn preferences_require_auth() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app
        .request(Method::GET, "/auth/preferences")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

async fn refresh(app: &common::TestApp, refresh_token: &str) -> reqwest::Response {
    let csrf = app.csrf().await;
    app.request(Method::POST, "/auth/refresh")
        .header("x-csrf-token", &csrf.token)
        .header(
            "Cookie",
            cookie_header(&[
                &csrf.cookie,
                &format!("excalidash-refresh-token={refresh_token}"),
            ]),
        )
        .send()
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn refresh_rotates_and_rejects_reuse(pool: PgPool) {
    seed_user(&pool, "u1", "alice@example.com", "Alice", true).await;
    let cfg = Config::for_tests();
    let pair = jwt::issue_pair(&cfg, "u1", "alice@example.com");
    store_refresh_token(&pool, "u1", &pair.refresh, cfg.jwt_refresh_ttl)
        .await
        .unwrap();
    let app = spawn_app(pool.clone()).await;

    let res = refresh(&app, &pair.refresh).await;
    assert_eq!(res.status(), 200);
    let cookies = set_cookies(&res);
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("excalidash-access-token=ey")));
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("excalidash-refresh-token=ey")));
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"ok": true}));

    let rows: Vec<(String, bool)> =
        sqlx::query_as(r#"SELECT token, revoked FROM "RefreshToken" ORDER BY "createdAt""#)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], (jwt::hash_token(&pair.refresh), true));
    assert!(!rows[1].1);

    let reuse = refresh(&app, &pair.refresh).await;
    assert_eq!(reuse.status(), 401);
    let body: Value = reuse.json().await.unwrap();
    assert_eq!(body["message"], "Invalid or revoked refresh token");
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn logout_revokes_all_refresh_tokens(pool: PgPool) {
    seed_user(&pool, "u1", "alice@example.com", "Alice", true).await;
    let cfg = Config::for_tests();
    let pair = jwt::issue_pair(&cfg, "u1", "alice@example.com");
    store_refresh_token(&pool, "u1", &pair.refresh, cfg.jwt_refresh_ttl)
        .await
        .unwrap();
    let app = spawn_app(pool.clone()).await;
    let csrf = app.csrf().await;
    let res = app
        .request(Method::POST, "/auth/logout")
        .header("x-csrf-token", &csrf.token)
        .header(
            "Cookie",
            cookie_header(&[
                &csrf.cookie,
                &format!("excalidash-access-token={}", pair.access),
            ]),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let live: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM "RefreshToken" WHERE NOT revoked"#)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(live, 0);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn preferences_round_trip_and_validation(pool: PgPool) {
    seed_user(&pool, "u1", "alice@example.com", "Alice", true).await;
    let pair = jwt::issue_pair(&Config::for_tests(), "u1", "alice@example.com");
    let app = spawn_app(pool).await;
    let csrf = app.csrf().await;
    let auth = format!("excalidash-access-token={}", pair.access);
    let put = |body: Value| {
        app.request(Method::PUT, "/auth/preferences")
            .header("x-csrf-token", &csrf.token)
            .header("Cookie", cookie_header(&[&csrf.cookie, &auth]))
            .json(&body)
            .send()
    };

    let res = put(json!({"theme": "dark", "gridStep": 5})).await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!({"preferences": {"theme": "dark", "gridStep": 5}})
    );

    let res = put(json!({"compactSidebar": true})).await.unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["preferences"],
        json!({"theme": "dark", "gridStep": 5, "compactSidebar": true})
    );

    for bad in [
        json!({"theme": "purple"}),
        json!({"unknown": 1}),
        json!({"gridStep": 0}),
    ] {
        let res = put(bad).await.unwrap();
        assert_eq!(res.status(), 400);
        let body: Value = res.json().await.unwrap();
        assert_eq!(
            body,
            json!({"error": "Validation error", "message": "Invalid preferences"})
        );
    }

    let res = app
        .request(Method::GET, "/auth/preferences")
        .header("Cookie", &auth)
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["preferences"]["compactSidebar"], true);
}
