mod common;

use common::{seed_user, spawn_app, spawn_app_with, unreachable_pool};
use excalidash_server::{
    auth::jwt,
    config::{AuthMode, Config},
};
use serde_json::{json, Value};
use sqlx::PgPool;

fn password_policy() -> Value {
    json!({
        "minLength": 12, "maxLength": 100, "requireUppercase": true,
        "requireLowercase": true, "requireNumber": true, "requireSymbol": true
    })
}

fn disabled_cfg() -> Config {
    let mut cfg = Config::for_tests();
    cfg.auth_mode = AuthMode::Disabled;
    cfg.oidc = None;
    cfg
}

#[tokio::test]
async fn status_oidc_enforced_anonymous() {
    let app = spawn_app(unreachable_pool()).await;
    let body: Value = app
        .client
        .get(app.url("/auth/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        body,
        json!({
            "enabled": true, "authenticated": false, "authEnabled": true,
            "authMode": "oidc_enforced", "oidcEnabled": true, "oidcEnforced": true,
            "oidcProvider": "OIDC", "oidcJitProvisioningEnabled": true,
            "registrationEnabled": false, "bootstrapRequired": false,
            "authOnboardingRequired": false, "authOnboardingMode": null,
            "authOnboardingRecommended": null, "passwordPolicy": password_policy(),
            "user": null
        })
    );
}

#[tokio::test]
async fn status_disabled_mode() {
    let app = spawn_app_with(disabled_cfg(), unreachable_pool()).await;
    let body: Value = app
        .client
        .get(app.url("/auth/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        body,
        json!({
            "enabled": false, "authenticated": false, "authEnabled": false,
            "authMode": "disabled", "oidcEnabled": false, "oidcEnforced": false,
            "oidcProvider": "OIDC", "oidcJitProvisioningEnabled": false,
            "registrationEnabled": false, "bootstrapRequired": false,
            "authOnboardingRequired": false, "authOnboardingMode": null,
            "authOnboardingRecommended": null, "passwordPolicy": password_policy(),
            "user": null
        })
    );
}

#[tokio::test]
async fn me_requires_token() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app.client.get(app.url("/auth/me")).send().await.unwrap();
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!({"error": "Unauthorized", "message": "Authentication token required"})
    );
}

#[tokio::test]
async fn me_rejects_garbage_token() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app
        .client
        .get(app.url("/auth/me"))
        .header("Authorization", "Bearer not-a-jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!({"error": "Unauthorized", "message": "Invalid or expired token"})
    );
}

#[tokio::test]
async fn me_rejects_refresh_token_used_as_access() {
    let app = spawn_app(unreachable_pool()).await;
    let pair = jwt::issue_pair(&Config::for_tests(), "u1", "alice@example.com");
    let res = app
        .client
        .get(app.url("/auth/me"))
        .header(
            "Cookie",
            format!("excalidash-access-token={}", pair.refresh),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn me_with_access_cookie_returns_user(pool: PgPool) {
    seed_user(&pool, "u1", "alice@example.com", "Alice", true).await;
    let app = spawn_app(pool).await;
    let pair = jwt::issue_pair(&Config::for_tests(), "u1", "alice@example.com");
    let res = app
        .client
        .get(app.url("/auth/me"))
        .header("Cookie", format!("excalidash-access-token={}", pair.access))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let user = &body["user"];
    assert_eq!(user["id"], "u1");
    assert_eq!(user["username"], Value::Null);
    assert_eq!(user["email"], "alice@example.com");
    assert_eq!(user["name"], "Alice");
    assert_eq!(user["role"], "USER");
    assert_eq!(user["mustResetPassword"], false);
    assert!(user["createdAt"].as_str().unwrap().ends_with('Z'));
    assert!(user["updatedAt"].as_str().is_some());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn me_accepts_bearer_token(pool: PgPool) {
    seed_user(&pool, "u1", "alice@example.com", "Alice", true).await;
    let app = spawn_app(pool).await;
    let pair = jwt::issue_pair(&Config::for_tests(), "u1", "alice@example.com");
    let res = app
        .client
        .get(app.url("/auth/me"))
        .bearer_auth(&pair.access)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn me_rejects_inactive_user(pool: PgPool) {
    seed_user(&pool, "u1", "alice@example.com", "Alice", false).await;
    let app = spawn_app(pool).await;
    let pair = jwt::issue_pair(&Config::for_tests(), "u1", "alice@example.com");
    let res = app
        .client
        .get(app.url("/auth/me"))
        .bearer_auth(&pair.access)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["message"], "User account not found or inactive");
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn status_exposes_authenticated_user(pool: PgPool) {
    seed_user(&pool, "u1", "alice@example.com", "Alice", true).await;
    let app = spawn_app(pool).await;
    let pair = jwt::issue_pair(&Config::for_tests(), "u1", "alice@example.com");
    let body: Value = app
        .client
        .get(app.url("/auth/status"))
        .bearer_auth(&pair.access)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["authenticated"], true);
    assert_eq!(
        body["user"],
        json!({
            "id": "u1", "username": null, "email": "alice@example.com",
            "name": "Alice", "role": "USER", "mustResetPassword": false
        })
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn disabled_mode_uses_bootstrap_user(pool: PgPool) {
    let app = spawn_app_with(disabled_cfg(), pool.clone()).await;
    let res = app.client.get(app.url("/auth/me")).send().await.unwrap();
    assert_eq!(res.status(), 404);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!({"error": "Not found", "message": "Authentication is disabled"})
    );
    let (role, active): (String, bool) =
        sqlx::query_as(r#"SELECT role, "isActive" FROM "User" WHERE id = 'bootstrap-admin'"#)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(role, "ADMIN");
    assert!(!active);
}
