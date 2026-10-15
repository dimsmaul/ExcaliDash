mod common;

use common::{
    idp::{TestIdp, CLIENT_ID},
    spawn_app_with, unreachable_pool, TestApp,
};
use excalidash_server::{
    auth::oidc::{self, FlowPayload},
    config::{AuthMode, Config},
};
use reqwest::Response;
use serde_json::{json, Value};
use sqlx::PgPool;

/// `Config::for_tests().frontend_origins[0]`: the backend redirects back to the frontend
/// after login, which may live on another host than the API (e.g. Vercel).
const FRONTEND: &str = "http://localhost:6767";
const NONCE: &str = "nonce-123";
const STATE: &str = "state-123";

fn flow_cookie(cfg: &Config, return_to: &str) -> String {
    let flow = FlowPayload {
        state: STATE.into(),
        nonce: NONCE.into(),
        code_verifier: "verifier".into(),
        return_to: return_to.into(),
        expires_at: chrono::Utc::now().timestamp_millis() + oidc::FLOW_TTL_MS,
    };
    format!(
        "{}={}",
        oidc::FLOW_COOKIE,
        oidc::encode_flow(&flow, &cfg.jwt_secret)
    )
}

async fn callback(app: &TestApp, cfg: &Config, query: &str) -> Response {
    app.client
        .get(app.url(&format!("/auth/oidc/callback?{query}")))
        .header("Cookie", flow_cookie(cfg, "/drawings/1"))
        .send()
        .await
        .unwrap()
}

fn location(res: &Response) -> String {
    res.headers()["location"].to_str().unwrap().to_string()
}

fn set_cookies(res: &Response) -> Vec<String> {
    res.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

async fn assert_login_error(res: Response, code: &str) {
    assert_eq!(res.status(), 302);
    let loc = location(&res);
    assert!(
        loc.starts_with(&format!("{FRONTEND}/login?oidcError={code}&")),
        "{loc}"
    );
    assert!(set_cookies(&res)
        .iter()
        .any(|c| c.starts_with("excalidash-oidc-flow=; Max-Age=0")));
}

#[tokio::test]
async fn start_redirects_to_provider_with_pkce() {
    let idp = TestIdp::start().await;
    let cfg = idp.config();
    let app = spawn_app_with(cfg.clone(), unreachable_pool()).await;
    let res = app
        .client
        .get(app.url("/auth/oidc/start?returnTo=/drawings/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 302);
    let loc = url::Url::parse(&location(&res)).unwrap();
    assert_eq!(loc.path(), "/authorize");
    let q: std::collections::HashMap<_, _> = loc.query_pairs().into_owned().collect();
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["scope"], "openid profile email");
    assert_eq!(q["redirect_uri"], cfg.oidc.as_ref().unwrap().redirect_uri);
    assert_eq!(q["code_challenge_method"], "S256");

    let cookie = set_cookies(&res)
        .into_iter()
        .find(|c| c.starts_with("excalidash-oidc-flow="))
        .unwrap();
    assert!(
        cookie.contains("Max-Age=600; Path=/; HttpOnly; SameSite=Lax"),
        "{cookie}"
    );
    let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
    let flow = oidc::decode_flow(
        value,
        &cfg.jwt_secret,
        chrono::Utc::now().timestamp_millis(),
    )
    .expect("valid flow cookie");
    assert_eq!(flow.return_to, "/drawings/x");
    assert_eq!(q["state"], flow.state);
    assert_eq!(q["nonce"], flow.nonce);
    assert_eq!(
        q["code_challenge"],
        oidc::code_challenge(&flow.code_verifier)
    );
}

#[tokio::test]
async fn start_sanitizes_return_to() {
    let idp = TestIdp::start().await;
    let cfg = idp.config();
    let app = spawn_app_with(cfg.clone(), unreachable_pool()).await;
    let res = app
        .client
        .get(app.url("/auth/oidc/start?returnTo=//evil.example"))
        .send()
        .await
        .unwrap();
    let cookie = set_cookies(&res).remove(0);
    let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1;
    let flow = oidc::decode_flow(
        value,
        &cfg.jwt_secret,
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap();
    assert_eq!(flow.return_to, "/");
}

#[tokio::test]
async fn start_is_404_when_auth_disabled() {
    let mut cfg = Config::for_tests();
    cfg.auth_mode = AuthMode::Disabled;
    cfg.oidc = None;
    let app = spawn_app_with(cfg, unreachable_pool()).await;
    let res = app
        .client
        .get(app.url("/auth/oidc/start"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!({"error": "Not found", "message": "Authentication is disabled"})
    );
}

#[tokio::test]
async fn callback_without_flow_cookie() {
    let idp = TestIdp::start().await;
    let app = spawn_app_with(idp.config(), unreachable_pool()).await;
    let res = app
        .client
        .get(app.url("/auth/oidc/callback?code=c&state=s"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        location(&res),
        format!("{FRONTEND}/login?oidcError=missing_flow&oidcErrorMessage=Missing+or+expired+OIDC+login+flow.+Please+try+again.")
    );
    assert_login_error(res, "missing_flow").await;
}

#[tokio::test]
async fn callback_provider_error_keeps_return_to() {
    let idp = TestIdp::start().await;
    let cfg = idp.config();
    let app = spawn_app_with(cfg.clone(), unreachable_pool()).await;
    let res = callback(&app, &cfg, "error=access_denied&state=state-123").await;
    assert!(
        location(&res).ends_with("&returnTo=%2Fdrawings%2F1"),
        "{}",
        location(&res)
    );
    assert_login_error(res, "provider_error").await;
}

#[tokio::test]
async fn callback_rejects_state_mismatch() {
    let idp = TestIdp::start().await;
    let cfg = idp.config();
    let app = spawn_app_with(cfg.clone(), unreachable_pool()).await;
    let res = callback(&app, &cfg, "code=c&state=other").await;
    assert_login_error(res, "callback_failed").await;
}

/// Uses an email outside the allowlist: a token that passes verification ends in
/// `email_not_allowed` (see the allowlist test), so `callback_failed` here proves the
/// token was rejected during verification, not later at the database.
async fn assert_rejected_during_verification(nonce: &str, overrides: Value, kid: &str) {
    let idp = TestIdp::start().await;
    let cfg = idp.config();
    let token = TestIdp::sign(&idp.claims(nonce, OUTSIDER, overrides), kid);
    idp.respond_with_id_token(&token).await;
    let app = spawn_app_with(cfg.clone(), unreachable_pool()).await;
    let res = callback(&app, &cfg, "code=c&state=state-123").await;
    assert_login_error(res, "callback_failed").await;
}

const OUTSIDER: &str = "mallory@example.com";

#[tokio::test]
async fn callback_rejects_wrong_nonce() {
    assert_rejected_during_verification("other-nonce", json!({}), "test-key").await;
}

#[tokio::test]
async fn callback_rejects_wrong_audience() {
    assert_rejected_during_verification(NONCE, json!({"aud": "someone-else"}), "test-key").await;
}

#[tokio::test]
async fn callback_rejects_wrong_issuer() {
    assert_rejected_during_verification(NONCE, json!({"iss": "https://evil.example"}), "test-key")
        .await;
}

#[tokio::test]
async fn callback_rejects_expired_id_token() {
    let past = chrono::Utc::now().timestamp() - 600;
    assert_rejected_during_verification(NONCE, json!({"exp": past}), "test-key").await;
}

#[tokio::test]
async fn callback_rejects_unknown_signing_key() {
    assert_rejected_during_verification(NONCE, json!({}), "other-kid").await;
}

#[tokio::test]
async fn callback_rejects_unverified_email() {
    let idp = TestIdp::start().await;
    let cfg = idp.config();
    let token = TestIdp::sign(
        &idp.claims(NONCE, "alice@example.com", json!({"email_verified": false})),
        "test-key",
    );
    idp.respond_with_id_token(&token).await;
    let app = spawn_app_with(cfg.clone(), unreachable_pool()).await;
    let res = callback(&app, &cfg, "code=c&state=state-123").await;
    assert_login_error(res, "unverified_email").await;
}

#[tokio::test]
async fn callback_rejects_email_outside_allowlist_before_touching_db() {
    let idp = TestIdp::start().await;
    let cfg = idp.config();
    let token = TestIdp::sign(
        &idp.claims(NONCE, "mallory@example.com", json!({})),
        "test-key",
    );
    idp.respond_with_id_token(&token).await;
    let app = spawn_app_with(cfg.clone(), unreachable_pool()).await;
    let res = callback(&app, &cfg, "code=c&state=state-123").await;
    assert_login_error(res, "email_not_allowed").await;
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn first_login_creates_admin_with_trash_identity_and_session(pool: PgPool) {
    let idp = TestIdp::start().await;
    let cfg = idp.config();
    let token = TestIdp::sign(
        &idp.claims(NONCE, "Alice@Example.com", json!({})),
        "test-key",
    );
    idp.respond_with_id_token(&token).await;
    let app = spawn_app_with(cfg.clone(), pool.clone()).await;
    let res = callback(&app, &cfg, "code=c&state=state-123").await;
    assert_eq!(res.status(), 302);
    assert_eq!(location(&res), format!("{FRONTEND}/drawings/1"));
    let cookies = set_cookies(&res);
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("excalidash-access-token=ey")));
    assert!(cookies
        .iter()
        .any(|c| c.starts_with("excalidash-refresh-token=ey")));

    let (id, email, role, name): (String, String, String, String) =
        sqlx::query_as(r#"SELECT id, email, role, name FROM "User""#)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(email, "alice@example.com");
    assert_eq!(role, "ADMIN");
    assert_eq!(name, "Alice Example");
    let trash: String = sqlx::query_scalar(r#"SELECT name FROM "Collection" WHERE id = $1"#)
        .bind(format!("trash:{id}"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(trash, "Trash");
    let (provider, issuer, subject): (String, String, String) = sqlx::query_as(
        r#"SELECT provider, issuer, subject FROM "AuthIdentity" WHERE "userId" = $1"#,
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(provider, "oidc");
    assert_eq!(issuer, idp.issuer());
    assert_eq!(subject, "sub-Alice@Example.com");
    let stored: String =
        sqlx::query_scalar(r#"SELECT token FROM "RefreshToken" WHERE "userId" = $1"#)
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored.len(), 64, "sha256 hex, never the raw token");
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn second_user_is_regular_and_returning_user_is_matched(pool: PgPool) {
    let idp = TestIdp::start().await;
    let cfg = idp.config();
    let app = spawn_app_with(cfg.clone(), pool.clone()).await;
    for email in ["alice@example.com", "bob@example.com", "alice@example.com"] {
        let token = TestIdp::sign(&idp.claims(NONCE, email, json!({})), "test-key");
        idp.respond_once_with_id_token(&token).await;
        let res = callback(&app, &cfg, "code=c&state=state-123").await;
        assert_eq!(res.status(), 302, "{email}");
        assert_eq!(location(&res), format!("{FRONTEND}/drawings/1"));
    }
    let rows: Vec<(String, String)> =
        sqlx::query_as(r#"SELECT email, role FROM "User" ORDER BY "createdAt""#)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![
            ("alice@example.com".to_string(), "ADMIN".to_string()),
            ("bob@example.com".to_string(), "USER".to_string())
        ]
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn inactive_user_is_rejected(pool: PgPool) {
    common::seed_user(&pool, "u1", "alice@example.com", "Alice", false).await;
    let idp = TestIdp::start().await;
    let cfg = idp.config();
    let token = TestIdp::sign(
        &idp.claims(NONCE, "alice@example.com", json!({})),
        "test-key",
    );
    idp.respond_with_id_token(&token).await;
    let app = spawn_app_with(cfg.clone(), pool).await;
    let res = callback(&app, &cfg, "code=c&state=state-123").await;
    assert_login_error(res, "account_inactive").await;
}
