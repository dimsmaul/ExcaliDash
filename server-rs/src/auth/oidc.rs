use std::{collections::HashMap, time::Duration};

use axum::{
    extract::{Query, State},
    http::{
        header::{LOCATION, SET_COOKIE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;
use url::{form_urlencoded, Url};

use super::{
    cookies::{clear_cookie, read_cookie, set_cookie, ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE},
    jwt::{hash_token, issue_pair, TokenPair},
    routes::ensure_auth_enabled,
};
use crate::{
    config::{Config, OidcConfig},
    state::AppState,
    time::NOW_UTC,
};

pub const FLOW_COOKIE: &str = "excalidash-oidc-flow";
pub const FLOW_TTL_MS: i64 = 10 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowPayload {
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub return_to: String,
    pub expires_at: i64,
}

fn flow_signature(encoded_payload: &str, secret: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(encoded_payload.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Node `encodeFlowPayload`: `b64url(JSON).b64url(HMAC-SHA256(secret, b64url(JSON)))`.
pub fn encode_flow(payload: &FlowPayload, secret: &str) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("serializable"));
    let signature = flow_signature(&encoded, secret);
    format!("{encoded}.{signature}")
}

/// Node `decodeFlowPayload` (signature, shape, expiry; returnTo re-sanitized).
pub fn decode_flow(cookie: &str, secret: &str, now_ms: i64) -> Option<FlowPayload> {
    let (encoded, provided) = cookie.split_once('.')?;
    let expected = flow_signature(encoded, secret);
    if expected.len() != provided.len()
        || !bool::from(expected.as_bytes().ct_eq(provided.as_bytes()))
    {
        return None;
    }
    let mut flow: FlowPayload =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()?;
    if now_ms > flow.expires_at {
        return None;
    }
    flow.return_to = sanitize_return_to(Some(&flow.return_to));
    Some(flow)
}

/// Node `sanitizeReturnTo`: only same-site absolute paths.
pub fn sanitize_return_to(raw: Option<&str>) -> String {
    let Some(value) = raw.map(str::trim) else {
        return "/".into();
    };
    let safe = value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains(['\r', '\n'])
        && value.len() <= 2048;
    if safe {
        value.to_string()
    } else {
        "/".into()
    }
}

/// 32 random bytes, base64url (openid-client `generators.state/nonce/codeVerifier`).
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// PKCE S256 challenge.
pub fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Node `getOidcErrorMessage` plus our allowlist rejection.
pub fn error_message(code: &str) -> &'static str {
    match code {
        "missing_flow" => "Missing or expired OIDC login flow. Please try again.",
        "provider_error" => "OIDC provider returned an error.",
        "missing_subject" => "OIDC response is missing required subject claim.",
        "missing_email" => "OIDC response is missing required email claim.",
        "unverified_email" => "OIDC account email is not verified.",
        "account_inactive" => "Your account is inactive.",
        "email_not_allowed" => "This account is not allowed to sign in.",
        "callback_failed" => "OIDC callback validation failed.",
        _ => "OIDC sign-in failed.",
    }
}

/// `/login?oidcError=..&oidcErrorMessage=..[&returnTo=..]`
pub fn login_error_location(code: &str, return_to: Option<&str>) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("oidcError", code);
    query.append_pair("oidcErrorMessage", error_message(code));
    if let Some(return_to) = return_to {
        query.append_pair("returnTo", &sanitize_return_to(Some(return_to)));
    }
    format!("/login?{}", query.finish())
}

pub fn is_email_allowed(cfg: &Config, email: &str) -> bool {
    let email = email.trim().to_lowercase();
    cfg.allowed_emails.contains(&email)
}

/// Provider metadata from `<issuer>/.well-known/openid-configuration`.
#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
}

const SCOPES: &str = "openid profile email";
const ID_TOKEN_ALGS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn oidc_config(state: &AppState) -> Result<&OidcConfig, String> {
    state
        .cfg
        .oidc
        .as_ref()
        .ok_or_else(|| "OIDC is not configured".to_string())
}

async fn discovery(state: &AppState) -> Result<Discovery, String> {
    let oidc = oidc_config(state)?;
    state
        .oidc_discovery
        .get_or_try_init(|| async {
            let url = format!(
                "{}/.well-known/openid-configuration",
                oidc.issuer_url.trim_end_matches('/')
            );
            state
                .http
                .get(url)
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|e| e.to_string())?
                .json::<Discovery>()
                .await
                .map_err(|e| e.to_string())
        })
        .await
        .cloned()
}

fn redirect(location: &str, cookies: &[String]) -> Response {
    let mut res = StatusCode::FOUND.into_response();
    let headers = res.headers_mut();
    if let Ok(value) = HeaderValue::from_str(location) {
        headers.insert(LOCATION, value);
    }
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(cookie) {
            headers.append(SET_COOKIE, value);
        }
    }
    res
}

/// `GET /auth/oidc/start?returnTo=/path`
pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if let Err(err) = ensure_auth_enabled(&state) {
        return err.into_response();
    }
    let disc = match discovery(&state).await {
        Ok(disc) => disc,
        Err(err) => {
            tracing::error!(%err, "OIDC discovery failed");
            return redirect(
                &login_error_location("callback_failed", None),
                &[clear_cookie(&headers, FLOW_COOKIE)],
            );
        }
    };
    let Ok(oidc) = oidc_config(&state) else {
        return redirect(&login_error_location("callback_failed", None), &[]);
    };
    let flow = FlowPayload {
        state: random_token(),
        nonce: random_token(),
        code_verifier: random_token(),
        return_to: sanitize_return_to(query.get("returnTo").map(String::as_str)),
        expires_at: now_ms() + FLOW_TTL_MS,
    };
    let Ok(mut url) = Url::parse(&disc.authorization_endpoint) else {
        return redirect(&login_error_location("callback_failed", None), &[]);
    };
    url.query_pairs_mut()
        .append_pair("client_id", &oidc.client_id)
        .append_pair("scope", SCOPES)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &oidc.redirect_uri)
        .append_pair("state", &flow.state)
        .append_pair("nonce", &flow.nonce)
        .append_pair("code_challenge", &code_challenge(&flow.code_verifier))
        .append_pair("code_challenge_method", "S256");
    let cookie = set_cookie(
        &headers,
        FLOW_COOKIE,
        &encode_flow(&flow, &state.cfg.jwt_secret),
        Duration::from_millis(FLOW_TTL_MS as u64),
    );
    redirect(url.as_str(), &[cookie])
}

/// `GET /auth/oidc/callback`
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let clear_flow = clear_cookie(&headers, FLOW_COOKIE);
    let flow = read_cookie(&headers, FLOW_COOKIE)
        .and_then(|cookie| decode_flow(&cookie, &state.cfg.jwt_secret, now_ms()));
    let Some(flow) = flow else {
        return redirect(&login_error_location("missing_flow", None), &[clear_flow]);
    };
    let fail = |code: &str| {
        redirect(
            &login_error_location(code, Some(&flow.return_to)),
            std::slice::from_ref(&clear_flow),
        )
    };
    if let Err(err) = ensure_auth_enabled(&state) {
        let mut res = err.into_response();
        if let Ok(value) = HeaderValue::from_str(&clear_flow) {
            res.headers_mut().append(SET_COOKIE, value);
        }
        return res;
    }
    if params.contains_key("error") {
        return fail("provider_error");
    }
    match complete_login(&state, &flow, &params).await {
        Ok(tokens) => redirect(
            &flow.return_to,
            &[
                clear_flow.clone(),
                set_cookie(
                    &headers,
                    ACCESS_TOKEN_COOKIE,
                    &tokens.access,
                    state.cfg.jwt_access_ttl,
                ),
                set_cookie(
                    &headers,
                    REFRESH_TOKEN_COOKIE,
                    &tokens.refresh,
                    state.cfg.jwt_refresh_ttl,
                ),
            ],
        ),
        Err(LoginError::Code(code)) => fail(code),
        Err(LoginError::Failed(err)) => {
            tracing::error!(%err, "OIDC callback error");
            fail("callback_failed")
        }
    }
}

enum LoginError {
    /// A user-facing OIDC error code (redirected to /login).
    Code(&'static str),
    /// Anything unexpected; logged and reported as `callback_failed`.
    Failed(String),
}

impl From<sqlx::Error> for LoginError {
    fn from(err: sqlx::Error) -> Self {
        LoginError::Failed(err.to_string())
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    access_token: Option<String>,
}

async fn complete_login(
    state: &AppState,
    flow: &FlowPayload,
    params: &HashMap<String, String>,
) -> Result<TokenPair, LoginError> {
    let failed = |e: String| LoginError::Failed(e);
    let code = params
        .get("code")
        .filter(|_| params.get("state") == Some(&flow.state))
        .ok_or_else(|| failed("state mismatch or missing code".into()))?;
    let oidc = oidc_config(state).map_err(failed)?;
    let disc = discovery(state).await.map_err(failed)?;

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", oidc.redirect_uri.as_str()),
        ("code_verifier", flow.code_verifier.as_str()),
    ];
    let mut request = state.http.post(&disc.token_endpoint);
    match &oidc.client_secret {
        Some(secret) => request = request.basic_auth(&oidc.client_id, Some(secret)),
        None => form.push(("client_id", oidc.client_id.as_str())),
    }
    let tokens: TokenResponse = request
        .form(&form)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| failed(e.to_string()))?
        .json()
        .await
        .map_err(|e| failed(e.to_string()))?;
    let id_token = tokens
        .id_token
        .ok_or_else(|| failed("token response without id_token".into()))?;
    let jwks: JwkSet = state
        .http
        .get(&disc.jwks_uri)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| failed(e.to_string()))?
        .json()
        .await
        .map_err(|e| failed(e.to_string()))?;
    let id_claims = verify_id_token(&id_token, &jwks, &disc.issuer, &oidc.client_id, &flow.nonce)
        .map_err(failed)?;

    let mut claims = id_claims.clone();
    if string_claim(&id_claims, "email").is_none() {
        if let (Some(endpoint), Some(access)) = (&disc.userinfo_endpoint, &tokens.access_token) {
            match fetch_userinfo(state, endpoint, access).await {
                Ok(userinfo) => {
                    let mut merged = userinfo;
                    merged.extend(id_claims.clone());
                    claims = merged;
                }
                Err(err) => tracing::error!(%err, "OIDC userinfo request failed"),
            }
        }
    }

    let subject = string_claim(&claims, "sub").ok_or(LoginError::Code("missing_subject"))?;
    let email = string_claim(&claims, "email")
        .map(|e| e.to_lowercase())
        .ok_or(LoginError::Code("missing_email"))?;
    // Trust email_verified only from the signed ID token, never from userinfo.
    if bool_claim(&id_claims, "email_verified") != Some(true) {
        return Err(LoginError::Code("unverified_email"));
    }
    if !is_email_allowed(&state.cfg, &email) {
        return Err(LoginError::Code("email_not_allowed"));
    }
    let name = string_claim(&claims, "name")
        .or_else(|| string_claim(&claims, "preferred_username"))
        .or_else(|| email.split('@').next().map(str::to_string))
        .unwrap_or_else(|| "User".into());

    let user = resolve_user(&state.db, &disc.issuer, &subject, &email, &name).await?;
    if !user.is_active {
        return Err(LoginError::Code("account_inactive"));
    }
    let pair = issue_pair(&state.cfg, &user.id, &user.email);
    store_refresh_token(
        &state.db,
        &user.id,
        &pair.refresh,
        state.cfg.jwt_refresh_ttl,
    )
    .await?;
    Ok(pair)
}

/// Validates signature (JWKS), issuer, audience, expiry, nonce and azp.
fn verify_id_token(
    token: &str,
    jwks: &JwkSet,
    issuer: &str,
    client_id: &str,
    nonce: &str,
) -> Result<Map<String, Value>, String> {
    let header = decode_header(token).map_err(|e| e.to_string())?;
    if !ID_TOKEN_ALGS.contains(&header.alg) {
        return Err(format!("unsupported id_token alg {:?}", header.alg));
    }
    let jwk = match &header.kid {
        Some(kid) => jwks.find(kid),
        None if jwks.keys.len() == 1 => jwks.keys.first(),
        None => None,
    }
    .ok_or("no JWKS key matches the id_token")?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| e.to_string())?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    let claims = decode::<Map<String, Value>>(token, &key, &validation)
        .map_err(|e| e.to_string())?
        .claims;
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Err("nonce mismatch".into());
    }
    let multi_audience = claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|aud| aud.len() > 1);
    if multi_audience && claims.get("azp").and_then(Value::as_str) != Some(client_id) {
        return Err("azp mismatch".into());
    }
    Ok(claims)
}

async fn fetch_userinfo(
    state: &AppState,
    endpoint: &str,
    access_token: &str,
) -> Result<Map<String, Value>, String> {
    state
        .http
        .get(endpoint)
        .bearer_auth(access_token)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())
}

/// Node `readStringClaim`: trimmed non-empty string.
fn string_claim(claims: &Map<String, Value>, key: &str) -> Option<String> {
    claims
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Node `readBooleanClaim`: bool, or "true"/"1"/"false"/"0".
fn bool_claim(claims: &Map<String, Value>, key: &str) -> Option<bool> {
    match claims.get(key)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_lowercase().as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Display name for a JIT-created user: no control characters, at most 100 chars.
fn clean_display_name(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).take(100).collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "User".into()
    } else {
        cleaned.to_string()
    }
}

#[derive(sqlx::FromRow)]
struct OidcUser {
    id: String,
    email: String,
    #[sqlx(rename = "isActive")]
    is_active: bool,
}

/// Node callback transaction: match by (issuer, subject), then by email, else JIT-create.
async fn resolve_user(
    db: &PgPool,
    issuer: &str,
    subject: &str,
    email: &str,
    name: &str,
) -> Result<OidcUser, LoginError> {
    let mut tx = db.begin().await?;

    let linked: Option<(String, String, String, bool)> = sqlx::query_as(
        r#"SELECT ai.id, u.id, u.email, u."isActive"
           FROM "AuthIdentity" ai JOIN "User" u ON u.id = ai."userId"
           WHERE ai.issuer = $1 AND ai.subject = $2"#,
    )
    .bind(issuer)
    .bind(subject)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((identity_id, id, email_db, is_active)) = linked {
        sqlx::query(&format!(
            r#"UPDATE "AuthIdentity" SET "lastLoginAt" = {NOW_UTC}, "emailAtLink" = $2, "updatedAt" = {NOW_UTC}
               WHERE id = $1"#
        ))
        .bind(&identity_id)
        .bind(email)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(OidcUser {
            id,
            email: email_db,
            is_active,
        });
    }

    let existing: Option<OidcUser> =
        sqlx::query_as(r#"SELECT id, email, "isActive" FROM "User" WHERE email = $1"#)
            .bind(email)
            .fetch_optional(&mut *tx)
            .await?;
    let user = match existing {
        Some(user) if !user.is_active => {
            tx.commit().await?;
            return Ok(user);
        }
        Some(user) => user,
        None => {
            let active_users: i64 =
                sqlx::query_scalar(r#"SELECT COUNT(*) FROM "User" WHERE "isActive""#)
                    .fetch_one(&mut *tx)
                    .await?;
            let role = if active_users == 0 { "ADMIN" } else { "USER" };
            let user: OidcUser = sqlx::query_as(&format!(
                r#"INSERT INTO "User" (id, email, username, "passwordHash", name, role, "mustResetPassword", "isActive", "createdAt", "updatedAt")
                   VALUES ($1, $2, NULL, '', $3, $4, false, true, {NOW_UTC}, {NOW_UTC})
                   RETURNING id, email, "isActive""#
            ))
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(email)
            .bind(clean_display_name(name))
            .bind(role)
            .fetch_one(&mut *tx)
            .await?;
            crate::authz::ensure_trash_collection(&mut tx, &user.id).await?;
            user
        }
    };

    let updated = sqlx::query(&format!(
        r#"UPDATE "AuthIdentity" SET issuer = $2, subject = $3, "emailAtLink" = $4,
               "lastLoginAt" = {NOW_UTC}, "updatedAt" = {NOW_UTC}
           WHERE provider = 'oidc' AND "userId" = $1"#
    ))
    .bind(&user.id)
    .bind(issuer)
    .bind(subject)
    .bind(email)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        sqlx::query(&format!(
            r#"INSERT INTO "AuthIdentity" (id, "userId", provider, issuer, subject, "emailAtLink", "lastLoginAt", "createdAt", "updatedAt")
               VALUES ($1, $2, 'oidc', $3, $4, $5, {NOW_UTC}, {NOW_UTC}, {NOW_UTC})"#
        ))
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&user.id)
        .bind(issuer)
        .bind(subject)
        .bind(email)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(user)
}

/// Persists the sha256 of a refresh token (Node rotation storage).
pub async fn store_refresh_token(
    db: impl sqlx::PgExecutor<'_>,
    user_id: &str,
    refresh_token: &str,
    ttl: Duration,
) -> Result<(), sqlx::Error> {
    sqlx::query(&format!(
        r#"INSERT INTO "RefreshToken" (id, "userId", token, "expiresAt", "createdAt")
           VALUES ($1, $2, $3, {NOW_UTC} + make_interval(secs => $4), {NOW_UTC})"#
    ))
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(hash_token(refresh_token))
    .bind(ttl.as_secs_f64())
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "jwt-secret";
    const NOW: i64 = 1_760_000_000_000;

    fn flow(return_to: &str) -> FlowPayload {
        FlowPayload {
            state: "st".into(),
            nonce: "no".into(),
            code_verifier: "cv".into(),
            return_to: return_to.into(),
            expires_at: NOW + FLOW_TTL_MS,
        }
    }

    #[test]
    fn flow_cookie_round_trips() {
        let encoded = encode_flow(&flow("/drawings/1"), SECRET);
        assert_eq!(
            decode_flow(&encoded, SECRET, NOW),
            Some(flow("/drawings/1"))
        );
    }

    #[test]
    fn flow_cookie_rejects_tampering_wrong_secret_and_expiry() {
        let encoded = encode_flow(&flow("/"), SECRET);
        assert_eq!(decode_flow(&encoded, "other", NOW), None);
        let (payload, sig) = encoded.split_once('.').unwrap();
        let forged_payload = encode_flow(&flow("/evil"), "other");
        let (forged, _) = forged_payload.split_once('.').unwrap();
        assert_eq!(decode_flow(&format!("{forged}.{sig}"), SECRET, NOW), None);
        assert_eq!(decode_flow(payload, SECRET, NOW), None);
        assert_eq!(decode_flow(&encoded, SECRET, NOW + FLOW_TTL_MS + 1), None);
        assert_eq!(decode_flow("garbage", SECRET, NOW), None);
    }

    #[test]
    fn decoded_return_to_is_resanitized() {
        let encoded = encode_flow(&flow("//evil.example"), SECRET);
        assert_eq!(decode_flow(&encoded, SECRET, NOW).unwrap().return_to, "/");
    }

    #[test]
    fn return_to_sanitizing() {
        assert_eq!(
            sanitize_return_to(Some("/drawings/x?y=1")),
            "/drawings/x?y=1"
        );
        assert_eq!(sanitize_return_to(Some("  /a ")), "/a");
        assert_eq!(sanitize_return_to(Some("//evil.example")), "/");
        assert_eq!(sanitize_return_to(Some("https://evil.example")), "/");
        assert_eq!(sanitize_return_to(Some("/a\r\nSet-Cookie: x")), "/");
        assert_eq!(
            sanitize_return_to(Some(&format!("/{}", "a".repeat(2048)))),
            "/"
        );
        assert_eq!(sanitize_return_to(None), "/");
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_example() {
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn random_tokens_are_43_char_base64url_and_unique() {
        let a = random_token();
        assert_eq!(a.len(), 43);
        assert!(a
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(a, random_token());
    }

    #[test]
    fn login_error_location_encodes_like_url_search_params() {
        assert_eq!(
            login_error_location("missing_flow", None),
            "/login?oidcError=missing_flow&oidcErrorMessage=Missing+or+expired+OIDC+login+flow.+Please+try+again."
        );
        assert_eq!(
            login_error_location("provider_error", Some("/drawings/a b")),
            "/login?oidcError=provider_error&oidcErrorMessage=OIDC+provider+returned+an+error.&returnTo=%2Fdrawings%2Fa+b"
        );
        assert_eq!(error_message("whatever"), "OIDC sign-in failed.");
    }

    #[test]
    fn allowlist_is_case_insensitive() {
        let cfg = Config::for_tests();
        assert!(is_email_allowed(&cfg, "Alice@Example.com"));
        assert!(!is_email_allowed(&cfg, "mallory@example.com"));
    }
}
