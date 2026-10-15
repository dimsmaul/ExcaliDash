use axum::{
    extract::{Request, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::Sha256;

use super::cookies::{parse_cookies, request_is_https};
use crate::{config::Config, error::AppError, state::AppState};

pub const CSRF_CLIENT_COOKIE: &str = "excalidash-csrf-client";
pub const CSRF_HEADER: &str = "x-csrf-token";

const TOKEN_EXPIRY_MS: i64 = 24 * 60 * 60 * 1000;
const FUTURE_SKEW_MS: i64 = 5 * 60 * 1000;
const NONCE_BYTES: usize = 16;
const TOKEN_MAX_LENGTH: usize = 2048;

fn mac(secret: &str, client_id: &str, ts: i64, nonce: &str) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(format!("{client_id}|{ts}|{nonce}").as_bytes());
    mac
}

/// Node `createCsrfToken`: `b64url(JSON{ts,nonce}).b64url(HMAC(secret, clientId|ts|nonce))`.
pub fn create_token(secret: &str, client_id: &str, now_ms: i64) -> String {
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let payload = format!(r#"{{"ts":{now_ms},"nonce":"{nonce}"}}"#);
    let sig = mac(secret, client_id, now_ms, &nonce)
        .finalize()
        .into_bytes();
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload),
        URL_SAFE_NO_PAD.encode(sig)
    )
}

/// Node `validateCsrfToken`.
pub fn validate_token(secret: &str, client_id: &str, token: &str, now_ms: i64) -> bool {
    if token.is_empty() || token.len() > TOKEN_MAX_LENGTH {
        return false;
    }
    let Some((payload_b64, sig_b64)) = token.split_once('.') else {
        return false;
    };
    if sig_b64.contains('.') {
        return false;
    }
    let Some(payload) = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    else {
        return false;
    };
    let (Some(ts), Some(nonce)) = (payload["ts"].as_i64(), payload["nonce"].as_str()) else {
        return false;
    };
    if nonce.len() < 8 || now_ms - ts > TOKEN_EXPIRY_MS || ts - now_ms > FUTURE_SKEW_MS {
        return false;
    }
    let Ok(sig) = URL_SAFE_NO_PAD.decode(sig_b64) else {
        return false;
    };
    mac(secret, client_id, ts, nonce).verify_slice(&sig).is_ok()
}

/// Node `getOriginFromReferer`: `protocol//host` of an http(s) URL.
pub fn origin_from_referer(referer: &str) -> Option<String> {
    let (scheme, rest) = referer.trim().split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => ":80",
        "https" => ":443",
        _ => return None,
    };
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let host = host.strip_suffix(default_port).unwrap_or(&host);
    if host.is_empty() || host.contains(char::is_whitespace) || host.contains('@') {
        return None;
    }
    Some(format!("{scheme}://{host}"))
}

/// Valid `excalidash-csrf-client` cookie value, if present.
pub fn client_cookie(headers: &HeaderMap) -> Option<String> {
    let value = parse_cookies(headers).remove(CSRF_CLIENT_COOKIE)?;
    let valid = (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    valid.then_some(value)
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn forbidden(error: &str, message: &str) -> AppError {
    AppError::status(StatusCode::FORBIDDEN, error, message)
}

/// Node `requireCsrf` / `csrfProtectionMiddleware` checks for one request.
pub fn require(cfg: &Config, headers: &HeaderMap) -> Result<(), AppError> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let allowed = |origin: &str| cfg.frontend_origins.iter().any(|o| o == origin);
    if let Some(origin) = header("origin").filter(|o| !o.is_empty()) {
        if !allowed(origin) {
            return Err(forbidden("CSRF origin mismatch", "Origin not allowed"));
        }
    } else if let Some(referer) = header("referer").filter(|r| !r.is_empty()) {
        if !origin_from_referer(referer).is_some_and(|o| allowed(&o)) {
            return Err(forbidden("CSRF referer mismatch", "Referer not allowed"));
        }
    }
    let token = header(CSRF_HEADER)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| forbidden("CSRF token missing", "Missing x-csrf-token header"))?;
    let valid = client_cookie(headers).is_some_and(|client| {
        validate_token(
            &cfg.csrf_secret,
            &format!("cookie:{client}"),
            token,
            now_ms(),
        )
    });
    if valid {
        Ok(())
    } else {
        Err(forbidden(
            "CSRF token invalid",
            "Invalid or expired CSRF token. Please refresh and try again.",
        ))
    }
}

/// `GET /csrf-token`
pub async fn token_route(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (client, set_cookie) = match client_cookie(&headers) {
        Some(existing) => (existing, None),
        None => {
            let fresh = uuid::Uuid::new_v4().simple().to_string();
            let secure = if request_is_https(&headers) {
                "; Secure"
            } else {
                ""
            };
            let cookie = format!(
                "{CSRF_CLIENT_COOKIE}={fresh}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{secure}"
            );
            (fresh, Some(cookie))
        }
    };
    let token = create_token(
        &state.cfg.csrf_secret,
        &format!("cookie:{client}"),
        now_ms(),
    );
    let mut res = Json(json!({ "token": token, "header": CSRF_HEADER })).into_response();
    if let Some(cookie) = set_cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
        res.headers_mut().append(SET_COOKIE, cookie);
    }
    res
}

/// Enforces CSRF on every non-safe method outside `/auth/*` (auth routes call `require`).
pub async fn middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if safe || req.uri().path().starts_with("/auth/") {
        return next.run(req).await;
    }
    match require(&state.cfg, req.headers()) {
        Ok(()) => next.run(req).await,
        Err(err) => err.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde_json::Value;

    const SECRET: &str = "csrf-secret";
    const CLIENT: &str = "cookie:0123456789abcdef0123456789abcdef";
    const NOW: i64 = 1_760_000_000_000;

    #[test]
    fn token_round_trips_for_same_client() {
        let token = create_token(SECRET, CLIENT, NOW);
        assert!(validate_token(SECRET, CLIENT, &token, NOW + 1_000));
        assert!(!validate_token(
            SECRET,
            "cookie:other-client-id-123",
            &token,
            NOW
        ));
        assert!(!validate_token("other-secret", CLIENT, &token, NOW));
    }

    #[test]
    fn token_payload_matches_node_shape() {
        let token = create_token(SECRET, CLIENT, NOW);
        let (payload, sig) = token.split_once('.').unwrap();
        let json: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(json["ts"], NOW);
        let nonce = json["nonce"].as_str().unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(nonce).unwrap().len(), 16);
        assert_eq!(URL_SAFE_NO_PAD.decode(sig).unwrap().len(), 32);
        assert!(payload.starts_with(&URL_SAFE_NO_PAD.encode(b"{\"ts\":")));
    }

    #[test]
    fn rejects_tampered_expired_future_and_oversized_tokens() {
        let token = create_token(SECRET, CLIENT, NOW);
        let mut tampered = token.clone();
        tampered.pop();
        tampered.push(if token.ends_with('A') { 'B' } else { 'A' });
        assert!(!validate_token(SECRET, CLIENT, &tampered, NOW));
        assert!(!validate_token(
            SECRET,
            CLIENT,
            &token,
            NOW + 24 * 3_600_000 + 1
        ));
        assert!(validate_token(SECRET, CLIENT, &token, NOW + 24 * 3_600_000));
        let future = create_token(SECRET, CLIENT, NOW + 5 * 60_000 + 1);
        assert!(!validate_token(SECRET, CLIENT, &future, NOW));
        assert!(!validate_token(SECRET, CLIENT, &"a".repeat(2049), NOW));
        assert!(!validate_token(SECRET, CLIENT, "no-dot", NOW));
        assert!(!validate_token(SECRET, CLIENT, "", NOW));
    }

    #[test]
    fn referer_origin() {
        assert_eq!(
            origin_from_referer("https://Draw.Example.com/a/b?c#d").as_deref(),
            Some("https://draw.example.com")
        );
        assert_eq!(
            origin_from_referer("http://localhost:6767/x").as_deref(),
            Some("http://localhost:6767")
        );
        assert_eq!(
            origin_from_referer("https://x.example:443/").as_deref(),
            Some("https://x.example")
        );
        assert_eq!(origin_from_referer("ftp://x.example/"), None);
        assert_eq!(origin_from_referer("not a url"), None);
    }

    #[test]
    fn client_cookie_requires_safe_value() {
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            HeaderValue::from_static("excalidash-csrf-client=0123456789abcdef"),
        );
        assert_eq!(client_cookie(&h).as_deref(), Some("0123456789abcdef"));
        h.insert(
            "cookie",
            HeaderValue::from_static("excalidash-csrf-client=short"),
        );
        assert_eq!(client_cookie(&h), None);
        h.insert(
            "cookie",
            HeaderValue::from_static("excalidash-csrf-client=bad%20value%20with%20spaces"),
        );
        assert_eq!(client_cookie(&h), None);
    }
}
