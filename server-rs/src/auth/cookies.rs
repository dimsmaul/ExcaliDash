use std::{collections::HashMap, time::Duration};

use axum::http::HeaderMap;

pub const ACCESS_TOKEN_COOKIE: &str = "excalidash-access-token";
pub const REFRESH_TOKEN_COOKIE: &str = "excalidash-refresh-token";

/// Parses a `Cookie` header like Node's `parseCookieHeader` (percent-decoded values).
pub fn parse_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for header in headers.get_all(axum::http::header::COOKIE) {
        let Ok(raw) = header.to_str() else { continue };
        for part in raw.split(';') {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            let value = value.trim();
            let decoded = percent_decode(value).unwrap_or_else(|| value.to_string());
            cookies.insert(key.to_string(), decoded);
        }
    }
    cookies
}

/// Non-empty cookie value, or None.
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    parse_cookies(headers)
        .remove(name)
        .filter(|v| !v.trim().is_empty())
}

/// True when the first hop of `X-Forwarded-Proto` is https (Caddy terminates TLS).
pub fn request_is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .is_some_and(|hop| hop.trim().eq_ignore_ascii_case("https"))
}

/// `Set-Cookie` value: HttpOnly; SameSite=Lax; Path=/; Max-Age; Secure over https.
pub fn set_cookie(headers: &HeaderMap, name: &str, value: &str, max_age: Duration) -> String {
    format!(
        "{name}={value}; Max-Age={}; Path=/; HttpOnly{}; SameSite=Lax",
        max_age.as_secs(),
        secure_attr(headers)
    )
}

/// `Set-Cookie` value that expires the cookie immediately.
pub fn clear_cookie(headers: &HeaderMap, name: &str) -> String {
    format!(
        "{name}=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly{}; SameSite=Lax",
        secure_attr(headers)
    )
}

fn secure_attr(headers: &HeaderMap) -> &'static str {
    if request_is_https(headers) {
        "; Secure"
    } else {
        ""
    }
}

/// decodeURIComponent; None on malformed escapes or invalid UTF-8.
fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = raw.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn parses_cookie_header() {
        let h = headers(&[(
            "cookie",
            "a=1; excalidash-access-token=tok=en; b=hello%20world; junk",
        )]);
        let c = parse_cookies(&h);
        assert_eq!(c["a"], "1");
        assert_eq!(c[ACCESS_TOKEN_COOKIE], "tok=en");
        assert_eq!(c["b"], "hello world");
        assert!(!c.contains_key("junk"));
    }

    #[test]
    fn read_cookie_ignores_blank_values() {
        let h = headers(&[("cookie", "excalidash-refresh-token= ; x=y")]);
        assert_eq!(read_cookie(&h, REFRESH_TOKEN_COOKIE), None);
        assert_eq!(read_cookie(&h, "x").as_deref(), Some("y"));
        assert_eq!(read_cookie(&HeaderMap::new(), "x"), None);
    }

    #[test]
    fn https_detection_uses_first_forwarded_hop() {
        assert!(request_is_https(&headers(&[(
            "x-forwarded-proto",
            "https, http"
        )])));
        assert!(!request_is_https(&headers(&[(
            "x-forwarded-proto",
            "http"
        )])));
        assert!(!request_is_https(&HeaderMap::new()));
    }

    #[test]
    fn set_cookie_attributes() {
        let plain = set_cookie(&HeaderMap::new(), "n", "v", Duration::from_secs(900));
        assert_eq!(plain, "n=v; Max-Age=900; Path=/; HttpOnly; SameSite=Lax");
        let secure = set_cookie(
            &headers(&[("x-forwarded-proto", "https")]),
            "n",
            "v",
            Duration::from_secs(60),
        );
        assert_eq!(
            secure,
            "n=v; Max-Age=60; Path=/; HttpOnly; Secure; SameSite=Lax"
        );
    }

    #[test]
    fn clear_cookie_expires_immediately() {
        assert_eq!(
            clear_cookie(&HeaderMap::new(), "n"),
            "n=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax"
        );
    }
}
