use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    OidcEnforced,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub provider_name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub frontend_origins: Vec<String>,
    pub auth_mode: AuthMode,
    pub jwt_secret: String,
    pub csrf_secret: String,
    pub jwt_access_ttl: Duration,
    pub jwt_refresh_ttl: Duration,
    pub oidc: Option<OidcConfig>,
    pub allowed_emails: Vec<String>,
    pub body_limit_bytes: usize,
    pub file_upload_max_bytes: usize,
    pub snapshot_retention: Duration,
    /// Default lifetime of "anyone with the link" edit links.
    pub link_share_edit_ttl: Duration,
    /// Default lifetime of "anyone with the link" view links.
    pub link_share_view_ttl: Duration,
    /// Cap for edit-link lifetimes.
    pub link_share_max_ttl: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let get = |key: &str| get(key).filter(|v| !v.trim().is_empty());

        let mut missing = Vec::new();
        let mut required = |key: &'static str| {
            get(key).unwrap_or_else(|| {
                missing.push(key);
                String::new()
            })
        };
        let database_url = required("DATABASE_URL");
        let jwt_secret = required("JWT_SECRET");
        let csrf_secret = required("CSRF_SECRET");
        if !missing.is_empty() {
            return Err(format!(
                "Missing required environment variable(s): {}",
                missing.join(", ")
            ));
        }

        let auth_mode = match get("AUTH_MODE").as_deref().map(str::trim) {
            None | Some("oidc_enforced") => AuthMode::OidcEnforced,
            Some("disabled") => AuthMode::Disabled,
            Some(other) => {
                return Err(format!(
                    "Invalid AUTH_MODE '{other}': supported values are oidc_enforced, disabled"
                ))
            }
        };

        let oidc = match auth_mode {
            AuthMode::Disabled => None,
            AuthMode::OidcEnforced => {
                let issuer_url = get("OIDC_ISSUER_URL");
                let client_id = get("OIDC_CLIENT_ID");
                let redirect_uri = get("OIDC_REDIRECT_URI");
                let absent: Vec<&str> = [
                    ("OIDC_ISSUER_URL", &issuer_url),
                    ("OIDC_CLIENT_ID", &client_id),
                    ("OIDC_REDIRECT_URI", &redirect_uri),
                ]
                .into_iter()
                .filter(|(_, v)| v.is_none())
                .map(|(k, _)| k)
                .collect();
                if !absent.is_empty() {
                    return Err(format!(
                        "AUTH_MODE=oidc_enforced requires OIDC configuration. Missing: {}",
                        absent.join(", ")
                    ));
                }
                Some(OidcConfig {
                    provider_name: get("OIDC_PROVIDER_NAME").unwrap_or_else(|| "OIDC".into()),
                    issuer_url: issuer_url.unwrap_or_default(),
                    client_id: client_id.unwrap_or_default(),
                    client_secret: get("OIDC_CLIENT_SECRET"),
                    redirect_uri: redirect_uri.unwrap_or_default(),
                })
            }
        };

        let duration = |key: &str, default: &str| {
            let raw = get(key).unwrap_or_else(|| default.into());
            parse_ms(&raw).ok_or_else(|| format!("Invalid duration for {key}: '{raw}'"))
        };
        let number = |key: &str, default: u64| match get(key) {
            None => Ok(default),
            Some(raw) => raw
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("Invalid number for {key}: '{raw}'")),
        };
        const MB: u64 = 1024 * 1024;

        let allowed_emails: Vec<String> = get("ALLOWED_EMAILS")
            .unwrap_or_default()
            .split(',')
            .map(|e| e.trim().to_lowercase())
            .filter(|e| !e.is_empty())
            .collect();

        Ok(Config {
            port: u16::try_from(number("PORT", 8000)?).map_err(|_| "Invalid PORT".to_string())?,
            database_url,
            frontend_origins: normalize_origins(get("FRONTEND_URL").as_deref()),
            auth_mode,
            jwt_secret,
            csrf_secret,
            jwt_access_ttl: duration("JWT_ACCESS_EXPIRES_IN", "15m")?,
            jwt_refresh_ttl: duration("JWT_REFRESH_EXPIRES_IN", "7d")?,
            oidc,
            allowed_emails,
            body_limit_bytes: (number("BODY_LIMIT_MB", 50)? * MB) as usize,
            file_upload_max_bytes: (number("FILE_UPLOAD_MAX_MB", 100)? * MB) as usize,
            snapshot_retention: Duration::from_secs(number("SNAPSHOT_RETENTION_DAYS", 2)? * 86_400),
            link_share_edit_ttl: Duration::from_millis(number(
                "LINK_SHARE_EDIT_DEFAULT_TTL_MS",
                7 * 86_400_000,
            )?),
            link_share_view_ttl: Duration::from_millis(number(
                "LINK_SHARE_VIEW_DEFAULT_TTL_MS",
                30 * 86_400_000,
            )?),
            link_share_max_ttl: Duration::from_millis(number(
                "LINK_SHARE_MAX_TTL_MS",
                90 * 86_400_000,
            )?),
        })
    }

    pub fn for_tests() -> Self {
        Config {
            port: 0,
            database_url: "postgres://u:p@127.0.0.1:1/db".into(),
            frontend_origins: vec!["http://localhost:6767".into()],
            auth_mode: AuthMode::OidcEnforced,
            jwt_secret: "test-jwt-secret-test-jwt-secret-32".into(),
            csrf_secret: "test-csrf-secret".into(),
            jwt_access_ttl: Duration::from_secs(15 * 60),
            jwt_refresh_ttl: Duration::from_secs(7 * 86_400),
            oidc: Some(OidcConfig {
                provider_name: "OIDC".into(),
                issuer_url: "http://127.0.0.1:1".into(),
                client_id: "test-client".into(),
                client_secret: Some("test-client-secret".into()),
                redirect_uri: "http://localhost:6767/api/auth/oidc/callback".into(),
            }),
            allowed_emails: vec!["alice@example.com".into(), "bob@example.com".into()],
            body_limit_bytes: 50 * 1024 * 1024,
            file_upload_max_bytes: 100 * 1024 * 1024,
            snapshot_retention: Duration::from_secs(2 * 86_400),
            link_share_edit_ttl: Duration::from_secs(7 * 86_400),
            link_share_view_ttl: Duration::from_secs(30 * 86_400),
            link_share_max_ttl: Duration::from_secs(90 * 86_400),
        }
    }
}

/// Parses durations the way the `ms` npm package does (used by jsonwebtoken's
/// `expiresIn`): `"15m"`, `"7d"`, `"1.5h"`, `"100"` (milliseconds).
pub fn parse_ms(raw: &str) -> Option<Duration> {
    let s = raw.trim().to_lowercase();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let value: f64 = num.parse().ok()?;
    let ms_per_unit: f64 = match unit.trim() {
        "" | "ms" | "msec" | "msecs" | "millisecond" | "milliseconds" => 1.0,
        "s" | "sec" | "secs" | "second" | "seconds" => 1_000.0,
        "m" | "min" | "mins" | "minute" | "minutes" => 60_000.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000.0,
        "d" | "day" | "days" => 86_400_000.0,
        "w" | "week" | "weeks" => 604_800_000.0,
        "y" | "yr" | "yrs" | "year" | "years" => 31_557_600_000.0,
        _ => return None,
    };
    Some(Duration::from_millis((value * ms_per_unit).round() as u64))
}

/// Mirrors `normalizeOrigins` in backend/src/index.ts.
pub fn normalize_origins(raw: Option<&str>) -> Vec<String> {
    let origins: Vec<String> = raw
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|o| !o.is_empty())
        .map(|o| {
            let o = if o.starts_with("http://") || o.starts_with("https://") {
                o.to_string()
            } else {
                format!("http://{o}")
            };
            o.strip_suffix('/').map(str::to_string).unwrap_or(o)
        })
        .collect();
    if origins.is_empty() {
        vec!["http://localhost:6767".into()]
    } else {
        origins
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| map.get(key).cloned()
    }

    const BASE: [(&str, &str); 3] = [
        ("DATABASE_URL", "postgres://u:p@localhost/db"),
        ("JWT_SECRET", "jwt-secret"),
        ("CSRF_SECRET", "csrf-secret"),
    ];

    fn with_base(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
        let mut pairs = BASE.to_vec();
        pairs.extend_from_slice(extra);
        pairs
    }

    #[test]
    fn parse_ms_units() {
        assert_eq!(parse_ms("15m"), Some(Duration::from_secs(15 * 60)));
        assert_eq!(parse_ms("7d"), Some(Duration::from_secs(7 * 86_400)));
        assert_eq!(parse_ms("2 hours"), Some(Duration::from_secs(7_200)));
        assert_eq!(parse_ms("1.5h"), Some(Duration::from_secs(5_400)));
        assert_eq!(parse_ms("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_ms("1w"), Some(Duration::from_secs(7 * 86_400)));
        assert_eq!(parse_ms("250"), Some(Duration::from_millis(250)));
        assert_eq!(parse_ms("10MS"), Some(Duration::from_millis(10)));
    }

    #[test]
    fn parse_ms_rejects_garbage() {
        assert_eq!(parse_ms(""), None);
        assert_eq!(parse_ms("abc"), None);
        assert_eq!(parse_ms("5 parsecs"), None);
        assert_eq!(parse_ms("-5m"), None);
    }

    #[test]
    fn normalize_origins_matches_node() {
        assert_eq!(normalize_origins(None), vec!["http://localhost:6767"]);
        assert_eq!(normalize_origins(Some("  ")), vec!["http://localhost:6767"]);
        assert_eq!(
            normalize_origins(Some("https://draw.example.com/, localhost:5173 ,,")),
            vec!["https://draw.example.com", "http://localhost:5173"]
        );
    }

    #[test]
    fn disabled_mode_defaults() {
        let cfg = Config::from_lookup(lookup(&with_base(&[("AUTH_MODE", "disabled")]))).unwrap();
        assert_eq!(cfg.auth_mode, AuthMode::Disabled);
        assert_eq!(cfg.port, 8000);
        assert!(cfg.oidc.is_none());
        assert_eq!(cfg.jwt_access_ttl, Duration::from_secs(15 * 60));
        assert_eq!(cfg.jwt_refresh_ttl, Duration::from_secs(7 * 86_400));
        assert_eq!(cfg.body_limit_bytes, 50 * 1024 * 1024);
        assert_eq!(cfg.file_upload_max_bytes, 100 * 1024 * 1024);
        assert_eq!(cfg.snapshot_retention, Duration::from_secs(2 * 86_400));
        assert_eq!(cfg.link_share_edit_ttl, Duration::from_secs(7 * 86_400));
        assert_eq!(cfg.link_share_view_ttl, Duration::from_secs(30 * 86_400));
        assert_eq!(cfg.link_share_max_ttl, Duration::from_secs(90 * 86_400));
        assert_eq!(cfg.frontend_origins, vec!["http://localhost:6767"]);
    }

    #[test]
    fn oidc_enforced_requires_provider_settings() {
        let err = Config::from_lookup(lookup(&with_base(&[
            ("AUTH_MODE", "oidc_enforced"),
            ("OIDC_CLIENT_ID", "cid"),
        ])))
        .unwrap_err();
        assert!(err.contains("OIDC_ISSUER_URL"), "{err}");
        assert!(err.contains("OIDC_REDIRECT_URI"), "{err}");
    }

    #[test]
    fn oidc_enforced_parses_provider_and_allowlist() {
        let cfg = Config::from_lookup(lookup(&with_base(&[
            ("AUTH_MODE", "oidc_enforced"),
            ("OIDC_ISSUER_URL", "https://accounts.google.com"),
            ("OIDC_CLIENT_ID", "cid"),
            ("OIDC_CLIENT_SECRET", "csecret"),
            (
                "OIDC_REDIRECT_URI",
                "https://draw.example.com/api/auth/oidc/callback",
            ),
            ("ALLOWED_EMAILS", " Alice@Example.com, ,bob@example.com "),
            ("PORT", "9000"),
            ("JWT_ACCESS_EXPIRES_IN", "5m"),
            ("SNAPSHOT_RETENTION_DAYS", "7"),
        ])))
        .unwrap();
        assert_eq!(cfg.auth_mode, AuthMode::OidcEnforced);
        let oidc = cfg.oidc.unwrap();
        assert_eq!(oidc.provider_name, "OIDC");
        assert_eq!(oidc.issuer_url, "https://accounts.google.com");
        assert_eq!(oidc.client_secret.as_deref(), Some("csecret"));
        assert_eq!(
            cfg.allowed_emails,
            vec!["alice@example.com", "bob@example.com"]
        );
        assert_eq!(cfg.port, 9000);
        assert_eq!(cfg.jwt_access_ttl, Duration::from_secs(300));
        assert_eq!(cfg.snapshot_retention, Duration::from_secs(7 * 86_400));
    }

    #[test]
    fn allowlist_is_optional() {
        let cfg = Config::from_lookup(lookup(&with_base(&[
            ("AUTH_MODE", "oidc_enforced"),
            ("OIDC_ISSUER_URL", "https://accounts.google.com"),
            ("OIDC_CLIENT_ID", "cid"),
            ("OIDC_REDIRECT_URI", "https://x/api/auth/oidc/callback"),
            ("ALLOWED_EMAILS", " , "),
        ])))
        .unwrap();
        assert!(cfg.allowed_emails.is_empty());
    }

    #[test]
    fn rejects_unknown_auth_mode() {
        let err = Config::from_lookup(lookup(&with_base(&[("AUTH_MODE", "local")]))).unwrap_err();
        assert!(err.contains("AUTH_MODE"), "{err}");
    }

    #[test]
    fn requires_secrets_and_database_url() {
        let err = Config::from_lookup(lookup(&[("AUTH_MODE", "disabled")])).unwrap_err();
        assert!(err.contains("DATABASE_URL"), "{err}");
        assert!(err.contains("JWT_SECRET"), "{err}");
        assert!(err.contains("CSRF_SECRET"), "{err}");
    }
}
