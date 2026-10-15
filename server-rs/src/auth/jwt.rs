use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Claims {
    pub user_id: String,
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonator_id: Option<String>,
    pub auth_provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_groups: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub token_type: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Clone)]
pub struct TokenPair {
    pub access: String,
    pub refresh: String,
}

/// Issues an access + refresh pair shaped like Node's `generateTokens(..., {authProvider:"oidc"})`.
pub fn issue_pair(cfg: &Config, user_id: &str, email: &str) -> TokenPair {
    TokenPair {
        access: sign(
            cfg,
            user_id,
            email,
            "access",
            cfg.jwt_access_ttl.as_secs() as i64,
        ),
        refresh: sign(
            cfg,
            user_id,
            email,
            "refresh",
            cfg.jwt_refresh_ttl.as_secs() as i64,
        ),
    }
}

pub fn verify_access(cfg: &Config, token: &str) -> Option<Claims> {
    verify(cfg, token, "access")
}

pub fn verify_refresh(cfg: &Config, token: &str) -> Option<Claims> {
    verify(cfg, token, "refresh")
}

/// Signature/expiry check only; callers inspect `token_type` themselves.
pub fn verify_any(cfg: &Config, token: &str) -> Option<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        &validation,
    )
    .ok()
    .map(|data| data.claims)
}

/// Node `hashTokenForStorage`: refresh tokens are stored as sha256 hex.
pub fn hash_token(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn sign(cfg: &Config, user_id: &str, email: &str, token_type: &str, ttl_secs: i64) -> String {
    let iat = chrono::Utc::now().timestamp();
    let claims = Claims {
        user_id: user_id.into(),
        email: email.into(),
        impersonator_id: None,
        auth_provider: "oidc".into(),
        oidc_groups: Some(vec![]),
        token_type: token_type.into(),
        jti: uuid::Uuid::new_v4().to_string(),
        iat,
        exp: iat + ttl_secs,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
    )
    .expect("HS256 signing cannot fail")
}

fn verify(cfg: &Config, token: &str, token_type: &str) -> Option<Claims> {
    verify_any(cfg, token).filter(|claims| claims.token_type == token_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(cfg: &Config, claims: &Claims) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn issued_access_token_round_trips() {
        let cfg = Config::for_tests();
        let pair = issue_pair(&cfg, "u1", "a@example.com");
        let claims = verify_access(&cfg, &pair.access).expect("valid access");
        assert_eq!(claims.user_id, "u1");
        assert_eq!(claims.email, "a@example.com");
        assert_eq!(claims.auth_provider, "oidc");
        assert_eq!(claims.oidc_groups, Some(vec![]));
        assert_eq!(claims.token_type, "access");
        assert_eq!(claims.exp - claims.iat, 15 * 60);
        assert!(uuid::Uuid::parse_str(&claims.jti).is_ok());
    }

    #[test]
    fn refresh_token_is_not_an_access_token() {
        let cfg = Config::for_tests();
        let pair = issue_pair(&cfg, "u1", "a@example.com");
        assert!(verify_access(&cfg, &pair.refresh).is_none());
        let refresh = verify_refresh(&cfg, &pair.refresh).expect("valid refresh");
        assert_eq!(refresh.exp - refresh.iat, 7 * 86_400);
        assert!(verify_refresh(&cfg, &pair.access).is_none());
    }

    #[test]
    fn hash_token_is_sha256_hex() {
        assert_eq!(
            hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_any_accepts_both_types() {
        let cfg = Config::for_tests();
        let pair = issue_pair(&cfg, "u1", "a@example.com");
        assert_eq!(
            verify_any(&cfg, &pair.refresh).unwrap().token_type,
            "refresh"
        );
        assert_eq!(verify_any(&cfg, &pair.access).unwrap().token_type, "access");
        assert!(verify_any(&cfg, "garbage").is_none());
    }

    #[test]
    fn tokens_get_unique_ids() {
        let cfg = Config::for_tests();
        let a = issue_pair(&cfg, "u1", "a@example.com");
        let b = issue_pair(&cfg, "u1", "a@example.com");
        assert_ne!(a.access, b.access);
        assert_ne!(a.refresh, b.refresh);
    }

    #[test]
    fn rejects_expired_token() {
        let cfg = Config::for_tests();
        let now = chrono::Utc::now().timestamp();
        let token = sign(
            &cfg,
            &Claims {
                user_id: "u1".into(),
                email: "a@example.com".into(),
                impersonator_id: None,
                auth_provider: "oidc".into(),
                oidc_groups: Some(vec![]),
                token_type: "access".into(),
                jti: "j".into(),
                iat: now - 120,
                exp: now - 1,
            },
        );
        assert!(verify_access(&cfg, &token).is_none());
    }

    #[test]
    fn rejects_token_signed_with_other_secret() {
        let cfg = Config::for_tests();
        let mut other = Config::for_tests();
        other.jwt_secret = "another-secret-another-secret-xx".into();
        let pair = issue_pair(&other, "u1", "a@example.com");
        assert!(verify_access(&cfg, &pair.access).is_none());
    }

    #[test]
    fn accepts_node_style_token_without_optional_fields() {
        let cfg = Config::for_tests();
        let now = chrono::Utc::now().timestamp();
        let token = encode(
            &Header::default(),
            &serde_json::json!({
                "userId": "u1", "email": "a@example.com", "authProvider": "local",
                "type": "access", "jti": "j", "iat": now, "exp": now + 60
            }),
            &EncodingKey::from_secret(cfg.jwt_secret.as_bytes()),
        )
        .unwrap();
        let claims = verify_access(&cfg, &token).expect("valid");
        assert_eq!(claims.oidc_groups, None);
    }
}
