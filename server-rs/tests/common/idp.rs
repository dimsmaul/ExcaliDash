//! Fake OpenID provider (discovery, JWKS, token endpoint) signing with a test-only RSA key.

use excalidash_server::config::Config;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

pub const CLIENT_ID: &str = "test-client";

pub struct TestIdp {
    pub server: MockServer,
}

impl TestIdp {
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "userinfo_endpoint": format!("{issuer}/userinfo"),
                "id_token_signing_alg_values_supported": ["RS256"],
            })))
            .mount(&server)
            .await;
        let jwk: Value =
            serde_json::from_str(include_str!("../fixtures/test-idp-jwk.json")).unwrap();
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [jwk] })))
            .mount(&server)
            .await;
        TestIdp { server }
    }

    pub fn issuer(&self) -> String {
        self.server.uri()
    }

    pub fn config(&self) -> Config {
        let mut cfg = Config::for_tests();
        let oidc = cfg.oidc.as_mut().unwrap();
        oidc.issuer_url = self.issuer();
        oidc.client_id = CLIENT_ID.into();
        cfg
    }

    /// Standard valid claims for `email`, overridable by `extra`.
    pub fn claims(&self, nonce: &str, email: &str, extra: Value) -> Value {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({
            "iss": self.issuer(), "aud": CLIENT_ID, "sub": format!("sub-{email}"),
            "email": email, "email_verified": true, "name": "Alice Example",
            "nonce": nonce, "iat": now, "exp": now + 300,
        });
        for (k, v) in extra.as_object().unwrap() {
            claims[k] = v.clone();
        }
        claims
    }

    pub fn sign(claims: &Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_der(include_bytes!("../fixtures/test-idp-key.der")),
        )
        .unwrap()
    }

    fn token_mock() -> wiremock::MockBuilder {
        Mock::given(method("POST")).and(path("/token"))
    }

    fn token_response(id_token: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at", "token_type": "Bearer", "expires_in": 3600,
            "id_token": id_token,
        }))
    }

    pub async fn respond_with_id_token(&self, id_token: &str) {
        Self::token_mock()
            .respond_with(Self::token_response(id_token))
            .mount(&self.server)
            .await;
    }

    /// Serves this id_token for exactly one token request (for multi-login tests).
    pub async fn respond_once_with_id_token(&self, id_token: &str) {
        Self::token_mock()
            .respond_with(Self::token_response(id_token))
            .up_to_n_times(1)
            .mount(&self.server)
            .await;
    }
}
