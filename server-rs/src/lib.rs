pub mod auth;
pub mod authz;
pub mod config;
pub mod drawing;
pub mod error;
pub mod files_store;
pub mod routes;
pub mod sanitize;
pub mod snapshot_codec;
pub mod state;
pub mod time;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, HeaderValue, Method},
    middleware,
    routing::get,
    Router,
};
use config::Config;
use socketioxide::SocketIo;
use sqlx::PgPool;
use state::AppState;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    set_header::SetResponseHeaderLayer,
};

const CSP: &str = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; connect-src 'self'";
const HSTS: &str = "max-age=31536000; includeSubDomains; preload";

pub fn build_app(db: PgPool, cfg: Config) -> Router {
    let cfg = Arc::new(cfg);
    let (socket_layer, io) = SocketIo::builder()
        .max_buffer_size(cfg.body_limit_bytes)
        .build_layer();
    let state = AppState {
        db,
        cfg: cfg.clone(),
        io,
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("http client"),
        oidc_discovery: Default::default(),
    };

    Router::new()
        .route("/health", get(routes::misc::health))
        .route("/csrf-token", get(auth::csrf::token_route))
        .merge(auth::routes::router())
        .merge(routes::collections::router())
        .merge(routes::drawings::router())
        .merge(routes::history::router())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::csrf::middleware,
        ))
        .with_state(state)
        .layer(socket_layer)
        .layer(DefaultBodyLimit::max(cfg.body_limit_bytes))
        .layer(cors_layer(&cfg.frontend_origins))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS),
        ))
}

fn cors_layer(origins: &[String]) -> CorsLayer {
    let origins: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static("x-csrf-token"),
            HeaderName::from_static("x-imported-file"),
        ])
        .expose_headers([
            HeaderName::from_static("x-csrf-token"),
            HeaderName::from_static("x-request-id"),
        ])
}
