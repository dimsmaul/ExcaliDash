#![allow(dead_code)]

use std::time::Duration;

use excalidash_server::{build_app, config::Config};
use sqlx::{postgres::PgPoolOptions, PgPool};

pub struct TestApp {
    pub base_url: String,
    pub client: reqwest::Client,
}

impl TestApp {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

/// A pool that never connects; DB-touching routes fail fast instead of hanging.
pub fn unreachable_pool() -> PgPool {
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(2))
        .connect_lazy("postgres://u:p@127.0.0.1:1/db")
        .expect("lazy pool")
}

pub async fn spawn_app(pool: PgPool) -> TestApp {
    spawn_app_with(Config::for_tests(), pool).await
}

pub async fn spawn_app_with(cfg: Config, pool: PgPool) -> TestApp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_app(pool, cfg);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    TestApp {
        base_url: format!("http://{addr}"),
        client: reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}
