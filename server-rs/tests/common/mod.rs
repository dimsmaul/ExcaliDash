#![allow(dead_code)]

pub mod idp;

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

    /// A CSRF token plus the `excalidash-csrf-client=...` cookie pair it is bound to.
    pub async fn csrf(&self) -> Csrf {
        let res = reqwest::get(self.url("/csrf-token")).await.unwrap();
        let cookie = res.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let body: serde_json::Value = res.json().await.unwrap();
        Csrf {
            token: body["token"].as_str().unwrap().to_string(),
            cookie,
        }
    }

    /// Request signed in as `user_id`, with a valid CSRF token + cookie attached.
    pub async fn as_user(
        &self,
        method: reqwest::Method,
        path: &str,
        user_id: &str,
    ) -> reqwest::RequestBuilder {
        let csrf = self.csrf().await;
        let pair = excalidash_server::auth::jwt::issue_pair(
            &Config::for_tests(),
            user_id,
            &format!("{user_id}@example.com"),
        );
        self.request(method, path)
            .header("x-csrf-token", csrf.token)
            .header(
                "Cookie",
                format!("{}; excalidash-access-token={}", csrf.cookie, pair.access),
            )
    }

    /// Request without the cookie store, so tests control the `Cookie` header exactly.
    pub fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
            .request(method, self.url(path))
    }
}

pub struct Csrf {
    pub token: String,
    pub cookie: String,
}

pub fn set_cookies(res: &reqwest::Response) -> Vec<String> {
    res.headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

/// A pool that never connects; DB-touching routes fail fast instead of hanging.
pub fn unreachable_pool() -> PgPool {
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(2))
        .connect_lazy("postgres://u:p@127.0.0.1:1/db")
        .expect("lazy pool")
}

pub async fn seed_user(pool: &PgPool, id: &str, email: &str, name: &str, active: bool) {
    sqlx::query(
        r#"INSERT INTO "User" (id, email, "passwordHash", name, "isActive", "updatedAt")
           VALUES ($1, $2, '', $3, $4, timezone('utc', now()))"#,
    )
    .bind(id)
    .bind(email)
    .bind(name)
    .bind(active)
    .execute(pool)
    .await
    .expect("seed user");
}

pub async fn seed_collection(pool: &PgPool, id: &str, user_id: &str, name: &str) {
    sqlx::query(
        r#"INSERT INTO "Collection" (id, name, "userId", "updatedAt")
           VALUES ($1, $2, $3, timezone('utc', now()))"#,
    )
    .bind(id)
    .bind(name)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed collection");
}

pub async fn seed_drawing(pool: &PgPool, id: &str, user_id: &str, collection_id: Option<&str>) {
    sqlx::query(
        r#"INSERT INTO "Drawing" (id, name, elements, "appState", "userId", "collectionId", "updatedAt")
           VALUES ($1, $1, '[]', '{}', $2, $3, timezone('utc', now()))"#,
    )
    .bind(id)
    .bind(user_id)
    .bind(collection_id)
    .execute(pool)
    .await
    .expect("seed drawing");
}

pub async fn seed_drawing_permission(
    pool: &PgPool,
    drawing_id: &str,
    grantee: &str,
    permission: &str,
) {
    sqlx::query(
        r#"INSERT INTO "DrawingPermission" (id, "drawingId", "granteeUserId", permission, "createdByUserId", "updatedAt")
           SELECT gen_random_uuid()::text, $1, $2, $3, d."userId", timezone('utc', now())
           FROM "Drawing" d WHERE d.id = $1"#,
    )
    .bind(drawing_id)
    .bind(grantee)
    .bind(permission)
    .execute(pool)
    .await
    .expect("seed drawing permission");
}

pub async fn seed_collection_share(pool: &PgPool, collection_id: &str, grantee: &str, role: &str) {
    sqlx::query(
        r#"INSERT INTO "CollectionShare" (id, "collectionId", "granteeUserId", role, "createdByUserId", "updatedAt")
           SELECT gen_random_uuid()::text, $1, $2, $3, c."userId", timezone('utc', now())
           FROM "Collection" c WHERE c.id = $1"#,
    )
    .bind(collection_id)
    .bind(grantee)
    .bind(role)
    .execute(pool)
    .await
    .expect("seed collection share");
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
