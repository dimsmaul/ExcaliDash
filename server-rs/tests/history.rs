mod common;

use std::time::Duration;

use common::{seed_drawing, seed_drawing_permission, seed_user, spawn_app, TestApp};
use excalidash_server::routes::history::delete_old_snapshots;
use reqwest::Method;
use serde_json::{json, Value};
use sqlx::PgPool;

async fn call(
    app: &TestApp,
    method: Method,
    path: &str,
    user: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut req = app.as_user(method, path, user).await;
    if let Some(body) = body {
        req = req.json(&body);
    }
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

async fn drawing_with_two_saves(pool: &PgPool, app: &TestApp) {
    seed_user(pool, "u1", "u1@example.com", "Alice", true).await;
    seed_drawing(pool, "d1", "u1", None).await;
    let elements = json!([{"id": "e1", "type": "rectangle"}]).to_string();
    sqlx::query(r#"UPDATE "Drawing" SET elements = $1 WHERE id = 'd1'"#)
        .bind(&elements)
        .execute(pool)
        .await
        .unwrap();
    for v in [1, 2] {
        let (status, _) = call(
            app,
            Method::PUT,
            "/drawings/d1",
            "u1",
            Some(json!({"elements": [{"id": format!("v{v}")}], "version": v})),
        )
        .await;
        assert_eq!(status, 200);
    }
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn list_get_and_restore(pool: PgPool) {
    let app = spawn_app(pool.clone()).await;
    drawing_with_two_saves(&pool, &app).await;

    let (status, list) = call(&app, Method::GET, "/drawings/d1/history", "u1", None).await;
    assert_eq!(status, 200);
    assert_eq!(list["totalCount"], 2);
    let versions: Vec<i64> = list["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["version"].as_i64().unwrap())
        .collect();
    assert_eq!(versions, vec![2, 1], "newest first");
    let first = list["snapshots"][1]["id"].as_str().unwrap().to_string();

    let (status, snap) = call(
        &app,
        Method::GET,
        &format!("/drawings/d1/history/{first}"),
        "u1",
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(snap["elements"], json!([{"id": "e1", "type": "rectangle"}]));
    assert_eq!(snap["drawingId"], "d1");

    let (status, restored) = call(
        &app,
        Method::POST,
        &format!("/drawings/d1/history/{first}/restore"),
        "u1",
        None,
    )
    .await;
    assert_eq!(status, 200, "{restored}");
    assert_eq!(
        restored["elements"],
        json!([{"id": "e1", "type": "rectangle"}])
    );
    assert_eq!(restored["version"], 4);
    assert_eq!(restored["preview"], Value::Null);
    assert_eq!(restored["accessLevel"], "owner");
    let (_, list) = call(
        &app,
        Method::GET,
        "/drawings/d1/history?limit=1",
        "u1",
        None,
    )
    .await;
    assert_eq!(
        list["totalCount"], 3,
        "restore snapshots the state it replaces"
    );

    let (status, body) = call(
        &app,
        Method::GET,
        "/drawings/d1/history?limit=0",
        "u1",
        None,
    )
    .await;
    assert_eq!(
        (status, body),
        (400, json!({"error": "Invalid history pagination"}))
    );
    let (status, body) = call(&app, Method::GET, "/drawings/d1/history/nope", "u1", None).await;
    assert_eq!(
        (status, body),
        (404, json!({"error": "Snapshot not found"}))
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn restore_requires_edit_and_rejects_corrupt_snapshots(pool: PgPool) {
    let app = spawn_app(pool.clone()).await;
    drawing_with_two_saves(&pool, &app).await;
    seed_user(&pool, "u2", "u2@example.com", "Bob", true).await;
    seed_drawing_permission(&pool, "d1", "u2", "view").await;
    let snap: String =
        sqlx::query_scalar(r#"SELECT id FROM "DrawingSnapshot" ORDER BY version LIMIT 1"#)
            .fetch_one(&pool)
            .await
            .unwrap();

    let (status, _) = call(&app, Method::GET, "/drawings/d1/history", "u2", None).await;
    assert_eq!(status, 200, "viewers can browse history");
    let (status, body) = call(
        &app,
        Method::POST,
        &format!("/drawings/d1/history/{snap}/restore"),
        "u2",
        None,
    )
    .await;
    assert_eq!((status, body), (404, json!({"error": "Drawing not found"})));

    sqlx::query(r#"UPDATE "DrawingSnapshot" SET elements = '{"not":"an array"}' WHERE id = $1"#)
        .bind(&snap)
        .execute(&pool)
        .await
        .unwrap();
    let (status, body) = call(
        &app,
        Method::POST,
        &format!("/drawings/d1/history/{snap}/restore"),
        "u1",
        None,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "Invalid drawing history snapshot");
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn cleanup_deletes_only_expired_snapshots(pool: PgPool) {
    let app = spawn_app(pool.clone()).await;
    drawing_with_two_saves(&pool, &app).await;
    sqlx::query(r#"UPDATE "DrawingSnapshot" SET "createdAt" = "createdAt" - interval '3 days' WHERE version = 1"#)
        .execute(&pool)
        .await
        .unwrap();
    let deleted = delete_old_snapshots(&pool, Duration::from_secs(2 * 86_400))
        .await
        .unwrap();
    assert_eq!(deleted, 1);
    let left: Vec<i32> = sqlx::query_scalar(r#"SELECT version FROM "DrawingSnapshot""#)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(left, vec![2]);
}
