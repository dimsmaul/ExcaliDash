mod common;

use common::{
    seed_drawing, seed_drawing_permission, seed_user, spawn_app, unreachable_pool, TestApp,
};
use reqwest::Method;
use serde_json::{json, Value};
use sqlx::PgPool;

#[tokio::test]
async fn system_update_without_outbound_check() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app
        .request(Method::GET, "/system/update?channel=PRERELEASE")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.json::<Value>().await.unwrap(),
        json!({
            "channel": "prerelease", "outboundEnabled": false, "latestVersion": null,
            "latestUrl": null, "publishedAt": null, "isUpdateAvailable": null,
            "currentVersion": "0.6.5"
        })
    );
}

#[tokio::test]
async fn library_requires_auth() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app.request(Method::GET, "/library").send().await.unwrap();
    assert_eq!(res.status(), 401);
}

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

async fn people(pool: &PgPool) {
    seed_user(pool, "u1", "alice@example.com", "Alice", true).await;
    seed_user(pool, "u2", "bob@example.com", "Bob", true).await;
    seed_user(pool, "u3", "carol@example.com", "Carol", false).await;
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn drawing_sharing_flow(pool: PgPool) {
    people(&pool).await;
    seed_drawing(&pool, "d1", "u1", None).await;
    let app = spawn_app(pool).await;

    let (_, body) = call(
        &app,
        Method::GET,
        "/drawings/d1/share-resolve?q=bo",
        "u1",
        None,
    )
    .await;
    assert_eq!(body, json!({"users": []}), "needs 3+ chars");
    let (_, body) = call(
        &app,
        Method::GET,
        "/drawings/d1/share-resolve?q=BOB",
        "u1",
        None,
    )
    .await;
    assert_eq!(
        body,
        json!({"users": [{"id": "u2", "name": "Bob", "email": "bob@example.com"}]})
    );
    let (status, _) = call(
        &app,
        Method::GET,
        "/drawings/d1/share-resolve?q=bob",
        "u2",
        None,
    )
    .await;
    assert_eq!(status, 404, "owner only");

    let (status, body) = call(
        &app,
        Method::POST,
        "/drawings/d1/permissions",
        "u1",
        Some(json!({"granteeUserId": "u2", "permission": "view"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["permission"]["permission"], "view");
    assert_eq!(
        body["permission"]["granteeUser"],
        json!({"id": "u2", "name": "Bob", "email": "bob@example.com"})
    );
    let perm_id = body["permission"]["id"].as_str().unwrap().to_string();
    let (_, body) = call(
        &app,
        Method::POST,
        "/drawings/d1/permissions",
        "u1",
        Some(json!({"granteeUserId": "u2", "permission": "edit"})),
    )
    .await;
    assert_eq!(body["permission"]["id"], perm_id, "upsert keeps the row");
    assert_eq!(body["permission"]["permission"], "edit");

    for (payload, status, expected) in [
        (
            json!({"granteeUserId": "u2", "permission": "owner"}),
            400,
            json!({"error": "Validation error", "message": "Invalid grantee or permission"}),
        ),
        (
            json!({"granteeUserId": "u1", "permission": "view"}),
            400,
            json!({"error": "Validation error", "message": "Cannot share with yourself"}),
        ),
        (
            json!({"granteeUserId": "u3", "permission": "view"}),
            404,
            json!({"error": "User not found"}),
        ),
    ] {
        let (s, b) = call(
            &app,
            Method::POST,
            "/drawings/d1/permissions",
            "u1",
            Some(payload),
        )
        .await;
        assert_eq!((s, b), (status, expected));
    }

    let (_, body) = call(&app, Method::GET, "/drawings/d1/sharing", "u1", None).await;
    assert_eq!(body["linkShares"], json!([]));
    assert_eq!(body["permissions"][0]["granteeUserId"], "u2");

    let (status, body) = call(
        &app,
        Method::DELETE,
        &format!("/drawings/d1/permissions/{perm_id}"),
        "u1",
        None,
    )
    .await;
    assert_eq!((status, body), (200, json!({"success": true})));
    let (_, body) = call(&app, Method::GET, "/drawings/d1/sharing", "u1", None).await;
    assert_eq!(body["permissions"], json!([]));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn grantee_can_hide_shared_drawing(pool: PgPool) {
    people(&pool).await;
    seed_drawing(&pool, "d1", "u1", None).await;
    seed_drawing_permission(&pool, "d1", "u2", "view").await;
    let app = spawn_app(pool).await;
    let (status, body) = call(
        &app,
        Method::PATCH,
        "/drawings/d1/shared-visibility",
        "u2",
        Some(json!({"hidden": true})),
    )
    .await;
    assert_eq!(
        (status, body),
        (200, json!({"success": true, "hidden": true}))
    );
    let (status, body) = call(
        &app,
        Method::PATCH,
        "/drawings/d1/shared-visibility",
        "u1",
        Some(json!({"hidden": true})),
    )
    .await;
    assert_eq!(
        (status, body),
        (404, json!({"error": "Shared drawing not found"}))
    );
    let (status, body) = call(
        &app,
        Method::PATCH,
        "/drawings/d1/shared-visibility",
        "u2",
        Some(json!({"hidden": "yes"})),
    )
    .await;
    assert_eq!(
        (status, body),
        (
            400,
            json!({"error": "Validation error", "message": "`hidden` must be a boolean"})
        )
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn library_round_trip(pool: PgPool) {
    people(&pool).await;
    let app = spawn_app(pool).await;
    let (_, body) = call(&app, Method::GET, "/library", "u1", None).await;
    assert_eq!(body, json!({"items": []}));
    let (_, body) = call(
        &app,
        Method::PUT,
        "/library",
        "u1",
        Some(json!({"items": [{"id": "lib1"}]})),
    )
    .await;
    assert_eq!(body, json!({"items": [{"id": "lib1"}]}));
    let (_, body) = call(&app, Method::GET, "/library", "u1", None).await;
    assert_eq!(body, json!({"items": [{"id": "lib1"}]}));
    let (status, body) = call(
        &app,
        Method::PUT,
        "/library",
        "u1",
        Some(json!({"items": {}})),
    )
    .await;
    assert_eq!(
        (status, body),
        (400, json!({"error": "Items must be an array"}))
    );
}
