mod common;

use common::{
    seed_collection, seed_collection_share, seed_drawing, seed_drawing_permission, seed_user,
    spawn_app, unreachable_pool, TestApp,
};
use reqwest::Method;
use serde_json::{json, Value};
use sqlx::PgPool;

const PNG: &str = "data:image/png;base64,iVBORw0KGgo=";

#[tokio::test]
async fn listing_requires_auth() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app.request(Method::GET, "/drawings").send().await.unwrap();
    assert_eq!(res.status(), 401);
}

async fn people(pool: &PgPool) {
    seed_user(pool, "u1", "u1@example.com", "Alice", true).await;
    seed_user(pool, "u2", "u2@example.com", "Bob", true).await;
    seed_user(pool, "u3", "u3@example.com", "Carol", true).await;
}

async fn json_of(
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

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn create_interns_images_and_read_returns_owner_view(pool: PgPool) {
    people(&pool).await;
    let app = spawn_app(pool.clone()).await;
    let (status, created) = json_of(
        &app,
        Method::POST,
        "/drawings",
        "u1",
        Some(json!({
            "name": "Board",
            "elements": [{"id": "e1", "type": "image", "fileId": "f1"}],
            "appState": {"viewBackgroundColor": "#fff"},
            "files": {"f1": {"id": "f1", "mimeType": "image/png", "dataURL": PNG}},
            "preview": format!(r#"<svg><image href="{PNG}"></image></svg>"#)
        })),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    let url = format!("/api/files/{id}/f1");
    assert_eq!(created["files"]["f1"]["dataURL"], url);
    assert!(created["preview"].as_str().unwrap().contains(&url));
    assert_eq!(created["version"], 1);
    assert_eq!(created["collectionId"], Value::Null);
    assert!(created.get("accessLevel").is_none());
    let size: i32 = sqlx::query_scalar(
        r#"SELECT "sizeBytes" FROM "DrawingFile" WHERE "drawingId" = $1 AND "fileId" = 'f1'"#,
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(size, 8);

    let (status, read) = json_of(&app, Method::GET, &format!("/drawings/{id}"), "u1", None).await;
    assert_eq!(status, 200);
    assert_eq!(read["accessLevel"], "owner");
    assert_eq!(read["elements"][0]["id"], "e1");
    assert_eq!(read["appState"]["viewBackgroundColor"], "#fff");

    let (status, _) = json_of(&app, Method::GET, &format!("/drawings/{id}"), "u2", None).await;
    assert_eq!(status, 404);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn create_into_foreign_collection_needs_edit_share(pool: PgPool) {
    people(&pool).await;
    seed_collection(&pool, "c2", "u2", "Bob's").await;
    let app = spawn_app(pool.clone()).await;
    let (status, body) = json_of(
        &app,
        Method::POST,
        "/drawings",
        "u1",
        Some(json!({"collectionId": "c2"})),
    )
    .await;
    assert_eq!(
        (status, body),
        (403, json!({"error": "No edit access to this collection"}))
    );
    seed_collection_share(&pool, "c2", "u1", "edit").await;
    let (status, _) = json_of(
        &app,
        Method::POST,
        "/drawings",
        "u1",
        Some(json!({"collectionId": "c2"})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, body) = json_of(
        &app,
        Method::POST,
        "/drawings",
        "u1",
        Some(json!({"collectionId": "nope"})),
    )
    .await;
    assert_eq!(
        (status, body),
        (404, json!({"error": "Collection not found"}))
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn list_filters_sorts_and_paginates(pool: PgPool) {
    people(&pool).await;
    seed_collection(&pool, "c1", "u1", "Mine").await;
    seed_collection(&pool, "trash:u1", "u1", "Trash").await;
    seed_drawing(&pool, "b-loose", "u1", None).await;
    seed_drawing(&pool, "a-in-c1", "u1", Some("c1")).await;
    seed_drawing(&pool, "c-trashed", "u1", Some("trash:u1")).await;
    seed_drawing(&pool, "other-user", "u2", None).await;
    let app = spawn_app(pool).await;

    let ids = |body: &Value| -> Vec<String> {
        body["drawings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap().to_string())
            .collect()
    };
    let (_, all) = json_of(&app, Method::GET, "/drawings?sortField=name", "u1", None).await;
    assert_eq!(ids(&all), vec!["a-in-c1", "b-loose"]);
    assert_eq!(all["totalCount"], 2);
    assert_eq!(all["limit"], 50);
    assert_eq!(all["drawings"][0]["creatorName"], "Alice");
    assert!(all["drawings"][0].get("elements").is_none());

    let (_, loose) = json_of(&app, Method::GET, "/drawings?collectionId=null", "u1", None).await;
    assert_eq!(ids(&loose), vec!["b-loose"]);
    let (_, trash) = json_of(
        &app,
        Method::GET,
        "/drawings?collectionId=trash",
        "u1",
        None,
    )
    .await;
    assert_eq!(ids(&trash), vec!["c-trashed"]);
    assert_eq!(trash["drawings"][0]["collectionId"], "trash");
    let (_, search) = json_of(&app, Method::GET, "/drawings?search=loose", "u1", None).await;
    assert_eq!(ids(&search), vec!["b-loose"]);
    let (_, page) = json_of(
        &app,
        Method::GET,
        "/drawings?sortField=name&limit=1&offset=1",
        "u1",
        None,
    )
    .await;
    assert_eq!(ids(&page), vec!["b-loose"]);
    assert_eq!(page["totalCount"], 2);
    let (_, full) = json_of(
        &app,
        Method::GET,
        "/drawings?collectionId=c1&includeData=true",
        "u1",
        None,
    )
    .await;
    assert_eq!(full["drawings"][0]["elements"], json!([]));
    let (status, body) = json_of(&app, Method::GET, "/drawings?collectionId=c1", "u3", None).await;
    assert_eq!(
        (status, body),
        (404, json!({"error": "Collection not found"}))
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn shared_collection_and_shared_with_me(pool: PgPool) {
    people(&pool).await;
    seed_collection(&pool, "team", "u1", "Team").await;
    seed_collection_share(&pool, "team", "u2", "edit").await;
    seed_drawing(&pool, "by-alice", "u1", Some("team")).await;
    seed_drawing(&pool, "by-bob", "u2", Some("team")).await;
    seed_drawing(&pool, "direct", "u1", None).await;
    seed_drawing_permission(&pool, "direct", "u2", "edit").await;
    seed_drawing(&pool, "hidden", "u1", None).await;
    seed_drawing_permission(&pool, "hidden", "u2", "view").await;
    sqlx::query(r#"UPDATE "DrawingPermission" SET hidden = true WHERE "drawingId" = 'hidden'"#)
        .execute(&pool)
        .await
        .unwrap();
    let app = spawn_app(pool).await;

    let (_, team) = json_of(
        &app,
        Method::GET,
        "/drawings?collectionId=team&sortField=name",
        "u2",
        None,
    )
    .await;
    assert_eq!(team["totalCount"], 2, "all creators are listed");
    let (_, shared) = json_of(&app, Method::GET, "/drawings/shared", "u2", None).await;
    assert_eq!(shared["totalCount"], 1);
    assert_eq!(shared["drawings"][0]["id"], "direct");
    assert_eq!(shared["drawings"][0]["accessLevel"], "edit");
    assert_eq!(shared["drawings"][0]["collectionId"], Value::Null);

    let (status, read) = json_of(&app, Method::GET, "/drawings/by-alice", "u2", None).await;
    assert_eq!(status, 200);
    assert_eq!(read["accessLevel"], "edit");
    assert_eq!(
        read["collectionId"],
        Value::Null,
        "owner collection ids are not leaked"
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn scene_updates_are_versioned_with_snapshots(pool: PgPool) {
    people(&pool).await;
    seed_drawing(&pool, "d1", "u1", None).await;
    let app = spawn_app(pool.clone()).await;

    let (status, body) = json_of(
        &app,
        Method::PUT,
        "/drawings/d1",
        "u1",
        Some(json!({"elements": [{"id": "e1"}], "version": 1})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["version"], 2);
    assert_eq!(body["accessLevel"], "owner");
    let snaps: Vec<(i32, String)> = sqlx::query_as(
        r#"SELECT version, elements FROM "DrawingSnapshot" WHERE "drawingId" = 'd1'"#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(snaps, vec![(1, "[]".to_string())]);

    let (status, body) = json_of(
        &app,
        Method::PUT,
        "/drawings/d1",
        "u1",
        Some(json!({"elements": [], "version": 1})),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(body["code"], "VERSION_CONFLICT");
    assert_eq!(body["currentVersion"], 2);

    let (status, body) = json_of(
        &app,
        Method::PUT,
        "/drawings/d1",
        "u1",
        Some(json!({"name": "Renamed"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["version"], 2,
        "metadata-only updates do not bump the version"
    );
    let count: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM "DrawingSnapshot""#)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn concurrent_saves_with_same_version_have_one_winner(pool: PgPool) {
    people(&pool).await;
    seed_drawing(&pool, "d1", "u1", None).await;
    let app = spawn_app(pool.clone()).await;
    let a = app
        .as_user(Method::PUT, "/drawings/d1", "u1")
        .await
        .json(&json!({"elements": [{"id": "a"}], "version": 1}));
    let b = app
        .as_user(Method::PUT, "/drawings/d1", "u1")
        .await
        .json(&json!({"elements": [{"id": "b"}], "version": 1}));
    let (ra, rb) = tokio::join!(a.send(), b.send());
    let mut statuses = vec![ra.unwrap().status().as_u16(), rb.unwrap().status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, vec![200, 409]);
    let snapshots: i64 = sqlx::query_scalar(r#"SELECT COUNT(*) FROM "DrawingSnapshot""#)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(snapshots, 1, "the loser's snapshot is rolled back");
    let version: i32 = sqlx::query_scalar(r#"SELECT version FROM "Drawing" WHERE id = 'd1'"#)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 2);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn files_merge_and_blank_entries_never_clobber(pool: PgPool) {
    people(&pool).await;
    seed_drawing(&pool, "d1", "u1", None).await;
    let app = spawn_app(pool).await;
    let (_, body) = json_of(
        &app,
        Method::PUT,
        "/drawings/d1",
        "u1",
        Some(json!({"files": {"f1": {"dataURL": PNG}}})),
    )
    .await;
    assert_eq!(body["files"]["f1"]["dataURL"], "/api/files/d1/f1");
    let (_, body) = json_of(&app, Method::PUT, "/drawings/d1", "u1",
        Some(json!({"files": {"f1": {"dataURL": ""}, "f2": {"dataURL": "https://cdn.example/x.png"}}}))).await;
    assert_eq!(body["files"]["f1"]["dataURL"], "/api/files/d1/f1");
    assert_eq!(body["files"]["f2"]["dataURL"], "https://cdn.example/x.png");
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn permissions_on_update(pool: PgPool) {
    people(&pool).await;
    seed_drawing(&pool, "d1", "u1", None).await;
    seed_drawing_permission(&pool, "d1", "u2", "edit").await;
    seed_drawing_permission(&pool, "d1", "u3", "view").await;
    let app = spawn_app(pool).await;
    let (status, _) = json_of(
        &app,
        Method::PUT,
        "/drawings/d1",
        "u3",
        Some(json!({"name": "x"})),
    )
    .await;
    assert_eq!(status, 404, "view-only cannot write");
    let (status, _) = json_of(
        &app,
        Method::PUT,
        "/drawings/d1",
        "u2",
        Some(json!({"elements": []})),
    )
    .await;
    assert_eq!(status, 200);
    let (status, body) = json_of(
        &app,
        Method::PUT,
        "/drawings/d1",
        "u2",
        Some(json!({"collectionId": null})),
    )
    .await;
    assert_eq!(
        (status, body),
        (
            403,
            json!({"error": "Forbidden", "message": "Only the owner can move drawings between collections"})
        )
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn duplicate_copies_files_and_delete_removes_them(pool: PgPool) {
    people(&pool).await;
    let app = spawn_app(pool.clone()).await;
    let (_, created) = json_of(
        &app,
        Method::POST,
        "/drawings",
        "u1",
        Some(json!({"name": "Orig", "files": {"f1": {"dataURL": PNG}}})),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    let (status, copy) = json_of(
        &app,
        Method::POST,
        &format!("/drawings/{id}/duplicate"),
        "u1",
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(copy["name"], "Orig (Copy)");
    let copy_id = copy["id"].as_str().unwrap().to_string();
    assert_eq!(
        copy["files"]["f1"]["dataURL"],
        format!("/api/files/{copy_id}/f1")
    );

    let (status, body) =
        json_of(&app, Method::DELETE, &format!("/drawings/{id}"), "u2", None).await;
    assert_eq!((status, body), (404, json!({"error": "Drawing not found"})));
    let (status, body) =
        json_of(&app, Method::DELETE, &format!("/drawings/{id}"), "u1", None).await;
    assert_eq!((status, body), (200, json!({"success": true})));
    let left: Vec<String> = sqlx::query_scalar(r#"SELECT "drawingId" FROM "DrawingFile""#)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(left, vec![copy_id]);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn preview_is_etag_cached(pool: PgPool) {
    people(&pool).await;
    seed_drawing(&pool, "d1", "u1", None).await;
    let app = spawn_app(pool).await;
    let res = app
        .as_user(Method::GET, "/drawings/d1/preview", "u1")
        .await
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let etag = res.headers()["etag"].to_str().unwrap().to_string();
    assert!(etag.starts_with("W/\"preview-d1-"), "{etag}");
    assert_eq!(
        res.headers()["cache-control"],
        "private, max-age=0, must-revalidate"
    );
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["preview"], Value::Null);
    assert!(body["updatedAt"].is_i64());
    let res = app
        .as_user(Method::GET, "/drawings/d1/preview", "u1")
        .await
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 304);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn invalid_token_with_refresh_cookie_gets_401_not_404(pool: PgPool) {
    people(&pool).await;
    seed_drawing(&pool, "d1", "u1", None).await;
    let app = spawn_app(pool).await;
    let res = app
        .request(Method::GET, "/drawings/d1")
        .header("Cookie", "excalidash-refresh-token=whatever")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body,
        json!({"error": "Unauthorized", "message": "Invalid or expired token"})
    );
    let res = app
        .request(Method::GET, "/drawings/d1")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}
