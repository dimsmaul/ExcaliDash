mod common;

use common::{
    seed_collection, seed_collection_share, seed_drawing, seed_drawing_permission, seed_user,
    spawn_app, unreachable_pool,
};
use excalidash_server::authz::{self, Access};
use reqwest::Method;
use serde_json::{json, Value};
use sqlx::PgPool;

#[tokio::test]
async fn collections_require_auth() {
    let app = spawn_app(unreachable_pool()).await;
    let res = app
        .request(Method::GET, "/collections")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

async fn seed_people(pool: &PgPool) {
    seed_user(pool, "u1", "u1@example.com", "Alice", true).await;
    seed_user(pool, "u2", "u2@example.com", "Bob", true).await;
    seed_user(pool, "u3", "u3@example.com", "Carol", true).await;
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn drawing_access_rules(pool: PgPool) {
    seed_people(&pool).await;
    seed_collection(&pool, "c1", "u1", "Shared").await;
    seed_drawing(&pool, "d1", "u1", Some("c1")).await;
    seed_drawing_permission(&pool, "d1", "u2", "view").await;
    seed_collection_share(&pool, "c1", "u2", "edit").await;
    seed_collection(&pool, "c3", "u3", "Carol's").await;
    seed_drawing(&pool, "d3", "u1", Some("c3")).await;

    let access = |user: &'static str, drawing: &'static str| {
        let pool = pool.clone();
        async move {
            authz::drawing_access(&pool, Some(user), drawing)
                .await
                .unwrap()
        }
    };
    assert_eq!(access("u1", "d1").await, Some(Access::Owner));
    assert_eq!(access("u2", "d1").await, Some(Access::Edit));
    assert_eq!(access("u3", "d1").await, None);
    assert_eq!(
        access("u3", "d3").await,
        Some(Access::Owner),
        "owns the collection"
    );
    assert_eq!(access("u1", "missing").await, None);
    assert_eq!(
        authz::drawing_access(&pool, None, "d1").await.unwrap(),
        None
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn list_includes_trash_owned_and_shared(pool: PgPool) {
    seed_people(&pool).await;
    seed_collection(&pool, "mine", "u1", "Mine").await;
    seed_collection(&pool, "theirs", "u2", "Theirs").await;
    seed_collection_share(&pool, "theirs", "u1", "view").await;
    seed_collection_share(&pool, "mine", "u3", "edit").await;
    let app = spawn_app(pool).await;

    let res = app
        .as_user(Method::GET, "/collections", "u1")
        .await
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let list: Vec<Value> = res.json().await.unwrap();
    let find = |id: &str| list.iter().find(|c| c["id"] == id).unwrap().clone();

    let trash = find("trash");
    assert_eq!(trash["name"], "Trash");
    assert_eq!(trash["isOwner"], true);
    assert_eq!(trash["isShared"], false);
    let mine = find("mine");
    assert_eq!(mine["isShared"], true);
    assert_eq!(mine["sharedRole"], Value::Null);
    assert_eq!(mine["userId"], "u1");
    let theirs = find("theirs");
    assert_eq!(theirs["isOwner"], false);
    assert_eq!(theirs["sharedRole"], "view");
    assert_eq!(
        theirs["user"],
        json!({"id": "u2", "name": "Bob", "email": "u2@example.com"})
    );
    assert!(theirs.get("isShared").is_none());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn create_rename_delete_collection(pool: PgPool) {
    seed_people(&pool).await;
    let app = spawn_app(pool.clone()).await;

    let res = app
        .as_user(Method::POST, "/collections", "u1")
        .await
        .json(&json!({"name": "  <b>Plans</b><script>x</script> "}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let created: Value = res.json().await.unwrap();
    assert_eq!(created["name"], "<b>Plans</b>");
    assert_eq!(created["isOwner"], true);
    assert_eq!(created["sharedRole"], Value::Null);
    let id = created["id"].as_str().unwrap().to_string();

    for bad in [
        json!({"name": "   "}),
        json!({"name": "x".repeat(101)}),
        json!({}),
    ] {
        let res = app
            .as_user(Method::POST, "/collections", "u1")
            .await
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400);
        let body: Value = res.json().await.unwrap();
        assert_eq!(
            body,
            json!({"error": "Validation error", "message": "Collection name must be between 1 and 100 characters"})
        );
    }

    let res = app
        .as_user(Method::PUT, &format!("/collections/{id}"), "u1")
        .await
        .json(&json!({"name": "Renamed"}))
        .send()
        .await
        .unwrap();
    let renamed: Value = res.json().await.unwrap();
    assert_eq!(renamed["name"], "Renamed");

    let res = app
        .as_user(Method::PUT, &format!("/collections/{id}"), "u2")
        .await
        .json(&json!({"name": "Hijack"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"error": "Collection not found"}));

    seed_drawing(&pool, "d1", "u1", Some(&id)).await;
    let res = app
        .as_user(Method::DELETE, &format!("/collections/{id}"), "u1")
        .await
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, json!({"success": true}));
    let collection: Option<String> =
        sqlx::query_scalar(r#"SELECT "collectionId" FROM "Drawing" WHERE id = 'd1'"#)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(collection, None);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn trash_cannot_be_renamed_or_deleted(pool: PgPool) {
    seed_people(&pool).await;
    let app = spawn_app(pool).await;
    for (method, message) in [
        (Method::PUT, "Trash collection cannot be renamed"),
        (Method::DELETE, "Trash collection cannot be deleted"),
    ] {
        let res = app
            .as_user(method, "/collections/trash", "u1")
            .await
            .json(&json!({"name": "x"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400);
        let body: Value = res.json().await.unwrap();
        assert_eq!(
            body,
            json!({"error": "Validation error", "message": message})
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn collection_sharing_flow(pool: PgPool) {
    seed_people(&pool).await;
    seed_collection(&pool, "c1", "u1", "Team").await;
    let app = spawn_app(pool).await;
    let url = "/collections/c1/shares";

    let res = app
        .as_user(Method::POST, url, "u1")
        .await
        .json(&json!({"identifier": "U2@Example.com", "role": "view"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["share"]["role"], "view");
    assert_eq!(
        body["share"]["granteeUser"],
        json!({"id": "u2", "name": "Bob", "email": "u2@example.com"})
    );

    for (payload, status, error) in [
        (
            json!({"identifier": "u2@example.com", "role": "owner"}),
            400,
            "identifier and role (view|edit) are required",
        ),
        (
            json!({"identifier": "nobody@example.com", "role": "view"}),
            404,
            "User not found",
        ),
        (
            json!({"identifier": "u1@example.com", "role": "view"}),
            400,
            "Cannot share with yourself",
        ),
    ] {
        let res = app
            .as_user(Method::POST, url, "u1")
            .await
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), status);
        let body: Value = res.json().await.unwrap();
        assert_eq!(body, json!({ "error": error }));
    }

    let res = app
        .as_user(Method::PATCH, "/collections/c1/shares/u2", "u1")
        .await
        .json(&json!({"role": "edit"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.json::<Value>().await.unwrap(), json!({"success": true}));

    let res = app
        .as_user(Method::GET, url, "u1")
        .await
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["shares"][0]["role"], "edit");
    assert_eq!(body["shares"][0]["granteeUserId"], "u2");

    let res = app
        .as_user(Method::GET, "/collections/c1/share-resolve?q=example", "u1")
        .await
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(
        body["users"],
        json!([{"id": "u3", "name": "Carol", "email": "u3@example.com"}])
    );

    let res = app
        .as_user(Method::GET, "/collections/c1/share-resolve?q=e", "u1")
        .await
        .send()
        .await
        .unwrap();
    assert_eq!(res.json::<Value>().await.unwrap(), json!({"users": []}));

    let res = app
        .as_user(Method::GET, url, "u2")
        .await
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404, "only the owner manages shares");

    let res = app
        .as_user(Method::DELETE, "/collections/c1/shares/u2", "u1")
        .await
        .send()
        .await
        .unwrap();
    assert_eq!(res.json::<Value>().await.unwrap(), json!({"success": true}));
    let res = app
        .as_user(Method::PATCH, "/collections/c1/shares/u2", "u1")
        .await
        .json(&json!({"role": "view"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(
        res.json::<Value>().await.unwrap(),
        json!({"error": "Share not found"})
    );
}
