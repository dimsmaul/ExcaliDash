mod common;

use std::time::Duration;

use common::{
    seed_drawing, seed_drawing_permission, seed_user, spawn_app, unreachable_pool, TestApp,
};
use excalidash_server::{auth::jwt, config::Config};
use futures_util::FutureExt;
use reqwest::Method;
use rust_socketio::{
    asynchronous::{Client, ClientBuilder},
    Payload,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

struct Peer {
    client: Client,
    events: UnboundedReceiver<(String, Value)>,
}

fn forward(tx: UnboundedSender<(String, Value)>, name: String, payload: Payload) {
    if let Payload::Text(values) = payload {
        let _ = tx.send((name, values.into_iter().next().unwrap_or(Value::Null)));
    }
}

async fn connect(app: &TestApp, user: Option<&str>) -> Peer {
    let (tx, events) = unbounded_channel();
    let (any_tx, err_tx) = (tx.clone(), tx);
    // rust_socketio's websocket transport fails its own handshake against a server that a
    // standard WebSocket client upgrades fine (verified with Node's WebSocket), so tests use
    // long-polling; the event protocol under test is identical on both transports.
    // Unlike socket.io-client, rust_socketio does not buffer emits until the namespace is
    // connected, so wait for the server's namespace CONNECT before handing the client out.
    let connected = std::sync::Arc::new(tokio::sync::Notify::new());
    let on_connect = connected.clone();
    let mut builder = ClientBuilder::new(app.base_url.clone())
        .transport_type(rust_socketio::TransportType::Polling)
        .on(rust_socketio::Event::Connect, move |_, _| {
            on_connect.notify_one();
            async {}.boxed()
        })
        .on_any(move |event, payload, _| {
            forward(any_tx.clone(), event.to_string(), payload);
            async {}.boxed()
        })
        .on("error", move |payload, _| {
            forward(err_tx.clone(), "error".into(), payload);
            async {}.boxed()
        });
    if let Some(user) = user {
        let token =
            jwt::issue_pair(&Config::for_tests(), user, &format!("{user}@example.com")).access;
        builder = builder.auth(json!({ "token": token }));
    }
    let client = builder.connect().await.expect("socket connects");
    tokio::time::timeout(Duration::from_secs(5), connected.notified())
        .await
        .expect("namespace connected");
    Peer { client, events }
}

impl Peer {
    async fn next(&mut self, name: &str) -> Value {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(left, self.events.recv()).await {
                Ok(Some((event, value))) if event == name => return value,
                Ok(Some(_)) => continue,
                _ => panic!("no `{name}` event received"),
            }
        }
    }

    async fn none(&mut self, name: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
        while let Ok(Some((event, value))) = tokio::time::timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            self.events.recv(),
        )
        .await
        {
            assert_ne!(event, name, "unexpected `{name}`: {value}");
        }
    }

    async fn join(&self, drawing: &str, name: &str) {
        self.client
            .emit("join-room", json!({"drawingId": drawing, "user": {"id": "spoofed", "name": name, "color": "#123456"}}))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn engine_io_payload_limit_matches_body_limit() {
    let app = spawn_app(unreachable_pool()).await;
    let open = app
        .request(Method::GET, "/socket.io/?EIO=4&transport=polling")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let handshake: Value = serde_json::from_str(open.trim_start_matches('0')).unwrap();
    assert_eq!(
        handshake["maxPayload"],
        Config::for_tests().body_limit_bytes,
        "scene deltas up to BODY_LIMIT_MB must fit (Node maxHttpBufferSize)"
    );
}

/// Anonymous sockets are only let in through an active link share (see
/// `anonymous_visitor_joins_through_an_edit_link`); without one they are refused.
#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn anonymous_socket_cannot_join_a_drawing(pool: PgPool) {
    setup(&pool).await;
    let app = spawn_app(pool).await;
    let mut peer = connect(&app, None).await;
    peer.join("d1", "Mallory").await;
    assert_eq!(
        peer.next("error").await,
        json!({"message": "You do not have access to this drawing"})
    );
}

async fn setup(pool: &PgPool) {
    seed_user(pool, "u1", "u1@example.com", "Alice", true).await;
    seed_user(pool, "u2", "u2@example.com", "Bob", true).await;
    seed_user(pool, "u3", "u3@example.com", "Carol", true).await;
    seed_drawing(pool, "d1", "u1", None).await;
    seed_drawing_permission(pool, "d1", "u2", "edit").await;
    seed_drawing_permission(pool, "d1", "u3", "view").await;
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn presence_cursor_and_element_relay(pool: PgPool) {
    setup(&pool).await;
    let app = spawn_app(pool).await;
    let mut alice = connect(&app, Some("u1")).await;
    let mut bob = connect(&app, Some("u2")).await;
    let mut carol = connect(&app, Some("u3")).await;

    alice.join("d1", "ignored").await;
    let presence = alice.next("presence-update").await;
    assert_eq!(
        presence[0]["id"], "u1",
        "identity comes from the server, not the client"
    );
    assert_eq!(presence[0]["name"], "Alice");
    assert_eq!(presence[0]["initials"], "AL");
    assert_eq!(presence[0]["color"], "#123456");
    assert_eq!(presence[0]["isActive"], true);

    // Each event runs as its own task (as in Node), so a peer's later events can overtake
    // its join; wait for each join to land, like the editor does before broadcasting.
    bob.join("d1", "Bob").await;
    bob.next("presence-update").await;
    carol.join("d1", "Carol").await;
    carol.next("presence-update").await;
    let presence = alice.next("presence-update").await;
    assert!(presence.as_array().unwrap().len() >= 2);

    bob.client
        .emit("cursor-move", json!({"drawingId": "d1", "pointer": {"x": 1, "y": 2}, "userId": "spoof", "username": "spoof"}))
        .await
        .unwrap();
    let cursor = alice.next("cursor-move").await;
    assert_eq!(cursor["userId"], "u2");
    assert_eq!(cursor["username"], "Bob");
    assert_eq!(cursor["pointer"], json!({"x": 1, "y": 2}));

    bob.client
        .emit(
            "element-update",
            json!({"drawingId": "d1", "elements": [{"id": "e1"}]}),
        )
        .await
        .unwrap();
    assert_eq!(
        alice.next("element-update").await["elements"],
        json!([{"id": "e1"}])
    );

    carol
        .client
        .emit(
            "element-update",
            json!({"drawingId": "d1", "elements": [{"id": "evil"}]}),
        )
        .await
        .unwrap();
    assert_eq!(
        carol.next("error").await,
        json!({"message": "Read-only access: cannot edit this drawing"})
    );
    alice.none("element-update").await;

    bob.client
        .emit(
            "user-activity",
            json!({"drawingId": "d1", "isActive": false}),
        )
        .await
        .unwrap();
    let presence = alice.next("presence-update").await;
    let bob_entry = presence
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == "u2")
        .unwrap()
        .clone();
    assert_eq!(bob_entry["isActive"], false);

    bob.client.disconnect().await.unwrap();
    let presence = alice.next("presence-update").await;
    assert!(presence.as_array().unwrap().iter().all(|u| u["id"] != "u2"));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn revoking_a_share_kicks_the_collaborator(pool: PgPool) {
    setup(&pool).await;
    let app = spawn_app(pool.clone()).await;
    let mut alice = connect(&app, Some("u1")).await;
    let mut bob = connect(&app, Some("u2")).await;
    alice.join("d1", "Alice").await;
    bob.join("d1", "Bob").await;
    alice.next("presence-update").await;

    let perm: String =
        sqlx::query_scalar(r#"SELECT id FROM "DrawingPermission" WHERE "granteeUserId" = 'u2'"#)
            .fetch_one(&pool)
            .await
            .unwrap();
    let res = app
        .as_user(
            Method::DELETE,
            &format!("/drawings/d1/permissions/{perm}"),
            "u1",
        )
        .await
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        bob.next("error").await,
        json!({"message": "Your access to this drawing was revoked"})
    );
    let _ = bob
        .client
        .emit("element-update", json!({"drawingId": "d1", "elements": []}))
        .await;
    alice.none("element-update").await;
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn scene_save_broadcasts_persisted_update(pool: PgPool) {
    setup(&pool).await;
    let app = spawn_app(pool).await;
    let mut bob = connect(&app, Some("u2")).await;
    bob.join("d1", "Bob").await;
    bob.next("presence-update").await;
    let res = app
        .as_user(Method::PUT, "/drawings/d1", "u1")
        .await
        .json(&json!({"elements": [{"id": "saved"}], "version": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let update = bob.next("element-update").await;
    assert_eq!(update["persisted"], true);
    assert_eq!(update["drawingId"], "d1");
    assert_eq!(update["elementOrder"], json!(["saved"]));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "needs postgres"]
async fn anonymous_visitor_joins_through_an_edit_link(pool: PgPool) {
    setup(&pool).await;
    sqlx::query(
        r#"INSERT INTO "DrawingLinkShare" (id, "drawingId", permission, "tokenHash", "createdByUserId", "updatedAt")
           VALUES ('ls1', 'd1', 'edit', 'hash', 'u1', timezone('utc', now()))"#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let app = spawn_app(pool).await;
    let mut alice = connect(&app, Some("u1")).await;
    alice.join("d1", "Alice").await;
    alice.next("presence-update").await;

    let mut guest = connect(&app, None).await;
    guest.join("d1", "Guest").await;
    let presence = guest.next("presence-update").await;
    let me = presence
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["name"] == "Guest")
        .unwrap()
        .clone();
    assert!(
        me["id"].as_str().unwrap().starts_with("anon:"),
        "anonymous identity is server-assigned"
    );

    guest
        .client
        .emit(
            "element-update",
            json!({"drawingId": "d1", "elements": [{"id": "g"}]}),
        )
        .await
        .unwrap();
    assert_eq!(
        alice.next("element-update").await["elements"],
        json!([{"id": "g"}])
    );
}
