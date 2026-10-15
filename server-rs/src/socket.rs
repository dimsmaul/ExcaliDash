//! Realtime collaboration over socket.io (backend/src/server/socket.ts, socketAccess.ts).
//!
//! The server only relays scene deltas between room members; persistence goes through
//! the HTTP save path. Every mutation re-checks edit access against the database.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::{json, Value};
use socketioxide::{
    extract::{AckSender, SocketRef, TryData},
    socket::Sid,
};

use crate::{
    auth::{
        cookies::{read_cookie, ACCESS_TOKEN_COOKIE},
        jwt,
        middleware::BOOTSTRAP_USER_ID,
    },
    authz::{drawing_access, Access},
    config::AuthMode,
    state::AppState,
};

const ACCESS_CACHE_TTL: Duration = Duration::from_millis(1500);

/// Per-socket state (Node keeps it on `socket.data`).
#[derive(Default)]
struct SocketState {
    principal: Option<String>,
    access: HashMap<String, (Access, Instant)>,
    joined: HashSet<String>,
}

/// Room presence and per-socket state for this process.
#[derive(Default)]
pub struct Collab {
    rooms: Mutex<HashMap<String, Vec<PresenceUser>>>,
    sockets: Mutex<HashMap<Sid, SocketState>>,
}

fn room_of(drawing_id: &str) -> String {
    format!("drawing_{drawing_id}")
}

/// Registers the default namespace handlers.
pub fn register(state: &AppState) {
    let state = state.clone();
    state
        .io
        .clone()
        .ns("/", move |s: SocketRef, TryData(auth): TryData<Value>| {
            let state = state.clone();
            async move { on_connect(state, s, auth.ok()).await }
        });
}

async fn resolve_principal(state: &AppState, token: Option<String>) -> Option<String> {
    if state.cfg.auth_mode == AuthMode::Disabled {
        return Some(BOOTSTRAP_USER_ID.to_string());
    }
    let claims = jwt::verify_access(&state.cfg, &token?)?;
    let active: Option<bool> = sqlx::query_scalar(r#"SELECT "isActive" FROM "User" WHERE id = $1"#)
        .bind(&claims.user_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    (active == Some(true)).then_some(claims.user_id)
}

async fn on_connect(state: AppState, s: SocketRef, auth: Option<Value>) {
    let token = auth
        .as_ref()
        .and_then(|a| a.get("token"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| read_cookie(&s.req_parts().headers, ACCESS_TOKEN_COOKIE));
    let principal = resolve_principal(&state, token).await;
    state.collab.sockets.lock().unwrap().insert(
        s.id,
        SocketState {
            principal,
            ..Default::default()
        },
    );

    let st = state.clone();
    s.on(
        "join-room",
        move |s: SocketRef, TryData(data): TryData<Value>, ack: AckSender| {
            let state = st.clone();
            async move { join_room(&state, &s, data.unwrap_or_default(), ack).await }
        },
    );
    let st = state.clone();
    s.on(
        "cursor-move",
        move |s: SocketRef, TryData(data): TryData<Value>| {
            let state = st.clone();
            async move { cursor_move(&state, &s, data.unwrap_or_default()).await }
        },
    );
    let st = state.clone();
    s.on(
        "element-update",
        move |s: SocketRef, TryData(data): TryData<Value>| {
            let state = st.clone();
            async move { element_update(&state, &s, data.unwrap_or_default()).await }
        },
    );
    let st = state.clone();
    s.on(
        "user-activity",
        move |s: SocketRef, TryData(data): TryData<Value>| {
            let state = st.clone();
            async move { user_activity(&state, &s, data.unwrap_or_default()).await }
        },
    );
    let st = state.clone();
    s.on_disconnect(move |s: SocketRef| {
        let state = st.clone();
        async move { on_disconnect(&state, &s).await }
    });
}

fn principal_of(state: &AppState, sid: Sid) -> Option<String> {
    state
        .collab
        .sockets
        .lock()
        .unwrap()
        .get(&sid)
        .and_then(|st| st.principal.clone())
}

fn has_joined_access(state: &AppState, sid: Sid, drawing_id: &str) -> bool {
    state
        .collab
        .sockets
        .lock()
        .unwrap()
        .get(&sid)
        .is_some_and(|st| st.access.contains_key(drawing_id))
}

fn remember_access(state: &AppState, sid: Sid, drawing_id: &str, access: Option<Access>) {
    if let Some(st) = state.collab.sockets.lock().unwrap().get_mut(&sid) {
        match access {
            Some(a) => {
                st.access
                    .insert(drawing_id.to_string(), (a, Instant::now()));
            }
            None => {
                st.access.remove(drawing_id);
            }
        }
    }
}

/// Fresh database check, remembered for the socket.
async fn fresh_access(
    state: &AppState,
    sid: Sid,
    drawing_id: &str,
) -> Result<Option<Access>, sqlx::Error> {
    let principal = principal_of(state, sid);
    let access = drawing_access(&state.db, principal.as_deref(), drawing_id).await;
    match &access {
        Ok(a) => remember_access(state, sid, drawing_id, *a),
        Err(_) => remember_access(state, sid, drawing_id, None),
    }
    access
}

/// Node `getCachedOrFreshAccess` (1.5 s TTL).
async fn cached_or_fresh_access(
    state: &AppState,
    sid: Sid,
    drawing_id: &str,
) -> Result<Option<Access>, sqlx::Error> {
    let cached = state
        .collab
        .sockets
        .lock()
        .unwrap()
        .get(&sid)
        .and_then(|st| st.access.get(drawing_id).copied())
        .filter(|(_, at)| at.elapsed() < ACCESS_CACHE_TTL)
        .map(|(a, _)| a);
    match cached {
        Some(a) => Ok(Some(a)),
        None => fresh_access(state, sid, drawing_id).await,
    }
}

async fn emit_presence(state: &AppState, room: &str) {
    let users = state
        .collab
        .rooms
        .lock()
        .unwrap()
        .get(room)
        .cloned()
        .unwrap_or_default();
    if let Some(ns) = state.io.of("/") {
        let _ = ns
            .to(room.to_string())
            .emit("presence-update", &users)
            .await;
    }
}

/// Drop this socket's presence from a drawing it can no longer access.
async fn drop_drawing_access(state: &AppState, s: &SocketRef, drawing_id: &str) {
    let room = room_of(drawing_id);
    let changed = remove_socket_from_rooms(
        &mut state.collab.rooms.lock().unwrap(),
        std::slice::from_ref(&room),
        &s.id.to_string(),
    );
    for changed_room in changed {
        emit_presence(state, &changed_room).await;
    }
    if let Some(st) = state.collab.sockets.lock().unwrap().get_mut(&s.id) {
        st.joined.remove(&room);
    }
    s.leave(room);
}

fn drawing_id_of(data: &Value) -> Option<String> {
    data.get("drawingId")
        .and_then(Value::as_str)
        .map(str::to_string)
}

async fn join_room(state: &AppState, s: &SocketRef, data: Value, ack: AckSender) {
    let drawing_id = drawing_id_of(&data).unwrap_or_default();
    let access = match cached_or_fresh_access(state, s.id, &drawing_id).await {
        Ok(access) => access,
        Err(err) => {
            tracing::error!(%err, "join-room access check failed");
            let _ = s.emit("error", &json!({ "message": "Failed to join room" }));
            return;
        }
    };
    if access.is_none() {
        let _ = s.emit(
            "error",
            &json!({ "message": "You do not have access to this drawing" }),
        );
        return;
    }
    let room = room_of(&drawing_id);
    s.join(room.clone());
    let sid = s.id.to_string();
    let client_user = data.get("user");
    let mut name = presence_name(client_user.and_then(|u| u.get("name")));
    let mut id = format!("anon:{sid}");
    if let Some(user_id) = principal_of(state, s.id).filter(|p| p != BOOTSTRAP_USER_ID) {
        let account: Option<String> =
            sqlx::query_scalar(r#"SELECT name FROM "User" WHERE id = $1"#)
                .bind(&user_id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        if let Some(account_name) = account {
            id = user_id;
            name = presence_name(Some(&Value::String(account_name)));
        }
    }
    let user = PresenceUser {
        initials: presence_initials(&name),
        color: presence_color(client_user.and_then(|u| u.get("color"))),
        id,
        name,
        socket_id: sid.clone(),
        is_active: true,
    };
    {
        let mut rooms = state.collab.rooms.lock().unwrap();
        let users = rooms.entry(room.clone()).or_default();
        users.retain(|u| u.socket_id != sid);
        users.push(user.clone());
    }
    if let Some(st) = state.collab.sockets.lock().unwrap().get_mut(&s.id) {
        st.joined.insert(room.clone());
    }
    emit_presence(state, &room).await;
    let _ = ack.send(&json!({
        "user": { "id": user.id, "name": user.name, "initials": user.initials, "color": user.color }
    }));
}

fn self_presence(state: &AppState, room: &str, sid: &str) -> Option<PresenceUser> {
    state
        .collab
        .rooms
        .lock()
        .unwrap()
        .get(room)
        .and_then(|users| users.iter().find(|u| u.socket_id == sid).cloned())
}

async fn cursor_move(state: &AppState, s: &SocketRef, data: Value) {
    let Some(drawing_id) = drawing_id_of(&data) else {
        return;
    };
    if !has_joined_access(state, s.id, &drawing_id) {
        return;
    }
    if !matches!(
        cached_or_fresh_access(state, s.id, &drawing_id).await,
        Ok(Some(_))
    ) {
        drop_drawing_access(state, s, &drawing_id).await;
        return;
    }
    let room = room_of(&drawing_id);
    let Some(me) = self_presence(state, &room, &s.id.to_string()) else {
        return;
    };
    let mut payload = data.as_object().cloned().unwrap_or_default();
    payload.insert("drawingId".into(), drawing_id.into());
    payload.insert("userId".into(), me.id.into());
    payload.insert("username".into(), me.name.into());
    payload.insert("color".into(), me.color.into());
    let _ = s
        .to(room)
        .emit("cursor-move", &Value::Object(payload))
        .await;
}

async fn element_update(state: &AppState, s: &SocketRef, data: Value) {
    let Some(drawing_id) = drawing_id_of(&data) else {
        return;
    };
    if !has_joined_access(state, s.id, &drawing_id) {
        return;
    }
    // Mutations always re-check (no TTL cache) so a revoked editor cannot keep writing.
    let access = match fresh_access(state, s.id, &drawing_id).await {
        Ok(access) => access,
        Err(err) => {
            tracing::error!(%err, "failed to revalidate socket edit access");
            return;
        }
    };
    match access {
        None => drop_drawing_access(state, s, &drawing_id).await,
        Some(a) if !a.can_edit() => {
            let _ = s.emit(
                "error",
                &json!({ "message": "Read-only access: cannot edit this drawing" }),
            );
        }
        Some(_) => {
            let _ = s
                .to(room_of(&drawing_id))
                .emit("element-update", &data)
                .await;
        }
    }
}

async fn user_activity(state: &AppState, s: &SocketRef, data: Value) {
    let Some(drawing_id) = drawing_id_of(&data) else {
        return;
    };
    if !has_joined_access(state, s.id, &drawing_id) {
        return;
    }
    if !matches!(
        cached_or_fresh_access(state, s.id, &drawing_id).await,
        Ok(Some(_))
    ) {
        drop_drawing_access(state, s, &drawing_id).await;
        return;
    }
    let room = room_of(&drawing_id);
    let sid = s.id.to_string();
    let found = {
        let mut rooms = state.collab.rooms.lock().unwrap();
        rooms
            .get_mut(&room)
            .and_then(|users| users.iter_mut().find(|u| u.socket_id == sid))
            .map(|user| {
                user.is_active = data
                    .get("isActive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .is_some()
    };
    if found {
        emit_presence(state, &room).await;
    }
}

async fn on_disconnect(state: &AppState, s: &SocketRef) {
    let joined: Vec<String> = state
        .collab
        .sockets
        .lock()
        .unwrap()
        .remove(&s.id)
        .map(|st| st.joined.into_iter().collect())
        .unwrap_or_default();
    let changed = remove_socket_from_rooms(
        &mut state.collab.rooms.lock().unwrap(),
        &joined,
        &s.id.to_string(),
    );
    for room in changed {
        emit_presence(state, &room).await;
    }
}

/// One participant in a drawing room (keyed per socket, not per user).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceUser {
    pub id: String,
    pub name: String,
    pub initials: String,
    pub color: String,
    pub socket_id: String,
    pub is_active: bool,
}

/// Node `toPresenceName`: trimmed, ≤120 chars, "User" when empty or not a string.
pub fn presence_name(value: Option<&Value>) -> String {
    let name: String = value
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .chars()
        .take(120)
        .collect();
    if name.is_empty() {
        "User".into()
    } else {
        name
    }
}

/// Node `toPresenceInitials`.
pub fn presence_initials(name: &str) -> String {
    let trimmed = name.trim();
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    let initials: String = match parts.as_slice() {
        [] => return "U".into(),
        [first, .., last] => first.chars().take(1).chain(last.chars().take(1)).collect(),
        [only] => only.chars().take(2).collect(),
    };
    initials.to_uppercase()
}

/// Node `toPresenceColor`: `#hex` (3-8 digits) or the default indigo.
pub fn presence_color(value: Option<&Value>) -> String {
    let candidate = value.and_then(Value::as_str).unwrap_or_default().trim();
    let is_hex = candidate.strip_prefix('#').is_some_and(|hex| {
        (3..=8).contains(&hex.len()) && hex.bytes().all(|b| b.is_ascii_hexdigit())
    });
    if is_hex {
        candidate.to_string()
    } else {
        "#4f46e5".into()
    }
}

/// Node `removeSocketFromRooms`: drop the socket from each room (deleting empty
/// rooms) and return the rooms whose membership changed.
pub fn remove_socket_from_rooms(
    rooms: &mut HashMap<String, Vec<PresenceUser>>,
    room_ids: &[String],
    socket_id: &str,
) -> Vec<String> {
    let mut changed = Vec::new();
    for room_id in room_ids {
        let Some(users) = rooms.get_mut(room_id) else {
            continue;
        };
        let before = users.len();
        users.retain(|u| u.socket_id != socket_id);
        if users.len() == before {
            continue;
        }
        if users.is_empty() {
            rooms.remove(room_id);
        }
        changed.push(room_id.clone());
    }
    changed
}

/// Node `revalidateRoomSockets`: re-check every socket in the drawing's room and
/// disconnect the ones that lost access.
pub async fn revalidate_drawing_access(state: &AppState, drawing_id: &str) {
    let Some(ns) = state.io.of("/") else {
        return;
    };
    let room = room_of(drawing_id);
    for socket in ns.within(room.clone()).sockets() {
        let access = fresh_access(state, socket.id, drawing_id)
            .await
            .unwrap_or_else(|err| {
                tracing::error!(%err, "failed to revalidate drawing socket access");
                None
            });
        if access.is_some() {
            continue;
        }
        let changed = remove_socket_from_rooms(
            &mut state.collab.rooms.lock().unwrap(),
            std::slice::from_ref(&room),
            &socket.id.to_string(),
        );
        for changed_room in changed {
            emit_presence(state, &changed_room).await;
        }
        if let Some(st) = state.collab.sockets.lock().unwrap().get_mut(&socket.id) {
            st.joined.remove(&room);
        }
        let _ = socket.emit(
            "error",
            &json!({ "message": "Your access to this drawing was revoked" }),
        );
        let _ = socket.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn user(socket: &str) -> PresenceUser {
        PresenceUser {
            id: format!("id-{socket}"),
            name: "N".into(),
            initials: "N".into(),
            color: "#000".into(),
            socket_id: socket.into(),
            is_active: true,
        }
    }

    #[test]
    fn names() {
        assert_eq!(presence_name(Some(&json!("  Alice  "))), "Alice");
        assert_eq!(presence_name(Some(&json!("   "))), "User");
        assert_eq!(presence_name(Some(&json!(5))), "User");
        assert_eq!(presence_name(None), "User");
        assert_eq!(presence_name(Some(&json!("x".repeat(200)))).len(), 120);
    }

    #[test]
    fn initials() {
        assert_eq!(presence_initials("Alice Example Smith"), "AS");
        assert_eq!(presence_initials("bob"), "BO");
        assert_eq!(presence_initials(" "), "U");
        assert_eq!(presence_initials("é"), "É");
    }

    #[test]
    fn colors() {
        assert_eq!(presence_color(Some(&json!("#a1B2c3"))), "#a1B2c3");
        assert_eq!(presence_color(Some(&json!(" #fff "))), "#fff");
        assert_eq!(presence_color(Some(&json!("red"))), "#4f46e5");
        assert_eq!(presence_color(Some(&json!("#12"))), "#4f46e5");
        assert_eq!(presence_color(None), "#4f46e5");
    }

    #[test]
    fn removing_sockets_prunes_empty_rooms() {
        let mut rooms = HashMap::from([
            ("r1".to_string(), vec![user("a"), user("b")]),
            ("r2".to_string(), vec![user("a")]),
            ("r3".to_string(), vec![user("c")]),
        ]);
        let mut changed = remove_socket_from_rooms(
            &mut rooms,
            &["r1".into(), "r2".into(), "r3".into(), "missing".into()],
            "a",
        );
        changed.sort();
        assert_eq!(changed, vec!["r1", "r2"]);
        assert_eq!(rooms["r1"], vec![user("b")]);
        assert!(!rooms.contains_key("r2"));
        assert_eq!(rooms["r3"], vec![user("c")]);
    }
}
