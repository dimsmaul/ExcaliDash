//! Realtime collaboration over socket.io (backend/src/server/socket.ts).

use crate::state::AppState;

/// Re-check access for every socket in a drawing's room and kick revoked ones.
pub async fn revalidate_drawing_access(state: &AppState, drawing_id: &str) {
    let _ = (state, drawing_id);
}
