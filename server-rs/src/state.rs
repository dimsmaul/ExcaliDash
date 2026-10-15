use std::sync::Arc;

use socketioxide::SocketIo;
use sqlx::PgPool;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cfg: Arc<Config>,
    pub io: SocketIo,
}
