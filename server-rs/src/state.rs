use std::sync::Arc;

use socketioxide::SocketIo;
use sqlx::PgPool;
use tokio::sync::OnceCell;

use crate::{auth::oidc::Discovery, config::Config, socket::Collab};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cfg: Arc<Config>,
    pub io: SocketIo,
    pub http: reqwest::Client,
    /// Provider metadata, fetched on first use and kept for the process lifetime.
    pub oidc_discovery: Arc<OnceCell<Discovery>>,
    /// Realtime room presence and per-socket state.
    pub collab: Arc<Collab>,
}
