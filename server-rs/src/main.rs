use excalidash_server::{build_app, config::Config, routes::history::delete_old_snapshots};
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = Config::from_env()?;
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect_lazy(&cfg.database_url)?;
    sqlx::migrate!("./migrations").run(&db).await?;

    spawn_snapshot_cleanup(db.clone(), cfg.snapshot_retention);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, auth_mode = ?cfg.auth_mode, "server listening");

    axum::serve(listener, build_app(db.clone(), cfg))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    db.close().await;
    Ok(())
}

/// Hourly deletion of snapshots older than `SNAPSHOT_RETENTION_DAYS` (Node's setInterval job).
fn spawn_snapshot_cleanup(db: sqlx::PgPool, retention: std::time::Duration) {
    const HOUR: std::time::Duration = std::time::Duration::from_secs(3600);
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + HOUR, HOUR);
        loop {
            ticks.tick().await;
            match delete_old_snapshots(&db, retention).await {
                Ok(0) => {}
                Ok(count) => tracing::info!(count, "deleted old drawing snapshots"),
                Err(err) => tracing::error!(%err, "snapshot cleanup failed"),
            }
        }
    });
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}
