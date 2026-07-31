use jfr::{
    Config, Result,
    api::{AppState, router},
    auth::AuthService,
    metrics::Metrics,
    store::PgStore,
};
use secrecy::ExposeSecret;
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load()?;
    init_tracing(config.log_format);
    let store = PgStore::connect(&config).await?;
    store.migrate().await?;
    let auth = AuthService::new(store.clone(), config.api_key_pepper.clone());
    auth.bootstrap(
        &config.bootstrap_tenant,
        &config.bootstrap_key_name,
        config.bootstrap_api_key.expose_secret(),
    )
    .await?;
    let state = AppState {
        runtime: jfr::FiberRuntime::new(store),
        auth,
        metrics: Metrics::new(),
        max_request_bytes: config.max_request_bytes,
    };
    let app = router(state, &config)?;
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|error| jfr::JfrError::Internal(format!("bind failed: {error}")))?;
    tracing::info!(
        address = %config.bind,
        version = env!("CARGO_PKG_VERSION"),
        "Jacobian Fiber Runtime is ready"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| jfr::JfrError::Internal(format!("server failed: {error}")))
}

fn init_tracing(format: jfr::config::LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("jfr=info,tower_http=info"));
    let registry = tracing_subscriber::registry().with(filter);
    match format {
        jfr::config::LogFormat::Json => registry
            .with(tracing_subscriber::fmt::layer().json())
            .init(),
        jfr::config::LogFormat::Pretty => registry
            .with(tracing_subscriber::fmt::layer().pretty())
            .init(),
    }
}

async fn shutdown_signal() {
    let control_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = control_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
