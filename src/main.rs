use std::net::SocketAddr;

use anyhow::Context;
use tokio::net::TcpListener;
use totp_server::{AppConfig, AppState, build_router, crypto};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("keygen") => keygen(),
        Some("--version" | "-V") => {
            println!("totp-server {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("--help" | "-h") => {
            print_help();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n");
            print_help();
            std::process::exit(2);
        }
        None => serve().await,
    }
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .with(fmt::layer())
        .init();
}

async fn serve() -> anyhow::Result<()> {
    init_tracing();

    let cfg = AppConfig::load().context("failed to load configuration")?;
    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port)
        .parse()
        .context("invalid server host/port")?;

    let state = AppState::new(cfg)
        .await
        .context("failed to initialize application state")?;
    let app = build_router(state);

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    tracing::info!(%addr, "TOTP server listening (UI: /, docs: /docs, metrics: /metrics)");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server error")?;

    tracing::info!("shutdown complete");
    Ok(())
}

/// Resolve when either Ctrl-C or SIGTERM (container stop) is received.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl-C, shutting down"),
        _ = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}

fn keygen() -> anyhow::Result<()> {
    println!("# Add these to settings.toml under [security], or export as env vars.");
    println!("# Keep them secret and stable — rotating them invalidates stored data.");
    println!("secret_encryption_key = \"{}\"", crypto::generate_key_hex());
    println!("paseto_key            = \"{}\"", crypto::generate_key_hex());
    Ok(())
}

fn print_help() {
    println!(
        "totp-server {}\n\n\
         A hardened RFC 6238 TOTP two-factor-authentication server.\n\n\
         USAGE:\n    \
             totp-server            Run the HTTP server\n    \
             totp-server keygen     Generate encryption + session keys\n    \
             totp-server --version  Print version\n    \
             totp-server --help     Print this help\n\n\
         CONFIG:\n    \
             Reads settings.toml (override path with TOTP_CONFIG) and TOTP_*\n    \
             environment variables. See settings.example.toml.",
        env!("CARGO_PKG_VERSION")
    );
}
