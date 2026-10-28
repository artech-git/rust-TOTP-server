use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use totp_server::{AppConfig, AppState, build_router, crypto, crypto::KeyRing, store::Store};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("keygen") => keygen(),
        Some("migrate") => migrate().await,
        Some("rekey") => rekey().await,
        Some("healthcheck") => healthcheck().await,
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

/// Apply the embedded migrations and exit. Meant for a release-phase or
/// pre-deploy job when `database.run_migrations_on_start` is off.
async fn migrate() -> anyhow::Result<()> {
    init_tracing();
    let cfg = AppConfig::load().context("failed to load configuration")?;
    Store::migrate(&cfg.database)
        .await
        .context("failed to apply migrations")?;
    tracing::info!("migrations applied; schema is current");
    Ok(())
}

/// Re-seal every stored TOTP secret with the active encryption key, so a
/// retired key can be removed from the configuration.
async fn rekey() -> anyhow::Result<()> {
    init_tracing();
    let cfg = AppConfig::load().context("failed to load configuration")?;
    let active = cfg
        .security
        .secret_encryption_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .context("security.secret_encryption_key must be set to rekey")?;
    let keys = KeyRing::new(active, &cfg.security.retired_encryption_keys)
        .context("invalid encryption keys")?;
    let store = Store::connect(&cfg.database).await?;
    let report = totp_server::ops::rekey_all(&store, &keys).await?;
    tracing::info!(
        examined = report.examined,
        resealed = report.resealed,
        skipped = report.skipped,
        "rekey complete"
    );
    Ok(())
}

/// Probe the running server's `/livez` (for the container HEALTHCHECK, which
/// has no curl). Exits non-zero unless it answers 200.
async fn healthcheck() -> anyhow::Result<()> {
    let cfg = AppConfig::load().context("failed to load configuration")?;
    let host = match cfg.server.host.as_str() {
        "0.0.0.0" | "::" | "[::]" => "127.0.0.1",
        host => host,
    };
    let addr = format!("{host}:{}", cfg.server.port);
    let timeout = Duration::from_secs(3);

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .with_context(|| format!("timed out connecting to {addr}"))?
        .with_context(|| format!("failed to connect to {addr}"))?;
    stream
        .write_all(
            format!("GET /livez HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    tokio::time::timeout(timeout, stream.read_to_end(&mut response))
        .await
        .context("timed out waiting for the response")??;

    let status_line = response
        .split(|&b| b == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_string())
        .unwrap_or_default();
    anyhow::ensure!(status_line.contains(" 200 "), "unhealthy: {status_line:?}");
    println!("ok: {status_line}");
    Ok(())
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
             totp-server              Run the HTTP server\n    \
             totp-server migrate      Apply database migrations and exit\n    \
             totp-server rekey        Re-seal stored secrets with the active encryption key\n    \
             totp-server healthcheck  Probe the running server's /livez (exit 0 = healthy)\n    \
             totp-server keygen       Generate encryption + session keys\n    \
             totp-server --version    Print version\n    \
             totp-server --help       Print this help\n\n\
         CONFIG:\n    \
             Reads settings.toml (override path with TOTP_CONFIG) and TOTP_*\n    \
             environment variables. See settings.example.toml.",
        env!("CARGO_PKG_VERSION")
    );
}
