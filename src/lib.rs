//! A hardened TOTP (RFC 6238) two-factor-authentication server.
//!
//! The crate is split into focused modules so the security-critical pieces can
//! be unit-tested in isolation and reused by the integration test suite:
//!
//! - [`crypto`] — authenticated encryption of TOTP secrets at rest
//! - [`totp`] — RFC 6238 code generation/verification with a drift window
//! - [`tokens`] — PASETO v4.local session tokens
//! - [`recovery`] — one-time recovery codes (Argon2id at rest)
//! - [`ratelimit`] — failure lockout + fixed-window request limiting
//! - [`store`] — Postgres persistence with replay-safe atomic updates
//! - [`routes`] — the HTTP API surface

pub mod config;
pub mod crypto;
pub mod error;
pub mod extract;
pub mod metrics;
pub mod openapi;
pub mod ratelimit;
pub mod recovery;
pub mod routes;
pub mod state;
pub mod store;
pub mod tokens;
pub mod totp;

pub use config::AppConfig;
pub use routes::build_router;
pub use state::AppState;
