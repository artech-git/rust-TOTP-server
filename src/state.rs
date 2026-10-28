use std::sync::Arc;
use std::time::Duration;

use metrics_exporter_prometheus::PrometheusHandle;
use tokio::sync::Semaphore;

use crate::{
    config::{AppConfig, RateLimitBackendKind},
    crypto::KeyRing,
    ratelimit::{FailureLimiter, MemoryBackend, PostgresBackend, RateLimitBackend, WindowLimiter},
    recovery::RecoveryHasher,
    store::Store,
    tokens::TokenService,
    totp::TotpService,
};

/// Stand-in material for the "account does not exist" paths.
///
/// Unknown or unconfirmed accounts are run through the same decrypt, HOTP and
/// Argon2 work as real ones, against this material, so response timing does
/// not reveal whether an email is enrolled.
pub struct Decoy {
    pub secret_enc: Vec<u8>,
    pub aad: Vec<u8>,
    pub recovery_hash: String,
}

/// Shared application state; cheap to clone (everything is `Arc` or a pool).
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AppConfig>,
    pub store: Store,
    /// Active + retired encryption keys for TOTP secrets at rest.
    pub keys: Arc<KeyRing>,
    pub tokens: Arc<TokenService>,
    pub totp: Arc<TotpService>,
    pub recovery_hasher: Arc<RecoveryHasher>,
    /// Per-account failure budget and lockout for login, confirm and recovery.
    pub login_limiter: Arc<FailureLimiter>,
    /// Per-client-IP budget for enrollment.
    pub enroll_limiter: Arc<WindowLimiter>,
    /// Per-client-IP budget shared by login, confirm and recovery, so one
    /// source cannot spray attempts across many accounts.
    pub auth_ip_limiter: Arc<WindowLimiter>,
    /// Bounds how many Argon2id operations run at once. Each one pins a
    /// blocking thread and `argon2.memory_kib` of RAM for ~20 ms.
    pub argon2_gate: Arc<Semaphore>,
    pub decoy: Arc<Decoy>,
    pub metrics: PrometheusHandle,
}

impl AppState {
    pub async fn new(cfg: AppConfig) -> anyhow::Result<Self> {
        cfg.validate()?;

        let enc_key = resolve_key(
            cfg.security.secret_encryption_key.as_deref(),
            "secret_encryption_key",
        );
        let paseto_key = resolve_key(cfg.security.paseto_key.as_deref(), "paseto_key");
        if cfg
            .server
            .metrics_token
            .as_deref()
            .is_none_or(|t| t.trim().is_empty())
        {
            tracing::warn!(
                "server.metrics_token is not set — /metrics is readable by anyone who can \
                 reach the server. Set it unless the scrape path is firewalled."
            );
        }

        let store = Store::connect(&cfg.database).await?;
        let limits: Arc<dyn RateLimitBackend> = match cfg.rate_limit.backend {
            RateLimitBackendKind::Memory => {
                tracing::info!(
                    "rate limits are per instance (memory); set rate_limit.backend = \
                     \"postgres\" when running more than one replica"
                );
                Arc::new(MemoryBackend::new())
            }
            RateLimitBackendKind::Postgres => {
                tracing::info!("rate limits are shared across replicas (postgres)");
                Arc::new(PostgresBackend::new(store.pool().clone()))
            }
        };
        let keys = KeyRing::new(&enc_key, &cfg.security.retired_encryption_keys)?;
        let recovery_hasher = RecoveryHasher::new(&cfg.security.argon2)?;

        let decoy_aad = b"decoy".to_vec();
        let decoy = Decoy {
            secret_enc: keys.seal(&TotpService::new_secret(), &decoy_aad)?,
            aad: decoy_aad,
            recovery_hash: recovery_hasher.hash(&crate::recovery::generate_codes(1)[0])?,
        };

        let argon2_permits = match cfg.security.argon2.max_concurrency {
            0 => std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2),
            n => n as usize,
        };

        Ok(Self {
            keys: Arc::new(keys),
            tokens: Arc::new(TokenService::new(
                &paseto_key,
                &cfg.security.retired_paseto_keys,
                cfg.security.session_ttl_secs,
            )?),
            totp: Arc::new(TotpService::new(&cfg.totp)),
            recovery_hasher: Arc::new(recovery_hasher),
            login_limiter: Arc::new(FailureLimiter::new(
                limits.clone(),
                "account",
                cfg.rate_limit.login_max_failures,
                Duration::from_secs(cfg.rate_limit.login_window_secs),
                Duration::from_secs(cfg.rate_limit.lockout_secs),
            )),
            enroll_limiter: Arc::new(WindowLimiter::new(
                limits.clone(),
                "enroll-ip",
                cfg.rate_limit.enroll_max_per_window,
                Duration::from_secs(cfg.rate_limit.enroll_window_secs),
            )),
            auth_ip_limiter: Arc::new(WindowLimiter::new(
                limits,
                "auth-ip",
                cfg.rate_limit.auth_ip_max_per_window,
                Duration::from_secs(cfg.rate_limit.auth_ip_window_secs),
            )),
            argon2_gate: Arc::new(Semaphore::new(argon2_permits)),
            decoy: Arc::new(decoy),
            metrics: crate::metrics::prometheus_handle(),
            store,
            cfg: Arc::new(cfg),
        })
    }
}

fn resolve_key(configured: Option<&str>, name: &str) -> String {
    match configured {
        Some(key) if !key.trim().is_empty() => key.trim().to_string(),
        _ => {
            tracing::warn!(
                "security.{name} is not configured — generated an EPHEMERAL key. \
                 Sessions and stored secrets will NOT survive a restart. \
                 Run `totp-server keygen` and set the keys for production use."
            );
            crate::crypto::generate_key_hex()
        }
    }
}
