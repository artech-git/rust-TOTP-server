use std::sync::Arc;
use std::time::Duration;

use metrics_exporter_prometheus::PrometheusHandle;

use crate::{
    config::AppConfig,
    crypto::SecretCipher,
    ratelimit::{FailureLimiter, WindowLimiter},
    recovery::RecoveryHasher,
    store::Store,
    tokens::TokenService,
    totp::TotpService,
};

/// Shared application state; cheap to clone (everything is `Arc` or a pool).
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AppConfig>,
    pub store: Store,
    pub cipher: Arc<SecretCipher>,
    pub tokens: Arc<TokenService>,
    pub totp: Arc<TotpService>,
    pub recovery_hasher: Arc<RecoveryHasher>,
    pub login_limiter: Arc<FailureLimiter>,
    pub enroll_limiter: Arc<WindowLimiter>,
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

        let store = Store::connect(&cfg.database).await?;

        Ok(Self {
            cipher: Arc::new(SecretCipher::from_hex_key(&enc_key)?),
            tokens: Arc::new(TokenService::from_hex_key(
                &paseto_key,
                cfg.security.session_ttl_secs,
            )?),
            totp: Arc::new(TotpService::new(&cfg.totp)),
            recovery_hasher: Arc::new(RecoveryHasher::new(&cfg.security.argon2)?),
            login_limiter: Arc::new(FailureLimiter::new(
                cfg.rate_limit.login_max_failures,
                Duration::from_secs(cfg.rate_limit.login_window_secs),
                Duration::from_secs(cfg.rate_limit.lockout_secs),
            )),
            enroll_limiter: Arc::new(WindowLimiter::new(
                cfg.rate_limit.enroll_max_per_window,
                Duration::from_secs(cfg.rate_limit.enroll_window_secs),
            )),
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
