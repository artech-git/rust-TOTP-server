use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

/// Full application configuration.
///
/// Values are resolved in order of precedence (highest wins):
/// 1. environment variables prefixed with `TOTP_` (`__` separates levels,
///    e.g. `TOTP_SERVER__PORT=8080`)
/// 2. the TOML file named by `TOTP_CONFIG` (default `settings.toml`), if present
/// 3. built-in defaults
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub totp: TotpConfig,
    pub security: SecurityConfig,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Trust `X-Forwarded-For` when extracting the client IP (set only behind
    /// a reverse proxy you control).
    pub trust_proxy: bool,
    /// Origins allowed via CORS. Empty disables CORS entirely (same-origin
    /// only); `["*"]` allows any origin — useful when the demo UI is hosted
    /// elsewhere (e.g. Netlify) and talks to this API cross-origin.
    pub cors_allowed_origins: Vec<String>,
    /// Number of reverse proxies that append to `X-Forwarded-For` before a
    /// request reaches this server (used only with `trust_proxy`). The client
    /// address is taken that many entries from the *end* of the header; the
    /// leading entries are client-controlled and never trusted.
    pub trusted_proxy_hops: u8,
    /// Header the edge proxy *overwrites* with the client address (for
    /// example `CF-Connecting-IP` or `True-Client-IP`). Preferred over
    /// `X-Forwarded-For` when set and `trust_proxy` is on.
    pub client_ip_header: Option<String>,
    /// Bearer token required to read `/metrics`. Unset leaves the endpoint
    /// open and logs a warning at startup.
    pub metrics_token: Option<String>,
    /// Emit `Strict-Transport-Security` with this max-age (0 disables). Turn
    /// on only when the service is reached over HTTPS end to end.
    pub hsts_max_age_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Postgres connection string. For Supabase, use the **Session pooler** URI
    /// (host `...pooler.supabase.com`, port 5432) — the transaction pooler on
    /// 6543 does not support the prepared statements sqlx relies on. Can also be
    /// supplied via the standard `DATABASE_URL` environment variable.
    pub url: String,
    /// Maximum pooled connections. Keep this modest on Supabase's free tier.
    pub max_connections: u32,
    /// Seconds to wait for a free pool connection before erroring.
    pub connect_timeout_secs: u64,
    /// Optional Postgres schema to isolate into (sets the connection
    /// `search_path`). Unset means the default (`public`) schema; the
    /// integration tests use this for per-test isolation on one database.
    /// Needs `pooler_mode = "session"`.
    pub schema: Option<String>,
    /// Apply the embedded migrations when the server starts (default). With
    /// several replicas, turn this off and apply them once per deploy with
    /// `totp-server migrate`; the server then only verifies the schema
    /// version at boot.
    pub run_migrations_on_start: bool,
    /// Attempts to reach the database at startup before giving up, with
    /// exponential backoff (1, 2, 4, … seconds). Lets a paused or still
    /// booting database come up without the service crash-looping.
    pub connect_retries: u32,
    /// `session` (default) or `transaction`. Transaction-mode poolers
    /// (Supabase on port 6543, PgBouncer) share server connections between
    /// clients, so the prepared-statement cache is disabled in that mode.
    pub pooler_mode: PoolerMode,
}

/// How the connection string's endpoint multiplexes connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PoolerMode {
    #[default]
    Session,
    Transaction,
}

/// Where rate-limit counters live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitBackendKind {
    /// Per process. Correct for a single instance.
    #[default]
    Memory,
    /// The `rate_limits` table in the application database, shared by every
    /// replica. Use this whenever more than one instance runs.
    Postgres,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TotpConfig {
    /// Issuer shown in authenticator apps.
    pub issuer: String,
    /// Code length; 6–8 digits.
    pub digits: u32,
    /// Time-step in seconds (RFC 6238 default: 30).
    pub step: u64,
    /// Accepted clock drift in steps on either side of "now".
    pub skew: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// 64 hex chars (32 bytes). Encrypts TOTP secrets at rest.
    /// Generate with `totp-server keygen`. When unset, an ephemeral key is
    /// generated at startup (dev only — data is unreadable after restart).
    pub secret_encryption_key: Option<String>,
    /// 64 hex chars (32 bytes). Signs/encrypts PASETO v4.local session tokens.
    pub paseto_key: Option<String>,
    /// Previous `secret_encryption_key`s, kept so secrets sealed under them
    /// can still be opened. Such a secret is re-sealed with the active key the
    /// next time it is used, and `totp-server rekey` does it for every row at
    /// once; remove a key from this list once nothing references it.
    pub retired_encryption_keys: Vec<String>,
    /// Previous `paseto_key`s: sessions issued under them stay valid until
    /// they expire, while new sessions use the active key.
    pub retired_paseto_keys: Vec<String>,
    /// Session token lifetime in seconds.
    pub session_ttl_secs: u64,
    /// Number of one-time recovery codes issued at enrollment.
    pub recovery_code_count: u8,
    pub argon2: Argon2Config,
}

/// Argon2id cost parameters for hashing recovery codes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Argon2Config {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    /// Maximum Argon2 operations in flight at once (0 = number of CPU cores).
    /// Each one pins a blocking thread and `memory_kib` of RAM for its
    /// duration.
    pub max_concurrency: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// `memory` (default, single instance) or `postgres` (shared by replicas).
    pub backend: RateLimitBackendKind,
    /// Failed code/recovery attempts allowed per window before lockout.
    pub login_max_failures: u32,
    pub login_window_secs: u64,
    /// Lockout duration once the failure budget is exhausted.
    pub lockout_secs: u64,
    /// Enrollment requests allowed per client IP per window.
    pub enroll_max_per_window: u32,
    pub enroll_window_secs: u64,
    /// Login, confirm and recovery attempts allowed per client IP per window,
    /// across all accounts. Bounds the work one source can trigger.
    pub auth_ip_max_per_window: u32,
    pub auth_ip_window_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: 3000,
            trust_proxy: false,
            cors_allowed_origins: Vec::new(),
            trusted_proxy_hops: 1,
            client_ip_header: None,
            metrics_token: None,
            hsts_max_age_secs: 0,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            // Matches `supabase start` and the bundled docker-compose Postgres,
            // so local development works with no configuration.
            url: "postgres://postgres:postgres@127.0.0.1:54322/postgres".into(),
            max_connections: 5,
            connect_timeout_secs: 10,
            schema: None,
            run_migrations_on_start: true,
            connect_retries: 5,
            pooler_mode: PoolerMode::Session,
        }
    }
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: "TOTP Server".into(),
            digits: 6,
            step: 30,
            skew: 1,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            secret_encryption_key: None,
            paseto_key: None,
            retired_encryption_keys: Vec::new(),
            retired_paseto_keys: Vec::new(),
            session_ttl_secs: 3600,
            recovery_code_count: 10,
            argon2: Argon2Config::default(),
        }
    }
}

impl Default for Argon2Config {
    fn default() -> Self {
        // OWASP-recommended interactive profile: 19 MiB, 2 iterations.
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
            max_concurrency: 0,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            backend: RateLimitBackendKind::Memory,
            login_max_failures: 5,
            login_window_secs: 300,
            lockout_secs: 900,
            enroll_max_per_window: 20,
            enroll_window_secs: 3600,
            auth_ip_max_per_window: 60,
            auth_ip_window_secs: 60,
        }
    }
}

impl AppConfig {
    /// Load configuration from defaults, optional TOML file, and environment.
    pub fn load() -> anyhow::Result<Self> {
        let file = std::env::var("TOTP_CONFIG").unwrap_or_else(|_| "settings.toml".into());
        let mut cfg: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file(file))
            .merge(Env::prefixed("TOTP_").split("__"))
            .extract()?;

        // Honor the platform conventions used by Supabase/Render/Fly/Railway:
        // a plain `DATABASE_URL` for the connection string and `PORT` for the
        // listen port. The explicit `TOTP_*` variables always win when set.
        if std::env::var_os("TOTP_DATABASE__URL").is_none()
            && let Ok(url) = std::env::var("DATABASE_URL")
            && !url.trim().is_empty()
        {
            cfg.database.url = url;
        }
        if std::env::var_os("TOTP_SERVER__PORT").is_none()
            && let Ok(port) = std::env::var("PORT")
            && let Ok(port) = port.trim().parse::<u16>()
        {
            cfg.server.port = port;
        }

        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (6..=8).contains(&self.totp.digits),
            "totp.digits must be between 6 and 8"
        );
        anyhow::ensure!(
            self.totp.step >= 15,
            "totp.step must be at least 15 seconds"
        );
        anyhow::ensure!(
            self.totp.skew <= 2,
            "totp.skew above 2 steps defeats the point of TOTP"
        );
        anyhow::ensure!(
            (1..=25).contains(&self.security.recovery_code_count),
            "security.recovery_code_count must be between 1 and 25"
        );
        anyhow::ensure!(
            self.security.session_ttl_secs >= 60,
            "session_ttl_secs must be >= 60"
        );
        anyhow::ensure!(
            self.database.max_connections >= 1,
            "database.max_connections must be >= 1"
        );
        anyhow::ensure!(
            self.server.trusted_proxy_hops >= 1,
            "server.trusted_proxy_hops must be >= 1"
        );
        anyhow::ensure!(
            self.rate_limit.auth_ip_max_per_window >= 1,
            "rate_limit.auth_ip_max_per_window must be >= 1"
        );
        anyhow::ensure!(
            !self.database.url.trim().is_empty(),
            "database.url must be set (e.g. TOTP_DATABASE__URL or DATABASE_URL)"
        );
        anyhow::ensure!(
            !(self.database.pooler_mode == PoolerMode::Transaction
                && self
                    .database
                    .schema
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())),
            "database.schema isolation relies on a per-connection search_path and needs \
             pooler_mode = \"session\""
        );
        Ok(())
    }
}
