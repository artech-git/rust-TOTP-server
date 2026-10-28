use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::{
    Connection, Row,
    migrate::Migrator,
    postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions, PgRow},
};

use crate::{
    config::{DatabaseConfig, PoolerMode},
    recovery::HashedCode,
};

/// Migrations embedded at build time from `./migrations`.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as i64
}

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: String,
    pub email: String,
    pub secret_enc: Vec<u8>,
    pub totp_confirmed: bool,
    pub last_used_period: i64,
    pub created_at: i64,
}

fn row_to_user(row: &PgRow) -> UserRecord {
    UserRecord {
        id: row.get("id"),
        email: row.get("email"),
        secret_enc: row.get("secret_enc"),
        totp_confirmed: row.get("totp_confirmed"),
        last_used_period: row.get("last_used_period"),
        created_at: row.get("created_at"),
    }
}

const USER_COLUMNS: &str = "id, email, secret_enc, totp_confirmed, last_used_period, created_at";

/// A Postgres schema name is safe to interpolate only if it is a plain
/// identifier. We double-quote it anyway, but reject anything exotic up front
/// so a misconfigured `TOTP_DATABASE__SCHEMA` can never inject SQL.
fn is_safe_schema(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Postgres-backed persistence (Supabase or any Postgres).
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Connect for serving: open the pool (retrying while the database comes
    /// up), then either apply the embedded migrations or, when
    /// `run_migrations_on_start` is off, verify that they have been applied.
    pub async fn connect(cfg: &DatabaseConfig) -> anyhow::Result<Self> {
        let store = Self::open(cfg).await?;
        if cfg.run_migrations_on_start {
            store.apply_migrations().await?;
        } else {
            store.ensure_schema_current().await?;
        }
        Ok(store)
    }

    /// Apply the embedded migrations and return (`totp-server migrate`).
    pub async fn migrate(cfg: &DatabaseConfig) -> anyhow::Result<()> {
        Self::open(cfg).await?.apply_migrations().await
    }

    /// The underlying pool, for components that keep their own tables (the
    /// Postgres rate-limit backend).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn open(cfg: &DatabaseConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(!cfg.url.trim().is_empty(), "database.url must be set");
        let mut connect_options: PgConnectOptions = cfg
            .url
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid database.url: {e}"))?;
        if cfg.pooler_mode == PoolerMode::Transaction {
            // Behind a transaction pooler, server connections are shared
            // between clients, so a named prepared statement cached on one
            // connection may not exist on the next. Unnamed statements are
            // still used, so parameters stay bound server-side.
            connect_options = connect_options.statement_cache_capacity(0);
        }

        // Optional schema isolation. Production leaves this unset (the default
        // `public` schema); the integration tests point each test at its own
        // throwaway schema so they stay independent on one shared database.
        let schema = match cfg.schema.as_deref() {
            Some(s) if !s.trim().is_empty() => {
                let s = s.trim().to_string();
                anyhow::ensure!(
                    is_safe_schema(&s),
                    "database.schema is not a valid identifier"
                );
                Some(s)
            }
            _ => None,
        };

        let mut attempt = 0u32;
        loop {
            match Self::try_open(&connect_options, schema.as_deref(), cfg).await {
                Ok(pool) => return Ok(Self { pool }),
                Err(err) if attempt < cfg.connect_retries => {
                    let delay = Duration::from_secs(1u64 << attempt.min(5));
                    attempt += 1;
                    tracing::warn!(
                        attempt,
                        retries = cfg.connect_retries,
                        delay_secs = delay.as_secs(),
                        error = %err,
                        "database not reachable yet; retrying"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn try_open(
        connect_options: &PgConnectOptions,
        schema: Option<&str>,
        cfg: &DatabaseConfig,
    ) -> anyhow::Result<PgPool> {
        if let Some(s) = schema {
            // Create it once up front so concurrent pool connections don't
            // race on `CREATE SCHEMA IF NOT EXISTS`.
            let mut conn = PgConnection::connect_with(connect_options).await?;
            sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{s}\""))
                .execute(&mut conn)
                .await?;
            conn.close().await?;
        }

        let mut pool_options = PgPoolOptions::new()
            .max_connections(cfg.max_connections)
            .acquire_timeout(Duration::from_secs(cfg.connect_timeout_secs));

        if let Some(schema) = schema {
            // Pin every pooled connection to the chosen schema.
            let sql = format!("SET search_path TO \"{schema}\", public");
            pool_options = pool_options.after_connect(move |conn, _meta| {
                let sql = sql.clone();
                Box::pin(async move {
                    sqlx::query(&sql).execute(conn).await?;
                    Ok(())
                })
            });
        }

        Ok(pool_options.connect_with(connect_options.clone()).await?)
    }

    async fn apply_migrations(&self) -> anyhow::Result<()> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    /// Fail unless every embedded migration has been applied, so a replica
    /// started against a stale schema stops at boot instead of erroring on
    /// its first query.
    pub async fn ensure_schema_current(&self) -> anyhow::Result<()> {
        let expected = MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0);
        let table: Option<String> =
            sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations')::text")
                .fetch_one(&self.pool)
                .await?;
        let applied: Option<i64> = match table {
            Some(_) => {
                sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
                    .fetch_one(&self.pool)
                    .await?
            }
            None => None,
        };
        anyhow::ensure!(
            applied == Some(expected),
            "database schema is at migration {} but this build expects {expected}; \
             run `totp-server migrate` (or set database.run_migrations_on_start = true)",
            applied.map_or("none".to_string(), |v| v.to_string())
        );
        Ok(())
    }

    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Create a pending (unconfirmed) enrollment, or reset the secret of an
    /// existing unconfirmed one. Returns the id of the row that persisted (an
    /// existing pending row keeps its original id), or `None` when the email
    /// already belongs to a confirmed account (nothing is modified then).
    pub async fn upsert_pending_user(
        &self,
        id: &str,
        email: &str,
        secret_enc: &[u8],
    ) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query(
            "INSERT INTO users (id, email, secret_enc, totp_confirmed, last_used_period, created_at, updated_at) \
             VALUES ($1, $2, $3, FALSE, 0, $4, $4) \
             ON CONFLICT (email) DO UPDATE SET \
               secret_enc = EXCLUDED.secret_enc, \
               last_used_period = 0, \
               updated_at = EXCLUDED.updated_at \
             WHERE users.totp_confirmed = FALSE \
             RETURNING id",
        )
        .bind(id)
        .bind(email)
        .bind(secret_enc)
        .bind(unix_now())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get("id")))
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {USER_COLUMNS} FROM users WHERE email = $1"
        ))
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_user))
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<UserRecord>, sqlx::Error> {
        let row = sqlx::query(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_user))
    }

    /// Mark enrollment as confirmed and consume the confirming time-step.
    pub async fn confirm_user(&self, id: &str, period: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE users SET totp_confirmed = TRUE, last_used_period = $1, updated_at = $2 \
             WHERE id = $3 AND totp_confirmed = FALSE",
        )
        .bind(period)
        .bind(unix_now())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Atomically consume a TOTP time-step for a confirmed user. Returns
    /// `false` when the step was already used (replay) or the user is gone.
    pub async fn try_consume_period(&self, id: &str, period: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE users SET last_used_period = $1, updated_at = $2 \
             WHERE id = $3 AND totp_confirmed = TRUE AND last_used_period < $1",
        )
        .bind(period)
        .bind(unix_now())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Replace all recovery codes for a user with a fresh set (single tx,
    /// one bulk insert).
    pub async fn replace_recovery_codes(
        &self,
        user_id: &str,
        codes: &[HashedCode],
    ) -> Result<(), sqlx::Error> {
        let hashes: Vec<&str> = codes.iter().map(|c| c.hash.as_str()).collect();
        let lookups: Vec<&str> = codes.iter().map(|c| c.lookup.as_str()).collect();
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO recovery_codes (user_id, code_hash, lookup) \
             SELECT $1, hash, lookup FROM UNNEST($2::text[], $3::text[]) AS t(hash, lookup)",
        )
        .bind(user_id)
        .bind(&hashes)
        .bind(&lookups)
        .execute(&mut *tx)
        .await?;
        tx.commit().await
    }

    /// Unused codes that could match a presented code: those sharing its
    /// lookup prefix (normally one), plus any legacy rows written before the
    /// prefix column existed.
    pub async fn candidate_recovery_codes(
        &self,
        user_id: &str,
        lookup: &str,
    ) -> Result<Vec<(i64, String)>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, code_hash FROM recovery_codes \
             WHERE user_id = $1 AND used_at IS NULL AND (lookup = $2 OR lookup IS NULL) \
             ORDER BY id",
        )
        .bind(user_id)
        .bind(lookup)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| (r.get("id"), r.get("code_hash")))
            .collect())
    }

    /// Burn a recovery code; `false` when it was already used (race lost).
    pub async fn mark_recovery_code_used(&self, code_id: i64) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("UPDATE recovery_codes SET used_at = $1 WHERE id = $2 AND used_at IS NULL")
                .bind(unix_now())
                .bind(code_id)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn count_unused_recovery_codes(&self, user_id: &str) -> Result<i64, sqlx::Error> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get("n"))
    }

    pub async fn delete_user(&self, id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}
