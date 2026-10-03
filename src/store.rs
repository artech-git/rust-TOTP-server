use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::{
    Connection, Row,
    postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions, PgRow},
};

use crate::config::DatabaseConfig;

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

/// Postgres-backed persistence (Supabase or any Postgres), with embedded
/// migrations applied on connect.
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    pub async fn connect(cfg: &DatabaseConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(!cfg.url.trim().is_empty(), "database.url must be set");
        let connect_options: PgConnectOptions = cfg
            .url
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid database.url: {e}"))?;

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
                // Create it once up front so concurrent pool connections don't
                // race on `CREATE SCHEMA IF NOT EXISTS`.
                let mut conn = PgConnection::connect_with(&connect_options).await?;
                sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{s}\""))
                    .execute(&mut conn)
                    .await?;
                conn.close().await?;
                Some(s)
            }
            _ => None,
        };

        let mut pool_options = PgPoolOptions::new()
            .max_connections(cfg.max_connections)
            .acquire_timeout(Duration::from_secs(cfg.connect_timeout_secs));

        if let Some(schema) = schema {
            // Pin every pooled connection to the chosen schema.
            pool_options = pool_options.after_connect(move |conn, _meta| {
                let sql = format!("SET search_path TO \"{schema}\", public");
                Box::pin(async move {
                    sqlx::query(&sql).execute(conn).await?;
                    Ok(())
                })
            });
        }

        let pool = pool_options.connect_with(connect_options).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Create a pending (unconfirmed) enrollment, or reset the secret of an
    /// existing unconfirmed one. Returns `false` when the email already
    /// belongs to a confirmed account (nothing is modified in that case).
    pub async fn upsert_pending_user(
        &self,
        id: &str,
        email: &str,
        secret_enc: &[u8],
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO users (id, email, secret_enc, totp_confirmed, last_used_period, created_at, updated_at) \
             VALUES ($1, $2, $3, FALSE, 0, $4, $4) \
             ON CONFLICT (email) DO UPDATE SET \
               secret_enc = EXCLUDED.secret_enc, \
               last_used_period = 0, \
               updated_at = EXCLUDED.updated_at \
             WHERE users.totp_confirmed = FALSE",
        )
        .bind(id)
        .bind(email)
        .bind(secret_enc)
        .bind(unix_now())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
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

    /// Replace all recovery codes for a user with a fresh set (single tx).
    pub async fn replace_recovery_codes(
        &self,
        user_id: &str,
        code_hashes: &[String],
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for hash in code_hashes {
            sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)")
                .bind(user_id)
                .bind(hash)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await
    }

    pub async fn unused_recovery_codes(
        &self,
        user_id: &str,
    ) -> Result<Vec<(i64, String)>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, code_hash FROM recovery_codes \
             WHERE user_id = $1 AND used_at IS NULL ORDER BY id",
        )
        .bind(user_id)
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
