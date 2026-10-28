//! Rate limiting over pluggable state.
//!
//! Two policies are needed: a fixed-window counter (enrollments per IP,
//! login-family attempts per IP) and a failure budget with lockout (per
//! account). Both are expressed over a [`RateLimitBackend`] that owns the
//! counters. [`MemoryBackend`] is correct for a single instance;
//! [`PostgresBackend`] shares the state between replicas so a lockout reached
//! on one is enforced by all.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sqlx::{Row, postgres::PgPool};

use crate::store::unix_now;

/// Outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Limited { retry_after_secs: u64 },
}

/// Fixed window: at most `max` hits per `window`.
#[derive(Debug, Clone, Copy)]
pub struct WindowRule {
    pub max: u32,
    pub window: Duration,
}

/// Failure budget: `max_failures` within `window` locks the key for `lockout`.
#[derive(Debug, Clone, Copy)]
pub struct LockoutRule {
    pub max_failures: u32,
    pub window: Duration,
    pub lockout: Duration,
}

/// Storage for rate-limit counters. Keys are already namespaced by the
/// limiter that owns them.
#[async_trait]
pub trait RateLimitBackend: Send + Sync {
    /// Count one hit against `key`'s fixed window.
    async fn hit(&self, key: &str, rule: WindowRule) -> anyhow::Result<Decision>;
    /// Whether `key` is currently locked out.
    async fn check_lockout(&self, key: &str) -> anyhow::Result<Decision>;
    /// Record a failed attempt; `Some(lockout_secs)` when this one triggered
    /// a lockout.
    async fn record_failure(&self, key: &str, rule: LockoutRule) -> anyhow::Result<Option<u64>>;
    /// Forget `key` (after a successful authentication).
    async fn clear(&self, key: &str) -> anyhow::Result<()>;
}

/// Fixed-window request limiter (e.g. enrollments per IP per hour).
pub struct WindowLimiter {
    backend: std::sync::Arc<dyn RateLimitBackend>,
    namespace: &'static str,
    rule: WindowRule,
}

impl WindowLimiter {
    pub fn new(
        backend: std::sync::Arc<dyn RateLimitBackend>,
        namespace: &'static str,
        max: u32,
        window: Duration,
    ) -> Self {
        Self {
            backend,
            namespace,
            rule: WindowRule {
                max: max.max(1),
                window,
            },
        }
    }

    pub async fn try_acquire(&self, key: &str) -> anyhow::Result<Decision> {
        self.backend
            .hit(&format!("{}:{key}", self.namespace), self.rule)
            .await
    }
}

/// Tracks authentication failures per key (an account) and locks the key out
/// once the failure budget for the window is exhausted.
pub struct FailureLimiter {
    backend: std::sync::Arc<dyn RateLimitBackend>,
    namespace: &'static str,
    rule: LockoutRule,
}

impl FailureLimiter {
    pub fn new(
        backend: std::sync::Arc<dyn RateLimitBackend>,
        namespace: &'static str,
        max_failures: u32,
        window: Duration,
        lockout: Duration,
    ) -> Self {
        Self {
            backend,
            namespace,
            rule: LockoutRule {
                max_failures: max_failures.max(1),
                window,
                lockout,
            },
        }
    }

    fn key(&self, key: &str) -> String {
        format!("{}:{key}", self.namespace)
    }

    pub async fn check(&self, key: &str) -> anyhow::Result<Decision> {
        self.backend.check_lockout(&self.key(key)).await
    }

    pub async fn record_failure(&self, key: &str) -> anyhow::Result<Option<u64>> {
        self.backend.record_failure(&self.key(key), self.rule).await
    }

    pub async fn clear(&self, key: &str) -> anyhow::Result<()> {
        self.backend.clear(&self.key(key)).await
    }
}

fn retry_after_secs(until: Instant, now: Instant) -> u64 {
    until.saturating_duration_since(now).as_secs().max(1)
}

// ------------------------------- in-memory backend -------------------------------

/// Entries are pruned opportunistically once a map grows past this size,
/// bounding memory without a background task.
const PRUNE_THRESHOLD: usize = 4096;

struct WindowEntry {
    count: u32,
    start: Instant,
    window: Duration,
}

struct FailureEntry {
    count: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

/// Process-local counters on a monotonic clock. Correct for one instance;
/// with several replicas each one has its own budget, so use
/// [`PostgresBackend`] there.
#[derive(Default)]
pub struct MemoryBackend {
    windows: Mutex<HashMap<String, WindowEntry>>,
    failures: Mutex<HashMap<String, FailureEntry>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RateLimitBackend for MemoryBackend {
    async fn hit(&self, key: &str, rule: WindowRule) -> anyhow::Result<Decision> {
        let now = Instant::now();
        let mut entries = self.windows.lock().expect("limiter lock poisoned");
        if entries.len() > PRUNE_THRESHOLD {
            entries.retain(|_, e| now.duration_since(e.start) < e.window);
        }
        let entry = entries.entry(key.to_string()).or_insert(WindowEntry {
            count: 0,
            start: now,
            window: rule.window,
        });
        if now.duration_since(entry.start) >= rule.window {
            entry.count = 0;
            entry.start = now;
        }
        if entry.count >= rule.max {
            return Ok(Decision::Limited {
                retry_after_secs: retry_after_secs(entry.start + rule.window, now),
            });
        }
        entry.count += 1;
        Ok(Decision::Allowed)
    }

    async fn check_lockout(&self, key: &str) -> anyhow::Result<Decision> {
        let now = Instant::now();
        let entries = self.failures.lock().expect("limiter lock poisoned");
        if let Some(entry) = entries.get(key)
            && let Some(until) = entry.locked_until
            && until > now
        {
            return Ok(Decision::Limited {
                retry_after_secs: retry_after_secs(until, now),
            });
        }
        Ok(Decision::Allowed)
    }

    async fn record_failure(&self, key: &str, rule: LockoutRule) -> anyhow::Result<Option<u64>> {
        let now = Instant::now();
        let mut entries = self.failures.lock().expect("limiter lock poisoned");
        if entries.len() > PRUNE_THRESHOLD {
            entries.retain(|_, e| {
                e.locked_until.is_some_and(|u| u > now)
                    || now.duration_since(e.window_start) < rule.window
            });
        }
        let entry = entries.entry(key.to_string()).or_insert(FailureEntry {
            count: 0,
            window_start: now,
            locked_until: None,
        });

        if entry.locked_until.is_some_and(|u| u <= now) {
            entry.locked_until = None;
            entry.count = 0;
            entry.window_start = now;
        }
        if now.duration_since(entry.window_start) >= rule.window {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;
        if entry.count >= rule.max_failures {
            entry.locked_until = Some(now + rule.lockout);
            entry.count = 0;
            return Ok(Some(rule.lockout.as_secs()));
        }
        Ok(None)
    }

    async fn clear(&self, key: &str) -> anyhow::Result<()> {
        self.failures
            .lock()
            .expect("limiter lock poisoned")
            .remove(key);
        Ok(())
    }
}

// -------------------------------- Postgres backend --------------------------------

/// Rows untouched for this long (and not under lockout) are garbage; no
/// configured window comes close.
const PRUNE_AFTER_SECS: i64 = 24 * 3600;
/// Prune once every this many writes.
const PRUNE_EVERY: u32 = 1024;

/// Counters in the `rate_limits` table, shared by every replica. Each check
/// is a single round trip (an upsert that returns the new count), so the
/// cost is one small write per authentication attempt.
pub struct PostgresBackend {
    pool: PgPool,
    writes: AtomicU32,
}

impl PostgresBackend {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            writes: AtomicU32::new(0),
        }
    }

    async fn maybe_prune(&self, now: i64) -> anyhow::Result<()> {
        if !self
            .writes
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(PRUNE_EVERY)
        {
            return Ok(());
        }
        sqlx::query(
            "DELETE FROM rate_limits \
             WHERE updated_at < $1 AND (locked_until IS NULL OR locked_until < $2)",
        )
        .bind(now - PRUNE_AFTER_SECS)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl RateLimitBackend for PostgresBackend {
    async fn hit(&self, key: &str, rule: WindowRule) -> anyhow::Result<Decision> {
        let now = unix_now();
        let window = rule.window.as_secs() as i64;
        self.maybe_prune(now).await?;
        let row = sqlx::query(
            "INSERT INTO rate_limits (key, count, window_start, locked_until, updated_at) \
             VALUES ($1, 1, $2, NULL, $2) \
             ON CONFLICT (key) DO UPDATE SET \
               count = CASE WHEN rate_limits.window_start + $3 <= $2 \
                            THEN 1 ELSE rate_limits.count + 1 END, \
               window_start = CASE WHEN rate_limits.window_start + $3 <= $2 \
                                   THEN $2 ELSE rate_limits.window_start END, \
               updated_at = $2 \
             RETURNING count, window_start",
        )
        .bind(key)
        .bind(now)
        .bind(window)
        .fetch_one(&self.pool)
        .await?;
        let count: i32 = row.get("count");
        let window_start: i64 = row.get("window_start");
        if count > rule.max as i32 {
            return Ok(Decision::Limited {
                retry_after_secs: (window_start + window - now).max(1) as u64,
            });
        }
        Ok(Decision::Allowed)
    }

    async fn check_lockout(&self, key: &str) -> anyhow::Result<Decision> {
        let now = unix_now();
        let row = sqlx::query(
            "SELECT locked_until FROM rate_limits \
             WHERE key = $1 AND locked_until IS NOT NULL AND locked_until > $2",
        )
        .bind(key)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Decision::Limited {
                retry_after_secs: (r.get::<i64, _>("locked_until") - now).max(1) as u64,
            },
            None => Decision::Allowed,
        })
    }

    async fn record_failure(&self, key: &str, rule: LockoutRule) -> anyhow::Result<Option<u64>> {
        let now = unix_now();
        let window = rule.window.as_secs() as i64;
        self.maybe_prune(now).await?;
        // A fresh window starts when the previous one expired or an old
        // lockout has lapsed; an active lockout is kept as is.
        let row = sqlx::query(
            "INSERT INTO rate_limits (key, count, window_start, locked_until, updated_at) \
             VALUES ($1, 1, $2, NULL, $2) \
             ON CONFLICT (key) DO UPDATE SET \
               count = CASE WHEN (rate_limits.locked_until IS NOT NULL AND rate_limits.locked_until <= $2) \
                              OR rate_limits.window_start + $3 <= $2 \
                            THEN 1 ELSE rate_limits.count + 1 END, \
               window_start = CASE WHEN (rate_limits.locked_until IS NOT NULL AND rate_limits.locked_until <= $2) \
                                     OR rate_limits.window_start + $3 <= $2 \
                                   THEN $2 ELSE rate_limits.window_start END, \
               locked_until = CASE WHEN rate_limits.locked_until IS NOT NULL AND rate_limits.locked_until > $2 \
                                   THEN rate_limits.locked_until ELSE NULL END, \
               updated_at = $2 \
             RETURNING count",
        )
        .bind(key)
        .bind(now)
        .bind(window)
        .fetch_one(&self.pool)
        .await?;
        let count: i32 = row.get("count");
        if count < rule.max_failures as i32 {
            return Ok(None);
        }
        let lockout = rule.lockout.as_secs() as i64;
        sqlx::query(
            "UPDATE rate_limits SET locked_until = $2, count = 0, updated_at = $3 WHERE key = $1",
        )
        .bind(key)
        .bind(now + lockout)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(Some(lockout as u64))
    }

    async fn clear(&self, key: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM rate_limits WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn failure_limiter(max: u32) -> FailureLimiter {
        FailureLimiter::new(
            Arc::new(MemoryBackend::new()),
            "test",
            max,
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
    }

    #[tokio::test]
    async fn locks_after_budget_and_clears_on_success() {
        let limiter = failure_limiter(3);
        assert_eq!(limiter.check("k").await.unwrap(), Decision::Allowed);
        assert!(limiter.record_failure("k").await.unwrap().is_none());
        assert!(limiter.record_failure("k").await.unwrap().is_none());
        assert_eq!(limiter.record_failure("k").await.unwrap(), Some(60));
        assert!(matches!(
            limiter.check("k").await.unwrap(),
            Decision::Limited { .. }
        ));

        limiter.clear("k").await.unwrap();
        assert_eq!(limiter.check("k").await.unwrap(), Decision::Allowed);
    }

    #[tokio::test]
    async fn keys_are_independent() {
        let limiter = failure_limiter(1);
        assert_eq!(limiter.record_failure("a").await.unwrap(), Some(60));
        assert!(matches!(
            limiter.check("a").await.unwrap(),
            Decision::Limited { .. }
        ));
        assert_eq!(limiter.check("b").await.unwrap(), Decision::Allowed);
    }

    #[tokio::test]
    async fn window_limiter_enforces_budget() {
        let limiter = WindowLimiter::new(
            Arc::new(MemoryBackend::new()),
            "test",
            2,
            Duration::from_secs(60),
        );
        assert_eq!(limiter.try_acquire("ip").await.unwrap(), Decision::Allowed);
        assert_eq!(limiter.try_acquire("ip").await.unwrap(), Decision::Allowed);
        let Decision::Limited { retry_after_secs } = limiter.try_acquire("ip").await.unwrap()
        else {
            panic!("third hit must be limited");
        };
        assert!((1..=60).contains(&retry_after_secs));
        assert_eq!(
            limiter.try_acquire("other-ip").await.unwrap(),
            Decision::Allowed
        );
    }

    #[tokio::test]
    async fn namespaces_keep_limiters_apart_on_a_shared_backend() {
        let backend: Arc<dyn RateLimitBackend> = Arc::new(MemoryBackend::new());
        let enroll = WindowLimiter::new(backend.clone(), "enroll", 1, Duration::from_secs(60));
        let auth = WindowLimiter::new(backend, "auth", 1, Duration::from_secs(60));
        assert_eq!(
            enroll.try_acquire("1.2.3.4").await.unwrap(),
            Decision::Allowed
        );
        assert_eq!(
            auth.try_acquire("1.2.3.4").await.unwrap(),
            Decision::Allowed
        );
        assert!(matches!(
            enroll.try_acquire("1.2.3.4").await.unwrap(),
            Decision::Limited { .. }
        ));
    }
}
