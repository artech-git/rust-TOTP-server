use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Entries are pruned opportunistically once the map grows past this size,
/// bounding memory without a background task.
const PRUNE_THRESHOLD: usize = 4096;

/// Tracks authentication failures per key (email or IP) and locks the key
/// out once the failure budget for the window is exhausted.
///
/// State is in-memory and monotonic-clock based: correct for a single
/// instance (the free-tier deployment model — one Render/Fly container in
/// front of Supabase Postgres). Scaling horizontally would need a shared
/// store such as Redis.
pub struct FailureLimiter {
    max_failures: u32,
    window: Duration,
    lockout: Duration,
    entries: Mutex<HashMap<String, FailureEntry>>,
}

struct FailureEntry {
    count: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

impl FailureLimiter {
    pub fn new(max_failures: u32, window: Duration, lockout: Duration) -> Self {
        Self {
            max_failures: max_failures.max(1),
            window,
            lockout,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Err(retry_after_secs) when the key is currently locked out.
    pub fn check(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let entries = self.entries.lock().expect("limiter lock poisoned");
        if let Some(entry) = entries.get(key)
            && let Some(until) = entry.locked_until
            && until > now
        {
            return Err(retry_after_secs(until, now));
        }
        Ok(())
    }

    /// Record a failed attempt. Returns `Some(lockout_secs)` if this failure
    /// triggered a lockout.
    pub fn record_failure(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("limiter lock poisoned");
        if entries.len() > PRUNE_THRESHOLD {
            let window = self.window;
            entries.retain(|_, e| {
                e.locked_until.is_some_and(|u| u > now)
                    || now.duration_since(e.window_start) < window
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
        if now.duration_since(entry.window_start) >= self.window {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;
        if entry.count >= self.max_failures {
            let until = now + self.lockout;
            entry.locked_until = Some(until);
            entry.count = 0;
            return Some(self.lockout.as_secs());
        }
        None
    }

    /// Clear failure state after a successful authentication.
    pub fn clear(&self, key: &str) {
        self.entries
            .lock()
            .expect("limiter lock poisoned")
            .remove(key);
    }
}

/// Fixed-window request limiter (e.g. enrollments per IP per hour).
pub struct WindowLimiter {
    max: u32,
    window: Duration,
    entries: Mutex<HashMap<String, (u32, Instant)>>,
}

impl WindowLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max: max.max(1),
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Err(retry_after_secs) when the key is over budget for this window.
    pub fn try_acquire(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("limiter lock poisoned");
        if entries.len() > PRUNE_THRESHOLD {
            let window = self.window;
            entries.retain(|_, (_, start)| now.duration_since(*start) < window);
        }
        let (count, start) = entries.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(*start) >= self.window {
            *count = 0;
            *start = now;
        }
        if *count >= self.max {
            return Err(retry_after_secs(*start + self.window, now));
        }
        *count += 1;
        Ok(())
    }
}

fn retry_after_secs(until: Instant, now: Instant) -> u64 {
    until.saturating_duration_since(now).as_secs().max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_after_budget_and_clears_on_success() {
        let limiter = FailureLimiter::new(3, Duration::from_secs(60), Duration::from_secs(60));
        assert!(limiter.check("k").is_ok());
        assert!(limiter.record_failure("k").is_none());
        assert!(limiter.record_failure("k").is_none());
        assert_eq!(limiter.record_failure("k"), Some(60));
        assert!(limiter.check("k").is_err());

        limiter.clear("k");
        assert!(limiter.check("k").is_ok());
    }

    #[test]
    fn keys_are_independent() {
        let limiter = FailureLimiter::new(1, Duration::from_secs(60), Duration::from_secs(60));
        assert_eq!(limiter.record_failure("a"), Some(60));
        assert!(limiter.check("a").is_err());
        assert!(limiter.check("b").is_ok());
    }

    #[test]
    fn window_limiter_enforces_budget() {
        let limiter = WindowLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.try_acquire("ip").is_ok());
        assert!(limiter.try_acquire("ip").is_ok());
        let retry = limiter.try_acquire("ip").unwrap_err();
        assert!((1..=60).contains(&retry));
        assert!(limiter.try_acquire("other-ip").is_ok());
    }
}
