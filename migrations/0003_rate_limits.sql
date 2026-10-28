-- Shared rate-limit state for the "postgres" backend, so lockouts and
-- per-IP budgets hold across every replica. Keys are namespaced by the
-- application (e.g. "login:<email>", "auth-ip:<ip>"). Rows are pruned
-- opportunistically once their window and lockout have expired.
CREATE TABLE rate_limits (
    key          TEXT    PRIMARY KEY,
    count        INTEGER NOT NULL DEFAULT 0,
    window_start BIGINT  NOT NULL,
    locked_until BIGINT,
    updated_at   BIGINT  NOT NULL
);

CREATE INDEX idx_rate_limits_updated_at ON rate_limits (updated_at);
