<div align="center">
  <img src="./assets/key-chain.png" width="90" height="90"/>
  <h1>TOTP Server</h1>
  <p><b>A hardened RFC 6238 two-factor-authentication server in Rust.</b></p>
  <p>
    <img alt="rust" src="https://img.shields.io/badge/rust-1.94%2B-orange"/>
    <img alt="axum" src="https://img.shields.io/badge/axum-0.8-blue"/>
    <img alt="license" src="https://img.shields.io/badge/license-MIT-green"/>
  </p>
</div>

---

A small, fast TOTP service built on **axum 0.8** and **Postgres** (**Supabase** in
production). It issues authenticator-app secrets, verifies 6–8 digit codes, hands out PASETO
session tokens, and ships with recovery codes, replay protection, rate limiting, a Swagger
UI, Prometheus metrics, and a demo web UI. It runs end-to-end on **free tiers** — Render for
compute, Supabase for the database (see [Deployment](#deployment)).

```bash
docker compose up -d   # local Postgres on :54322 (or run `supabase start`)
cargo run              # starts on http://localhost:3000  (open it in a browser)
```

> The server is stateless; all data lives in Postgres, and it applies its embedded
> migrations on startup. With no database reachable it won't boot — bring one up first.

## Why this exists

This started as a learning project wired directly to DynamoDB with credentials committed to
the repo, no encryption of secrets at rest, no rate limiting, no replay protection, and TOTP
codes compared with `==`. It has been **re-architected from scratch** into a layered,
testable service with the security properties a 2FA server actually needs.

## Features

| | |
|---|---|
| 🔐 **Secrets encrypted at rest** | TOTP secrets are sealed with XChaCha20-Poly1305, bound to the owning email (AAD). A stolen database dump reveals nothing without the key. |
| 🎫 **PASETO v4.local sessions** | Stateless, encrypted, expiring bearer tokens — no JWT `alg` footguns. |
| 🔁 **Replay protection** | Each accepted code's time-step is recorded; the same code can never be used twice, enforced atomically in SQL. |
| 🧯 **Recovery codes** | One-time backup codes (Argon2id-hashed) for lost devices, regenerable from the API. |
| 🚦 **Rate limiting & lockout** | Per-account failure lockout plus per-IP throttles on enrollment and on every login-family endpoint. |
| ⏱️ **Constant-time checks** | Codes compared with `subtle`; no user-enumeration (login always returns a generic 401). |
| 📖 **OpenAPI + Swagger UI** | Interactive docs at `/docs`, spec at `/api-docs/openapi.json`. |
| 📊 **Prometheus metrics** | Request and auth-event counters/histograms at `/metrics`. |
| 🖥️ **Demo web UI** | Full enroll → scan → confirm → login flow at `/`. |

## Architecture

The crate is a library (`src/lib.rs`) plus a thin binary (`src/main.rs`), so every
security-critical piece is unit-testable and reused by the integration suite.

```
src/
├── config.rs      Layered config (defaults → settings.toml → TOTP_* env), validated
├── crypto.rs      XChaCha20-Poly1305 sealing of secrets at rest
├── totp.rs        RFC 6238 generate/verify with drift window + constant-time compare
├── tokens.rs      PASETO v4.local session issue/verify
├── recovery.rs    One-time recovery codes (Argon2id)
├── ratelimit.rs   Failure-lockout + fixed-window limiters
├── store.rs       Postgres persistence; atomic, replay-safe updates
├── state.rs       Shared AppState wiring the services together
├── extract.rs     Axum extractors: Bearer auth + client IP
├── metrics.rs     Prometheus recorder + HTTP middleware
├── error.rs       Typed API errors → JSON responses
├── openapi.rs     OpenAPI 3.1 document
└── routes/        enroll · confirm · login · recovery · account · meta
migrations/        Embedded Postgres migrations (run on startup)
web/index.html     Demo UI (served at / and publishable to Netlify)
tests/api.rs       End-to-end tests over the real router; each isolates into its own schema
```

## API

Base path `/api/v1`. Full schema at `/docs`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/enroll` | — | Provision a secret; returns QR + `otpauth://` URL |
| `POST` | `/enroll/confirm` | — | Confirm with first code; returns recovery codes (shown once) |
| `POST` | `/login` | — | Exchange a TOTP code for a session token |
| `POST` | `/login/recovery` | — | Log in with a one-time recovery code |
| `GET` | `/me` | Bearer | Current account + recovery codes remaining |
| `POST` | `/recovery/regenerate` | Bearer | Replace recovery codes |
| `POST` | `/logout` | Bearer | Log out everywhere (revoke every session for the account) |
| `DELETE` | `/me` | Bearer | Delete the account and all its data |
| `GET` | `/health` · `/metrics` · `/docs` | — | Ops endpoints |

### Example

```bash
# 1. Enroll — returns a secret, otpauth URL, and an inline SVG QR code
curl -s -XPOST localhost:3000/api/v1/enroll \
  -H 'content-type: application/json' -d '{"email":"alice@example.com"}'

# 2. Add the otpauth URL to your authenticator, then confirm with the code it shows
curl -s -XPOST localhost:3000/api/v1/enroll/confirm \
  -H 'content-type: application/json' -d '{"email":"alice@example.com","code":"123456"}'
#    → { "confirmed": true, "recovery_codes": ["ABCD-EFGH-JKMN", ...] }

# 3. Log in to get a session token
curl -s -XPOST localhost:3000/api/v1/login \
  -H 'content-type: application/json' -d '{"email":"alice@example.com","code":"654321"}'
#    → { "token": "v4.local....", "expires_at": 1735689600, ... }
```

## Configuration

Config resolves from built-in defaults → `settings.toml` (override path with `TOTP_CONFIG`)
→ `TOTP_*` environment variables (highest precedence). See
[`settings.example.toml`](./settings.example.toml) for every option.

**Generate the required keys** (encryption + session signing):

```bash
cargo run -- keygen      # prints secret_encryption_key and paseto_key
```

Set them under `[security]` in `settings.toml`, or as
`TOTP_SECURITY__SECRET_ENCRYPTION_KEY` / `TOTP_SECURITY__PASETO_KEY`. Without them the
server boots with **ephemeral** keys (dev only — data is unreadable after a restart) and
logs a warning.

## Deployment

The whole stack runs on **free tiers**: Supabase (Postgres), Render (compute), and
optionally Netlify (demo UI). Nothing here needs a paid plan.

```
Netlify (static UI)  ──calls──▶  Render (Rust API, free web service)  ──▶  Supabase Postgres
```

### 1. Database — Supabase (free)

1. Create a project at [supabase.com](https://supabase.com) (free plan).
2. **Connect → Session pooler**, and copy the URI. It looks like:
   `postgres://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres`
   Append `?sslmode=require`.

   > The **Session** pooler (port **5432**) works as is. The **Transaction** pooler (6543)
   > shares server connections between clients, so set `database.pooler_mode = "transaction"`
   > for it (this turns off sqlx's prepared-statement cache). The direct connection also works
   > but is IPv6-only, which Render/Fly egress may not have.

   No schema setup is needed — the server creates its tables on first boot via the embedded
   migrations. (Free Postgres pauses after ~7 days of inactivity; the first request wakes it.)

### 2. Compute — Render (free)

[`render.yaml`](./render.yaml) is a Blueprint for a free Docker web service. Create a
Blueprint from this repo in the Render dashboard, then set the `sync: false` env vars:

| Env var | Value |
|---|---|
| `DATABASE_URL` | the Supabase Session pooler URI from step 1 |
| `TOTP_SECURITY__SECRET_ENCRYPTION_KEY` | `cargo run -- keygen` (64 hex) |
| `TOTP_SECURITY__PASETO_KEY` | `cargo run -- keygen` (64 hex) |
| `TOTP_SERVER__CORS_ALLOWED_ORIGINS` | e.g. `["https://your-ui.netlify.app"]` |

Render injects `PORT` (honored automatically) and sets `TRUST_PROXY=true` from the
blueprint. It auto-deploys on every push to `main`. Free web services spin down after ~15
min idle and cold-start on the next request. (Fly.io works too — the same `Dockerfile`
deploys there; just supply `DATABASE_URL` and the keys.)

### 3. Demo UI — Netlify (optional, free)

[`netlify.toml`](./netlify.toml) publishes the static UI in [`web/`](./web). After deploy,
open the site, expand **Settings**, and point **API base URL** at your Render URL. (The same
`web/index.html` is also served at `/` by the API for same-origin use.)

### Local / self-hosted (Docker)

The image is stateless — point it at any Postgres:

```bash
docker build -t totp-server .
docker run -p 3000:3000 \
  -e DATABASE_URL='postgres://user:pw@host:5432/db?sslmode=require' \
  -e TOTP_SECURITY__SECRET_ENCRYPTION_KEY=<64 hex> \
  -e TOTP_SECURITY__PASETO_KEY=<64 hex> \
  totp-server
```

## Scaling out

The service is stateless apart from its rate-limit counters, and the two things that must be
exact across instances — TOTP replay protection and recovery-code burning — are atomic
conditional updates in Postgres. Running several replicas behind a load balancer is therefore
safe once the counters are shared:

1. **Share the rate limits.** Set `rate_limit.backend = "postgres"`
   (`TOTP_RATE_LIMIT__BACKEND=postgres`). Account lockouts and per-IP budgets then live in the
   `rate_limits` table and are enforced by every replica; each check is one small upsert. The
   default `memory` backend is per process and only correct for a single instance.
2. **Apply migrations once per deploy, not once per replica.** Set
   `database.run_migrations_on_start = false` and run `totp-server migrate` as a release-phase
   or pre-deploy job. Replicas then verify the schema version at boot and refuse to start
   against a stale one.
3. **Use a transaction pooler when replicas multiply.** Supabase's transaction pooler (port
   6543) and PgBouncer share server connections; with `database.pooler_mode = "transaction"`
   the prepared-statement cache is disabled so that works. Keep the sum of `max_connections`
   across replicas under the pooler's client limit.
4. **Probe the right things.** `/livez` answers whenever the process is up and is the
   liveness probe (it is also what the Docker `HEALTHCHECK` calls through
   `totp-server healthcheck`); `/health` additionally pings the database and is the readiness
   probe. Keeping them apart means a database blip does not restart every replica at once.
5. **Let the database come up.** Startup retries the connection with backoff
   (`database.connect_retries`), so a paused free-tier database or a slow boot does not
   crash-loop the service.

Capacity: one small instance serves on the order of 10k authenticated requests/s against a
loopback database; the only expensive operation is Argon2id for recovery codes (~20 ms per
hash, bounded by `argon2.max_concurrency`). Replicas are for availability and regional latency
more than throughput. Keep them in one region next to the single Postgres primary, since the
login path writes on every request.

## Development

Bring up a local Postgres (or `supabase start`), then:

```bash
docker compose up -d       # Postgres on :54322 (matches the default DATABASE_URL)

cargo test                 # unit tests + 11 integration tests (see note below)
cargo clippy --all-targets # lint
cargo fmt --all            # format
cargo run -- --help        # CLI usage (serve, migrate, healthcheck, keygen)
```

The integration tests in [`tests/api.rs`](./tests/api.rs) need a Postgres; point
`TEST_DATABASE_URL` (or `DATABASE_URL`) at one and each test isolates into its own schema:

```bash
TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:54322/postgres cargo test
```

Without that variable the DB-backed tests **skip** (with a notice) rather than fail, so the
unit tests still run anywhere; with `CI` set they refuse to skip. Each run also drops the
test schemas a previous run left behind. CI (GitHub Actions) spins up a `postgres:16`
service and runs fmt, clippy (`-D warnings`), the full test suite, `cargo audit` against
the lockfile, a `gitleaks` secret scan, and a Docker build on every push and PR. Dependabot
keeps Cargo, Actions and Docker dependencies current, and tagging `vX.Y.Z` publishes the
image to GHCR via the release workflow.

## Security notes

- **One instance by default, more with one setting.** Rate-limit state is in-memory unless
  `rate_limit.backend = "postgres"`; with the default, run one instance (the free-tier model:
  one Render/Fly container in front of Supabase Postgres). See [Scaling out](#scaling-out)
  for the multi-replica setup.
- **Account-lockout tradeoff.** Login failures lock the *account* to stop code brute-forcing;
  this is the standard 2FA control and does allow a known-email actor to force a temporary
  lockout. Tune the window in `[rate_limit]`. A separate per-client-IP budget
  (`auth_ip_max_per_window`) covers login, confirm and recovery together, so one source cannot
  spray attempts across many accounts.
- **Behind a proxy, count your hops.** With `server.trust_proxy`, the client address is read
  from `X-Forwarded-For` *from the end*, `trusted_proxy_hops` entries back (default 1), because
  proxies append and the leading entries are whatever the client sent. If your edge sets a
  dedicated header (Cloudflare's `CF-Connecting-IP`), name it in `client_ip_header` instead.
- **Recovery codes cost one hash.** Each code's first two symbols are stored in clear as an
  index so a recovery attempt verifies a single Argon2id hash (off the async runtime, bounded by
  `argon2.max_concurrency`) instead of every unused code; the remaining ten symbols keep ≈49
  bits behind the hash. Codes issued before this change keep working.
- **Protect `/metrics`.** Set `server.metrics_token` and scrape with `Authorization: Bearer`;
  without it the endpoint is open and the server logs a warning.
- **Sessions can be revoked.** Tokens carry the account's `token_version`; `POST /logout`
  bumps it, which invalidates every session for that account at once. Keep `session_ttl_secs`
  short for anything finer-grained.
- **Rotating keys.** Generate a new key with `keygen`, move the current `secret_encryption_key`
  into `retired_encryption_keys`, set the new one, and deploy. Secrets sealed under the old key
  are re-sealed the next time they are used; run `totp-server rekey` to do them all at once,
  then drop the old key from the list. `paseto_key` rotates the same way via
  `retired_paseto_keys`: old sessions stay valid until they expire, new ones use the new key.

## License

MIT — see [LICENSE](./LICENSE).
