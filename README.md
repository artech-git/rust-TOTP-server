<div align="center">
  <img src="./assets/key-chain.png" width="90" height="90"/>
  <h1>TOTP Server</h1>
  <p><b>A hardened RFC 6238 two-factor-authentication server in Rust.</b></p>
  <p>
    <img alt="rust" src="https://img.shields.io/badge/rust-1.88%2B-orange"/>
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
| 🚦 **Rate limiting & lockout** | Per-account failure lockout and per-IP enrollment throttling. |
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
#    → { "confirmed": true, "recovery_codes": ["ABCDE-FGHJK", ...] }

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

   > Use the **Session** pooler (port **5432**), **not** the Transaction pooler (6543): sqlx
   > relies on prepared statements, which the transaction pooler doesn't support. The direct
   > connection also works but is IPv6-only, which Render/Fly egress may not have.

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

## Development

Bring up a local Postgres (or `supabase start`), then:

```bash
docker compose up -d       # Postgres on :54322 (matches the default DATABASE_URL)

cargo test                 # unit tests + 11 integration tests (see note below)
cargo clippy --all-targets # lint
cargo fmt --all            # format
cargo run -- --help        # CLI usage
```

The integration tests in [`tests/api.rs`](./tests/api.rs) need a Postgres; point
`TEST_DATABASE_URL` (or `DATABASE_URL`) at one and each test isolates into its own schema:

```bash
TEST_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:54322/postgres cargo test
```

Without that variable the DB-backed tests **skip** (with a notice) rather than fail, so the
unit tests still run anywhere. CI (GitHub Actions) spins up a `postgres:16` service and runs
fmt, clippy (`-D warnings`), the full test suite, and a Docker build on every push and PR.

## Security notes

- **Single-instance by design.** Rate-limit state is in-memory, so run one instance (the
  free-tier model: one Render/Fly container in front of Supabase Postgres). The database
  itself scales independently; horizontal *compute* scaling would need a shared store (e.g.
  Redis) for the limiter — a deliberate scope choice.
- **Account-lockout tradeoff.** Login failures lock the *account* to stop code brute-forcing;
  this is the standard 2FA control and does allow a known-email actor to force a temporary
  lockout. Tune the window in `[rate_limit]`.
- **Keep your keys stable and secret.** Rotating `secret_encryption_key` makes stored secrets
  unreadable; rotating `paseto_key` invalidates all live sessions.

## License

MIT — see [LICENSE](./LICENSE).
