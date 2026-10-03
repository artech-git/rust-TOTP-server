# ---- build stage ----
FROM rust:1.88-slim-bookworm AS builder
WORKDIR /app

# Cache dependencies: build against a stub main, then the real sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --quiet 2>/dev/null || true
RUN rm -rf src

COPY migrations ./migrations
COPY web ./web
COPY src ./src
# Touch so cargo rebuilds with the real sources.
RUN touch src/main.rs src/lib.rs && cargo build --release

# ---- runtime stage ----
FROM debian:bookworm-slim AS runtime
# ca-certificates lets rustls verify the Postgres TLS chain when you use
# sslmode=verify-full (Supabase supports it).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /app appuser \
    && chown -R appuser:appuser /app

WORKDIR /app
COPY --from=builder /app/target/release/totp-server /usr/local/bin/totp-server

USER appuser
EXPOSE 3000
ENV TOTP_SERVER__HOST=0.0.0.0 \
    TOTP_SERVER__PORT=3000 \
    RUST_LOG=info,sqlx=warn

# The server is stateless — all data lives in Postgres (Supabase). It applies
# its embedded migrations on startup. Provide the connection string and keys at
# runtime (hosts that inject PORT / DATABASE_URL, e.g. Render, are honored too):
#   docker run \
#     -e DATABASE_URL="postgres://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:5432/postgres?sslmode=require" \
#     -e TOTP_SECURITY__SECRET_ENCRYPTION_KEY=... \
#     -e TOTP_SECURITY__PASETO_KEY=... \
#     -p 3000:3000 totp-server
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/totp-server", "--version"]

ENTRYPOINT ["/usr/local/bin/totp-server"]
