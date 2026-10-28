//! End-to-end API tests driving the real router over a Postgres database.
//!
//! Point `TEST_DATABASE_URL` (or `DATABASE_URL`) at a throwaway Postgres and
//! these run for real; each test gets its own schema so they stay isolated and
//! independently re-runnable. With neither variable set (e.g. a machine with no
//! Postgres) every test skips with a notice instead of failing. When `CI` is
//! set the skip is disabled and a missing database fails the run, so a
//! misconfigured pipeline can never go green with zero coverage.
//!
//! Schemas from a previous run are dropped the first time a test connects, so
//! a shared test database does not accumulate them.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use totp_server::{
    AppConfig, AppState, build_router,
    config::{Argon2Config, RateLimitBackendKind},
    crypto::generate_key_hex,
    ops::rekey_all,
    store::Store,
    totp::TotpService,
};
use tower::ServiceExt;

/// Build the app against a fresh, isolated schema, or `None` when no test
/// database is configured (the caller then skips the test).
async fn test_app() -> Option<(Router, AppState)> {
    test_app_with(|_| {}).await
}

/// Like [`test_app`], with a hook to adjust the configuration first.
async fn test_app_with(customize: impl FnOnce(&mut AppConfig)) -> Option<(Router, AppState)> {
    let mut cfg = fresh_config().await?;
    customize(&mut cfg);
    let state = AppState::new(cfg).await.expect("state");
    Some((build_router(state.clone()), state))
}

/// A second, independent `AppState` on the same schema: stands in for another
/// replica of the service behind a load balancer.
async fn replica_of(state: &AppState) -> Router {
    let cfg = (*state.cfg).clone();
    build_router(AppState::new(cfg).await.expect("replica state"))
}

/// Test configuration pointing at a fresh, isolated schema, or `None` when no
/// test database is configured (the caller then skips the test).
async fn fresh_config() -> Option<AppConfig> {
    static SCHEMA_SEQ: AtomicU32 = AtomicU32::new(0);

    let Some(url) = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
        .filter(|u| !u.trim().is_empty())
    else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI is set but no TEST_DATABASE_URL/DATABASE_URL is configured; \
             the DB-backed tests must not be skipped in CI"
        );
        eprintln!(
            "skipping DB-backed test: set TEST_DATABASE_URL (or DATABASE_URL) to a Postgres URL"
        );
        return None;
    };

    sweep_stale_schemas(&url).await;

    let mut cfg = AppConfig::default();
    cfg.database.url = url;
    // A unique schema per test gives SQLite-`:memory:`-style isolation on a
    // single shared Postgres database.
    cfg.database.schema = Some(format!(
        "totp_test_{}_{}",
        std::process::id(),
        SCHEMA_SEQ.fetch_add(1, Ordering::Relaxed),
    ));
    cfg.security.secret_encryption_key = Some(totp_server::crypto::generate_key_hex());
    cfg.security.paseto_key = Some(totp_server::crypto::generate_key_hex());
    // Keep Argon2 cheap so the recovery-code tests stay fast.
    cfg.security.argon2 = Argon2Config {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
        ..Argon2Config::default()
    };
    cfg.security.recovery_code_count = 4;
    Some(cfg)
}

/// Drop `totp_test_*` schemas left behind by earlier runs (other PIDs). Runs
/// once per test process; this run's own schemas are left for the next run.
async fn sweep_stale_schemas(url: &str) {
    static SWEPT: Mutex<bool> = Mutex::new(false);
    {
        let mut swept = SWEPT.lock().unwrap();
        if *swept {
            return;
        }
        *swept = true;
    }

    use sqlx::{Connection, Row, postgres::PgConnection};
    let mut conn = PgConnection::connect(url).await.expect("connect for sweep");
    let own_prefix = format!("totp_test_{}_", std::process::id());
    let stale: Vec<String> = sqlx::query(
        "SELECT schema_name FROM information_schema.schemata \
         WHERE schema_name LIKE 'totp_test_%' AND schema_name NOT LIKE $1",
    )
    .bind(format!("{own_prefix}%"))
    .fetch_all(&mut conn)
    .await
    .expect("list schemas")
    .into_iter()
    .map(|r| r.get::<String, _>("schema_name"))
    .collect();
    for schema in stale {
        // Names come from information_schema and match our own pattern, so
        // quoting them is sufficient.
        sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&mut conn)
            .await
            .expect("drop stale schema");
    }
    conn.close().await.ok();
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = bearer {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = if let Some(b) = body {
        req.header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string()))
            .unwrap()
    } else {
        req.body(Body::empty()).unwrap()
    };
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

/// Drive a full enroll → confirm → login happy path; returns the session token.
async fn enroll_confirm_login(
    app: &Router,
    state: &AppState,
    email: &str,
) -> (String, Vec<String>) {
    let (status, body) = call(
        app,
        "POST",
        "/api/v1/enroll",
        Some(json!({"email": email})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enroll: {body}");
    assert!(body["qr_svg"].as_str().unwrap().contains("svg"));

    // Recover the raw secret from the store to compute a valid code.
    let user = state.store.get_user_by_email(email).await.unwrap().unwrap();
    let secret = state
        .keys
        .open(
            &user.secret_enc,
            user.secret_key_id.as_deref(),
            email.as_bytes(),
        )
        .unwrap()
        .plaintext;
    let code = state.totp.code_at(&secret, TotpService::now()).unwrap();

    let (status, body) = call(
        app,
        "POST",
        "/api/v1/enroll/confirm",
        Some(json!({"email": email, "code": code})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm: {body}");
    let codes: Vec<String> = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_eq!(codes.len(), 4);

    let (status, body) = call(
        app,
        "POST",
        "/api/v1/login",
        Some(json!({"email": email, "code": code})),
        None,
    )
    .await;
    // Same code was just consumed by confirm → replay rejected. Use the next step.
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "login replay must fail: {body}"
    );

    let future = state
        .totp
        .code_at(&secret, TotpService::now() + 30)
        .unwrap();
    let (status, body) = call(
        app,
        "POST",
        "/api/v1/login",
        Some(json!({"email": email, "code": future})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login: {body}");
    (body["token"].as_str().unwrap().to_string(), codes)
}

#[tokio::test]
async fn full_happy_path_and_me() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let (token, _) = enroll_confirm_login(&app, &state, "alice@example.com").await;

    let (status, body) = call(&app, "GET", "/api/v1/me", None, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["recovery_codes_remaining"], 4);
}

#[tokio::test]
async fn totp_replay_is_rejected() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let email = "replay@example.com";
    call(
        &app,
        "POST",
        "/api/v1/enroll",
        Some(json!({"email": email})),
        None,
    )
    .await;
    let user = state.store.get_user_by_email(email).await.unwrap().unwrap();
    let secret = state
        .keys
        .open(
            &user.secret_enc,
            user.secret_key_id.as_deref(),
            email.as_bytes(),
        )
        .unwrap()
        .plaintext;

    let code = state.totp.code_at(&secret, TotpService::now()).unwrap();
    call(
        &app,
        "POST",
        "/api/v1/enroll/confirm",
        Some(json!({"email": email, "code": code})),
        None,
    )
    .await;

    let future = state
        .totp
        .code_at(&secret, TotpService::now() + 30)
        .unwrap();
    let (s1, _) = call(
        &app,
        "POST",
        "/api/v1/login",
        Some(json!({"email": email, "code": future})),
        None,
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    // Immediately replay the exact same code.
    let (s2, _) = call(
        &app,
        "POST",
        "/api/v1/login",
        Some(json!({"email": email, "code": future})),
        None,
    )
    .await;
    assert_eq!(
        s2,
        StatusCode::UNAUTHORIZED,
        "replayed code must be rejected"
    );
}

#[tokio::test]
async fn recovery_code_login_burns_the_code() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let email = "recover@example.com";
    let (_, codes) = enroll_confirm_login(&app, &state, email).await;

    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/login/recovery",
        Some(json!({"email": email, "recovery_code": codes[0]})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "recovery login: {body}");

    // Same code cannot be used twice.
    let (status, _) = call(
        &app,
        "POST",
        "/api/v1/login/recovery",
        Some(json!({"email": email, "recovery_code": codes[0]})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A different, unused code still works.
    let (status, _) = call(
        &app,
        "POST",
        "/api/v1/login/recovery",
        Some(json!({"email": email, "recovery_code": codes[1]})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn login_is_rate_limited_and_locks_out() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let email = "lock@example.com";
    enroll_confirm_login(&app, &state, email).await;

    // Default budget is 5 failures. Burn them with wrong codes.
    for _ in 0..5 {
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/login",
            Some(json!({"email": email, "code": "000000"})),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // Next attempt is locked out regardless of correctness.
    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/login",
        Some(json!({"email": email, "code": "000000"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "rate_limited");
}

#[tokio::test]
async fn unconfirmed_and_unknown_users_cannot_log_in() {
    let Some((app, _state)) = test_app().await else {
        return;
    };
    // Unknown user.
    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/login",
        Some(json!({"email": "ghost@example.com", "code": "123456"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body["message"], "invalid credentials",
        "must not leak user existence"
    );

    // Enrolled-but-unconfirmed user.
    call(
        &app,
        "POST",
        "/api/v1/enroll",
        Some(json!({"email": "pending@example.com"})),
        None,
    )
    .await;
    let (status, _) = call(
        &app,
        "POST",
        "/api/v1/login",
        Some(json!({"email": "pending@example.com", "code": "123456"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn duplicate_enrollment_of_confirmed_account_conflicts() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let email = "dupe@example.com";
    enroll_confirm_login(&app, &state, email).await;

    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/enroll",
        Some(json!({"email": email})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn invalid_email_is_rejected() {
    let Some((app, _state)) = test_app().await else {
        return;
    };
    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/enroll",
        Some(json!({"email": "not-an-email"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "bad_request");
}

#[tokio::test]
async fn protected_routes_require_a_valid_token() {
    let Some((app, _state)) = test_app().await else {
        return;
    };
    let (status, _) = call(&app, "GET", "/api/v1/me", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&app, "GET", "/api/v1/me", None, Some("v4.local.garbage")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn regenerate_recovery_invalidates_old_codes() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let email = "regen@example.com";
    let (token, old_codes) = enroll_confirm_login(&app, &state, email).await;

    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/recovery/regenerate",
        None,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let new_codes: Vec<String> = body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_string())
        .collect();
    assert_ne!(new_codes, old_codes);

    // Old code no longer valid.
    let (status, _) = call(
        &app,
        "POST",
        "/api/v1/login/recovery",
        Some(json!({"email": email, "recovery_code": old_codes[0]})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // New code works.
    let (status, _) = call(
        &app,
        "POST",
        "/api/v1/login/recovery",
        Some(json!({"email": email, "recovery_code": new_codes[0]})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn delete_account_removes_access() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let (token, _) = enroll_confirm_login(&app, &state, "delete@example.com").await;

    let (status, _) = call(&app, "DELETE", "/api/v1/me", None, Some(&token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Token is now stale: the user no longer exists.
    let (status, _) = call(&app, "GET", "/api/v1/me", None, Some(&token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn health_and_openapi_are_served() {
    let Some((app, _state)) = test_app().await else {
        return;
    };
    let (status, body) = call(&app, "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    let (status, body) = call(&app, "GET", "/api-docs/openapi.json", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["openapi"].as_str().unwrap().chars().next(), Some('3'));
}

#[tokio::test]
async fn login_family_is_throttled_per_client_ip() {
    let Some((app, _state)) = test_app_with(|cfg| cfg.rate_limit.auth_ip_max_per_window = 2).await
    else {
        return;
    };
    // Different emails from the same client: the per-IP budget is shared by
    // login, confirm and recovery, so the third attempt is throttled.
    for i in 0..2 {
        let (status, body) = call(
            &app,
            "POST",
            "/api/v1/login",
            Some(json!({"email": format!("u{i}@example.com"), "code": "000000"})),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }
    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/login/recovery",
        Some(json!({"email": "u9@example.com", "recovery_code": "AAAA-AAAA-AAAA"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "rate_limited");
}

#[tokio::test]
async fn metrics_require_the_configured_token() {
    let Some((app, _state)) =
        test_app_with(|cfg| cfg.server.metrics_token = Some("scrape-me".into())).await
    else {
        return;
    };
    let (status, _) = call(&app, "GET", "/metrics", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&app, "GET", "/metrics", None, Some("wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(&app, "GET", "/metrics", None, Some("scrape-me")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn responses_carry_hardening_headers_and_a_request_id() {
    let Some((app, _state)) = test_app().await else {
        return;
    };
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let headers = resp.headers();
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert!(
        headers.get("x-request-id").is_some(),
        "request id is echoed"
    );
    assert!(
        headers.get("strict-transport-security").is_none(),
        "HSTS is opt-in"
    );

    // API responses are never cacheable.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"email":"x@example.com","code":"000000"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn legacy_recovery_codes_without_a_lookup_prefix_still_work() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let email = "legacy@example.com";
    enroll_confirm_login(&app, &state, email).await;
    let user = state.store.get_user_by_email(email).await.unwrap().unwrap();

    // Simulate a row written before the lookup column existed.
    let legacy_code = totp_server::recovery::generate_codes(1).remove(0);
    let hash = state.recovery_hasher.hash(&legacy_code).unwrap();
    use sqlx::Connection;
    let url = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap();
    let schema = state.cfg.database.schema.clone().unwrap();
    let mut conn = sqlx::postgres::PgConnection::connect(&url).await.unwrap();
    sqlx::query(&format!("SET search_path TO \"{schema}\""))
        .execute(&mut conn)
        .await
        .unwrap();
    sqlx::query("INSERT INTO recovery_codes (user_id, code_hash, lookup) VALUES ($1, $2, NULL)")
        .bind(&user.id)
        .bind(&hash)
        .execute(&mut conn)
        .await
        .unwrap();

    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/login/recovery",
        Some(json!({"email": email, "recovery_code": legacy_code})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // ...and it is burned like any other code.
    let (status, _) = call(
        &app,
        "POST",
        "/api/v1/login/recovery",
        Some(json!({"email": email, "recovery_code": legacy_code})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

async fn wrong_login(app: &Router, email: &str) -> StatusCode {
    call(
        app,
        "POST",
        "/api/v1/login",
        Some(json!({"email": email, "code": "000000"})),
        None,
    )
    .await
    .0
}

#[tokio::test]
async fn memory_backend_limits_are_per_instance() {
    let Some((a, state)) = test_app_with(|cfg| cfg.rate_limit.login_max_failures = 3).await else {
        return;
    };
    let b = replica_of(&state).await;
    for _ in 0..3 {
        assert_eq!(
            wrong_login(&a, "solo@example.com").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        wrong_login(&a, "solo@example.com").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // The other instance never saw the failures, so it still lets the
    // attempt through: this is why replicas need the postgres backend.
    assert_eq!(
        wrong_login(&b, "solo@example.com").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn postgres_backend_shares_lockouts_and_ip_budgets_between_replicas() {
    let Some((a, state)) = test_app_with(|cfg| {
        cfg.rate_limit.backend = RateLimitBackendKind::Postgres;
        cfg.rate_limit.login_max_failures = 3;
        cfg.rate_limit.auth_ip_max_per_window = 5;
    })
    .await
    else {
        return;
    };
    let b = replica_of(&state).await;

    // Three failures on replica A lock the account...
    for _ in 0..3 {
        assert_eq!(
            wrong_login(&a, "shared@example.com").await,
            StatusCode::UNAUTHORIZED
        );
    }
    // ...and replica B enforces the lockout without having seen any of them.
    assert_eq!(
        wrong_login(&b, "shared@example.com").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // The per-IP budget (5) is shared as well: four attempts so far, one more
    // passes, the next is throttled even though it targets another account
    // through the other replica.
    assert_eq!(
        wrong_login(&b, "other@example.com").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        wrong_login(&a, "third@example.com").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn startup_verifies_the_schema_when_migrations_are_not_applied_on_start() {
    let Some(mut cfg) = fresh_config().await else {
        return;
    };
    cfg.database.run_migrations_on_start = false;
    cfg.database.connect_retries = 0;

    let err = AppState::new(cfg.clone())
        .await
        .err()
        .expect("a replica must refuse to start against a schema with no migrations");
    assert!(
        format!("{err:#}").contains("totp-server migrate"),
        "{err:#}"
    );

    Store::migrate(&cfg.database)
        .await
        .expect("migrate command");
    AppState::new(cfg)
        .await
        .expect("schema is current once the migrate command has run");
}

#[tokio::test]
async fn livez_is_served_alongside_health() {
    let Some((app, _state)) = test_app().await else {
        return;
    };
    let (status, body) = call(&app, "GET", "/livez", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "alive");
    let (status, body) = call(&app, "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn logout_revokes_every_session_for_the_account() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let email = "bye@example.com";
    let (first, codes) = enroll_confirm_login(&app, &state, email).await;
    // A second session, through a recovery code.
    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/login/recovery",
        Some(json!({"email": email, "recovery_code": codes[0]})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let second = body["token"].as_str().unwrap().to_string();
    for token in [&first, &second] {
        let (status, _) = call(&app, "GET", "/api/v1/me", None, Some(token)).await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, _) = call(&app, "POST", "/api/v1/logout", None, Some(&first)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    for token in [&first, &second] {
        let (status, _) = call(&app, "GET", "/api/v1/me", None, Some(token)).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "revoked sessions are rejected"
        );
    }
    let (status, _) = call(&app, "POST", "/api/v1/logout", None, Some(&first)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked session cannot act"
    );

    // Logging in again issues a working session under the new version.
    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/login/recovery",
        Some(json!({"email": email, "recovery_code": codes[1]})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = call(
        &app,
        "GET",
        "/api/v1/me",
        None,
        Some(body["token"].as_str().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn rotating_the_encryption_key_reseals_secrets_as_they_are_used() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let email = "rotate@example.com";
    let (status, _) = call(
        &app,
        "POST",
        "/api/v1/enroll",
        Some(json!({"email": email})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let before = state.store.get_user_by_email(email).await.unwrap().unwrap();
    assert_eq!(
        before.secret_key_id.as_deref(),
        Some(state.keys.active_id())
    );
    let secret = state
        .keys
        .open(
            &before.secret_enc,
            before.secret_key_id.as_deref(),
            email.as_bytes(),
        )
        .unwrap()
        .plaintext;
    let now = TotpService::now();
    let (status, body) = call(
        &app,
        "POST",
        "/api/v1/enroll/confirm",
        Some(json!({"email": email, "code": state.totp.code_at(&secret, now).unwrap()})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Rotate: a new active key, the previous one retired.
    let mut cfg = (*state.cfg).clone();
    let old_key = cfg.security.secret_encryption_key.clone().unwrap();
    cfg.security.secret_encryption_key = Some(generate_key_hex());
    cfg.security.retired_encryption_keys = vec![old_key];
    let rotated = AppState::new(cfg.clone()).await.unwrap();
    let rotated_app = build_router(rotated.clone());
    assert_ne!(rotated.keys.active_id(), state.keys.active_id());

    // Logging in through the rotated instance works and re-seals the row...
    let (status, body) = call(
        &rotated_app,
        "POST",
        "/api/v1/login",
        Some(json!({"email": email, "code": state.totp.code_at(&secret, now + 30).unwrap()})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = state.store.get_user_by_email(email).await.unwrap().unwrap();
    assert_eq!(
        after.secret_key_id.as_deref(),
        Some(rotated.keys.active_id())
    );
    assert_ne!(after.secret_enc, before.secret_enc);

    // ...so an instance that only knows the new key can read it, while the
    // old key alone no longer can.
    cfg.security.retired_encryption_keys.clear();
    let new_only = AppState::new(cfg).await.unwrap();
    assert_eq!(
        new_only
            .keys
            .open(
                &after.secret_enc,
                after.secret_key_id.as_deref(),
                email.as_bytes()
            )
            .unwrap()
            .plaintext,
        secret
    );
    assert!(
        state
            .keys
            .open(
                &after.secret_enc,
                after.secret_key_id.as_deref(),
                email.as_bytes()
            )
            .is_err()
    );
}

#[tokio::test]
async fn rekey_reseals_every_row_at_once() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    for i in 0..3 {
        let (status, _) = call(
            &app,
            "POST",
            "/api/v1/enroll",
            Some(json!({"email": format!("bulk{i}@example.com")})),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    let mut cfg = (*state.cfg).clone();
    let old_key = cfg.security.secret_encryption_key.clone().unwrap();
    cfg.security.secret_encryption_key = Some(generate_key_hex());
    cfg.security.retired_encryption_keys = vec![old_key];
    let rotated = AppState::new(cfg.clone()).await.unwrap();

    let report = rekey_all(&rotated.store, &rotated.keys).await.unwrap();
    assert_eq!(report.examined, 3);
    assert_eq!(report.resealed, 3);
    assert_eq!(report.skipped, 0);
    // Idempotent: nothing left to do.
    let again = rekey_all(&rotated.store, &rotated.keys).await.unwrap();
    assert_eq!(again.resealed, 0);

    cfg.security.retired_encryption_keys.clear();
    let new_only = AppState::new(cfg).await.unwrap();
    for i in 0..3 {
        let email = format!("bulk{i}@example.com");
        let user = state
            .store
            .get_user_by_email(&email)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            user.secret_key_id.as_deref(),
            Some(new_only.keys.active_id())
        );
        assert!(
            new_only
                .keys
                .open(
                    &user.secret_enc,
                    user.secret_key_id.as_deref(),
                    email.as_bytes()
                )
                .is_ok()
        );
    }
}

#[tokio::test]
async fn rotating_the_session_key_keeps_existing_sessions_until_they_expire() {
    let Some((app, state)) = test_app().await else {
        return;
    };
    let (token, _) = enroll_confirm_login(&app, &state, "paseto@example.com").await;

    let mut cfg = (*state.cfg).clone();
    let old_key = cfg.security.paseto_key.clone().unwrap();
    cfg.security.paseto_key = Some(generate_key_hex());
    cfg.security.retired_paseto_keys = vec![old_key];
    let rotated = build_router(AppState::new(cfg.clone()).await.unwrap());
    let (status, _) = call(&rotated, "GET", "/api/v1/me", None, Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "old sessions survive the rotation");

    cfg.security.retired_paseto_keys.clear();
    let dropped = build_router(AppState::new(cfg).await.unwrap());
    let (status, _) = call(&dropped, "GET", "/api/v1/me", None, Some(&token)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "dropping the retired key ends its sessions"
    );
}
