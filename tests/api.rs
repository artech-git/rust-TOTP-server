//! End-to-end API tests driving the real router over a Postgres database.
//!
//! Point `TEST_DATABASE_URL` (or `DATABASE_URL`) at a throwaway Postgres and
//! these run for real; each test gets its own schema so they stay isolated and
//! independently re-runnable. With neither variable set (e.g. a machine with no
//! Postgres) every test skips with a notice instead of failing — CI always
//! provides a database, so coverage there is unaffected.

use std::sync::atomic::{AtomicU32, Ordering};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use totp_server::{AppConfig, AppState, build_router, config::Argon2Config, totp::TotpService};
use tower::ServiceExt;

/// Build the app against a fresh, isolated schema, or `None` when no test
/// database is configured (the caller then skips the test).
async fn test_app() -> Option<(Router, AppState)> {
    static SCHEMA_SEQ: AtomicU32 = AtomicU32::new(0);

    let Some(url) = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
        .filter(|u| !u.trim().is_empty())
    else {
        eprintln!(
            "skipping DB-backed test: set TEST_DATABASE_URL (or DATABASE_URL) to a Postgres URL"
        );
        return None;
    };

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
    };
    cfg.security.recovery_code_count = 4;
    let state = AppState::new(cfg).await.expect("state");
    Some((build_router(state.clone()), state))
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
        .cipher
        .open(&user.secret_enc, email.as_bytes())
        .unwrap();
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
        .cipher
        .open(&user.secret_enc, email.as_bytes())
        .unwrap();

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
