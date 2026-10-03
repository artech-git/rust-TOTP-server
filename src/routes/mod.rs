pub mod account;
pub mod auth;
pub mod meta;

use std::time::Duration;

use axum::{
    Router,
    http::{HeaderValue, Method, StatusCode, header},
    routing::{delete, get, post},
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{error::ApiError, state::AppState};

/// Validate and normalize an email address (trimmed, lowercased).
pub fn normalize_email(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.len() > 254 {
        return Err(ApiError::BadRequest("email is too long".into()));
    }
    trimmed
        .parse::<email_address::EmailAddress>()
        .map_err(|_| ApiError::BadRequest("invalid email address".into()))?;
    Ok(trimmed.to_ascii_lowercase())
}

/// Assemble the full application router with middleware stack.
pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/enroll", post(auth::enroll))
        .route("/enroll/confirm", post(auth::confirm))
        .route("/login", post(auth::login))
        .route("/login/recovery", post(auth::login_recovery))
        .route("/me", get(account::me))
        .route("/me", delete(account::delete_me))
        .route("/recovery/regenerate", post(account::regenerate_recovery));

    Router::new()
        .route("/", get(meta::index))
        .route("/health", get(meta::health))
        .route("/metrics", get(meta::metrics))
        .route("/api-docs/openapi.json", get(meta::openapi_json))
        .route("/docs", get(meta::swagger_ui))
        .nest("/api/v1", api)
        .layer(axum::middleware::from_fn(crate::metrics::track_http))
        .layer(cors_layer(&state))
        // TOTP/recovery payloads are tiny; cap bodies to reject abuse early.
        .layer(RequestBodyLimitLayer::new(16 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn cors_layer(state: &AppState) -> CorsLayer {
    let origins = &state.cfg.server.cors_allowed_origins;
    let base = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .max_age(Duration::from_secs(3600));

    if origins.iter().any(|o| o == "*") {
        base.allow_origin(AllowOrigin::any())
    } else if origins.is_empty() {
        base
    } else {
        let parsed: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();
        base.allow_origin(parsed)
    }
}
