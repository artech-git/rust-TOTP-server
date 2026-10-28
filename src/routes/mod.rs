pub mod account;
pub mod auth;
pub mod meta;

use std::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Method, Request, StatusCode, header},
    routing::{delete, get, post},
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    set_header::SetResponseHeaderLayer,
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
        .route("/recovery/regenerate", post(account::regenerate_recovery))
        // Secrets, recovery codes and tokens must never land in a shared cache.
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ));

    let mut app = Router::new()
        .route("/", get(meta::index))
        .route("/health", get(meta::health))
        .route("/metrics", get(meta::metrics))
        .route("/api-docs/openapi.json", get(meta::openapi_json))
        .route("/docs", get(meta::swagger_ui))
        .nest("/api/v1", api)
        .layer(axum::middleware::from_fn(crate::metrics::track_http))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ));
    if let Some(hsts) = hsts_header(&state) {
        app = app.layer(SetResponseHeaderLayer::if_not_present(
            header::STRICT_TRANSPORT_SECURITY,
            hsts,
        ));
    }

    app.layer(cors_layer(&state))
        // TOTP/recovery payloads are tiny; cap bodies to reject abuse early.
        .layer(RequestBodyLimitLayer::new(16 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
        // Outermost: every request gets an id before anything else sees it,
        // and the id is echoed on the response for client-side correlation.
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .with_state(state)
}

/// Tracing span for each request, carrying the request id so log lines and
/// errors can be correlated with the `x-request-id` the client received.
fn request_span(req: &Request<Body>) -> tracing::Span {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    tracing::info_span!(
        "request",
        method = %req.method(),
        uri = %req.uri(),
        request_id = %request_id,
    )
}

fn hsts_header(state: &AppState) -> Option<HeaderValue> {
    let max_age = state.cfg.server.hsts_max_age_secs;
    if max_age == 0 {
        return None;
    }
    HeaderValue::from_str(&format!("max-age={max_age}; includeSubDomains")).ok()
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
