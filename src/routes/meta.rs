use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::{error::ApiError, state::AppState};

/// Self-contained demo web UI (also publishable as a static site).
const INDEX_HTML: &str = include_str!("../../web/index.html");

/// Swagger UI shell, loaded from a CDN and pointed at our OpenAPI document.
const SWAGGER_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>TOTP Server API</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui.min.css"/>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui-bundle.min.js" crossorigin></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: "/api-docs/openapi.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
      });
    };
  </script>
</body>
</html>"##;

/// Demo web UI at `/`.
pub async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// Liveness probe: the process is up and serving requests. Deliberately does
/// not touch the database, so an outage there does not get every replica
/// restarted; use `/health` as the readiness probe instead.
#[utoipa::path(
    get, path = "/livez", tag = "meta",
    responses((status = 200, description = "Process alive")),
)]
pub async fn livez() -> Response {
    (StatusCode::OK, Json(json!({"status": "alive"}))).into_response()
}

/// Readiness probe: the process is up and the database answers.
#[utoipa::path(
    get, path = "/health", tag = "meta",
    responses(
        (status = 200, description = "Service healthy"),
        (status = 503, description = "Database unavailable"),
    )
)]
pub async fn health(State(state): State<AppState>) -> Response {
    match state.store.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ok"}))).into_response(),
        Err(err) => {
            tracing::error!(error = ?err, "health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status": "degraded"})),
            )
                .into_response()
        }
    }
}

/// Prometheus metrics in text exposition format. When `server.metrics_token`
/// is set, the scrape must present it as a bearer token.
pub async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(expected) = state
        .cfg
        .server
        .metrics_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|h| {
                h.strip_prefix("Bearer ")
                    .or_else(|| h.strip_prefix("bearer "))
            })
            .map(str::trim)
            .unwrap_or("");
        if !bool::from(presented.as_bytes().ct_eq(expected.as_bytes())) {
            return ApiError::Unauthorized.into_response();
        }
    }
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
        .into_response()
}

/// OpenAPI 3.1 document.
pub async fn openapi_json() -> Response {
    use utoipa::OpenApi;
    Json(crate::openapi::ApiDoc::openapi()).into_response()
}

/// Swagger UI.
pub async fn swagger_ui() -> Html<&'static str> {
    Html(SWAGGER_HTML)
}
