use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde_json::json;

use crate::state::AppState;

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

/// Liveness + database readiness probe.
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

/// Prometheus metrics in text exposition format.
pub async fn metrics(State(state): State<AppState>) -> Response {
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
