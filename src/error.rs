use axum::{
    Json,
    http::{HeaderValue, StatusCode, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

/// Wire format for every non-2xx API response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    /// Stable machine-readable error code.
    #[schema(example = "unauthorized")]
    pub error: &'static str,
    /// Human-readable description.
    #[schema(example = "invalid credentials")]
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    /// Deliberately generic: never reveals whether the user exists, the code
    /// was wrong, or the code was replayed.
    #[error("invalid credentials")]
    Unauthorized,
    #[error("{0}")]
    Conflict(String),
    #[error("not found")]
    NotFound,
    #[error("too many attempts, try again later")]
    RateLimited { retry_after_secs: u64 },
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl ApiError {
    fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Conflict(_) => "conflict",
            Self::NotFound => "not_found",
            Self::RateLimited { .. } => "rate_limited",
            Self::Internal(_) => "internal",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(err) = &self {
            tracing::error!(error = ?err, "internal error while handling request");
        }
        let body = ErrorBody {
            error: self.code(),
            // Never leak internal error details to clients.
            message: match &self {
                Self::Internal(_) => "internal error".to_string(),
                other => other.to_string(),
            },
        };
        let mut resp = (self.status(), Json(body)).into_response();
        if let Self::RateLimited { retry_after_secs } = self
            && let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string())
        {
            resp.headers_mut().insert(RETRY_AFTER, v);
        }
        resp
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        Self::Internal(anyhow::Error::new(err).context("database error"))
    }
}
