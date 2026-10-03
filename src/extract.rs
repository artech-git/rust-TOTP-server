use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts},
};

use crate::{error::ApiError, state::AppState};

/// Extractor for authenticated routes: validates the `Authorization: Bearer`
/// PASETO session token and exposes its claims.
pub struct AuthUser {
    pub user_id: String,
    pub email: String,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or(ApiError::Unauthorized)?;
        let claims = state
            .tokens
            .verify(token.trim())
            .ok_or(ApiError::Unauthorized)?;
        Ok(Self {
            user_id: claims.user_id,
            email: claims.email,
        })
    }
}

/// Best-effort client IP for rate-limiting keys.
///
/// Uses the socket peer address; honors the first `X-Forwarded-For` entry
/// only when `server.trust_proxy` is enabled.
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if state.cfg.server.trust_proxy
            && let Some(forwarded) = parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
            && let Some(first) = forwarded.split(',').next()
            && let Ok(ip) = first.trim().parse::<IpAddr>()
        {
            return Ok(Self(ip));
        }
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        Ok(Self(ip))
    }
}
