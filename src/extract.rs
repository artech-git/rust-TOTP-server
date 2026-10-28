use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, header::AUTHORIZATION, request::Parts},
};

use crate::{config::ServerConfig, error::ApiError, state::AppState, store::UserRecord};

/// Extractor for authenticated routes: validates the `Authorization: Bearer`
/// PASETO session token, loads the account, and rejects sessions that have
/// been revoked (the token's `ver` claim must match the stored
/// `token_version`).
pub struct AuthUser {
    pub user_id: String,
    pub email: String,
    /// The account as currently stored.
    pub user: UserRecord,
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
        let user = state
            .store
            .get_user_by_id(&claims.user_id)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        if user.token_version != claims.version {
            return Err(ApiError::Unauthorized);
        }
        Ok(Self {
            user_id: claims.user_id,
            email: claims.email,
            user,
        })
    }
}

/// Best-effort client IP for rate-limiting keys.
///
/// Without `server.trust_proxy` this is the socket peer address. With it, the
/// address is recovered from the proxy chain; see [`resolve_client_ip`].
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        Ok(Self(resolve_client_ip(
            &parts.headers,
            peer,
            &state.cfg.server,
        )))
    }
}

/// Resolve the client address behind `trusted_proxy_hops` reverse proxies.
///
/// Proxies *append* the address they saw to `X-Forwarded-For`, so only the
/// last `trusted_proxy_hops` entries can be trusted; the leading entries are
/// whatever the client chose to send. With one trusted hop the client address
/// is the last entry, with two it is the second to last, and so on. A header
/// the edge itself overwrites (`client_ip_header`, e.g. `CF-Connecting-IP`)
/// takes precedence. When the chain is shorter than the configured hops the
/// request did not come through the proxies, and the peer address is used.
pub fn resolve_client_ip(headers: &HeaderMap, peer: Option<IpAddr>, cfg: &ServerConfig) -> IpAddr {
    let fallback = peer.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if !cfg.trust_proxy {
        return fallback;
    }

    if let Some(name) = cfg
        .client_ip_header
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        && let Some(value) = headers.get(name).and_then(|v| v.to_str().ok())
        && let Ok(ip) = value.trim().parse::<IpAddr>()
    {
        return ip;
    }

    // Repeated header lines are joined in order, matching how proxies that
    // add a new line rather than extend the value behave.
    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let hops = usize::from(cfg.trusted_proxy_hops.max(1));
    if let Some(index) = entries.len().checked_sub(hops)
        && let Ok(ip) = entries[index].parse::<IpAddr>()
    {
        return ip;
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    fn cfg(trust_proxy: bool, hops: u8, header: Option<&str>) -> ServerConfig {
        ServerConfig {
            trust_proxy,
            trusted_proxy_hops: hops,
            client_ip_header: header.map(String::from),
            ..ServerConfig::default()
        }
    }

    fn forwarded(lines: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append("x-forwarded-for", HeaderValue::from_str(line).unwrap());
        }
        headers
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forwarded_headers_are_ignored_unless_the_proxy_is_trusted() {
        let headers = forwarded(&["203.0.113.9"]);
        assert_eq!(
            resolve_client_ip(&headers, Some(PEER), &cfg(false, 1, None)),
            PEER
        );
    }

    #[test]
    fn forged_leading_entries_cannot_spoof_the_client_address() {
        // The client sent "198.51.100.7"; the trusted proxy appended the
        // address it actually saw.
        let headers = forwarded(&["198.51.100.7, 203.0.113.9"]);
        assert_eq!(
            resolve_client_ip(&headers, Some(PEER), &cfg(true, 1, None)),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn counts_back_through_multiple_trusted_hops() {
        let headers = forwarded(&["1.1.1.1, 203.0.113.9, 10.1.2.3"]);
        assert_eq!(
            resolve_client_ip(&headers, Some(PEER), &cfg(true, 2, None)),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn repeated_header_lines_are_joined_in_order() {
        let headers = forwarded(&["198.51.100.7", "203.0.113.9"]);
        assert_eq!(
            resolve_client_ip(&headers, Some(PEER), &cfg(true, 1, None)),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn chains_shorter_than_the_trusted_hops_fall_back_to_the_peer() {
        let headers = forwarded(&["203.0.113.9"]);
        assert_eq!(
            resolve_client_ip(&headers, Some(PEER), &cfg(true, 2, None)),
            PEER
        );
        assert_eq!(
            resolve_client_ip(&HeaderMap::new(), Some(PEER), &cfg(true, 1, None)),
            PEER
        );
    }

    #[test]
    fn an_edge_set_header_wins_over_forwarded_for() {
        let mut headers = forwarded(&["198.51.100.7, 203.0.113.9"]);
        headers.insert("cf-connecting-ip", HeaderValue::from_static("192.0.2.44"));
        assert_eq!(
            resolve_client_ip(
                &headers,
                Some(PEER),
                &cfg(true, 1, Some("CF-Connecting-IP"))
            ),
            ip("192.0.2.44")
        );
    }

    #[test]
    fn unparseable_entries_fall_back_to_the_peer() {
        let headers = forwarded(&["not-an-ip"]);
        assert_eq!(
            resolve_client_ip(&headers, Some(PEER), &cfg(true, 1, None)),
            PEER
        );
    }
}
