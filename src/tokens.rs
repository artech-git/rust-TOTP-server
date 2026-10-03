use anyhow::{Context, anyhow};
use rusty_paseto::prelude::*;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

/// Claims carried by a verified session token.
#[derive(Debug, Clone)]
pub struct SessionClaims {
    pub user_id: String,
    pub email: String,
}

/// Issues and verifies PASETO v4.local session tokens.
///
/// Tokens are symmetric-key encrypted (XChaCha20-Poly1305 under the hood),
/// carry `sub`, `email`, `iat`, `exp`, and are rejected after expiry by the
/// parser. Stateless by design: revocation happens by keeping TTLs short.
pub struct TokenService {
    key: PasetoSymmetricKey<V4, Local>,
    ttl: Duration,
}

impl TokenService {
    pub fn from_hex_key(hex_key: &str, ttl_secs: u64) -> anyhow::Result<Self> {
        let bytes = hex::decode(hex_key.trim()).context("paseto key is not valid hex")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("paseto key must be 32 bytes (64 hex chars)"))?;
        Ok(Self {
            key: PasetoSymmetricKey::from(Key::from(arr)),
            ttl: Duration::seconds(ttl_secs as i64),
        })
    }

    /// Issue a token for the user; returns `(token, expires_at_unix)`.
    pub fn issue(&self, user_id: &str, email: &str) -> anyhow::Result<(String, i64)> {
        let now = OffsetDateTime::now_utc();
        let exp = now + self.ttl;
        let token = PasetoBuilder::<V4, Local>::default()
            .set_claim(ExpirationClaim::try_from(exp.format(&Rfc3339)?)?)
            .set_claim(IssuedAtClaim::try_from(now.format(&Rfc3339)?)?)
            .set_claim(SubjectClaim::from(user_id))
            .set_claim(CustomClaim::try_from(("email", email))?)
            .build(&self.key)
            .map_err(|e| anyhow!("failed to build session token: {e}"))?;
        Ok((token, exp.unix_timestamp()))
    }

    /// Verify a token (authenticity + expiry) and extract its claims.
    pub fn verify(&self, token: &str) -> Option<SessionClaims> {
        let value: serde_json::Value = PasetoParser::<V4, Local>::default()
            .parse(token, &self.key)
            .ok()?;
        let user_id = value.get("sub")?.as_str()?.to_string();
        let email = value.get("email")?.as_str()?.to_string();
        Some(SessionClaims { user_id, email })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_key_hex;

    #[test]
    fn issue_and_verify_roundtrip() {
        let svc = TokenService::from_hex_key(&generate_key_hex(), 3600).unwrap();
        let (token, exp) = svc.issue("user-1", "a@example.com").unwrap();
        assert!(token.starts_with("v4.local."));
        assert!(exp > OffsetDateTime::now_utc().unix_timestamp());

        let claims = svc.verify(&token).expect("token must verify");
        assert_eq!(claims.user_id, "user-1");
        assert_eq!(claims.email, "a@example.com");
    }

    #[test]
    fn verify_rejects_forged_and_foreign_tokens() {
        let svc = TokenService::from_hex_key(&generate_key_hex(), 3600).unwrap();
        let other = TokenService::from_hex_key(&generate_key_hex(), 3600).unwrap();
        let (token, _) = svc.issue("user-1", "a@example.com").unwrap();

        assert!(
            other.verify(&token).is_none(),
            "different key must not verify"
        );
        assert!(svc.verify("v4.local.garbage").is_none());
        let mut tampered = token.clone();
        tampered.pop();
        assert!(svc.verify(&tampered).is_none());
    }

    #[test]
    fn verify_rejects_expired_tokens() {
        // TTL of 0 seconds: expired the moment it is issued.
        let svc = TokenService::from_hex_key(&generate_key_hex(), 60).unwrap();
        let expired = TokenService {
            key: svc.key,
            ttl: Duration::seconds(-5),
        };
        let (token, _) = expired.issue("user-1", "a@example.com").unwrap();
        assert!(
            expired.verify(&token).is_none(),
            "expired token must be rejected"
        );
    }
}
