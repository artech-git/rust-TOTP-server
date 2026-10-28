use anyhow::{Context, anyhow};
use rusty_paseto::prelude::*;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

/// Claims carried by a verified session token.
#[derive(Debug, Clone)]
pub struct SessionClaims {
    pub user_id: String,
    pub email: String,
    /// The account's `token_version` when the session was issued; a session
    /// is only valid while it still matches the stored value.
    pub version: i32,
}

/// Issues and verifies PASETO v4.local session tokens.
///
/// Tokens are symmetric-key encrypted (XChaCha20-Poly1305 under the hood),
/// carry `sub`, `email`, `ver`, `iat`, `exp`, and are rejected after expiry
/// by the parser. New tokens always use the active key; retired keys only
/// verify, so a key rotation does not log everyone out at once.
pub struct TokenService {
    active: PasetoSymmetricKey<V4, Local>,
    retired: Vec<PasetoSymmetricKey<V4, Local>>,
    ttl: Duration,
}

fn decode_key(hex_key: &str) -> anyhow::Result<PasetoSymmetricKey<V4, Local>> {
    let bytes = hex::decode(hex_key.trim()).context("paseto key is not valid hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("paseto key must be 32 bytes (64 hex chars)"))?;
    Ok(PasetoSymmetricKey::from(Key::from(arr)))
}

impl TokenService {
    pub fn new(active_hex: &str, retired_hex: &[String], ttl_secs: u64) -> anyhow::Result<Self> {
        Ok(Self {
            active: decode_key(active_hex)?,
            retired: retired_hex
                .iter()
                .map(|k| decode_key(k))
                .collect::<anyhow::Result<Vec<_>>>()?,
            ttl: Duration::seconds(ttl_secs as i64),
        })
    }

    pub fn from_hex_key(hex_key: &str, ttl_secs: u64) -> anyhow::Result<Self> {
        Self::new(hex_key, &[], ttl_secs)
    }

    /// Issue a token for the user; returns `(token, expires_at_unix)`.
    pub fn issue(&self, user_id: &str, email: &str, version: i32) -> anyhow::Result<(String, i64)> {
        let now = OffsetDateTime::now_utc();
        let exp = now + self.ttl;
        let token = PasetoBuilder::<V4, Local>::default()
            .set_claim(ExpirationClaim::try_from(exp.format(&Rfc3339)?)?)
            .set_claim(IssuedAtClaim::try_from(now.format(&Rfc3339)?)?)
            .set_claim(SubjectClaim::from(user_id))
            .set_claim(CustomClaim::try_from(("email", email))?)
            .set_claim(CustomClaim::try_from(("ver", version))?)
            .build(&self.active)
            .map_err(|e| anyhow!("failed to build session token: {e}"))?;
        Ok((token, exp.unix_timestamp()))
    }

    /// Verify a token (authenticity + expiry) with the active key or any
    /// retired key, and extract its claims.
    pub fn verify(&self, token: &str) -> Option<SessionClaims> {
        std::iter::once(&self.active)
            .chain(self.retired.iter())
            .find_map(|key| PasetoParser::<V4, Local>::default().parse(token, key).ok())
            .and_then(|value| {
                let user_id = value.get("sub")?.as_str()?.to_string();
                let email = value.get("email")?.as_str()?.to_string();
                // Sessions issued before the claim existed count as version 0,
                // which is what every account starts at.
                let version = value.get("ver").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                Some(SessionClaims {
                    user_id,
                    email,
                    version,
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_key_hex;

    #[test]
    fn issue_and_verify_roundtrip() {
        let svc = TokenService::from_hex_key(&generate_key_hex(), 3600).unwrap();
        let (token, exp) = svc.issue("user-1", "a@example.com", 3).unwrap();
        assert!(token.starts_with("v4.local."));
        assert!(exp > OffsetDateTime::now_utc().unix_timestamp());

        let claims = svc.verify(&token).expect("token must verify");
        assert_eq!(claims.user_id, "user-1");
        assert_eq!(claims.email, "a@example.com");
        assert_eq!(claims.version, 3);
    }

    #[test]
    fn verify_rejects_forged_and_foreign_tokens() {
        let svc = TokenService::from_hex_key(&generate_key_hex(), 3600).unwrap();
        let other = TokenService::from_hex_key(&generate_key_hex(), 3600).unwrap();
        let (token, _) = svc.issue("user-1", "a@example.com", 0).unwrap();

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
        let svc = TokenService::from_hex_key(&generate_key_hex(), 60).unwrap();
        let expired = TokenService {
            active: svc.active,
            retired: Vec::new(),
            ttl: Duration::seconds(-5),
        };
        let (token, _) = expired.issue("user-1", "a@example.com", 0).unwrap();
        assert!(
            expired.verify(&token).is_none(),
            "expired token must be rejected"
        );
    }

    #[test]
    fn retired_keys_verify_but_do_not_issue() {
        let old = generate_key_hex();
        let new = generate_key_hex();
        let (old_token, _) = TokenService::from_hex_key(&old, 3600)
            .unwrap()
            .issue("user-1", "a@example.com", 0)
            .unwrap();

        let rotated = TokenService::new(&new, std::slice::from_ref(&old), 3600).unwrap();
        assert!(
            rotated.verify(&old_token).is_some(),
            "old sessions stay valid"
        );
        let (new_token, _) = rotated.issue("user-1", "a@example.com", 0).unwrap();
        assert!(
            TokenService::from_hex_key(&old, 3600)
                .unwrap()
                .verify(&new_token)
                .is_none(),
            "new tokens are issued under the active key only"
        );
        assert!(
            TokenService::from_hex_key(&new, 3600)
                .unwrap()
                .verify(&old_token)
                .is_none(),
            "dropping the retired key ends its sessions"
        );
    }
}
