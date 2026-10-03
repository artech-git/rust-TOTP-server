use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::config::TotpConfig;

/// RFC 4226 recommends a 160-bit shared secret for SHA-1 based HOTP/TOTP.
pub const SECRET_LEN: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("could not build TOTP context: {0}")]
    Context(String),
    #[error("could not render QR code: {0}")]
    Qr(String),
}

/// Stateless RFC 6238 TOTP engine.
///
/// Verification accepts a configurable clock-drift window (`skew` steps on
/// each side of "now") and reports the matched time-step so callers can
/// enforce one-time use of each code (replay protection).
pub struct TotpService {
    issuer: String,
    digits: u32,
    step: u64,
    skew: u8,
}

impl TotpService {
    pub fn new(cfg: &TotpConfig) -> Self {
        Self {
            issuer: cfg.issuer.replace(':', "-"),
            digits: cfg.digits,
            step: cfg.step,
            skew: cfg.skew,
        }
    }

    pub fn digits(&self) -> u32 {
        self.digits
    }

    pub fn step(&self) -> u64 {
        self.step
    }

    /// Generate a fresh 160-bit shared secret.
    pub fn new_secret() -> Vec<u8> {
        crate::crypto::random_bytes::<SECRET_LEN>().to_vec()
    }

    pub fn secret_base32(secret: &[u8]) -> String {
        Secret::Raw(secret.to_vec()).to_encoded().to_string()
    }

    fn context(&self, secret: &[u8], account: &str) -> Result<TOTP, TotpError> {
        TOTP::new(
            Algorithm::SHA1,
            self.digits as usize,
            self.skew,
            self.step,
            secret.to_vec(),
            Some(self.issuer.clone()),
            account.replace(':', "-"),
        )
        .map_err(|e| TotpError::Context(e.to_string()))
    }

    /// `otpauth://` provisioning URI for authenticator apps.
    pub fn otpauth_url(&self, secret: &[u8], account: &str) -> Result<String, TotpError> {
        Ok(self.context(secret, account)?.get_url())
    }

    /// Render the provisioning URI as an SVG QR code.
    pub fn qr_svg(url: &str) -> Result<String, TotpError> {
        use qrcode::render::svg;
        let code = qrcode::QrCode::new(url.as_bytes()).map_err(|e| TotpError::Qr(e.to_string()))?;
        Ok(code
            .render::<svg::Color>()
            .min_dimensions(240, 240)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build())
    }

    /// Code for an explicit Unix timestamp (used by tests and tooling).
    pub fn code_at(&self, secret: &[u8], time: u64) -> Result<String, TotpError> {
        Ok(self.context(secret, "account")?.generate(time))
    }

    /// Verify `code` against the window `[now - skew*step, now + skew*step]`.
    ///
    /// Returns the matched time-step counter on success. Comparison is
    /// constant-time per candidate, and every candidate in the window is
    /// evaluated (no early exit).
    pub fn verify(&self, secret: &[u8], code: &str, now: u64) -> Result<Option<u64>, TotpError> {
        let code = code.trim();
        if code.len() != self.digits as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(None);
        }
        let ctx = self.context(secret, "account")?;
        let mut matched: Option<u64> = None;
        for offset in -(self.skew as i64)..=(self.skew as i64) {
            let t = now as i64 + offset * self.step as i64;
            if t < 0 {
                continue;
            }
            let candidate = ctx.generate(t as u64);
            if candidate.as_bytes().ct_eq(code.as_bytes()).into() {
                matched = Some(t as u64 / self.step);
            }
        }
        Ok(matched)
    }

    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_secs()
    }

    /// Time-step counter for a Unix timestamp.
    pub fn period(&self, time: u64) -> u64 {
        time / self.step
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> TotpService {
        TotpService::new(&TotpConfig::default())
    }

    #[test]
    fn verify_accepts_current_and_skewed_codes() {
        let svc = svc();
        let secret = TotpService::new_secret();
        let now = 1_700_000_000;

        for t in [now - 30, now, now + 30] {
            let code = svc.code_at(&secret, t).unwrap();
            let matched = svc.verify(&secret, &code, now).unwrap();
            assert_eq!(matched, Some(t / 30), "code generated at {t} must verify");
        }
    }

    #[test]
    fn verify_rejects_outside_window_and_garbage() {
        let svc = svc();
        let secret = TotpService::new_secret();
        let now = 1_700_000_000;

        let stale = svc.code_at(&secret, now - 120).unwrap();
        assert_eq!(svc.verify(&secret, &stale, now).unwrap(), None);
        assert_eq!(svc.verify(&secret, "12345", now).unwrap(), None);
        assert_eq!(svc.verify(&secret, "abcdef", now).unwrap(), None);
        assert_eq!(svc.verify(&secret, "", now).unwrap(), None);
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let svc = svc();
        let now = 1_700_000_000;
        let code = svc.code_at(&TotpService::new_secret(), now).unwrap();
        // Overwhelmingly unlikely to collide across the three window slots.
        assert_eq!(
            svc.verify(&TotpService::new_secret(), &code, now).unwrap(),
            None
        );
    }

    #[test]
    fn provisioning_url_is_wellformed() {
        let svc = svc();
        let secret = TotpService::new_secret();
        let url = svc.otpauth_url(&secret, "user@example.com").unwrap();
        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("secret="));
        let svg = TotpService::qr_svg(&url).unwrap();
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"));
    }
}
