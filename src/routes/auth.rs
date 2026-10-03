use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    error::ApiError, extract::ClientIp, metrics::auth_event, routes::normalize_email,
    state::AppState, totp::TotpService,
};

// ----------------------------- request/response DTOs -----------------------------

#[derive(Debug, Deserialize, ToSchema)]
pub struct EnrollRequest {
    #[schema(example = "alice@example.com")]
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EnrollResponse {
    pub user_id: String,
    /// Base32 shared secret for manual authenticator entry.
    pub secret: String,
    /// `otpauth://` provisioning URI.
    pub otpauth_url: String,
    /// Inline SVG QR code of the provisioning URI.
    pub qr_svg: String,
    pub digits: u32,
    pub period: u64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConfirmRequest {
    #[schema(example = "alice@example.com")]
    pub email: String,
    #[schema(example = "123456")]
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConfirmResponse {
    pub confirmed: bool,
    /// One-time recovery codes. Shown exactly once — store them now.
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    #[schema(example = "alice@example.com")]
    pub email: String,
    #[schema(example = "123456")]
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RecoveryLoginRequest {
    #[schema(example = "alice@example.com")]
    pub email: String,
    #[schema(example = "ABCDE-FGHJK")]
    pub recovery_code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionResponse {
    /// PASETO v4.local bearer token for `Authorization: Bearer <token>`.
    pub token: String,
    pub token_type: &'static str,
    /// Session expiry as a Unix timestamp (seconds).
    pub expires_at: i64,
    /// Recovery codes remaining (prompt the user to regenerate when low).
    pub recovery_codes_remaining: i64,
}

// ----------------------------------- handlers ------------------------------------

/// Begin TOTP enrollment: provision a secret and return a QR code.
#[utoipa::path(
    post, path = "/api/v1/enroll", tag = "enrollment",
    request_body = EnrollRequest,
    responses(
        (status = 200, description = "Enrollment started", body = EnrollResponse),
        (status = 400, description = "Invalid email", body = crate::error::ErrorBody),
        (status = 409, description = "Account already confirmed", body = crate::error::ErrorBody),
        (status = 429, description = "Too many enrollment attempts", body = crate::error::ErrorBody),
    )
)]
pub async fn enroll(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    if let Err(retry) = state.enroll_limiter.try_acquire(&ip.to_string()) {
        auth_event("enroll", "rate_limited");
        return Err(ApiError::RateLimited {
            retry_after_secs: retry,
        });
    }
    let email = normalize_email(&req.email)?;

    let secret = TotpService::new_secret();
    let secret_enc = state
        .cipher
        .seal(&secret, email.as_bytes())
        .map_err(|e| ApiError::Internal(e.into()))?;

    let user_id = Uuid::new_v4().to_string();
    let created = state
        .store
        .upsert_pending_user(&user_id, &email, &secret_enc)
        .await?;
    if !created {
        auth_event("enroll", "conflict");
        return Err(ApiError::Conflict(
            "an account with this email already exists".into(),
        ));
    }

    // Re-read so we return the id of the row that actually persisted (an
    // existing pending row keeps its original id on re-enrollment).
    let user = state
        .store
        .get_user_by_email(&email)
        .await?
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("user vanished after upsert")))?;

    let otpauth_url = state
        .totp
        .otpauth_url(&secret, &email)
        .map_err(|e| ApiError::Internal(e.into()))?;
    let qr_svg = TotpService::qr_svg(&otpauth_url).map_err(|e| ApiError::Internal(e.into()))?;

    auth_event("enroll", "started");
    Ok(Json(EnrollResponse {
        user_id: user.id,
        secret: TotpService::secret_base32(&secret),
        otpauth_url,
        qr_svg,
        digits: state.totp.digits(),
        period: state.totp.step(),
    }))
}

/// Confirm enrollment with the first code; returns one-time recovery codes.
#[utoipa::path(
    post, path = "/api/v1/enroll/confirm", tag = "enrollment",
    request_body = ConfirmRequest,
    responses(
        (status = 200, description = "Enrollment confirmed", body = ConfirmResponse),
        (status = 400, description = "Invalid email", body = crate::error::ErrorBody),
        (status = 401, description = "Wrong or already-used code", body = crate::error::ErrorBody),
        (status = 429, description = "Too many attempts", body = crate::error::ErrorBody),
    )
)]
pub async fn confirm(
    State(state): State<AppState>,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<ConfirmResponse>, ApiError> {
    let email = normalize_email(&req.email)?;
    let limiter_key = format!("confirm:{email}");
    if let Err(retry) = state.login_limiter.check(&limiter_key) {
        return Err(ApiError::RateLimited {
            retry_after_secs: retry,
        });
    }

    let Some(user) = state.store.get_user_by_email(&email).await? else {
        state.login_limiter.record_failure(&limiter_key);
        return Err(ApiError::Unauthorized);
    };
    if user.totp_confirmed {
        return Err(ApiError::Conflict("account is already confirmed".into()));
    }

    let secret = state
        .cipher
        .open(&user.secret_enc, email.as_bytes())
        .map_err(|e| ApiError::Internal(e.into()))?;

    let now = TotpService::now();
    let matched = state
        .totp
        .verify(&secret, &req.code, now)
        .map_err(|e| ApiError::Internal(e.into()))?;
    let Some(period) = matched else {
        state.login_limiter.record_failure(&limiter_key);
        auth_event("confirm", "failure");
        return Err(ApiError::Unauthorized);
    };

    if !state.store.confirm_user(&user.id, period as i64).await? {
        // Lost a race with a concurrent confirm; treat as already done.
        return Err(ApiError::Conflict("account is already confirmed".into()));
    }

    let codes = crate::recovery::generate_codes(state.cfg.security.recovery_code_count);
    let hashes = hash_codes(&state, &codes).await?;
    state
        .store
        .replace_recovery_codes(&user.id, &hashes)
        .await?;

    state.login_limiter.clear(&limiter_key);
    auth_event("confirm", "success");
    Ok(Json(ConfirmResponse {
        confirmed: true,
        recovery_codes: codes,
    }))
}

/// Authenticate with a TOTP code and receive a session token.
#[utoipa::path(
    post, path = "/api/v1/login", tag = "authentication",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Authenticated", body = SessionResponse),
        (status = 401, description = "Invalid credentials", body = crate::error::ErrorBody),
        (status = 429, description = "Account temporarily locked", body = crate::error::ErrorBody),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<SessionResponse>, ApiError> {
    let email = normalize_email(&req.email)?;
    if let Err(retry) = state.login_limiter.check(&email) {
        auth_event("login", "rate_limited");
        return Err(ApiError::RateLimited {
            retry_after_secs: retry,
        });
    }

    // Always resolve the user, but fold every failure into one generic error
    // so the endpoint never reveals whether the email exists.
    let user = state.store.get_user_by_email(&email).await?;
    let authenticated = match &user {
        Some(u) if u.totp_confirmed => {
            let secret = state
                .cipher
                .open(&u.secret_enc, email.as_bytes())
                .map_err(|e| ApiError::Internal(e.into()))?;
            match state
                .totp
                .verify(&secret, &req.code, TotpService::now())
                .map_err(|e| ApiError::Internal(e.into()))?
            {
                // Replay protection: the matched step must be strictly newer
                // than the last one consumed for this user.
                Some(period) => state.store.try_consume_period(&u.id, period as i64).await?,
                None => false,
            }
        }
        _ => false,
    };

    if !authenticated {
        register_failure(&state, &email);
        auth_event("login", "failure");
        return Err(ApiError::Unauthorized);
    }

    let user = user.expect("authenticated implies user exists");
    state.login_limiter.clear(&email);
    auth_event("login", "success");
    issue_session(&state, &user.id, &user.email).await
}

/// Authenticate with a one-time recovery code (lost-device fallback).
#[utoipa::path(
    post, path = "/api/v1/login/recovery", tag = "authentication",
    request_body = RecoveryLoginRequest,
    responses(
        (status = 200, description = "Authenticated", body = SessionResponse),
        (status = 401, description = "Invalid credentials", body = crate::error::ErrorBody),
        (status = 429, description = "Account temporarily locked", body = crate::error::ErrorBody),
    )
)]
pub async fn login_recovery(
    State(state): State<AppState>,
    Json(req): Json<RecoveryLoginRequest>,
) -> Result<Json<SessionResponse>, ApiError> {
    let email = normalize_email(&req.email)?;
    if let Err(retry) = state.login_limiter.check(&email) {
        auth_event("recovery_login", "rate_limited");
        return Err(ApiError::RateLimited {
            retry_after_secs: retry,
        });
    }

    let user = state.store.get_user_by_email(&email).await?;
    let mut authenticated_user = None;
    if let Some(u) = &user
        && u.totp_confirmed
    {
        for (code_id, hash) in state.store.unused_recovery_codes(&u.id).await? {
            if state.recovery_hasher.verify(&req.recovery_code, &hash) {
                // Atomically burn the code; if another request burned it
                // first, this attempt fails.
                if state.store.mark_recovery_code_used(code_id).await? {
                    authenticated_user = Some(u.clone());
                }
                break;
            }
        }
    }

    let Some(u) = authenticated_user else {
        register_failure(&state, &email);
        auth_event("recovery_login", "failure");
        return Err(ApiError::Unauthorized);
    };

    state.login_limiter.clear(&email);
    auth_event("recovery_login", "success");
    issue_session(&state, &u.id, &u.email).await
}

// ----------------------------------- helpers -------------------------------------

fn register_failure(state: &AppState, email: &str) {
    if let Some(secs) = state.login_limiter.record_failure(email) {
        auth_event("login", "lockout");
        tracing::warn!(
            lockout_secs = secs,
            "account locked after repeated failures"
        );
    }
}

async fn issue_session(
    state: &AppState,
    user_id: &str,
    email: &str,
) -> Result<Json<SessionResponse>, ApiError> {
    let (token, expires_at) = state
        .tokens
        .issue(user_id, email)
        .map_err(ApiError::Internal)?;
    let remaining = state.store.count_unused_recovery_codes(user_id).await?;
    Ok(Json(SessionResponse {
        token,
        token_type: "Bearer",
        expires_at,
        recovery_codes_remaining: remaining,
    }))
}

/// Hash recovery codes off the async runtime (Argon2id is CPU-bound).
pub async fn hash_codes(state: &AppState, codes: &[String]) -> Result<Vec<String>, ApiError> {
    let hasher = state.recovery_hasher.clone();
    let codes = codes.to_vec();
    tokio::task::spawn_blocking(move || {
        codes
            .iter()
            .map(|c| hasher.hash(c))
            .collect::<anyhow::Result<Vec<_>>>()
    })
    .await
    .map_err(|e| ApiError::Internal(e.into()))?
    .map_err(ApiError::Internal)
}
