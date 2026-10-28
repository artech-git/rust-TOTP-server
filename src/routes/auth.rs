use std::net::IpAddr;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    error::ApiError,
    extract::ClientIp,
    metrics::auth_event,
    ratelimit::Decision,
    recovery::{self, HashedCode},
    routes::normalize_email,
    state::AppState,
    store::UserRecord,
    totp::TotpService,
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
    #[schema(example = "ABCD-EFGH-JKMN")]
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
    if let Decision::Limited { retry_after_secs } =
        state.enroll_limiter.try_acquire(&ip.to_string()).await?
    {
        auth_event("enroll", "rate_limited");
        return Err(ApiError::RateLimited { retry_after_secs });
    }
    let email = normalize_email(&req.email)?;

    let secret = TotpService::new_secret();
    let secret_enc = state
        .keys
        .seal(&secret, email.as_bytes())
        .map_err(|e| ApiError::Internal(e.into()))?;

    // An existing pending row keeps its original id when enrollment is
    // restarted, so the id that actually persisted comes back from the store.
    let candidate_id = Uuid::new_v4().to_string();
    let Some(user_id) = state
        .store
        .upsert_pending_user(&candidate_id, &email, &secret_enc, state.keys.active_id())
        .await?
    else {
        auth_event("enroll", "conflict");
        return Err(ApiError::Conflict(
            "an account with this email already exists".into(),
        ));
    };

    let otpauth_url = state
        .totp
        .otpauth_url(&secret, &email)
        .map_err(|e| ApiError::Internal(e.into()))?;
    let qr_svg = TotpService::qr_svg(&otpauth_url).map_err(|e| ApiError::Internal(e.into()))?;

    auth_event("enroll", "started");
    Ok(Json(EnrollResponse {
        user_id,
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
    ClientIp(ip): ClientIp,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<ConfirmResponse>, ApiError> {
    throttle_ip(&state, ip, "confirm").await?;
    let email = normalize_email(&req.email)?;
    let limiter_key = format!("confirm:{email}");
    if let Decision::Limited { retry_after_secs } = state.login_limiter.check(&limiter_key).await? {
        return Err(ApiError::RateLimited { retry_after_secs });
    }

    let Some(user) = state.store.get_user_by_email(&email).await? else {
        decoy_totp_check(&state, &req.code);
        state.login_limiter.record_failure(&limiter_key).await?;
        return Err(ApiError::Unauthorized);
    };
    if user.totp_confirmed {
        return Err(ApiError::Conflict("account is already confirmed".into()));
    }

    let secret = open_secret(&state, &user).await?;

    let now = TotpService::now();
    let matched = state
        .totp
        .verify(&secret, &req.code, now)
        .map_err(|e| ApiError::Internal(e.into()))?;
    let Some(period) = matched else {
        state.login_limiter.record_failure(&limiter_key).await?;
        auth_event("confirm", "failure");
        return Err(ApiError::Unauthorized);
    };

    if !state.store.confirm_user(&user.id, period as i64).await? {
        // Lost a race with a concurrent confirm; treat as already done.
        return Err(ApiError::Conflict("account is already confirmed".into()));
    }

    let codes = recovery::generate_codes(state.cfg.security.recovery_code_count);
    let hashes = hash_codes(&state, &codes).await?;
    state
        .store
        .replace_recovery_codes(&user.id, &hashes)
        .await?;

    state.login_limiter.clear(&limiter_key).await?;
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
        (status = 429, description = "Account temporarily locked or client throttled", body = crate::error::ErrorBody),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<LoginRequest>,
) -> Result<Json<SessionResponse>, ApiError> {
    throttle_ip(&state, ip, "login").await?;
    let email = normalize_email(&req.email)?;
    if let Decision::Limited { retry_after_secs } = state.login_limiter.check(&email).await? {
        auth_event("login", "rate_limited");
        return Err(ApiError::RateLimited { retry_after_secs });
    }

    // Always resolve the user, but fold every failure into one generic error
    // so the endpoint never reveals whether the email exists.
    let user = state.store.get_user_by_email(&email).await?;
    let authenticated = match &user {
        Some(u) if u.totp_confirmed => {
            let secret = open_secret(&state, u).await?;
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
        _ => {
            decoy_totp_check(&state, &req.code);
            false
        }
    };

    if !authenticated {
        register_failure(&state, &email).await?;
        auth_event("login", "failure");
        return Err(ApiError::Unauthorized);
    }

    let user = user.expect("authenticated implies user exists");
    state.login_limiter.clear(&email).await?;
    auth_event("login", "success");
    issue_session(&state, &user).await
}

/// Authenticate with a one-time recovery code (lost-device fallback).
#[utoipa::path(
    post, path = "/api/v1/login/recovery", tag = "authentication",
    request_body = RecoveryLoginRequest,
    responses(
        (status = 200, description = "Authenticated", body = SessionResponse),
        (status = 401, description = "Invalid credentials", body = crate::error::ErrorBody),
        (status = 429, description = "Account temporarily locked or client throttled", body = crate::error::ErrorBody),
    )
)]
pub async fn login_recovery(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(req): Json<RecoveryLoginRequest>,
) -> Result<Json<SessionResponse>, ApiError> {
    throttle_ip(&state, ip, "recovery_login").await?;
    let email = normalize_email(&req.email)?;
    if let Decision::Limited { retry_after_secs } = state.login_limiter.check(&email).await? {
        auth_event("recovery_login", "rate_limited");
        return Err(ApiError::RateLimited { retry_after_secs });
    }

    let user = state.store.get_user_by_email(&email).await?;
    // Only the codes sharing the presented code's lookup prefix are candidates
    // (normally exactly one), so a recovery attempt costs one Argon2id
    // verification instead of one per unused code.
    let lookup = recovery::lookup_key(&req.recovery_code);
    let candidates = match &user {
        Some(u) if u.totp_confirmed => state.store.candidate_recovery_codes(&u.id, &lookup).await?,
        _ => Vec::new(),
    };
    let matched = verify_recovery_code(&state, &req.recovery_code, candidates).await?;

    let mut authenticated_user = None;
    if let (Some(u), Some(code_id)) = (&user, matched)
        // Atomically burn the code; if another request burned it first,
        // this attempt fails.
        && state.store.mark_recovery_code_used(code_id).await?
    {
        authenticated_user = Some(u.clone());
    }

    let Some(u) = authenticated_user else {
        register_failure(&state, &email).await?;
        auth_event("recovery_login", "failure");
        return Err(ApiError::Unauthorized);
    };

    state.login_limiter.clear(&email).await?;
    auth_event("recovery_login", "success");
    issue_session(&state, &u).await
}

// ----------------------------------- helpers -------------------------------------

/// Per-client-IP budget shared by login, confirm and recovery.
async fn throttle_ip(state: &AppState, ip: IpAddr, event: &'static str) -> Result<(), ApiError> {
    if let Decision::Limited { retry_after_secs } =
        state.auth_ip_limiter.try_acquire(&ip.to_string()).await?
    {
        auth_event(event, "ip_throttled");
        return Err(ApiError::RateLimited { retry_after_secs });
    }
    Ok(())
}

/// Do the decrypt + HOTP work of a real verification against decoy material,
/// so unknown and unconfirmed accounts take as long as real ones.
fn decoy_totp_check(state: &AppState, code: &str) {
    if let Ok(opened) = state.keys.open(
        &state.decoy.secret_enc,
        Some(state.keys.active_id()),
        &state.decoy.aad,
    ) {
        let _ = state
            .totp
            .verify(&opened.plaintext, code, TotpService::now());
    }
}

/// Open a user's sealed TOTP secret. A secret sealed by a retired key (or
/// before key ids were recorded) is re-sealed with the active key in passing,
/// so a key rotation completes lazily as accounts are used.
async fn open_secret(state: &AppState, user: &UserRecord) -> Result<Vec<u8>, ApiError> {
    let opened = state
        .keys
        .open(
            &user.secret_enc,
            user.secret_key_id.as_deref(),
            user.email.as_bytes(),
        )
        .map_err(|e| ApiError::Internal(e.into()))?;
    if opened.needs_reseal {
        let resealed = state
            .keys
            .seal(&opened.plaintext, user.email.as_bytes())
            .map_err(|e| ApiError::Internal(e.into()))?;
        if let Err(err) = state
            .store
            .reseal_secret(
                &user.id,
                &user.secret_enc,
                &resealed,
                state.keys.active_id(),
            )
            .await
        {
            tracing::warn!(error = %err, "could not re-seal the secret with the active key");
        }
    }
    Ok(opened.plaintext)
}

async fn register_failure(state: &AppState, email: &str) -> Result<(), ApiError> {
    if let Some(secs) = state.login_limiter.record_failure(email).await? {
        auth_event("login", "lockout");
        tracing::warn!(
            lockout_secs = secs,
            "account locked after repeated failures"
        );
    }
    Ok(())
}

async fn issue_session(
    state: &AppState,
    user: &UserRecord,
) -> Result<Json<SessionResponse>, ApiError> {
    let (token, expires_at) = state
        .tokens
        .issue(&user.id, &user.email, user.token_version)
        .map_err(ApiError::Internal)?;
    let remaining = state.store.count_unused_recovery_codes(&user.id).await?;
    Ok(Json(SessionResponse {
        token,
        token_type: "Bearer",
        expires_at,
        recovery_codes_remaining: remaining,
    }))
}

/// Hash recovery codes off the async runtime (Argon2id is CPU-bound), holding
/// a gate permit for the duration so bursts cannot exhaust the blocking pool.
pub async fn hash_codes(state: &AppState, codes: &[String]) -> Result<Vec<HashedCode>, ApiError> {
    let permit = state
        .argon2_gate
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| ApiError::Internal(e.into()))?;
    let hasher = state.recovery_hasher.clone();
    let codes = codes.to_vec();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        codes
            .iter()
            .map(|code| {
                Ok(HashedCode {
                    hash: hasher.hash(code)?,
                    lookup: recovery::lookup_key(code),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()
    })
    .await
    .map_err(|e| ApiError::Internal(e.into()))?
    .map_err(ApiError::Internal)
}

/// Verify a presented recovery code against the candidate hashes, off the
/// async runtime and behind the Argon2 gate. An empty candidate list (unknown
/// account, or no code with that prefix) still costs one verification, against
/// the decoy hash, so timing does not reveal which case it was. Returns the id
/// of the matching code.
async fn verify_recovery_code(
    state: &AppState,
    code: &str,
    candidates: Vec<(i64, String)>,
) -> Result<Option<i64>, ApiError> {
    let permit = state
        .argon2_gate
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| ApiError::Internal(e.into()))?;
    let hasher = state.recovery_hasher.clone();
    let decoy = state.decoy.clone();
    let code = code.to_string();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if candidates.is_empty() {
            hasher.verify(&code, &decoy.recovery_hash);
            return None;
        }
        candidates
            .into_iter()
            .find(|(_, hash)| hasher.verify(&code, hash))
            .map(|(id, _)| id)
    })
    .await
    .map_err(|e| ApiError::Internal(e.into()))
}
